//! mc-router — Minecraft Java Edition reverse proxy
//!
//! Tokio's multi-threaded runtime is used by default (one thread per CPU core),
//! so every core is utilised without any manual thread management.
//!
//! Per-connection flow:
//!   1. Accept TCP connection
//!   2. Buffer bytes until the Handshake packet is fully received
//!   3. Parse the ServerAddress field (hostname the client typed)
//!   4. Look up the route (with optional fallback via MC_DEFAULT_ROUTE)
//!   5a. Modern client (≥1.20.5) + login → send Transfer packet, client
//!       reconnects directly to backend, proxy is out of the loop.
//!   5b. Older client or status ping → open TCP to backend, replay buffered
//!       bytes, then copy_bidirectional for the rest of the session.

use std::{
    collections::HashMap,
    env,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use notify::{Event, RecursiveMode, Watcher};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Minimum Minecraft protocol version that supports the Transfer packet (1.20.5).
const TRANSFER_MIN_PROTOCOL: i32 = 766;

/// Drop the connection if the handshake hasn't arrived within this window.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Safety cap — no legitimate MC handshake comes anywhere close to this.
const MAX_HANDSHAKE_BYTES: usize = 4096;

// ─── Route map ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Route {
    host: String,
    port: u16,
}

/// The entire routing table.  Wrapped in Arc<ArcSwap<…>> so:
///   • Arc     — shared ownership across tasks without cloning the map
///   • ArcSwap — atomically replace the inner Arc on config reload;
///               readers never block and never see a half-written state
type RouteMap = HashMap<String, Route>;

fn load_config(path: &Path) -> Result<RouteMap> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Config is a flat JSON object: { "hostname": "host:port", … }
    let json: HashMap<String, String> =
        serde_json::from_str(&raw).context("parsing config JSON")?;

    let mut map = RouteMap::new();
    for (hostname, target) in json {
        // Split on the LAST colon so IPv6 addresses are handled correctly
        let route = match target.rfind(':') {
            Some(colon) => Route {
                host: target[..colon].to_string(),
                port: target[colon + 1..].parse::<u16>().unwrap_or(25565),
            },
            None => Route { host: target, port: 25565 },
        };
        map.insert(hostname.to_lowercase(), route);
    }

    println!("[config] loaded {} route(s)", map.len());
    Ok(map)
}

// ─── VarInt / String helpers ──────────────────────────────────────────────────
//
// Minecraft uses a compact variable-length integer encoding: each byte
// contributes 7 data bits; the high bit signals "more bytes follow".

/// Parse a VarInt from `buf` starting at `offset`.
/// Returns `Some((value, bytes_consumed))` or `None` if more data is needed.
fn read_varint(buf: &[u8], offset: usize) -> Option<(i32, usize)> {
    let mut value = 0i32;
    let mut shift = 0usize;
    let mut pos   = offset;
    loop {
        if pos >= buf.len() { return None; }
        let byte = buf[pos] as i32;
        pos += 1;
        value |= (byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 { return Some((value, pos - offset)); }
        if shift >= 35      { return None; } // malformed — too wide
    }
}

fn write_varint(mut value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 { byte |= 0x80; }
        out.push(byte);
        if value == 0 { break; }
    }
    out
}

/// Minecraft String: VarInt(byte_length) followed by raw UTF-8 bytes.
fn write_string(s: &str) -> Vec<u8> {
    let utf8 = s.as_bytes();
    let mut out = write_varint(utf8.len() as u32);
    out.extend_from_slice(utf8);
    out
}

// ─── Handshake parsing ────────────────────────────────────────────────────────

#[derive(Debug)]
struct Handshake {
    protocol_version: i32,
    server_address:   String, // cleaned: lowercase, Forge suffix stripped
    next_state:       i32,    // 1 = status ping, 2 = login, 3 = transfer (rare)
}

/// Read from `stream` into `buf` until a complete Handshake packet is
/// available, then return it.  `buf` accumulates ALL received bytes so
/// they can be replayed to the backend verbatim — nothing is lost.
async fn read_handshake(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<Handshake> {
    loop {
        match try_parse_handshake(buf)? {
            Some(hs) => return Ok(hs),
            None => {
                if buf.len() >= MAX_HANDSHAKE_BYTES {
                    bail!("handshake buffer overflow ({}B)", buf.len());
                }
                let mut tmp = [0u8; 512];
                let n = stream.read(&mut tmp).await.context("read during handshake")?;
                if n == 0 { bail!("connection closed before handshake completed"); }
                buf.extend_from_slice(&tmp[..n]);
            }
        }
    }
}

/// Try to parse a Handshake out of the bytes buffered so far.
/// Returns `Ok(None)` when more data is needed.
fn try_parse_handshake(buf: &[u8]) -> Result<Option<Handshake>> {
    let mut off = 0usize;

    // ── Outer packet framing: [length: VarInt][body…] ────────────────────────
    let (pkt_len, len_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    off += len_bytes;
    if buf.len() < off + pkt_len as usize { return Ok(None); }

    // ── Packet ID (0x00 = Handshake) ─────────────────────────────────────────
    let (pkt_id, id_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    if pkt_id != 0x00 {
        bail!("unexpected packet ID 0x{pkt_id:02x} (expected Handshake 0x00)");
    }
    off += id_bytes;

    // ── Protocol version ─────────────────────────────────────────────────────
    let (protocol_version, proto_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    off += proto_bytes;

    // ── Server address (VarInt-prefixed UTF-8) ────────────────────────────────
    let (addr_len, addr_len_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    off += addr_len_bytes;
    if buf.len() < off + addr_len as usize { return Ok(None); }
    let raw_addr = std::str::from_utf8(&buf[off..off + addr_len as usize])
        .context("server address is not valid UTF-8")?;
    off += addr_len as usize;

    // ── Server port (u16 big-endian) — read but not needed ───────────────────
    if buf.len() < off + 2 { return Ok(None); }
    off += 2;

    // ── Next state ───────────────────────────────────────────────────────────
    let (next_state, _) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };

    // Clean the address:
    //  • strip Forge/FML null-terminated suffix  ("host\0FML2\0…")
    //  • strip optional port suffix              ("host:25565")
    //  • normalise to lowercase
    let server_address = raw_addr
        .split('\0').next().unwrap_or("")
        .split(':').next().unwrap_or("")
        .to_lowercase();

    Ok(Some(Handshake { protocol_version, server_address, next_state }))
}

// ─── Transfer packet ──────────────────────────────────────────────────────────

/// Build a Login Success + Transfer packet pair.
///
/// The client sees Login Success ("you're in") then immediately reads the
/// Transfer packet and opens a new direct connection to the target — the
/// proxy is completely out of the data path from that moment on.
fn build_transfer_packets(host: &str, port: u16) -> Vec<u8> {
    // Login Success: UUID (16 zero bytes) + Name ("") + Properties ([])
    let mut login_payload = Vec::new();
    login_payload.extend_from_slice(&[0u8; 16]); // fake UUID, all zeros
    login_payload.extend(write_string(""));       // username (irrelevant)
    login_payload.extend(write_varint(0));        // property count (none)

    let mut login_body = write_varint(0x02); // Login Success packet ID
    login_body.extend(&login_payload);
    let mut login_frame = write_varint(login_body.len() as u32);
    login_frame.extend(login_body);

    // Transfer: Host (String) + Port (VarInt)
    let mut xfer_payload = Vec::new();
    xfer_payload.extend(write_string(host));
    xfer_payload.extend(write_varint(port as u32));

    let mut xfer_body = write_varint(0x0B); // Transfer packet ID
    xfer_body.extend(&xfer_payload);
    let mut xfer_frame = write_varint(xfer_body.len() as u32);
    xfer_frame.extend(xfer_body);

    let mut out = login_frame;
    out.extend(xfer_frame);
    out
}

// ─── Connection handler ───────────────────────────────────────────────────────

async fn handle_client(
    mut client:  TcpStream,
    routes:      Arc<ArcSwap<RouteMap>>,
    default_key: Arc<Option<String>>,
    client_addr: std::net::SocketAddr,
) {
    if let Err(e) = route_connection(&mut client, routes, default_key, client_addr).await {
        let msg = e.to_string();
        // Connection resets / EOF are completely normal — suppress them
        if !msg.contains("reset") && !msg.contains("closed") && !msg.contains("EOF") {
            eprintln!("[proxy] {client_addr} — {e:#}");
        }
        let _ = client.shutdown().await;
    }
}

async fn route_connection(
    client:      &mut TcpStream,
    routes:      Arc<ArcSwap<RouteMap>>,
    default_key: Arc<Option<String>>,
    client_addr: std::net::SocketAddr,
) -> Result<()> {
    // Disable Nagle's algorithm on the client socket immediately.
    // MC sends lots of small packets; coalescing them adds measurable latency.
    client.set_nodelay(true)?;

    let mut buf = Vec::new();

    let hs = timeout(HANDSHAKE_TIMEOUT, read_handshake(client, &mut buf))
        .await
        .context("handshake timed out")?
        .context("handshake failed")?;

    // ArcSwap::load() is a single atomic pointer read — no mutex, no blocking.
    let route_map = routes.load();

    let route = route_map
        .get(&hs.server_address)
        .or_else(|| {
            // Fall back to MC_DEFAULT_ROUTE key if set
            default_key.as_deref().and_then(|k| route_map.get(k))
        })
        .cloned();

    let route = match route {
        Some(r) => r,
        None => {
            eprintln!(
                "[proxy] {client_addr} → \"{}\" — no route, dropping",
                hs.server_address
            );
            return Ok(());
        }
    };

    // ── Transfer path (MC 1.20.5+ login only) ────────────────────────────────
    let use_transfer =
        hs.next_state == 2 && hs.protocol_version >= TRANSFER_MIN_PROTOCOL;

    if use_transfer {
        println!(
            "[proxy] {client_addr} → \"{}\" — TRANSFER → {}:{}",
            hs.server_address, route.host, route.port
        );
        let pkt = build_transfer_packets(&route.host, route.port);
        client.write_all(&pkt).await?;
        client.shutdown().await?;
        return Ok(());
    }

    // ── Proxy path ───────────────────────────────────────────────────────────
    println!(
        "[proxy] {client_addr} → \"{}\" — PIPE → {}:{}",
        hs.server_address, route.host, route.port
    );

    let mut server = TcpStream::connect((&*route.host, route.port))
        .await
        .with_context(|| format!("connecting to {}:{}", route.host, route.port))?;
    server.set_nodelay(true)?;

    // Replay all buffered bytes: full Handshake + anything else the client
    // sent in the same burst (e.g. Login Start immediately after Handshake).
    server.write_all(&buf).await?;

    // Bidirectional copy until either side closes.
    // Future upgrade path: replace with tokio-uring splice() calls for true
    // zero-copy kernel-to-kernel transfer on Linux.
    tokio::io::copy_bidirectional(client, &mut server).await?;

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

// #[tokio::main] expands to: create a multi-thread runtime with one worker
// thread per CPU core, then run the async main() on it.
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from(
        env::var("MC_CONFIG").unwrap_or_else(|_| "config.json".into()),
    );
    let port: u16 = env::var("MC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(25565);

    // MC_DEFAULT_ROUTE: config key used as fallback when no hostname matches.
    // Example: MC_DEFAULT_ROUTE=jonhosting.com
    let default_key: Arc<Option<String>> = Arc::new(
        env::var("MC_DEFAULT_ROUTE").ok().filter(|s| !s.is_empty()),
    );

    // ── Initial config load ──────────────────────────────────────────────────
    let initial = load_config(&config_path)?;
    let routes: Arc<ArcSwap<RouteMap>> = Arc::new(ArcSwap::from_pointee(initial));

    // ── Config hot-reload watcher ────────────────────────────────────────────
    {
        let routes      = Arc::clone(&routes);
        let config_path = config_path.clone();

        // channel(1): if multiple FS events arrive during the debounce window,
        // try_send silently drops the extras — only one reload fires.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        // notify uses a background OS thread; the closure forwards events into
        // the Tokio async world via the channel.
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    use notify::EventKind::*;
                    if matches!(event.kind, Modify(_) | Create(_)) {
                        let _ = tx.try_send(()); // non-blocking, drop if full
                    }
                }
            })?;
        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        tokio::spawn(async move {
            let _watcher = watcher; // move into task to keep the watcher alive

            while rx.recv().await.is_some() {
                // Debounce: wait 200 ms then drain any extras
                tokio::time::sleep(Duration::from_millis(200)).await;
                while rx.try_recv().is_ok() {}

                println!("[config] change detected, reloading…");
                match load_config(&config_path) {
                    Ok(new_map) => {
                        // Atomically publish the new map; tasks currently reading
                        // the old Arc finish safely, new tasks get the new one.
                        routes.store(Arc::new(new_map));
                    }
                    Err(e) => eprintln!("[config] reload failed: {e}"),
                }
            }
        });
    }

    // ── TCP listener ─────────────────────────────────────────────────────────
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("[server] mc-router listening on :{port}");
    println!("[server] config: {}", config_path.display());
    println!("[server] transfer support: protocol ≥ {TRANSFER_MIN_PROTOCOL} (MC 1.20.5+)");
    if let Some(k) = default_key.as_deref() {
        println!("[server] default route key: \"{k}\"");
    }

    loop {
        let (socket, addr) = listener.accept().await?;
        let routes      = Arc::clone(&routes);
        let default_key = Arc::clone(&default_key);

        // Spawn a lightweight green task per connection.
        // Tokio schedules these across all worker threads automatically —
        // no manual thread pooling needed.
        tokio::spawn(async move {
            handle_client(socket, routes, default_key, addr).await;
        });
    }
}
