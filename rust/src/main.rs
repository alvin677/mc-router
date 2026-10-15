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
//!       bytes, then splice bidirectionally (Linux) or copy_bidirectional.

// Only writes to console in debug mode
macro_rules! debug_print {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}
macro_rules! debug_error {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    };
}

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

const TRANSFER_MIN_PROTOCOL: i32 = 766;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKE_BYTES: usize = 4096;

// ─── Route map ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Route {
    host: String,
    port: u16,
}

type RouteMap = HashMap<String, Route>;

fn load_config(path: &Path) -> Result<RouteMap> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let json: HashMap<String, String> =
        serde_json::from_str(&raw).context("parsing config JSON")?;

    let mut map = RouteMap::new();
    for (hostname, target) in json {
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
        if shift >= 35      { return None; }
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
    server_address:   String,
    next_state:       i32,
}

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

fn try_parse_handshake(buf: &[u8]) -> Result<Option<Handshake>> {
    let mut off = 0usize;

    let (pkt_len, len_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    off += len_bytes;
    if buf.len() < off + pkt_len as usize { return Ok(None); }

    let (pkt_id, id_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    if pkt_id != 0x00 {
        bail!("unexpected packet ID 0x{pkt_id:02x} (expected Handshake 0x00)");
    }
    off += id_bytes;

    let (protocol_version, proto_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    off += proto_bytes;

    let (addr_len, addr_len_bytes) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };
    off += addr_len_bytes;
    if buf.len() < off + addr_len as usize { return Ok(None); }
    let raw_addr = std::str::from_utf8(&buf[off..off + addr_len as usize])
        .context("server address is not valid UTF-8")?;
    off += addr_len as usize;

    if buf.len() < off + 2 { return Ok(None); }
    off += 2;

    let (next_state, _) = match read_varint(buf, off) {
        Some(v) => v,
        None    => return Ok(None),
    };

    let server_address = raw_addr
        .split('\0').next().unwrap_or("")
        .split(':').next().unwrap_or("")
        .to_lowercase();

    Ok(Some(Handshake { protocol_version, server_address, next_state }))
}

// ─── Transfer packet ──────────────────────────────────────────────────────────

fn build_transfer_packets(host: &str, port: u16, protocol: i32) -> Vec<u8> {
    // Login Success payload by protocol version:
    //   766 (1.20.5): UUID + Name + Properties[] + Strict Error Handling (bool)
    //   768 (1.21.2): Strict Error Handling boolean removed
    //   776 (26.2):   Session ID UUID appended after Properties[]
    let mut login_payload = Vec::new();
    login_payload.extend_from_slice(&[0u8; 16]); // player UUID (zeros — client transfers away immediately)
    login_payload.extend(write_string(""));       // username (irrelevant before transfer)
    login_payload.extend(write_varint(0));        // property count (none)
    if protocol <= 767 {
        // Strict Error Handling boolean: added in 1.20.5 (766), removed in 1.21.2 (768).
        // Protocols 766 and 767 (1.20.5, 1.21, 1.21.1) require this field.
        login_payload.push(0x00); // false
    }
    if protocol >= 776 {
        // Session ID UUID: new field added in 26.2 (protocol 776)
        login_payload.extend_from_slice(&[0u8; 16]);
    }

    let mut login_body = write_varint(0x02);
    login_body.extend(&login_payload);
    let mut login_frame = write_varint(login_body.len() as u32);
    login_frame.extend(login_body);

    let mut xfer_payload = Vec::new();
    xfer_payload.extend(write_string(host));
    xfer_payload.extend(write_varint(port as u32));

    // Transfer packet ID in configuration state varies by protocol:
    //   766–776 (1.20.5–26.2): store_cookie = 0x0A, transfer = 0x0B
    //   ≥777    (26.3+):       CLIENTBOUND_POST_EFFECTS inserted at 0x0A,
    //                          pushing store_cookie → 0x0B, transfer → 0x0C
    let transfer_id: u32 = if protocol >= 777 { 0x0C } else { 0x0B };
    let mut xfer_body = write_varint(transfer_id);
    xfer_body.extend(&xfer_payload);
    let mut xfer_frame = write_varint(xfer_body.len() as u32);
    xfer_frame.extend(xfer_body);

    let mut out = login_frame;
    out.extend(xfer_frame);
    out
}

// ─── Zero-copy splice (Linux only) ───────────────────────────────────────────
//
// On Linux, splice(2) moves data between two file descriptors entirely inside
// the kernel — no copy into userspace at all.  The catch: you can't splice
// directly between two TCP sockets; you need a pipe as an intermediary kernel
// buffer:
//
//   client_fd ──splice──▶ pipe_write
//   pipe_read  ──splice──▶ server_fd
//
// We run one thread per direction so neither blocks the other.  The threads
// are handed to spawn_blocking so they don't occupy Tokio's async workers.
//
// Compared to copy_bidirectional (which copies data client→userspace→server
// via 8 KB stack buffers), splice:
//   • eliminates two memory copies per packet in each direction
//   • reduces syscall count with large pipe buffers (1 MiB)
//   • frees CPU that would otherwise be spent on memcpy
//
// The improvement is most visible under load (many concurrent connections)
// and for high-bandwidth sessions (e.g. resource-pack downloads).

#[cfg(target_os = "linux")]
mod zero_copy {
    use anyhow::Result;
    use std::net::TcpStream;
    use std::os::unix::io::AsRawFd;

    // ── RAII pipe fd wrapper ──────────────────────────────────────────────────
    //
    // Rust's ownership system doesn't track raw file descriptors, so we wrap
    // them in a struct that closes the fd when it goes out of scope.
    // This is the Rust equivalent of a smart pointer — "if it's owned, it gets
    // cleaned up automatically".

    struct OwnedFd(i32);

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            // SAFETY: self.0 is a valid, open fd that we own exclusively.
            unsafe { libc::close(self.0); }
        }
    }

    // OwnedFd is safe to send across threads: it's just an integer, and we
    // ensure exactly one OwnedFd owns each fd value.
    // SAFETY: i32 is trivially Send; we never alias the fd.
    unsafe impl Send for OwnedFd {}

    impl OwnedFd {
        fn raw(&self) -> i32 { self.0 }
    }

    // ── Pipe creation ─────────────────────────────────────────────────────────

    fn make_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0i32; 2];

        // pipe2 with O_CLOEXEC: the fds are automatically closed if we exec
        // another process (not that we do, but it's good hygiene).
        // SAFETY: fds is a valid 2-element array.
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // Request a 1 MiB pipe buffer.
        // Default is 64 KiB on most kernels.  A larger buffer means fewer
        // round-trips between the two splice calls (read-side blocks less
        // often waiting for the write-side to fill it).
        // F_SETPIPE_SZ may be limited by /proc/sys/fs/pipe-max-size (usually
        // 1 MiB for non-root), so we ignore failures gracefully.
        unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 1 << 20); }

        Ok((OwnedFd(fds[0]), OwnedFd(fds[1])))
    }

    // ── One-directional splice loop ───────────────────────────────────────────
    //
    // Moves bytes from src_fd → pipe → dst_fd until EOF or error.
    // On EOF, shuts down the write side of dst_fd so the remote peer sees a
    // clean FIN and the corresponding reverse splice exits too.

    fn splice_half(src_fd: i32, pipe_r: &OwnedFd, pipe_w: &OwnedFd, dst_fd: i32) {
        // 128 KiB per splice call.  Large enough to amortise syscall overhead;
        // the kernel will only move as many bytes as are actually available.
        const CHUNK: usize = 1 << 17;

        loop {
            // Phase 1: pull data from src into the pipe (kernel buffer).
            // This blocks until at least 1 byte is available.
            // SAFETY: all fds are valid and open for the duration of this call.
            let n = unsafe {
                libc::splice(
                    src_fd,        std::ptr::null_mut(),
                    pipe_w.raw(),  std::ptr::null_mut(),
                    CHUNK,
                    libc::SPLICE_F_MOVE,
                )
            };

            if n == 0 {
                // Clean EOF on src — signal dst that we're done.
                unsafe { libc::shutdown(dst_fd, libc::SHUT_WR); }
                return;
            }
            if n < 0 {
                // SAFETY: __errno_location() is always valid.
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR { continue; } // interrupted, retry
                // ECONNRESET, EPIPE, EBADF — peer gone, exit quietly.
                unsafe { libc::shutdown(dst_fd, libc::SHUT_WR); }
                return;
            }

            // Phase 2: push everything from the pipe out to dst.
            // Loop until all n bytes are consumed (short writes are possible).
            let mut remaining = n as usize;
            while remaining > 0 {
                let w = unsafe {
                    libc::splice(
                        pipe_r.raw(),  std::ptr::null_mut(),
                        dst_fd,        std::ptr::null_mut(),
                        remaining,
                        libc::SPLICE_F_MOVE,
                    )
                };
                if w <= 0 {
                    // dst went away — shut down the src side so the other
                    // direction's splice also unblocks and exits.
                    unsafe { libc::shutdown(src_fd, libc::SHUT_RD); }
                    return;
                }
                remaining -= w as usize;
            }
        }
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /// Bidirectional zero-copy proxy between two TCP streams.
    ///
    /// Spawns a second OS thread for the reverse direction, runs the forward
    /// direction on the calling thread, then joins before returning.
    /// Both sockets are dropped after both threads finish.
    ///
    /// Called from spawn_blocking so neither thread occupies a Tokio worker.
    pub fn splice_bidirectional(client: TcpStream, server: TcpStream) -> Result<()> {
        let (c2s_r, c2s_w) = make_pipe()?; // client → server pipe
        let (s2c_r, s2c_w) = make_pipe()?; // server → client pipe

        // Extract raw fd values (i32, Copy).
        // The actual socket objects stay alive in this scope, so the fds remain
        // valid for the entire lifetime of both threads (we join before drop).
        let client_fd = client.as_raw_fd();
        let server_fd = server.as_raw_fd();

        // Spawn the reverse direction (server → client) on its own thread.
        // It takes ownership of the s2c pipe fds; they close when it exits.
        let reverse = std::thread::spawn(move || {
            splice_half(server_fd, &s2c_r, &s2c_w, client_fd);
            // s2c_r and s2c_w are dropped here, closing the pipe.
        });

        // Run the forward direction (client → server) on this thread.
        // c2s pipe fds are dropped when this scope closes.
        splice_half(client_fd, &c2s_r, &c2s_w, server_fd);

        // Wait for the reverse direction to finish.
        // This also ensures the sockets aren't dropped until both threads done.
        let _ = reverse.join();

        // client and server are dropped here — OS closes the fds cleanly.
        drop(client);
        drop(server);

        Ok(())
    }
}

// ─── Connection handler ───────────────────────────────────────────────────────

async fn handle_client(
    client:      TcpStream,      // owned, not &mut — we may hand it to spawn_blocking
    routes:      Arc<ArcSwap<RouteMap>>,
    default_key: Arc<Option<String>>,
    client_addr: std::net::SocketAddr,
) {
    if let Err(e) = route_connection(client, routes, default_key, client_addr).await {
        let msg = e.to_string();
        if !msg.contains("reset") && !msg.contains("closed") && !msg.contains("EOF") {
            debug_error!("[proxy] {client_addr} — {e:#}");
        }
        // Socket is already dropped/closed by route_connection at this point.
    }
}

async fn route_connection(
    mut client:  TcpStream,      // owned so we can convert to std socket for splice
    routes:      Arc<ArcSwap<RouteMap>>,
    default_key: Arc<Option<String>>,
    client_addr: std::net::SocketAddr,
) -> Result<()> {
    client.set_nodelay(true)?;

    let mut buf = Vec::new();

    let hs = timeout(HANDSHAKE_TIMEOUT, read_handshake(&mut client, &mut buf))
        .await
        .context("handshake timed out")?
        .context("handshake failed")?;

    let route_map = routes.load();

    let route = route_map
        .get(&hs.server_address)
        .or_else(|| default_key.as_deref().and_then(|k| route_map.get(k)))
        .cloned();

    let route = match route {
        Some(r) => r,
        None => {
            debug_error!(
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
        debug_print!(
            "[proxy] {client_addr} → \"{}\" — TRANSFER → {}:{}",
            hs.server_address, route.host, route.port
        );
        let pkt = build_transfer_packets(&route.host, route.port, hs.protocol_version);
        client.write_all(&pkt).await?;
        client.shutdown().await?;

        // Drain bytes the client already sent (e.g. Login Start in the same
        // burst) to avoid RST — see earlier fix for full explanation.
        let mut sink = [0u8; 256];
        let drain = async {
            loop {
                match client.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        };
        let _ = timeout(Duration::from_secs(2), drain).await;
        return Ok(());
    }

    // ── Proxy path ───────────────────────────────────────────────────────────
    debug_print!(
        "[proxy] {client_addr} → \"{}\" — PIPE → {}:{}",
        hs.server_address, route.host, route.port
    );

    let mut server = TcpStream::connect((&*route.host, route.port))
        .await
        .with_context(|| format!("connecting to {}:{}", route.host, route.port))?;
    server.set_nodelay(true)?;

    // Replay all buffered bytes (Handshake + Login Start burst).
    server.write_all(&buf).await?;

    // ── Zero-copy splice (Linux) / async copy fallback (everything else) ──────

    #[cfg(target_os = "linux")]
    {
        // Convert the async tokio sockets into blocking std sockets.
        //
        // into_std() transfers ownership of the underlying fd to a
        // std::net::TcpStream without closing it.  We then switch to
        // blocking mode because the splice loop uses blocking syscalls —
        // non-blocking splice on a non-ready fd returns EAGAIN which would
        // require a poll loop (defeating the point).
        //
        // These conversions are infallible in practice (they're just
        // toggling O_NONBLOCK on the fd), but we propagate errors anyway.
        let client_std = client.into_std().context("client into_std")?;
        let server_std = server.into_std().context("server into_std")?;
        client_std.set_nonblocking(false).context("client set_nonblocking")?;
        server_std.set_nonblocking(false).context("server set_nonblocking")?;

        // Hand both sockets to a blocking thread pool thread.
        // This keeps Tokio's async worker threads free for accepting new
        // connections while the splice loops block on I/O.
        tokio::task::spawn_blocking(move || {
            zero_copy::splice_bidirectional(client_std, server_std)
        })
        .await
        .context("splice task panicked")??;
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On macOS / Windows / BSD: fall back to Tokio's async bidirectional
        // copy.  This copies data through userspace but works everywhere.
        tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    }

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from(
        env::var("MC_CONFIG").unwrap_or_else(|_| "config.json".into()),
    );
    let port: u16 = env::var("MC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(25565);

    let default_key: Arc<Option<String>> = Arc::new(
        env::var("MC_DEFAULT_ROUTE").ok().filter(|s| !s.is_empty()),
    );

    let initial = load_config(&config_path)?;
    let routes: Arc<ArcSwap<RouteMap>> = Arc::new(ArcSwap::from_pointee(initial));

    // ── Config hot-reload watcher ─────────────────────────────────────────────
    {
        let routes      = Arc::clone(&routes);
        let config_path = config_path.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    use notify::EventKind::*;
                    if matches!(event.kind, Modify(_) | Create(_)) {
                        let _ = tx.try_send(());
                    }
                }
            })?;
        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        tokio::spawn(async move {
            let _watcher = watcher;
            while rx.recv().await.is_some() {
                tokio::time::sleep(Duration::from_millis(200)).await;
                while rx.try_recv().is_ok() {}
                println!("[config] change detected, reloading…");
                match load_config(&config_path) {
                    Ok(new_map) => routes.store(Arc::new(new_map)),
                    Err(e)      => eprintln!("[config] reload failed: {e}"),
                }
            }
        });
    }

    // ── TCP listener ──────────────────────────────────────────────────────────
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("[server] mc-router listening on :{port}");
    println!("[server] config: {}", config_path.display());
    println!("[server] transfer support: protocol ≥ {TRANSFER_MIN_PROTOCOL} (MC 1.20.5+)");

    #[cfg(target_os = "linux")]
    println!("[server] proxy path: zero-copy splice(2)");
    #[cfg(not(target_os = "linux"))]
    println!("[server] proxy path: copy_bidirectional (non-Linux)");

    if let Some(k) = default_key.as_deref() {
        println!("[server] default route key: \"{k}\"");
    }

    loop {
        let (socket, addr) = listener.accept().await?;
        let routes      = Arc::clone(&routes);
        let default_key = Arc::clone(&default_key);
        tokio::spawn(async move {
            handle_client(socket, routes, default_key, addr).await;
        });
    }
}
