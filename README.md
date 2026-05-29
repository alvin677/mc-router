# mc-router

Minecraft Java Edition reverse proxy. Routes incoming connections to backend servers based on the hostname the client connected to (from the Handshake packet).

## Features

- **Hostname-based routing** — reads the `ServerAddress` field from the MC Handshake packet
- **Transfer packet support** — for 1.20.5+ clients (protocol ≥ 766) in login state, sends a `Transfer` packet so the client reconnects *directly* to the backend, removing the proxy from the data path entirely
- **Hot reload** — edit `config.json` and the router picks up changes within ~200 ms, no restart needed
- **Status ping proxying** — MOTD/ping requests are always proxied (Transfer only applies to logins)
- **Forge/FML safe** — strips the null-terminated Forge channel suffix from hostnames

## Quick start

```bash
node proxy.js
# or with file watching for auto-restart on source changes:
node --watch proxy.js
```

Listens on `:25565` by default.

## Config

`config.json` — map of incoming hostname → backend `host:port`:

```json
{
  "server1.jonhosting.com": "jonhosting.com:25650",
  "server2.jonhosting.com": "jonhosting.com:25630",
  "server3.jonhosting.com": "randomserver.aternos.me:25565"
}
```

Port defaults to `25565` if omitted. Keys are case-insensitive.

## Environment variables

| Variable    | Default       | Description                        |
|-------------|---------------|------------------------------------|
| `MC_PORT`   | `25565`       | Port to listen on                  |
| `MC_CONFIG` | `config.json` | Path to the routing config file    |
| `MC_DEFAULT_ROUTE` | *Not set* | Default/Fallback server key in config.json. (Node.js default: `jonhosting.com`) |

## How Transfer works

When a 1.20.5+ client (protocol version ≥ 766) sends a **Login** handshake:

1. Router reads the handshake hostname, finds the target route
2. Immediately sends `Login Success` + `Transfer` packets back to the client
3. Client closes the connection and opens a **new, direct** TCP connection to the target server
4. The proxy is no longer in the loop — no bandwidth overhead, no latency added

For older clients, or for **status pings** (F3 server list), the classic pipe path is used instead.

> **Note on Transfer targets**: the hostname in the Transfer packet is what the client's DNS resolves. If your backend is on the same machine and you use `/etc/hosts` to point a friendly name at `127.0.0.1`, that works perfectly — the client resolves it on their end, so make sure the hostname is publicly resolvable to the right IP, or use the actual IP/public hostname.

## Performance notes

- After the handshake is parsed, raw `socket.pipe(socket)` is used — fastest path for TCP splicing
- The handshake buffer is capped at 4 KB; connections that exceed it are dropped
- Connections that don't complete a handshake within 10 seconds are timed out
- No external dependencies — startup is instant
