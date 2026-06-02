/**
 * mc-router — Minecraft Java Edition SNI-style reverse proxy
 *
 * Flow:
 *   1. Accept TCP connection on :25565
 *   2. Buffer incoming bytes until we can parse the Handshake packet
 *   3. Extract the ServerAddress field (the hostname the client typed)
 *   4. Look up the target in config
 *   5a. If client supports transfers (protocol ≥ 766, i.e. 1.20.5+) AND
 *       the target is not a bare-IP: send a Login Success + Transfer packet
 *       so the client reconnects directly — zero ongoing proxy overhead.
 *   5b. Otherwise: open a TCP connection to the target and splice the
 *       streams together (including the buffered handshake bytes).
 */

"use strict";

const net  = require("net");
const fs   = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CONFIG_PATH = path.resolve(process.env.MC_CONFIG ?? "config.json");

let routeMap = {};   // hostname (lowercase) → { host, port }

function loadConfig() {
  try {
    const raw  = fs.readFileSync(CONFIG_PATH, "utf8");
    const json = JSON.parse(raw);
    const next = {};
    for (const [hostname, target] of Object.entries(json)) {
      const lastColon = target.lastIndexOf(":");
      if (lastColon === -1) {
        next[hostname.toLowerCase()] = { host: target, port: 25565 };
      } else {
        next[hostname.toLowerCase()] = {
          host: target.slice(0, lastColon),
          port: parseInt(target.slice(lastColon + 1), 10) || 25565,
        };
      }
    }
    routeMap = next;
    console.log(`[config] loaded ${Object.keys(next).length} route(s) from ${CONFIG_PATH}`);
  } catch (err) {
    console.error(`[config] failed to load: ${err.message}`);
  }
}

loadConfig();

// Watch for changes — debounce 200 ms to avoid double-fires on some editors
let reloadTimer = null;
fs.watch(CONFIG_PATH, () => {
  clearTimeout(reloadTimer);
  reloadTimer = setTimeout(() => {
    console.log("[config] change detected, reloading…");
    loadConfig();
  }, 200);
});

// ---------------------------------------------------------------------------
// Minecraft VarInt helpers
// ---------------------------------------------------------------------------

/**
 * Try to read a VarInt from a Buffer starting at `offset`.
 * Returns { value, bytesRead } or null if the buffer is too short.
 */
function readVarInt(buf, offset = 0) {
  let value = 0, shift = 0, pos = offset;
  do {
    if (pos >= buf.length) return null;   // need more data
    const byte = buf[pos++];
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if (!(byte & 0x80)) return { value, bytesRead: pos - offset };
    if (shift >= 35) throw new Error("VarInt too wide");
  } while (true);
}

/**
 * Encode a number as a VarInt Buffer.
 */
function writeVarInt(value) {
  const out = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    out.push(byte);
  } while (value !== 0);
  return Buffer.from(out);
}

/**
 * Encode a UTF-8 string as a Minecraft String (VarInt length prefix + UTF-8).
 */
function writeString(str) {
  const utf8 = Buffer.from(str, "utf8");
  return Buffer.concat([writeVarInt(utf8.length), utf8]);
}

// ---------------------------------------------------------------------------
// Handshake packet parser
// ---------------------------------------------------------------------------

// Minimum protocol version that supports the Transfer packet (1.20.5)
const TRANSFER_MIN_PROTOCOL = 766;

/**
 * Attempt to parse the Handshake packet out of `buf`.
 *
 * Minecraft framing: [packet length: VarInt][packet id: VarInt][payload…]
 * Handshake payload: [protocol version: VarInt][server address: String]
 *                    [server port: u16][next state: VarInt]
 *
 * Returns { protocolVersion, serverAddress, serverPort, nextState, totalBytes }
 * or null if more data is needed.
 */
function parseHandshake(buf) {
  let off = 0;

  // Packet length
  const lenRes = readVarInt(buf, off);
  if (!lenRes) return null;
  off += lenRes.bytesRead;

  if (buf.length < off + lenRes.value) return null;  // incomplete packet

  // Packet ID (must be 0x00 for Handshake)
  const idRes = readVarInt(buf, off);
  if (!idRes) return null;
  if (idRes.value !== 0x00) return null;             // unexpected packet
  off += idRes.bytesRead;

  // Protocol version
  const protoRes = readVarInt(buf, off);
  if (!protoRes) return null;
  off += protoRes.bytesRead;

  // Server address string: VarInt length + UTF-8 bytes
  const addrLenRes = readVarInt(buf, off);
  if (!addrLenRes) return null;
  off += addrLenRes.bytesRead;
  if (buf.length < off + addrLenRes.value) return null;
  const serverAddress = buf.slice(off, off + addrLenRes.value).toString("utf8");
  off += addrLenRes.value;

  // Server port (u16 BE)
  if (buf.length < off + 2) return null;
  const serverPort = buf.readUInt16BE(off);
  off += 2;

  // Next state
  const stateRes = readVarInt(buf, off);
  if (!stateRes) return null;
  off += stateRes.bytesRead;

  return {
    protocolVersion: protoRes.value,
    serverAddress: serverAddress.replace(/\0.*$/, ""), // strip FML/Forge null marker
    serverPort,
    nextState: stateRes.value,                         // 1 = status, 2 = login, 3 = transfer
    totalBytes: lenRes.bytesRead + lenRes.value,        // full packet byte count in buf
  };
}

// ---------------------------------------------------------------------------
// Transfer packet builder (Login → Transfer, 1.20.5+)
// ---------------------------------------------------------------------------

/**
 * Build a complete Login Success packet followed by a Transfer packet.
 * The client will disconnect and reconnect directly to (host, port).
 *
 * Login Success (0x02 in login state, simplified — just enough for vanilla):
 *   UUID (16 bytes) + Name (String) + Properties array (VarInt 0)
 *
 * Transfer (0x0B in login state, 1.20.5+):
 *   Host (String) + Port (VarInt)
 *
 * Important: we only use Transfer for nextState == 2 (login).
 * For status pings (nextState == 1) we still proxy normally.
 */
function buildTransferPackets(host, port) {
  // Fake UUID (all zeros) — client never sees a world, just transfers
  const fakeUUID = Buffer.alloc(16, 0);

  // Login Success payload
  const loginSuccessPayload = Buffer.concat([
    fakeUUID,                         // UUID
    writeString(""),                  // name (empty — doesn't matter)
    writeVarInt(0),                   // properties count
//    Buffer.from([0x00]),              // strict error handling (false)
  ]);
  const loginSuccessId    = writeVarInt(0x02);
  const loginSuccessBody  = Buffer.concat([loginSuccessId, loginSuccessPayload]);
  const loginSuccessFrame = Buffer.concat([writeVarInt(loginSuccessBody.length), loginSuccessBody]);

  // Transfer payload
  const transferPayload = Buffer.concat([
    writeString(host),
    writeVarInt(port),
  ]);
  const transferId    = writeVarInt(0x0B);
  const transferBody  = Buffer.concat([transferId, transferPayload]);
  const transferFrame = Buffer.concat([writeVarInt(transferBody.length), transferBody]);

  return Buffer.concat([loginSuccessFrame, transferFrame]);
}

// ---------------------------------------------------------------------------
// Proxy logic
// ---------------------------------------------------------------------------

function handleClient(clientSocket) {
  const clientAddr = `${clientSocket.remoteAddress}:${clientSocket.remotePort}`;
  let chunks = [];
  let totalBuffered = 0;
  const MAX_HANDSHAKE_BUFFER = 4096; // no legitimate handshake exceeds this

  function onData(chunk) {
    totalBuffered += chunk.length;
    if (totalBuffered > MAX_HANDSHAKE_BUFFER) {
      console.warn(`[proxy] ${clientAddr} sent oversized handshake, dropping`);
      clientSocket.destroy();
      return;
    }
    chunks.push(chunk);
    const buf = Buffer.concat(chunks);

    let hs;
    try {
      hs = parseHandshake(buf);
    } catch (err) {
      console.warn(`[proxy] ${clientAddr} bad handshake: ${err.message}`);
      clientSocket.destroy();
      return;
    }

    if (!hs) return; // need more data — stay in buffering mode

    // We have the full handshake — stop buffering
    clientSocket.removeListener("data", onData);
    clientSocket.setTimeout(0);
    clientSocket.pause(); // ← buffer any incoming bytes until pipe() resumes

    // Strip the port suffix Minecraft sometimes appends ("host:port" or "host\0…")
    const rawHostname = hs.serverAddress.split(":")[0].toLowerCase();

    // const route = routeMap[rawHostname];
    let route = routeMap[rawHostname];
    if (!route) {
      route = routeMap["jonhosting.com"];
      if (route) {
        console.log(`[proxy] ${clientAddr} → "${rawHostname}" — no route, falling back to default`);
      } else {
        console.log(`[proxy] ${clientAddr} → "${rawHostname}" — no route and no default, dropping`);
        clientSocket.destroy();
        return;
      }
      /*
      console.log(`[proxy] ${clientAddr} → "${rawHostname}" — no route, dropping`);
      clientSocket.destroy();
      return;
      */
    }

    const useTransfer =
      hs.nextState === 2 &&                        // login (not status ping)
      hs.protocolVersion >= TRANSFER_MIN_PROTOCOL; // client supports transfers

    if (useTransfer) {
      console.log(`[proxy] ${clientAddr} → "${rawHostname}" — TRANSFER to ${route.host}:${route.port}`);
      try {
        const pkt = buildTransferPackets(route.host, route.port);
        clientSocket.end(pkt);
      } catch (err) {
        console.error(`[proxy] transfer packet error: ${err.message}`);
        clientSocket.destroy();
      }
      return;
    }

    // --- Classic proxy path ---
    console.log(`[proxy] ${clientAddr} → "${rawHostname}" — PIPE to ${route.host}:${route.port}`);

    const serverSocket = net.createConnection({ host: route.host, port: route.port });

    serverSocket.once("connect", () => {
      // Replay all buffered bytes (includes the handshake) then splice
      serverSocket.write(buf);
      clientSocket.pipe(serverSocket);
      serverSocket.pipe(clientSocket);
    });

    serverSocket.on("error", (err) => {
      console.error(`[proxy] server socket error (${route.host}:${route.port}): ${err.message}`);
      clientSocket.destroy();
    });

    clientSocket.on("error", () => serverSocket.destroy());
    serverSocket.on("close", () => clientSocket.destroy());
    clientSocket.on("close", () => serverSocket.destroy());
  }

  clientSocket.on("data", onData);
  clientSocket.on("error", (err) => {
    console.error(`[proxy] client socket error (${clientAddr}): ${err.message}`);
  });

  // Kick idle connections that never finish the handshake
  clientSocket.setTimeout(10_000, () => {
    console.warn(`[proxy] ${clientAddr} handshake timeout`);
    clientSocket.destroy();
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.MC_PORT ?? "25565", 10);

const server = net.createServer({ allowHalfOpen: false });
server.on("connection", handleClient);
server.on("error", (err) => console.error("[server] error:", err));

server.listen(PORT, () => {
  console.log(`[server] mc-router listening on :${PORT}`);
  console.log(`[server] config: ${CONFIG_PATH}`);
  console.log(`[server] transfer support: protocol ≥ ${TRANSFER_MIN_PROTOCOL} (MC 1.20.5+)`);
});

// Graceful shutdown
process.on("SIGINT",  () => { server.close(); process.exit(0); });
process.on("SIGTERM", () => { server.close(); process.exit(0); });
