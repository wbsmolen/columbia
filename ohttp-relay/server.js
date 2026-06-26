// Columbia — OHTTP relay (RFC 9458)
//
// The relay is the split-trust counterpart to the gateway. It sees the client's
// IP and an OPAQUE ciphertext (message/ohttp-req) — never the plaintext, never
// the target. It forwards the ciphertext to the gateway, stripping every
// identifying header, and returns the encapsulated response. The gateway sees
// the relay's IP + plaintext but NOT the client's IP. Neither party ever holds
// identity + content together — that's the operator-blind property.
//
// NON-COLLUSION CAVEAT: for the security guarantee, relay and gateway MUST be
// run by different, non-colluding operators. Running both on one host validates
// the flow but provides no protection against the single operator. See
// ../SELFHOSTING.md. Logs are RED-only — no IP, no content, no headers.

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '8080', 10);
const GATEWAY = process.env.GATEWAY_URL; // e.g. https://<gateway-host>/gateway

// DoS bounds: cap how much we buffer in either direction so a single connection
// can't exhaust relay memory. Both are overridable via env.
const MAX_BODY = parseInt(process.env.MAX_BODY_BYTES || '65536', 10);
const MAX_RESP_BYTES = parseInt(process.env.MAX_RESP_BYTES || '1000000', 10);
const GW_TIMEOUT_MS = parseInt(process.env.GW_TIMEOUT_MS || '15000', 10);

// --- Abuse controls (all in-memory, ephemeral, NEVER logged) ----------------
// Per-IP fixed-window rate limit + a global in-flight concurrency cap. State is
// keyed ONLY by a transient client-IP bucket and is never written to a log,
// never tied to request content, and is dropped on restart.
const RATE_LIMIT_RPM = parseInt(process.env.RATE_LIMIT_RPM || '120', 10);   // requests/min/IP
const RATE_WINDOW_MS = parseInt(process.env.RATE_WINDOW_MS || '60000', 10); // window length
const MAX_INFLIGHT   = parseInt(process.env.MAX_INFLIGHT   || '256', 10);   // global concurrent relays
const RATE_MAX_KEYS  = parseInt(process.env.RATE_MAX_KEYS  || '100000', 10);// bound limiter memory

// --- Client auth ------------------------------------------------------------
// CLIENT_AUTH_MODE: 'off' (default; rely on network controls), 'secret' (interim
// shared-secret header), or 'token' (future Privacy Pass / Private Access Token).
// The verify function is pluggable so 'token' slots in without restructuring.
const CLIENT_AUTH_MODE = (process.env.CLIENT_AUTH_MODE || 'off').toLowerCase();
const CLIENT_SECRET    = process.env.CLIENT_SECRET || '';
const CLIENT_AUTH_HEADER = (process.env.CLIENT_AUTH_HEADER || 'authorization').toLowerCase();

// --- Relay -> gateway auth --------------------------------------------------
// Shared secret attached to the outbound request so the gateway can reject
// anything that didn't come through this relay. Sent as a single extra header on
// the otherwise clean-slate outbound request. Constant across all requests, so
// it identifies the RELAY, never the client, and leaks nothing.
const RELAY_GATEWAY_SECRET = process.env.RELAY_GATEWAY_SECRET || '';
const RELAY_GATEWAY_HEADER = 'x-columbia-relay-auth';

// --- Public key-config passthrough ------------------------------------------
// When the gateway runs internal-only, clients can no longer fetch its public
// GET /ohttp-configs (the key config they pin). The relay — the sole public hop
// — proxies it: a read-only GET that returns the gateway's PUBLIC key-config
// bytes verbatim. This leaks nothing: the key config is public material clients
// are MEANT to pin. Cached briefly so we don't hit the gateway per client.
const CONFIG_TTL_MS = parseInt(process.env.CONFIG_TTL_MS || '120000', 10);

function log(fields) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...fields }) + '\n');
}

// Validate GATEWAY_URL ONCE at startup. Parsing per-request both wasted work and
// hid a misconfiguration until the first relay attempt. Require https so the
// relay→gateway hop is always encrypted.
let gw;
try {
  gw = new URL(GATEWAY);
} catch {
  log({ event: 'fatal', reason: 'gateway_url_invalid' });
  process.exit(1);
}
if (gw.protocol !== 'https:') {
  log({ event: 'fatal', reason: 'gateway_not_https' });
  process.exit(1);
}
const GW_PORT = gw.port || 443; // honor a non-default port instead of hardcoding 443

// The gateway's /ohttp-configs URL — derived from GATEWAY_URL (same host) unless
// explicitly overridden. The relay reaches the gateway at the same FQDN whether
// the gateway is public or internal-only (same Container Apps environment).
const GATEWAY_CONFIGS_URL = process.env.GATEWAY_CONFIGS_URL || `${gw.protocol}//${gw.host}/ohttp-configs`;
let cfgGw = null;
try { cfgGw = new URL(GATEWAY_CONFIGS_URL); } catch { cfgGw = null; }

// Fixed-window per-IP counter. Map<ipBucket, { count, windowStart }>. Swept
// lazily on access; hard-capped key count so a spoofed-source flood can't grow
// the table unbounded.
const rateBuckets = new Map();
let inflight = 0;

// Rate-limit key: the client IP as seen by the TRUSTED ingress. Behind Azure
// Container Apps, the TCP peer (socket.remoteAddress) is the ingress proxy, not
// the client, so per-IP limiting must read the rightmost X-Forwarded-For entry
// (the address the trusted ingress appended — a client-spoofed value can only
// sit to its LEFT). Used ONLY as a transient limiter key; never logged, never
// forwarded to the gateway.
function clientIpKey(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) {
    const parts = xff.split(',');
    const last = parts[parts.length - 1].trim();
    if (last) return last;
  }
  return req.socket.remoteAddress || 'unknown';
}

function rateLimited(ipBucket) {
  if (RATE_LIMIT_RPM <= 0) return false; // 0 disables per-IP limiting
  const now = Date.now();
  let b = rateBuckets.get(ipBucket);
  if (!b || now - b.windowStart >= RATE_WINDOW_MS) {
    b = { count: 0, windowStart: now };
    rateBuckets.set(ipBucket, b);
  }
  b.count += 1;
  if (rateBuckets.size > RATE_MAX_KEYS) {
    rateBuckets.delete(rateBuckets.keys().next().value); // drop oldest-inserted
  }
  return b.count > RATE_LIMIT_RPM;
}

// Constant-time credential check. 'secret': require the header to equal
// CLIENT_SECRET (timing-safe). 'token': stub that fails closed until Privacy
// Pass / PAT verification is wired in — swap verifyAccessToken's body only. The
// credential is NEVER logged.
function clientAuthorized(req) {
  if (CLIENT_AUTH_MODE === 'off') return true;
  if (CLIENT_AUTH_MODE === 'secret') {
    if (!CLIENT_SECRET) return false; // misconfig => fail closed
    return timingSafeEqualStr(req.headers[CLIENT_AUTH_HEADER], CLIENT_SECRET);
  }
  if (CLIENT_AUTH_MODE === 'token') {
    return verifyAccessToken(req.headers[CLIENT_AUTH_HEADER]);
  }
  return false; // unknown mode => fail closed
}

// Placeholder for token mode; isolated so the swap is a single function body.
function verifyAccessToken(_presented) {
  return false;
}

// Length-independent constant-time string compare (hash both sides so length
// never leaks via timing; tolerates missing/short input).
function timingSafeEqualStr(presented, expected) {
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const ha = crypto.createHash('sha256').update(presented).digest();
  const hb = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Short-lived cache of the gateway's public key config. { body, contentType, fetchedAt }.
let configCache = null;

// Serve GET /ohttp-configs by proxying the gateway's public key config. Read-only,
// no secret needed (public material), cached for CONFIG_TTL_MS.
function serveConfig(res, start) {
  const now = Date.now();
  if (configCache && now - configCache.fetchedAt < CONFIG_TTL_MS) {
    res.writeHead(200, { 'Content-Type': configCache.contentType });
    res.end(configCache.body);
    log({ route: '/ohttp-configs', status: 200, durationMs: Date.now() - start });
    return;
  }
  if (!cfgGw) {
    res.writeHead(502); res.end();
    log({ route: '/ohttp-configs', status: 502, durationMs: Date.now() - start });
    return;
  }
  const opts = {
    hostname: cfgGw.hostname,
    port: cfgGw.port || 443,
    path: cfgGw.pathname,
    method: 'GET',
    timeout: GW_TIMEOUT_MS,
  };
  const creq = https.request(opts, (cres) => {
    const cc = [];
    let clen = 0;
    let cabort = false;
    cres.on('data', (d) => {
      if (cabort) return;
      clen += d.length;
      if (clen > MAX_RESP_BYTES) {
        cabort = true;
        cres.destroy();
        if (!res.headersSent) { res.writeHead(502); res.end(); }
        log({ route: '/ohttp-configs', status: 502, durationMs: Date.now() - start });
        return;
      }
      cc.push(d);
    });
    cres.on('end', () => {
      if (cabort) return;
      const body = Buffer.concat(cc);
      const contentType = cres.headers['content-type'] || 'application/octet-stream';
      if ((cres.statusCode || 0) === 200) {
        configCache = { body, contentType, fetchedAt: Date.now() };
      }
      res.writeHead(cres.statusCode || 502, { 'Content-Type': contentType });
      res.end(body);
      log({ route: '/ohttp-configs', status: cres.statusCode || 502, durationMs: Date.now() - start });
    });
  });
  creq.on('timeout', () => { creq.destroy(new Error('gw timeout')); });
  creq.on('error', () => {
    if (!res.headersSent) { res.writeHead(502); res.end(); }
    log({ route: '/ohttp-configs', status: 502, durationMs: Date.now() - start });
  });
  creq.end();
}

const server = http.createServer((req, res) => {
  const start = Date.now();

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    log({ route: '/health', status: 200, durationMs: Date.now() - start });
    return;
  }

  // Public key-config passthrough so the gateway can stay internal-only.
  if (req.method === 'GET' && req.url === '/ohttp-configs') {
    serveConfig(res, start);
    return;
  }

  // Only POST /relay is a relay request. Everything else → 404 (no probing other
  // paths, no relaying non-POST methods). req.url is matched exactly, so a query
  // string or trailing junk is rejected.
  if (!(req.method === 'POST' && req.url === '/relay')) {
    res.writeHead(404); res.end(); return;
  }

  // Enforce the OHTTP request media type. Strip any parameters before comparing
  // and reject anything that isn't message/ohttp-req.
  const ctype = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (ctype !== 'message/ohttp-req') {
    res.writeHead(415); res.end();
    log({ route: '/relay', status: 415, durationMs: Date.now() - start });
    return;
  }

  // Per-IP rate limit. The address is used ONLY as a transient limiter key and is
  // never logged. See clientIpKey for why we read the trusted X-Forwarded-For.
  if (rateLimited(clientIpKey(req))) {
    res.writeHead(429); res.end();
    log({ route: '/relay', status: 429, durationMs: Date.now() - start });
    return;
  }

  // Client credential check (pluggable: shared-secret today, token later). The
  // credential header is never logged.
  if (!clientAuthorized(req)) {
    res.writeHead(401); res.end();
    log({ route: '/relay', status: 401, durationMs: Date.now() - start });
    return;
  }

  // Global in-flight concurrency cap. Reserve a slot; release it on every
  // terminal path (success, error, abort, oversize, client disconnect).
  if (inflight >= MAX_INFLIGHT) {
    res.writeHead(429); res.end();
    log({ route: '/relay', status: 429, durationMs: Date.now() - start });
    return;
  }
  inflight += 1;
  let slotReleased = false;
  const releaseSlot = () => { if (!slotReleased) { slotReleased = true; inflight -= 1; } };
  res.on('close', releaseSlot);   // safety net for any teardown path
  req.on('aborted', releaseSlot);

  const chunks = [];
  let received = 0;
  let aborted = false;
  req.on('data', (c) => {
    if (aborted) return;
    received += c.length;
    if (received > MAX_BODY) {
      // Request body too large: refuse, tear down, and stop buffering.
      aborted = true;
      res.writeHead(413); res.end();
      log({ route: '/relay', status: 413, durationMs: Date.now() - start });
      releaseSlot();
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (aborted) return;
    const body = Buffer.concat(chunks);

    // Forward ONLY the opaque ciphertext + its content type. Deliberately send a
    // fresh request with NO client headers, NO X-Forwarded-For — the gateway must
    // not learn who the client is. The ONLY additional header is the relay→gateway
    // shared secret, which identifies the RELAY (not the client) so the gateway
    // can refuse traffic that didn't come through us.
    const outHeaders = { 'Content-Type': 'message/ohttp-req', 'Content-Length': body.length };
    if (RELAY_GATEWAY_SECRET) outHeaders[RELAY_GATEWAY_HEADER] = RELAY_GATEWAY_SECRET;
    const opts = {
      hostname: gw.hostname,
      port: GW_PORT,
      path: gw.pathname,
      method: 'POST',
      timeout: GW_TIMEOUT_MS,
      headers: outHeaders,
    };
    const greq = https.request(opts, (gres) => {
      const rc = [];
      let rcLen = 0;
      let respAborted = false;
      gres.on('data', (d) => {
        if (respAborted) return;
        rcLen += d.length;
        if (rcLen > MAX_RESP_BYTES) {
          // Gateway response too large: drop it and fail closed.
          respAborted = true;
          gres.destroy();
          if (!res.headersSent) { res.writeHead(502); res.end(); }
          log({ route: '/relay', status: 502, durationMs: Date.now() - start });
          releaseSlot();
          return;
        }
        rc.push(d);
      });
      gres.on('end', () => {
        if (respAborted) return;
        const rb = Buffer.concat(rc);
        // Pin the response content-type — never echo the gateway's header back.
        res.writeHead(gres.statusCode || 502, { 'Content-Type': 'message/ohttp-res' });
        res.end(rb);
        log({ route: '/relay', status: gres.statusCode || 502, durationMs: Date.now() - start });
        releaseSlot();
      });
    });
    greq.on('timeout', () => {
      greq.destroy(new Error('gw timeout'));
    });
    greq.on('error', () => {
      if (!res.headersSent) { res.writeHead(502); res.end(); }
      log({ route: '/relay', status: 502, durationMs: Date.now() - start });
      releaseSlot();
    });
    greq.write(body);
    greq.end();
  });
});

// Connection-level timeouts so slow-loris style clients can't pin sockets open.
server.requestTimeout = 20000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;

server.listen(PORT, () => log({ event: 'listen', port: PORT, role: 'ohttp-relay' }));
