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
// shared-secret header), or 'token' (Privacy Pass / Private Access Token).
// The verify function is pluggable so 'token' slots in without restructuring.
const CLIENT_AUTH_MODE = (process.env.CLIENT_AUTH_MODE || 'off').toLowerCase();
const CLIENT_SECRET    = process.env.CLIENT_SECRET || '';
// Header the client presents its credential in. Default 'x-lander-token' so the
// token mode reads exactly what the app sends (one header carrying the whole
// PrivateToken envelope) with no extra config. The 'secret' mode reuses the same
// header. An operator may override to 'authorization' if they prefer to carry the
// token there; the client would then send the same value under that header.
const CLIENT_AUTH_HEADER = (process.env.CLIENT_AUTH_HEADER || 'x-lander-token').toLowerCase();

// --- Token mode (Privacy Pass / Private Access Token) -----------------------
// In 'token' mode the client presents an anonymous, unlinkable blind-RSA token in
// the auth header. We verify it against the issuer's epoch PUBLIC key (RSA-PSS,
// SHA-384, the RFC 9578 / Apple PAT suite) and enforce spend-once. Public key is
// fetched ONCE from the issuer's GET /issuer-keys and cached, so there is NO
// per-request call to the issuer: verification is fully offline and the issuer
// never learns which token was spent (that is the unlinkability property).
const ISSUER_KEYS_URL   = process.env.ISSUER_KEYS_URL || '';          // e.g. https://<issuer-host>/issuer-keys
const ISSUER_KEYS_TTL_MS = parseInt(process.env.ISSUER_KEYS_TTL_MS || '300000', 10); // refresh window
const TOKEN_PSS_SALT_LEN = parseInt(process.env.TOKEN_PSS_SALT_LEN || '48', 10);      // SHA-384 digest length
const REDEMPTION_MAX_KEYS = parseInt(process.env.REDEMPTION_MAX_KEYS || '5000000', 10); // bound spend-set memory

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
// CLIENT_SECRET (timing-safe). 'token': verify the Privacy Pass / PAT token in the
// header via verifyAccessToken (offline RSA-PSS verify against the issuer epoch
// public key + spend-once). Both modes read CLIENT_AUTH_HEADER. The credential is
// NEVER logged. See ../token-issuer/PROTOCOL.md for the token wire format.
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

// --- Issuer epoch public-key cache ------------------------------------------
// Map<keyId, KeyObject>. Populated from the issuer's GET /issuer-keys (PUBLIC
// material). Refreshed lazily once per ISSUER_KEYS_TTL_MS. A failed refresh keeps
// the last good keys rather than dropping them, so a transient issuer outage does
// not take token verification down, but if we have NO keys we fail closed.
let issuerKeys = new Map();
let issuerKeysFetchedAt = 0;
let issuerKeysRefreshing = false;

// Kick off a refresh of the issuer public keys if the cache is stale. Non-blocking:
// verification uses whatever keys are currently cached. The fetched material is
// PUBLIC (epoch public keys + key ids), so caching it leaks nothing.
function maybeRefreshIssuerKeys() {
  if (!ISSUER_KEYS_URL) return;
  const now = Date.now();
  if (issuerKeys.size > 0 && now - issuerKeysFetchedAt < ISSUER_KEYS_TTL_MS) return;
  if (issuerKeysRefreshing) return;
  issuerKeysRefreshing = true;

  let u;
  try { u = new URL(ISSUER_KEYS_URL); } catch { issuerKeysRefreshing = false; return; }
  const opts = {
    hostname: u.hostname,
    port: u.port || 443,
    path: u.pathname + u.search,
    method: 'GET',
    timeout: GW_TIMEOUT_MS,
  };
  const ireq = https.request(opts, (ires) => {
    const cc = [];
    let clen = 0;
    let bad = false;
    ires.on('data', (d) => {
      if (bad) return;
      clen += d.length;
      if (clen > MAX_RESP_BYTES) { bad = true; ires.destroy(); }
      else cc.push(d);
    });
    ires.on('end', () => {
      issuerKeysRefreshing = false;
      if (bad || (ires.statusCode || 0) !== 200) return; // keep last good keys
      try {
        const doc = JSON.parse(Buffer.concat(cc).toString('utf8'));
        const next = new Map();
        for (const k of (doc.keys || [])) {
          if (!k || typeof k.keyId !== 'string' || typeof k.publicKeySpki !== 'string') continue;
          const der = Buffer.from(k.publicKeySpki, 'base64');
          const pub = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
          next.set(k.keyId, pub);
        }
        if (next.size > 0) { issuerKeys = next; issuerKeysFetchedAt = Date.now(); }
      } catch { /* malformed doc: keep last good keys */ }
    });
  });
  ireq.on('timeout', () => { ireq.destroy(new Error('issuer timeout')); });
  ireq.on('error', () => { issuerKeysRefreshing = false; });
  ireq.end();
}

// --- Spend-once redemption set ----------------------------------------------
// REDEMPTION STORE (production): this Set lives in one process and resets on
// restart, so with multiple relay replicas a token could be spent once per
// replica, and a restart forgets all prior spends. For a real deployment, move
// this to a shared atomic store (e.g. Redis SET with NX, keyed by the nullifier,
// with a TTL past the token's epoch so it self-expires). The nullifier is derived
// from the token signature only, no device id, nothing user-identifying.
const redeemed = new Set();

function nullifierFor(sigBytes) {
  return crypto.createHash('sha256').update(sigBytes).digest('hex');
}

// Mark a token spent. Returns false if it was ALREADY spent (double-spend),
// true if this is the first spend (and records it). Single-process atomic.
function tryRedeem(nullifier) {
  if (redeemed.has(nullifier)) return false;
  redeemed.add(nullifier);
  if (redeemed.size > REDEMPTION_MAX_KEYS) {
    // Bound memory: drop the oldest-inserted nullifier. A shared store with epoch
    // TTLs is the correct fix; this cap just keeps a single replica from OOMing.
    redeemed.delete(redeemed.values().next().value);
  }
  return true;
}

// Token mode verification. The client presents, in the CLIENT_AUTH_HEADER (default
// 'x-lander-token'), a compact token:
//   PrivateToken <base64url( JSON{ keyId, tokenInput, signature } )>
// where the outer envelope is base64url and tokenInput + signature inside the JSON
// are standard base64. signature is the finalized blind-RSA (RSA-PSS/SHA-384,
// 48-byte salt) signature over tokenInput, issued blindly so the issuer never saw
// this exact (tokenInput, signature) pair. A 'PrivateToken ' or 'Bearer ' prefix is
// optional. See ../token-issuer/PROTOCOL.md for the full contract.
//
// We (1) parse it, (2) look up the issuer epoch public key by keyId, (3) verify the
// RSA-PSS signature over tokenInput offline, (4) enforce spend-once via a nullifier
// = SHA-256(signature). All four must pass. The token is NEVER logged.
function verifyAccessToken(presented) {
  if (typeof presented !== 'string' || presented.length === 0) return false;

  // Allow an optional "PrivateToken " / "Bearer " prefix on the header value.
  const raw = presented.replace(/^(PrivateToken|Bearer)\s+/i, '').trim();

  // Refresh the issuer public keys if stale (non-blocking).
  maybeRefreshIssuerKeys();
  if (issuerKeys.size === 0) return false; // no keys => cannot verify => fail closed

  let tok;
  try {
    tok = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    return false;
  }
  const { keyId, tokenInput, signature } = tok || {};
  if (typeof keyId !== 'string' || typeof tokenInput !== 'string' || typeof signature !== 'string') {
    return false;
  }

  const pub = issuerKeys.get(keyId);
  if (!pub) return false; // unknown / expired epoch key => reject

  const inputBuf = Buffer.from(tokenInput, 'base64');
  const sigBuf = Buffer.from(signature, 'base64');
  if (inputBuf.length === 0 || sigBuf.length === 0) return false;

  // (3) Verify the RSA-PSS signature offline against the issuer epoch public key.
  let sigOk = false;
  try {
    sigOk = crypto.verify(
      'sha384',
      inputBuf,
      { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: TOKEN_PSS_SALT_LEN },
      sigBuf,
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) return false;

  // (4) Spend-once. A valid signature that has already been redeemed is rejected,
  // so a token can be spent exactly once. The nullifier is derived from the
  // signature only and carries no identity.
  if (!tryRedeem(nullifierFor(sigBuf))) return false;

  return true;
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

// Only bind the port when run directly as the entrypoint. Requiring this file
// (the test harness does, to exercise token verification without a live socket)
// must NOT start listening. Production behavior when run via `node server.js` is
// unchanged.
if (require.main === module) {
  server.listen(PORT, () => log({ event: 'listen', port: PORT, role: 'ohttp-relay' }));
}

// Test-only surface. Lets the harness exercise the token-mode verification path
// (signature check + spend-once) directly. Nothing here changes runtime behavior.
module.exports = {
  server,
  verifyAccessToken,
  tryRedeem,
  nullifierFor,
  setIssuerKeysForTest(map) { issuerKeys = map; issuerKeysFetchedAt = Date.now(); },
};
