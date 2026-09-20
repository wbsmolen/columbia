// Columbia - OHTTP relay (RFC 9458)
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The relay is the split-trust counterpart to the gateway. It sees the client's
// IP and an OPAQUE ciphertext (message/ohttp-req) - never the plaintext, never
// the target. It forwards the ciphertext to the gateway, stripping every
// identifying header, and returns the encapsulated response. The gateway sees
// the relay's IP + plaintext but NOT the client's IP. Neither party ever holds
// identity + content together - that's the operator-blind property.
//
// NON-COLLUSION CAVEAT: for the security guarantee, relay and gateway MUST be
// run by different, non-colluding operators. Running both on one host validates
// the flow but provides no protection against the single operator. See
// ../SELFHOSTING.md. Logs are RED-only - no IP, no content, no headers.

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { CLIENT_OPTIONS, memoryRedemptionStore, azureRedemptionStore } = require('./redemption-store');
const { createIssuerKeyCache } = require('./issuer-key-cache');

const PORT = parseInt(process.env.PORT || '8080', 10);
const GATEWAY = process.env.GATEWAY_URL; // e.g. https://<gateway-host>/gateway

// DoS bounds: cap how much we buffer in either direction so a single connection
// can't exhaust relay memory. Both are overridable via env.
const MAX_BODY = parseInt(process.env.MAX_BODY_BYTES || '65536', 10);
// 5 MB: large comment threads legitimately exceed the old 1 MB cap.
const MAX_RESP_BYTES = parseInt(process.env.MAX_RESP_BYTES || '5000000', 10);
const GW_TIMEOUT_MS = parseInt(process.env.GW_TIMEOUT_MS || '15000', 10);

// --- Abuse controls (all in-memory, ephemeral, NEVER logged) ----------------
// Per-IP fixed-window rate limit + a global in-flight concurrency cap. State is
// keyed ONLY by a transient client-IP bucket and is never written to a log,
// never tied to request content, and is dropped on restart.
const RATE_LIMIT_RPM = parseInt(process.env.RATE_LIMIT_RPM || '120', 10);   // requests/min/IP
const RATE_WINDOW_MS = parseInt(process.env.RATE_WINDOW_MS || '60000', 10); // window length
const MAX_INFLIGHT   = parseInt(process.env.MAX_INFLIGHT   || '256', 10);   // global concurrent relays
const RATE_MAX_KEYS  = parseInt(process.env.RATE_MAX_KEYS  || '100000', 10);// bound limiter memory
// TRUSTED_CLIENT_IP_HEADER: name of a header that a TRUSTED front proxy sets to
// the real client IP (e.g. 'x-azure-socketip' behind Azure Front Door,
// 'cf-connecting-ip' behind Cloudflare, 'true-client-ip' behind some CDNs).
// REQUIRED whenever the request passes through MORE THAN ONE proxy before the
// relay: with a multi-proxy chain (front proxy + platform ingress) the rightmost
// X-Forwarded-For entry is the *nearest* proxy's address, not the client, so
// every client collapses into a SINGLE rate-limit bucket and legitimate traffic
// gets 429'd in aggregate. Set this to the front proxy's trusted single-value
// client-IP header to key per real client. Empty (default) keeps the single-proxy
// rightmost-XFF behaviour. Like the XFF key, it is used ONLY as a transient
// limiter key and is never logged or forwarded to the gateway.
const TRUSTED_CLIENT_IP_HEADER = (process.env.TRUSTED_CLIENT_IP_HEADER || '').toLowerCase();

// --- Client auth ------------------------------------------------------------
// CLIENT_AUTH_MODE: 'off' (default; rely on network controls), 'secret' (interim
// shared-secret header), or 'token' (Privacy Pass / Private Access Token).
// The verify function is pluggable so 'token' slots in without restructuring.
const CLIENT_AUTH_MODE = (process.env.CLIENT_AUTH_MODE || 'off').toLowerCase();
const CLIENT_SECRET    = process.env.CLIENT_SECRET || '';
// Header the client presents its credential in. Default 'x-columbia-token' so the
// token mode reads exactly what the client sends (one header carrying the whole
// PrivateToken envelope) with no extra config. The 'secret' mode reuses the same
// header. An operator may override to 'authorization' if they prefer to carry the
// token there; the client would then send the same value under that header.
const CLIENT_AUTH_HEADER = (process.env.CLIENT_AUTH_HEADER || 'x-columbia-token').toLowerCase();

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

// --- Front door origin lock -------------------------------------------------
// When set, the relay accepts a request only if it arrived through a front door
// (a CDN or WAF, for example Azure Front Door), which injects the X-Azure-FDID
// header carrying the front door's profile id. This pins the public origin to the
// front door so the origin host can't be hit directly. Empty/unset => disabled,
// so the check is inert until an operator sets REQUIRE_FDID at deploy time once a
// front door is provisioned. The FDID value is NEVER logged.
const REQUIRE_FDID = process.env.REQUIRE_FDID || '';
// Header the edge front door injects to prove a request came through it. Azure
// Front Door uses X-Azure-FDID; override FDID_HEADER for a non-Azure CDN/WAF.
// Node lowercases all incoming header names, so match on the lowercase form.
const FDID_HEADER = (process.env.FDID_HEADER || 'x-azure-fdid').toLowerCase();

// --- Public key-config passthrough ------------------------------------------
// When the gateway runs internal-only, clients can no longer fetch its public
// GET /ohttp-configs (the key config they pin). The relay - the sole public hop
// - proxies it: a read-only GET that returns the gateway's PUBLIC key-config
// bytes verbatim. This leaks nothing: the key config is public material clients
// are MEANT to pin. Cached briefly so we don't hit the gateway per client.
const CONFIG_TTL_MS = parseInt(process.env.CONFIG_TTL_MS || '120000', 10);

function safeLogFields(fields) {
  const safe = {};
  if (fields.route !== undefined) safe.route = ['/relay', '/health', '/ohttp-configs'].includes(fields.route) ? fields.route : 'other';
  if (Number.isInteger(fields.status) && fields.status >= 100 && fields.status <= 599) safe.status = fields.status;
  if (Number.isFinite(fields.durationMs)) safe.durationMs = Math.max(0, Math.round(fields.durationMs));
  if (typeof fields.reused === 'boolean') safe.reused = fields.reused;
  if (['fatal', 'listen', 'uncaught_exception', 'unhandled_rejection'].includes(fields.event)) safe.event = fields.event;
  if (fields.errorType !== undefined) safe.errorType = ['Error', 'TypeError', 'ReferenceError', 'SyntaxError', 'RangeError', 'URIError', 'AggregateError'].includes(fields.errorType) ? fields.errorType : 'other';
  if (['gateway_url_invalid', 'gateway_not_https', 'resp_too_large', 'gres_error', 'gw_error', 'rate_limit', 'capacity', 'origin', 'client_auth', 'content_type', 'request_too_large', 'client_disconnect', 'state_unavailable'].includes(fields.reason)) safe.reason = fields.reason;
  if (fields.code !== undefined) safe.code = ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'ERR_STREAM_PREMATURE_CLOSE'].includes(fields.code) ? fields.code : 'other';
  return safe;
}
function log(fields) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...safeLogFields(fields) }) + '\n');
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

// Keep-alive pool for the relay→gateway hop (always https, enforced above).
// Reusing sockets avoids a TCP+TLS handshake per relay request; maxSockets
// bounds the pool (excess requests queue on the agent).
const gwAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

// The gateway's /ohttp-configs URL, derived from GATEWAY_URL (same host) unless
// explicitly overridden. The relay reaches the gateway at the same host whether
// the gateway is public or internal-only (same internal network).
const GATEWAY_CONFIGS_URL = process.env.GATEWAY_CONFIGS_URL || `${gw.protocol}//${gw.host}/ohttp-configs`;
let cfgGw = null;
try { cfgGw = new URL(GATEWAY_CONFIGS_URL); } catch { cfgGw = null; }

// Fixed-window per-IP counter. Map<ipBucket, { count, windowStart }>. Swept
// lazily on access; hard-capped key count so a spoofed-source flood can't grow
// the table unbounded.
const rateBuckets = new Map();
let inflight = 0;
let draining = false, httpClosed = false, shutdownTimer;
function finishDrain() {
  if (draining && httpClosed && inflight === 0) { clearTimeout(shutdownTimer); process.exit(0); }
}
function beginShutdown() {
  if (draining) return;
  draining = true;
  shutdownTimer = setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 25000);
  server.close(() => { httpClosed = true; finishDrain(); });
}

// Rate-limit key: the client IP as seen by the TRUSTED ingress. Behind a managed
// container platform, the TCP peer (socket.remoteAddress) is the ingress proxy, not
// the client, so per-IP limiting must read the rightmost X-Forwarded-For entry
// (the address the trusted ingress appended - a client-spoofed value can only
// sit to its LEFT). Used ONLY as a transient limiter key; never logged, never
// forwarded to the gateway.
function clientIpKey(req) {
  // Behind a multi-proxy chain (front proxy + platform ingress), prefer the
  // trusted single-value client-IP header the front proxy sets. The rightmost
  // X-Forwarded-For entry below is only correct for a SINGLE trusted proxy; with
  // two hops it is the nearest proxy's address and would collapse every client
  // into one bucket. See TRUSTED_CLIENT_IP_HEADER.
  if (TRUSTED_CLIENT_IP_HEADER) {
    const h = req.headers[TRUSTED_CLIENT_IP_HEADER];
    const v = Array.isArray(h) ? h[0] : h;
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
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
async function clientAuthorized(req) {
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

// Shared redemption state contains anonymous signature hashes only. It has no
// issuer device-state credentials. Never evict live spends or reset them on a
// replica restart; Azure rows remain until an explicit retired-key cleanup plan.
const REDEMPTION_CONNECTION = process.env.REDEMPTION_CONNECTION_STRING || '';
let redemption = REDEMPTION_CONNECTION ? azureRedemptionStore(require('@azure/data-tables').TableClient.fromConnectionString(
  REDEMPTION_CONNECTION, process.env.REDEMPTION_TABLE || 'columbiaredemptions', CLIENT_OPTIONS))
  : memoryRedemptionStore({ maxKeys: REDEMPTION_MAX_KEYS });
const issuerKeyCache = createIssuerKeyCache({ url: ISSUER_KEYS_URL, ttlMs: ISSUER_KEYS_TTL_MS });
function nullifierFor(sigBytes) { return crypto.createHash('sha256').update(sigBytes).digest('hex'); }

// Token mode verification. The client presents, in the CLIENT_AUTH_HEADER (default
// 'x-columbia-token'), a compact token:
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
async function verifyAccessToken(presented) {
  if (typeof presented !== 'string' || presented.length === 0) return false;

  // Allow an optional "PrivateToken " / "Bearer " prefix on the header value.
  const raw = presented.replace(/^(PrivateToken|Bearer)\s+/i, '').trim();

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

  const entry = await issuerKeyCache.get(keyId);
  if (!entry) return false; // an unknown key in a valid cached epoch is rejected
  const pub = entry.publicKey;

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
  if (!(await redemption.redeem(entry.fingerprint, nullifierFor(sigBuf)))) return false;

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

// Front door origin lock check. Returns true if the request is allowed to
// proceed: either REQUIRE_FDID is unset (lock disabled) or the request carries a
// matching X-Azure-FDID. A request may carry MULTIPLE x-azure-fdid values (Node
// comma-joins a repeated header), so we split and accept if ANY token matches
// REQUIRE_FDID via the constant-time compare. The header value is NEVER logged.
function frontDoorAllowed(req) {
  if (!REQUIRE_FDID) return true; // lock disabled => behavior unchanged
  const raw = req.headers[FDID_HEADER];
  if (typeof raw !== 'string' || raw.length === 0) return false;
  for (const tok of raw.split(',')) {
    if (timingSafeEqualStr(tok.trim(), REQUIRE_FDID)) return true;
  }
  return false;
}

// The set of paths exempt from the front door origin lock. Only GET /health is
// exempt on the relay: the platform health probe hits it in-environment with no
// front door in that hop. Every other relay route (/relay, /ohttp-configs)
// requires the FDID when REQUIRE_FDID is set.
function fdidExempt(req, path) {
  return req.method === 'GET' && path === '/health';
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
    agent: gwAgent, // same host as the gateway POST, share the keep-alive pool
  };
  proxyGatewayRequest(opts, undefined, res, start, '/ohttp-configs', (status, headers, body) => {
    const contentType = headers['content-type'] || 'application/octet-stream';
    if (status === 200) configCache = { body, contentType, fetchedAt: Date.now() };
    return { 'Content-Type': contentType };
  });
}

const server = http.createServer(async (req, res) => {
  if (draining) { res.writeHead(503, { 'Retry-After': '2' }); res.end(); return; }
  const start = Date.now();

  // Front door origin lock. When REQUIRE_FDID is set, every non-exempt request
  // must arrive through the front door (which injects X-Azure-FDID). This runs
  // BEFORE any route does work so a direct-to-origin hit is rejected up front.
  // GET /health is exempt so the platform probe still passes. The FDID value is
  // never logged; we log only the route + status. When REQUIRE_FDID is unset this
  // whole block is a no-op.
  if (REQUIRE_FDID) {
    const path = String(req.url || '').split('?')[0];
    if (!fdidExempt(req, path) && !frontDoorAllowed(req)) {
      res.writeHead(403); res.end();
      log({ route: path, status: 403, reason: 'origin', durationMs: Date.now() - start });
      return;
    }
  }

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    // Successful platform probes are NOT logged: at Container Apps probe
    // cadence they were ~125k rows/day/replica of pure Log Analytics
    // ingestion cost drowning the real RED signal. LOG_HEALTH=1 re-enables
    // for a debugging session. (A failing probe never reaches this branch,
    // so failures remain observable via the platform's own probe events.)
    if (process.env.LOG_HEALTH === '1') {
      log({ route: '/health', status: 200, durationMs: Date.now() - start });
    }
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
    log({ route: '/relay', status: 415, reason: 'content_type', durationMs: Date.now() - start });
    return;
  }

  // Per-IP rate limit. The address is used ONLY as a transient limiter key and is
  // never logged. See clientIpKey for why we read the trusted X-Forwarded-For.
  if (rateLimited(clientIpKey(req))) {
    res.writeHead(429); res.end();
    log({ route: '/relay', status: 429, reason: 'rate_limit', durationMs: Date.now() - start });
    return;
  }

  // Global in-flight concurrency cap. Reserve a slot; release it on every
  // terminal path (success, error, abort, oversize, client disconnect).
  if (inflight >= MAX_INFLIGHT) {
    res.writeHead(429); res.end();
    log({ route: '/relay', status: 429, reason: 'capacity', durationMs: Date.now() - start });
    return;
  }
  inflight += 1;
  let slotReleased = false, authPending = true, releaseRequested = false;
  const releaseSlot = () => {
    if (authPending) { releaseRequested = true; return; }
    if (!slotReleased) { slotReleased = true; inflight -= 1; finishDrain(); }
  };
  res.on('finish', releaseSlot); // retain capacity until buffered output is flushed
  res.on('close', releaseSlot);   // safety net for any teardown path

  // Reserve capacity before asynchronous shared-state admission. Request bodies
  // remain paused until authorization completes; disconnects release the slot.
  try {
    if (!(await clientAuthorized(req))) {
      if (!res.destroyed) { res.writeHead(401); res.end(); }
      log({ route: '/relay', status: 401, reason: 'client_auth', durationMs: Date.now() - start });
      return;
    }
  } catch {
    if (!res.destroyed) { res.writeHead(503, { 'Retry-After': '2' }); res.end(); }
    log({ route: '/relay', status: 503, reason: 'state_unavailable', durationMs: Date.now() - start });
    return;
  } finally {
    authPending = false;
    if (releaseRequested || req.destroyed || res.destroyed) releaseSlot();
  }
  if (req.destroyed || res.destroyed) { releaseSlot(); return; }

  const chunks = [];
  let received = 0;
  let aborted = false;
  req.on('aborted', () => {
    if (!aborted) log({ route: '/relay', status: 499, reason: 'client_disconnect', durationMs: Date.now() - start });
    aborted = true;
    releaseSlot();
  });
  req.on('data', (c) => {
    if (aborted) return;
    received += c.length;
    if (received > MAX_BODY) {
      // Request body too large: refuse, tear down, and stop buffering.
      aborted = true;
      res.writeHead(413); res.end();
      log({ route: '/relay', status: 413, reason: 'request_too_large', durationMs: Date.now() - start });
      releaseSlot();
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (aborted || res.destroyed) return;
    forwardToGateway(Buffer.concat(chunks), res, start);
  });
});

// Forward the (fully buffered) ciphertext to the gateway and buffer the answer
// back to the client. Forward ONLY the opaque ciphertext + its content type.
// Deliberately send a fresh request with NO client headers, NO X-Forwarded-For -
// the gateway must not learn who the client is. The ONLY additional header is the
// relay→gateway shared secret, which identifies the RELAY (not the client) so the
// gateway can refuse traffic that didn't come through us.
//
// Ciphertext may contain a write. A reset on a reused socket does not prove
// the gateway failed to dispatch it; only the client knows whether replay is
// safe. Return the ambiguous failure and let read clients choose to retry.
function forwardToGateway(body, res, start) {
  const outHeaders = { 'Content-Type': 'message/ohttp-req', 'Content-Length': body.length };
  if (RELAY_GATEWAY_SECRET) outHeaders[RELAY_GATEWAY_HEADER] = RELAY_GATEWAY_SECRET;
  const opts = {
    hostname: gw.hostname,
    port: GW_PORT,
    path: gw.pathname,
    method: 'POST',
    timeout: GW_TIMEOUT_MS,
    headers: outHeaders,
    agent: gwAgent,
  };
  proxyGatewayRequest(opts, body, res, start, '/relay', () => ({ 'Content-Type': 'message/ohttp-res' }));
}

// Both gateway endpoints use the same size limit and terminal-state handling.
// headersForResponse may cache successful public configs; it runs only after a
// complete response. A caller disconnect cancels work before capacity is freed.
function proxyGatewayRequest(opts, body, res, start, route, headersForResponse) {
  let completed = false;
  let gatewayResponse;
  // Request and response errors can both fire for the same socket teardown.
  // Complete once so RED logs count one relay outcome and cleanup is symmetric.
  const finish = (status, reason, error, responseBody, responseHeaders = {}) => {
    if (completed) return;
    completed = true;
    res.removeListener('close', clientClosed);
    if (!res.destroyed && !res.headersSent) {
      res.writeHead(status, responseHeaders);
      res.end(responseBody);
    }
    log({ route, status, reason, code: error?.code,
      reused: reason === 'gw_error' ? greq.reusedSocket : undefined, durationMs: Date.now() - start });
  };
  const clientClosed = () => {
    if (res.writableEnded || completed) return;
    // Releasing a slot without destroying its outbound work lets disconnecting
    // callers bypass MAX_INFLIGHT and fill the Agent's pending-request queue.
    finish(499, 'client_disconnect');
    gatewayResponse?.destroy();
    greq.destroy();
  };
  const greq = https.request(opts, (gres) => {
    gatewayResponse = gres;
    if (completed) { gres.destroy(); return; }
    const rc = [];
    let rcLen = 0;
    gres.on('data', (d) => {
      if (completed) return;
      rcLen += d.length;
      if (rcLen > MAX_RESP_BYTES) {
        finish(502, 'resp_too_large');
        gres.destroy();
        greq.destroy();
        return;
      }
      rc.push(d);
    });
    gres.on('end', () => {
      if (completed) return;
      const responseBody = Buffer.concat(rc, rcLen);
      const status = gres.statusCode || 502;
      finish(status, undefined, undefined, responseBody, headersForResponse(status, gres.headers, responseBody));
    });
    gres.on('error', (err) => {
      finish(502, 'gres_error', err);
      greq.destroy();
    });
  });
  res.prependListener('close', clientClosed); // cancel upstream before the slot-release listener
  greq.on('timeout', () => {
    greq.destroy(Object.assign(new Error('gw timeout'), { code: 'ETIMEDOUT' }));
  });
  greq.on('error', (err) => {
    finish(502, 'gw_error', err);
    gatewayResponse?.destroy();
  });
  if (res.destroyed) { clientClosed(); return; }
  greq.end(body);
}

// Crash forensics: an uncaught throw or unhandled rejection used to kill the
// process with NOTHING in the structured log stream. Log a bounded cause, then
// exit non-zero so the platform restarts the replica. Nothing request-derived
// is logged: free-form messages and stack text are discarded at the log boundary.
process.on('uncaughtException', (err) => {
  log({ event: 'uncaught_exception', code: err && err.code, errorType: err && err.name });
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  const e = reason instanceof Error ? reason : new Error(String(reason));
  log({ event: 'unhandled_rejection', code: e.code, errorType: e.name });
  process.exit(1);
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
  process.on('SIGTERM', beginShutdown);
  process.on('SIGINT', beginShutdown);
  server.listen(PORT, () => log({ event: 'listen', port: PORT, role: 'ohttp-relay' }));
}

// Test-only surface. Lets the harness exercise the token-mode verification path
// (signature check + spend-once) directly. Nothing here changes runtime behavior.
module.exports = {
  server,
  verifyAccessToken,
  nullifierFor,
  safeLogFields,
  beginShutdown,
  setIssuerKeysForTest(map, expiresAt) { issuerKeyCache.setForTest(map, expiresAt); },
  setRedemptionStoreForTest(store) { redemption = store; },
};
