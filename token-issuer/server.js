// Columbia - token issuer (Privacy Pass Attester + Issuer)
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// This is the Attester + Issuer roles of the Privacy Pass architecture
// (RFC 9576). It is the ONE component in the system that is allowed to learn a
// device's identity, and the whole design is built so that knowing it buys the
// operator nothing: the issuer only ever sees BLINDED token requests, blind-signs
// them (RFC 9474 blind RSA), and hands back blind signatures. It never sees the
// finished, unblinded tokens, and it never sees the content the tokens are later
// spent on. That separation is the point. The relay (a different operator) checks
// the tokens and sees content+IP but never the device id.
//
// Token construction is RSABSSA-SHA384-PSS-Deterministic over 2048-bit RSA, which
// is exactly the publicly-verifiable Privacy Pass token (Token Type 2, RFC 9578)
// that Apple's Private Access Tokens use. "Publicly verifiable" matters here: the
// relay verifies a spent token against the issuer's epoch PUBLIC key offline, with
// no per-request call back to the issuer.
//
// TRUST / NON-COLLUSION: the issuer must be run such that it never colludes with
// the relay. If one operator ran both, it could line up "device D asked for tokens
// in epoch E" (issuer view) against "a token from epoch E was spent on content C"
// (relay view) and, with enough traffic shaping, start to link device to content.
// Deploy the issuer as its own public service under separate control, exactly like
// the gateway. See ./README.md.
//
// LOGGING IS RED-ONLY. We never log the device id (keyId), the App Attest
// assertion, a blinded request, a blind signature, or anything else that could tie
// a device to its tokens. The device id is used transiently for the per-epoch
// quota check and then dropped. Counters in logs are aggregate only.

// Native ES module. @cloudflare/blindrsa-ts is ESM-only, so this whole package is
// ESM ("type": "module" in package.json). require() of an ESM dep throws
// ERR_REQUIRE_ESM on node 20 (the deploy runtime), so a CommonJS require() here
// would crash-loop the container even though it happens to work on newer node.

import http from 'node:http';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { TableClient } from '@azure/data-tables';
import { createIssuerState, memoryDeviceBackend, azureDeviceBackend, ISSUER_STATE_CLIENT_OPTIONS } from './state-store.js';

import { validateAppAttest, attestationFailureCategory, APP_ATTEST_READY } from './appattest.js';
import { createEpochKeyProvider, derivePublicKey, keyIdFromSpki } from './epoch-keys.js';

// --- Config -----------------------------------------------------------------

const PORT = parseInt(process.env.PORT || '8080', 10); // non-root can't bind <1024

// Epoch length. The issuer keypair rotates every epoch; the relay caches the
// current epoch public key and accepts only tokens from epochs it still holds.
// Default one week. Kept deliberately coarse so the anonymity set per epoch is
// large (everyone issued in the same epoch is indistinguishable at spend time).
const EPOCH_SECONDS = parseInt(process.env.EPOCH_SECONDS || String(7 * 24 * 3600), 10);

// Per-device per-epoch issuance quota. A device may obtain at most this many
// tokens per epoch. This is the abuse bound: even our own users are rate limited.
// Shared with registration/counter state when configured. Default 256 tokens/epoch.
const ISSUANCE_QUOTA_PER_EPOCH = Number(process.env.ISSUANCE_QUOTA_PER_EPOCH || '256');

// Max blinded token requests accepted in a single /issue call, so one request
// can't ask us to do unbounded RSA work. The client batches up to this many.
const MAX_TOKENS_PER_REQUEST = parseInt(process.env.MAX_TOKENS_PER_REQUEST || '64', 10);

// Body size cap (the assertion + N blinded messages). Bounds memory per request.
const MAX_BODY = parseInt(process.env.MAX_BODY_BYTES || '262144', 10);

// Bind the App Attest clientDataHash to the blinded[] payload (see handleIssue
// step a2). ON by default: App Attest then proves the device authorized THESE
// tokens, not just that a genuine device is present. Set to 0 only during client
// bring-up, before the iOS client computes clientDataHash over the batch.
const REQUIRE_CLIENT_DATA_BINDING = process.env.REQUIRE_CLIENT_DATA_BINDING !== '0';

// Legacy single-key configurations keep their wire contract. Explicit manifests
// supply distinct current/previous keys consistently across replicas; missing or
// malformed configured manifests fail closed, with no fallback to the old key.
const ISSUER_SIGNING_KEY_B64 = process.env.ISSUER_SIGNING_KEY || '';
const ISSUER_EPOCH_KEYS_JSON = process.env.ISSUER_EPOCH_KEYS_JSON;

// --- Front door origin lock -------------------------------------------------
// When set, the issuer accepts a request only if it arrived through a front door
// (a CDN or WAF, for example Azure Front Door), which injects the X-Azure-FDID
// header carrying the front door's profile id. This pins the public origin to the
// front door so the origin host can't be hit directly. Empty/unset => disabled, so
// the check is inert until an operator sets REQUIRE_FDID at deploy time once a
// front door is provisioned. The FDID value is NEVER logged.
// GET /health AND GET /issuer-keys are exempt: the relay fetches /issuer-keys
// directly, in-environment, with no front door in that hop, and it is public key
// material. Every other route (/issue and any /attest* endpoints) requires it.
const REQUIRE_FDID = process.env.REQUIRE_FDID || '';
// Header the edge front door injects to prove a request came through it. Azure
// Front Door uses X-Azure-FDID; override FDID_HEADER for a non-Azure CDN/WAF.
// Node lowercases all incoming header names, so match on the lowercase form.
const FDID_HEADER = (process.env.FDID_HEADER || 'x-azure-fdid').toLowerCase();

// RSA-PSS / blind-RSA parameters. SHA-384, 2048-bit modulus, deterministic PSS -
// the Apple PAT / RFC 9578 Token Type 2 suite.
const RSA_MODULUS_BITS = 2048;
const PSS_HASH = 'SHA-384';

const suite = RSABSSA.SHA384.PSS.Deterministic();

// --- Logging (RED-only) -----------------------------------------------------

function safeLogFields(fields) {
  const safe = {};
  if (fields.route !== undefined) safe.route = ['/health', '/issuer-keys', '/issue'].includes(fields.route) ? fields.route : 'other';
  if (Number.isInteger(fields.status) && fields.status >= 100 && fields.status <= 599) safe.status = fields.status;
  if (Number.isFinite(fields.durationMs)) safe.durationMs = Math.max(0, Math.round(fields.durationMs));
  if (['bad_json', 'missing_keyid', 'bad_batch_size', 'attest_failed', 'client_data_binding_failed', 'quota_exceeded', 'bad_blinded_type', 'bad_blinded_len', 'no_signing_key', 'blind_sign_error', 'state_unavailable', 'unhandled'].includes(fields.reason)) safe.reason = fields.reason;
  if (['attestation', 'assertion', 'missing'].includes(fields.proofMode)) safe.proofMode = fields.proofMode;
  if (['configuration', 'client_data', 'proof_format', 'unknown_device_key', 'state_unavailable', 'key_binding', 'counter', 'expired_epoch', 'quota', 'environment', 'app_identity', 'assertion_signature', 'certificate_chain', 'nonce_binding', 'verification'].includes(fields.attestFailure)) safe.attestFailure = fields.attestFailure;
  for (const key of ['issued', 'count']) {
    if (Number.isInteger(fields[key]) && fields[key] >= 0 && fields[key] <= MAX_TOKENS_PER_REQUEST) safe[key] = fields[key];
  }
  if (Number.isSafeInteger(fields.epoch) && fields.epoch >= 0) safe.epoch = fields.epoch;
  if (fields.event === 'listen') {
    safe.event = 'listen';
    safe.role = 'token-issuer';
    safe.appAttest = fields.appAttest === 'enforced' ? 'enforced' : 'stub-fail-closed';
    safe.signingKey = fields.signingKey === 'present' ? 'present' : 'missing-fail-closed';
  }
  return safe;
}

function log(fields) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...safeLogFields(fields) }) + '\n');
}

// --- Epoch math -------------------------------------------------------------

// Epoch id is a monotonically increasing integer: floor(unixSeconds / EPOCH_SECONDS).
// Both issuer and relay can compute it independently; tokens carry no timestamp,
// only the epoch's key id, so spend time leaks nothing finer than the epoch.
function currentEpoch() {
  return Math.floor(Date.now() / 1000 / EPOCH_SECONDS);
}

// The canonical value the device's App Attest challenge must hash to, so the
// attestation/assertion is bound to THIS blinded batch in THIS epoch (see the
// REQUIRE_CLIENT_DATA_BINDING gate in handleIssue). The client computes the same
// SHA-256 over the same bytes when it requests its App Attest assertion:
//   SHA-256( utf8(epoch) || 0x00 || blinded[0] || 0x00 || blinded[1] || 0x00 ... )
// where each blinded[i] is the raw (base64-decoded) blinded message. The 0x00
// separators and the leading epoch make the preimage unambiguous.
function expectedClientDataHash(epochId, blinded) {
  const h = crypto.createHash('sha256');
  h.update(String(epochId), 'utf8');
  for (const b of blinded) {
    h.update(Buffer.from([0x00]));
    h.update(Buffer.from(b, 'base64'));
  }
  return h.digest();
}

// The signing key must belong to the epoch the client actually blinded for.
// Matching a previous-epoch binding but signing with a new epoch key breaks
// finalization as soon as an operator rotates distinct keys.
function boundEpoch(clientDataHash, blinded, epochId) {
  if (typeof clientDataHash !== 'string') return null;
  let got;
  try { got = Buffer.from(clientDataHash, 'base64'); } catch { return null; }
  if (got.length !== 32) return null;
  for (const candidate of [epochId, epochId - 1]) {
    if (crypto.timingSafeEqual(got, expectedClientDataHash(candidate, blinded))) return candidate;
  }
  return null;
}

// --- Epoch key management ---------------------------------------------------
// Only the operator's current/previous manifest keys are eligible. The provider
// checks live epoch ownership even after asynchronous import. Legacy mode cannot
// provide cryptographic expiry while its one public key remains published.
const epochKeyProvider = createEpochKeyProvider({ legacySigningKeyB64: ISSUER_SIGNING_KEY_B64,
  manifestJSON: ISSUER_EPOCH_KEYS_JSON, currentEpoch });
const keysForEpoch = epoch => epochKeyProvider.keysForEpoch(epoch);

// One atomic registration/counter/quota row per salted canonical hardware key.
// Memory is a bounded single-process option. Azure requires a stable secret salt;
// salt mismatch against persisted configuration fails closed instead of resetting
// every device's identity and quota. Issuer credentials never belong to the relay.
const STATE_CONNECTION = process.env.ISSUER_STATE_CONNECTION_STRING || '';
const STATE_TABLE = process.env.ISSUER_STATE_TABLE || 'columbiaissuerstate';
const STATE_SALT = STATE_CONNECTION ? Buffer.from(process.env.ISSUER_STATE_SALT || '', 'base64') : crypto.randomBytes(32);
const ISSUER_STATE = createIssuerState({
  backend: STATE_CONNECTION ? azureDeviceBackend(TableClient.fromConnectionString(STATE_CONNECTION, STATE_TABLE,
    ISSUER_STATE_CLIENT_OPTIONS), { salt: STATE_SALT }) : memoryDeviceBackend(),
  salt: STATE_SALT, quota: ISSUANCE_QUOTA_PER_EPOCH,
});

// --- /issue -----------------------------------------------------------------
//
// Request JSON:
//   {
//     "keyId":        "<base64url App Attest key id>",   // the device identifier
//     "attestation":  "<base64 App Attest attestation>", // first call per device
//     "assertion":    "<base64 App Attest assertion>",   // subsequent calls
//     "clientDataHash": "<base64 sha256 of the request the device signed>",
//     "blinded": [ "<base64 blinded_msg>", ... ]         // 1..MAX blinded requests
//   }
//
// Response JSON:
//   {
//     "epoch":      <int>,
//     "keyId":      "<issuer epoch public key id>",
//     "blindSigs":  [ "<base64 blind signature>", ... ]  // same order as blinded
//   }
//
// The issuer blind-signs each blinded_msg and returns the blind signatures. It
// never unblinds, so it cannot see the finished tokens. The client finalizes them
// locally and spends them at the relay.
async function handleIssue(req, res, start, body) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    res.writeHead(400); res.end();
    log({ route: '/issue', status: 400, reason: 'bad_json', durationMs: Date.now() - start });
    return;
  }

  const { keyId, attestation, assertion, clientDataHash, blinded } = parsed || {};

  // Shape checks before any crypto work.
  if (typeof keyId !== 'string' || !keyId.length) {
    res.writeHead(400); res.end();
    log({ route: '/issue', status: 400, reason: 'missing_keyid', durationMs: Date.now() - start });
    return;
  }
  if (!Array.isArray(blinded) || blinded.length < 1 || blinded.length > MAX_TOKENS_PER_REQUEST) {
    res.writeHead(400); res.end();
    log({ route: '/issue', status: 400, reason: 'bad_batch_size', durationMs: Date.now() - start });
    return;
  }

  // Decode the blinded messages. Each must be exactly the RSA modulus size
  // (256 bytes for RSA-2048); reject anything malformed before signing.
  const expectedLen = RSA_MODULUS_BITS / 8;
  const blindedBufs = [];
  for (const b of blinded) {
    if (typeof b !== 'string') {
      res.writeHead(400); res.end();
      log({ route: '/issue', status: 400, reason: 'bad_blinded_type', durationMs: Date.now() - start });
      return;
    }
    const buf = Buffer.from(b, 'base64');
    if (buf.length !== expectedLen) {
      res.writeHead(400); res.end();
      log({ route: '/issue', status: 400, reason: 'bad_blinded_len', durationMs: Date.now() - start });
      return;
    }
    blindedBufs.push(new Uint8Array(buf));
  }

  // (a2) REQUEST-PAYLOAD BINDING. App Attest proves "a genuine device signed THIS
  // clientDataHash"; on its own it does NOT prove the device authorized THESE
  // blinded messages, because clientDataHash is an opaque 32 bytes from the client.
  // Without binding, a captured valid {keyId, assertion, clientDataHash} could be
  // replayed against a different `blinded[]` batch (still rate-limited by the
  // per-device quota, but not request-integrity-checked).
  //
  // To close that, the client MUST set its App Attest challenge so that
  //   clientDataHash == SHA-256( utf8("<epoch>") || 0x00 || each base64(blinded) joined by 0x00 )
  // i.e. clientDataHash commits to the exact batch being requested in this epoch.
  // We recompute that here and require equality. This is gated behind an env flag
  // (default ON in production once the client ships the matching hash; an operator
  // may set REQUIRE_CLIENT_DATA_BINDING=0 during client bring-up, accepting that
  // App Attest then only bounds abuse per-device and does not bind the payload).
  const epochId = currentEpoch();

  let signingEpochId = epochId;
  if (REQUIRE_CLIENT_DATA_BINDING) {
    signingEpochId = boundEpoch(clientDataHash, blinded, epochId);
    if (signingEpochId === null) {
      res.writeHead(401); res.end();
      log({ route: '/issue', status: 401, reason: 'client_data_binding_failed', durationMs: Date.now() - start });
      return;
    }
  }

  // (c) Sign with the epoch key matched by the binding, including at rollover.
  let keys;
  try {
    keys = await keysForEpoch(signingEpochId);
  } catch (e) {
    // Missing/invalid signing key => fail closed.
    res.writeHead(503); res.end();
    log({ route: '/issue', status: 503, reason: 'no_signing_key', durationMs: Date.now() - start });
    return;
  }

  // (a) Validate App Attest. This proves the request comes from a genuine,
  // unmodified iOS client install on real Apple hardware. FAILS CLOSED: if App Attest
  // is unconfigured (Apple root cert / team+bundle id not supplied), the validator
  // returns { ok: false } and we reject. We never log the assertion/attestation,
  // and we never log the coarse failure reason at a level that could fingerprint a
  // device (it is an aggregate counter only).
  //
  // Verification returns a candidate. The atomic reservation below owns all
  // registration, counter and quota mutation, including competing replicas.
  let attest;
  try {
    attest = await validateAppAttest({ keyId, attestation, assertion, clientDataHash, store: ISSUER_STATE });
  } catch {
    attest = { ok: false, reason: 'verification_exception' };
  }
  if (!attest || !attest.ok) {
    const unavailable = attest?.reason === 'state_unavailable';
    const status = unavailable ? 503 : 401;
    res.writeHead(status, { 'Content-Type': 'application/json', ...(unavailable ? { 'Retry-After': '2' } : {}) });
    res.end(JSON.stringify({ error: unavailable ? 'state_unavailable' : attest?.reason === 'unknown_device_key' ? 'unknown_device_key' : 'attest_failed' }));
    log({ route: '/issue', status, reason: unavailable ? 'state_unavailable' : 'attest_failed',
      proofMode: attestation ? 'attestation' : assertion ? 'assertion' : 'missing',
      attestFailure: attestationFailureCategory(attest), durationMs: Date.now() - start });
    return;
  }
  let reservation;
  try {
    reservation = await ISSUER_STATE.reserve({ keyId: attest.keyId, mode: attest.mode,
      publicKeyPem: attest.publicKeyPem, signCount: attest.signCount,
      epoch: epochId, count: blinded.length });
  } catch {
    res.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '2' });
    res.end(JSON.stringify({ error: 'state_unavailable' }));
    log({ route: '/issue', status: 503, reason: 'state_unavailable', durationMs: Date.now() - start });
    return;
  }
  if (!reservation.ok) {
    const limited = reservation.reason === 'quota_exceeded';
    const retryAfter = Math.max(1, Math.ceil((epochId + 1) * EPOCH_SECONDS - Date.now() / 1000));
    res.writeHead(limited ? 429 : 401, { 'Content-Type': 'application/json', ...(limited ? { 'Retry-After': String(retryAfter) } : {}) });
    res.end(JSON.stringify({ error: limited ? 'quota_exceeded' : reservation.reason === 'unknown_device_key' ? 'unknown_device_key' : 'attest_failed' }));
    log({ route: '/issue', status: limited ? 429 : 401, reason: limited ? 'quota_exceeded' : 'attest_failed',
      proofMode: attest.mode, attestFailure: attestationFailureCategory(reservation),
      count: blinded.length, durationMs: Date.now() - start });
    return;
  }

  const blindSigs = [];
  try {
    for (const bm of blindedBufs) {
      const sig = await suite.blindSign(keys.priv, bm);
      blindSigs.push(Buffer.from(sig).toString('base64'));
    }
  } catch {
    res.writeHead(500); res.end();
    log({ route: '/issue', status: 500, reason: 'blind_sign_error', durationMs: Date.now() - start });
    return;
  }

  // (d) Return the blind signatures. Same order as the request's blinded array.
  const out = JSON.stringify({ epoch: signingEpochId, keyId: keys.keyId, blindSigs });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(out);
  // Aggregate count only - never which device, never the signatures.
  log({ route: '/issue', status: 200, issued: blindSigs.length, epoch: epochId, durationMs: Date.now() - start });
}

// --- /issuer-keys -----------------------------------------------------------
//
// Publishes the current (and previous) epoch RSA PUBLIC key so the relay can
// verify spent tokens offline. Public material only - safe to serve to anyone.
//
// Response JSON:
//   {
//     "suite": "RSABSSA-SHA384-PSS-Deterministic",
//     "epoch": <currentEpochId>,
//     "keys": [
//       { "epoch": <id>, "keyId": "<id>", "publicKeySpki": "<base64 SPKI>" },
//       ...   // current + previous epoch, so in-flight tokens still verify
//     ]
//   }
async function handleIssuerKeys(res, start) {
  const epochId = currentEpoch();
  const keys = [];
  try {
    for (const id of [epochId, epochId - 1]) {
      const k = await keysForEpoch(id);
      keys.push({ epoch: id, keyId: k.keyId, publicKeySpki: k.spkiB64 });
    }
  } catch {
    res.writeHead(503); res.end();
    log({ route: '/issuer-keys', status: 503, reason: 'no_signing_key', durationMs: Date.now() - start });
    return;
  }
  const out = JSON.stringify({
    schemaVersion: 1,
    suite: 'RSABSSA-SHA384-PSS-Deterministic',
    epoch: epochId,
    epochSeconds: EPOCH_SECONDS,
    keys,
  });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(out);
  log({ route: '/issuer-keys', status: 200, epoch: epochId, durationMs: Date.now() - start });
}

// --- Front Door origin lock -------------------------------------------------

// Length-independent constant-time string compare (hash both sides so length
// never leaks via timing; tolerates missing/short input). Mirrors the relay's
// timingSafeEqualStr and the clientDataHash binding check, which already use
// crypto.timingSafeEqual for constant-time comparison.
function timingSafeEqualStr(presented, expected) {
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const ha = crypto.createHash('sha256').update(presented).digest();
  const hb = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Returns true if the request is allowed to proceed: either REQUIRE_FDID is unset
// (lock disabled) or the request carries a matching X-Azure-FDID. A request may
// carry MULTIPLE x-azure-fdid values (Node comma-joins a repeated header), so we
// split and accept if ANY token matches REQUIRE_FDID via the constant-time
// compare. The header value is NEVER logged.
function frontDoorAllowed(req) {
  if (!REQUIRE_FDID) return true; // lock disabled => behavior unchanged
  const raw = req.headers[FDID_HEADER];
  if (typeof raw !== 'string' || raw.length === 0) return false;
  for (const tok of raw.split(',')) {
    if (timingSafeEqualStr(tok.trim(), REQUIRE_FDID)) return true;
  }
  return false;
}

// Paths exempt from the Front Door origin lock. GET /health is the platform probe
// (in-environment, no Front Door hop). GET /issuer-keys is fetched directly by the
// relay in-environment and is public key material. Every other route (/issue and
// any /attest* endpoint) requires the FDID when REQUIRE_FDID is set.
function fdidExempt(req, path) {
  if (req.method !== 'GET') return false;
  return path === '/health' || path === '/issuer-keys';
}

// --- HTTP server ------------------------------------------------------------

let draining = false, httpClosed = false, activeWork = 0, shutdownTimer;
function finishDrain() {
  if (draining && httpClosed && activeWork === 0) { clearTimeout(shutdownTimer); process.exit(0); }
}
function beginShutdown() {
  if (draining) return;
  draining = true;
  shutdownTimer = setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 25000);
  server.close(() => { httpClosed = true; finishDrain(); });
}
function trackWork(promise) {
  activeWork++;
  return promise.finally(() => { activeWork--; finishDrain(); });
}
const server = http.createServer((req, res) => {
  if (draining) { res.writeHead(503, { 'Retry-After': '2' }); res.end(); return; }
  const start = Date.now();

  // Front door origin lock. When REQUIRE_FDID is set, every non-exempt request
  // must arrive through the front door (which injects X-Azure-FDID). This runs
  // BEFORE any route does work so a direct-to-origin hit is rejected up front.
  // GET /health and GET /issuer-keys are exempt (see fdidExempt). The FDID value
  // is never logged; we log only the route + status. When REQUIRE_FDID is unset
  // this whole block is a no-op.
  if (REQUIRE_FDID) {
    const path = String(req.url || '').split('?')[0];
    if (!fdidExempt(req, path) && !frontDoorAllowed(req)) {
      res.writeHead(403); res.end();
      log({ route: path, status: 403, durationMs: Date.now() - start });
      return;
    }
  }

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    // Successful platform probes are NOT logged (~110k rows/day of Log
    // Analytics ingestion drowning the real signal); LOG_HEALTH=1 re-enables
    // for a debugging session. Failing probes never reach this branch.
    if (process.env.LOG_HEALTH === '1') {
      log({ route: '/health', status: 200, durationMs: Date.now() - start });
    }
    return;
  }

  if (req.method === 'GET' && req.url === '/issuer-keys') {
    trackWork(handleIssuerKeys(res, start));
    return;
  }

  if (req.method === 'POST' && req.url === '/issue') {
    const ctype = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ctype !== 'application/json') {
      res.writeHead(415); res.end();
      log({ route: '/issue', status: 415, durationMs: Date.now() - start });
      return;
    }
    const chunks = [];
    let received = 0;
    let aborted = false;
    req.on('data', (c) => {
      if (aborted) return;
      received += c.length;
      if (received > MAX_BODY) {
        aborted = true;
        res.writeHead(413); res.end();
        log({ route: '/issue', status: 413, durationMs: Date.now() - start });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (aborted) return;
      if (draining) { res.writeHead(503, { 'Retry-After': '2' }); res.end(); return; }
      trackWork(handleIssue(req, res, start, Buffer.concat(chunks))).catch(() => {
        if (!res.headersSent) { res.writeHead(500); res.end(); }
        log({ route: '/issue', status: 500, reason: 'unhandled', durationMs: Date.now() - start });
      });
    });
    return;
  }

  // Anything else: 404. No probing other paths.
  res.writeHead(404); res.end();
});

// Connection-level timeouts so slow clients can't pin sockets.
server.requestTimeout = 20000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;

// Run as the entrypoint? The ESM equivalent of `require.main === module`: compare
// the file node was invoked with against this module's own URL. When imported by
// the test harness this is false, so requiring/importing the module does NOT bind
// a port.
const isEntrypoint = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

// Surface, at startup, whether App Attest is fully wired or still a fail-closed
// stub, and whether a signing key is present. This is the one place an operator
// learns the service is running in stub mode - it is NOT silent.
if (isEntrypoint) {
  process.on('SIGTERM', beginShutdown);
  process.on('SIGINT', beginShutdown);
  server.listen(PORT, () => {
    log({
      event: 'listen',
      port: PORT,
      role: 'token-issuer',
      appAttest: APP_ATTEST_READY ? 'enforced' : 'stub-fail-closed',
      signingKey: ISSUER_SIGNING_KEY_B64 || ISSUER_EPOCH_KEYS_JSON !== undefined ? 'present' : 'missing-fail-closed',
      epochSeconds: EPOCH_SECONDS,
    });
  });
}

// Export internals for the test harness (no network needed to unit test).
export {
  server,
  suite,
  currentEpoch,
  keysForEpoch,
  keyIdFromSpki,
  derivePublicKey,
  expectedClientDataHash,
  boundEpoch,
  safeLogFields,
  ISSUER_STATE,
  beginShutdown,
  EPOCH_SECONDS,
  RSA_MODULUS_BITS,
  PSS_HASH,
};
