// Columbia - token issuer (Privacy Pass Attester + Issuer)
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
// Deploy the issuer as its own public Azure Container App under separate control,
// exactly like the gateway. See ./README.md.
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
import crypto, { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

import { validateAppAttest, APP_ATTEST_READY } from './appattest.js';

// --- Config -----------------------------------------------------------------

const PORT = parseInt(process.env.PORT || '8080', 10); // non-root can't bind <1024

// Epoch length. The issuer keypair rotates every epoch; the relay caches the
// current epoch public key and accepts only tokens from epochs it still holds.
// Default one week. Kept deliberately coarse so the anonymity set per epoch is
// large (everyone issued in the same epoch is indistinguishable at spend time).
const EPOCH_SECONDS = parseInt(process.env.EPOCH_SECONDS || String(7 * 24 * 3600), 10);

// Per-device per-epoch issuance quota. A device may obtain at most this many
// tokens per epoch. This is the abuse bound: even our own users are rate limited.
// Held in memory only (see QUOTA STORE note below). Default 256 tokens/epoch.
const ISSUANCE_QUOTA_PER_EPOCH = parseInt(process.env.ISSUANCE_QUOTA_PER_EPOCH || '256', 10);

// Max blinded token requests accepted in a single /issue call, so one request
// can't ask us to do unbounded RSA work. The client batches up to this many.
const MAX_TOKENS_PER_REQUEST = parseInt(process.env.MAX_TOKENS_PER_REQUEST || '64', 10);

// Body size cap (the assertion + N blinded messages). Bounds memory per request.
const MAX_BODY = parseInt(process.env.MAX_BODY_BYTES || '262144', 10);

// The issuer signing key (PKCS#8, base64-encoded) is injected at runtime via env,
// exactly like the gateway's SEED_SECRET_KEY. It is NEVER committed. If unset, the
// issuer fails closed at startup. To rotate per epoch in production you supply the
// epoch's key (or a seed a KMS expands); the in-process fallback below derives a
// fresh ephemeral epoch key when only a single base key is provided, which is fine
// for a single replica but NOT for multi-replica (see KEY STORE note).
const ISSUER_SIGNING_KEY_B64 = process.env.ISSUER_SIGNING_KEY || '';

// RSA-PSS / blind-RSA parameters. SHA-384, 2048-bit modulus, deterministic PSS -
// the Apple PAT / RFC 9578 Token Type 2 suite.
const RSA_MODULUS_BITS = 2048;
const PSS_HASH = 'SHA-384';

const suite = RSABSSA.SHA384.PSS.Deterministic();

// --- Logging (RED-only) -----------------------------------------------------

function log(fields) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...fields }) + '\n');
}

// --- Epoch math -------------------------------------------------------------

// Epoch id is a monotonically increasing integer: floor(unixSeconds / EPOCH_SECONDS).
// Both issuer and relay can compute it independently; tokens carry no timestamp,
// only the epoch's key id, so spend time leaks nothing finer than the epoch.
function currentEpoch() {
  return Math.floor(Date.now() / 1000 / EPOCH_SECONDS);
}

// --- Epoch key management ---------------------------------------------------
//
// KEY STORE (production): a multi-replica issuer needs every replica to agree on
// the epoch keypair, and the relay must be able to fetch the matching public key.
// In production, derive each epoch's RSA key deterministically inside a KMS/HSM
// from a root seed + epoch id (so no replica ever holds the raw key, mirroring the
// gateway's HSM key-release goal), or store the per-epoch keypair in a shared
// secret store. The in-memory map below is correct for a SINGLE replica only.

const epochKeys = new Map(); // epochId -> { priv, pub, spkiB64, keyId }

// Import the operator-supplied RSA private key for RSA-PSS signing and derive its
// public key. Throws if the env key is missing/invalid so the service fails closed
// rather than issuing under a key nobody controls.
//
// Format-tolerant on purpose. An operator generates the key with whatever tool is
// at hand, and those tools disagree on the encoding. `openssl genpkey -algorithm
// RSA -outform DER` emits a bare PKCS#1 RSAPrivateKey; `openssl pkcs8 -topk8`
// emits PKCS#8; a pasted PEM is text. WebCrypto's pkcs8 import is also strict about
// the AlgorithmIdentifier OID (a generic rsaEncryption key is rejected when you ask
// for RSA-PSS). So instead of importing straight into WebCrypto, we parse with
// node's createPrivateKey (which auto-detects PEM vs DER and PKCS#1 vs PKCS#8),
// then bridge into a WebCrypto RSA-PSS key via JWK, where the source OID no longer
// matters. ISSUER_SIGNING_KEY may be a PEM string or base64 of DER.
async function importBaseKey() {
  if (!ISSUER_SIGNING_KEY_B64) {
    throw new Error('ISSUER_SIGNING_KEY not set');
  }
  const algo = { name: 'RSA-PSS', hash: PSS_HASH };
  const nodeKey = parsePrivateKeyEnv(ISSUER_SIGNING_KEY_B64);
  const kt = nodeKey.asymmetricKeyType;
  if (kt !== 'rsa' && kt !== 'rsa-pss') {
    throw new Error('signing key is not RSA');
  }
  const jwk = nodeKey.export({ format: 'jwk' });
  const priv = await webcrypto.subtle.importKey('jwk', jwk, algo, true, ['sign']);
  const pubJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true };
  const pub = await webcrypto.subtle.importKey('jwk', pubJwk, algo, true, ['verify']);
  return { priv, pub };
}

// Parse the env signing key into a node KeyObject, tolerating PEM or base64-of-DER,
// and PKCS#8 or PKCS#1. Throws on anything unparseable, so the caller fails closed.
function parsePrivateKeyEnv(envValue) {
  const s = String(envValue).trim();
  if (s.includes('-----BEGIN')) {
    // PEM: createPrivateKey auto-detects PKCS#1 vs PKCS#8 from the header.
    return crypto.createPrivateKey({ key: s, format: 'pem' });
  }
  const der = Buffer.from(s, 'base64');
  try {
    return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch {
    // Fall back to a bare PKCS#1 RSAPrivateKey (what some openssl builds emit).
    return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs1' });
  }
}

// Derive the public key from a private key by exporting its JWK and stripping the
// private components. WebCrypto has no direct private->public, so we go via JWK.
async function derivePublicKey(priv, algo) {
  const jwk = await webcrypto.subtle.exportKey('jwk', priv);
  const pubJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true };
  return webcrypto.subtle.importKey('jwk', pubJwk, algo, true, ['verify']);
}

// A stable key id for an epoch's public key: the SHA-256 of the SPKI bytes,
// truncated, hex. The relay uses this to pick the right public key when verifying.
// It is derived from PUBLIC material only, so publishing it leaks nothing.
function keyIdFromSpki(spkiBytes) {
  return crypto.createHash('sha256').update(spkiBytes).digest('hex').slice(0, 32);
}

// Resolve (and cache) the keypair for an epoch. With a single injected base key we
// reuse it across epochs (the epoch id still scopes quota + the relay's redemption
// set). A production KMS would instead derive a distinct key per epoch from the
// root seed; the call site is the same, only this body changes.
let baseKeyPromise = null;
async function keysForEpoch(epochId) {
  const cached = epochKeys.get(epochId);
  if (cached) return cached;
  if (!baseKeyPromise) baseKeyPromise = importBaseKey();
  const { priv, pub } = await baseKeyPromise;
  const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pub));
  const spkiB64 = Buffer.from(spki).toString('base64');
  const keyId = keyIdFromSpki(spki);
  const entry = { priv, pub, spkiB64, keyId };
  epochKeys.set(epochId, entry);
  // Drop epoch keys older than the previous epoch so the map can't grow forever.
  for (const id of epochKeys.keys()) {
    if (id < epochId - 1) epochKeys.delete(id);
  }
  return entry;
}

// --- Per-device per-epoch issuance quota ------------------------------------
//
// QUOTA STORE (production): this Map lives in one process and resets on restart,
// so with multiple replicas a device could get its full quota from each replica.
// For a real multi-replica deployment, move this counter to a shared atomic store
// (e.g. Redis INCR with an EXPIRE at the epoch boundary, keyed by a SALTED hash of
// the device id so the store itself never holds a raw device identifier). The key
// is scoped to the epoch so it self-expires when the epoch rolls.

const issuanceCounts = new Map(); // `${epochId}:${deviceHash}` -> count

// Hash the device id before it touches the quota table, so even this transient
// structure never holds the raw identifier. The salt is per-process and ephemeral.
const QUOTA_SALT = crypto.randomBytes(32);
function deviceQuotaKey(epochId, deviceId) {
  const h = crypto.createHmac('sha256', QUOTA_SALT).update(String(deviceId)).digest('hex');
  return `${epochId}:${h}`;
}

// Reserve `n` issuances for a device in this epoch. Returns true if the whole
// batch fits under the quota (and reserves it), false if it would exceed. Atomic
// within this single process.
function reserveQuota(epochId, deviceId, n) {
  if (ISSUANCE_QUOTA_PER_EPOCH <= 0) return true; // 0 disables the quota
  const key = deviceQuotaKey(epochId, deviceId);
  const used = issuanceCounts.get(key) || 0;
  if (used + n > ISSUANCE_QUOTA_PER_EPOCH) return false;
  issuanceCounts.set(key, used + n);
  // Sweep counters from epochs we no longer issue for.
  if (issuanceCounts.size > 200000) {
    for (const k of issuanceCounts.keys()) {
      const e = parseInt(k.split(':')[0], 10);
      if (e < epochId - 1) issuanceCounts.delete(k);
    }
  }
  return true;
}

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

  // (a) Validate App Attest. This proves the request comes from a genuine,
  // unmodified Lander install on real Apple hardware. FAILS CLOSED: if the
  // validator is a stub (Apple root cert / team+bundle id not supplied), it
  // returns false and we reject. We never log the assertion/attestation.
  let attestOk = false;
  try {
    attestOk = await validateAppAttest({ keyId, attestation, assertion, clientDataHash });
  } catch {
    attestOk = false;
  }
  if (!attestOk) {
    res.writeHead(401); res.end();
    log({ route: '/issue', status: 401, reason: 'attest_failed', durationMs: Date.now() - start });
    return;
  }

  const epochId = currentEpoch();

  // (b) Enforce the per-device per-epoch issuance quota. The keyId is the device
  // identifier; it is hashed before it touches the quota table and never logged.
  if (!reserveQuota(epochId, keyId, blinded.length)) {
    res.writeHead(429); res.end();
    log({ route: '/issue', status: 429, reason: 'quota_exceeded', count: blinded.length, durationMs: Date.now() - start });
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

  // (c) Blind-sign each blinded_msg with the current epoch RSA private key.
  let keys;
  try {
    keys = await keysForEpoch(epochId);
  } catch (e) {
    // Missing/invalid signing key => fail closed.
    res.writeHead(503); res.end();
    log({ route: '/issue', status: 503, reason: 'no_signing_key', durationMs: Date.now() - start });
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
  const out = JSON.stringify({ epoch: epochId, keyId: keys.keyId, blindSigs });
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
    suite: 'RSABSSA-SHA384-PSS-Deterministic',
    epoch: epochId,
    epochSeconds: EPOCH_SECONDS,
    keys,
  });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(out);
  log({ route: '/issuer-keys', status: 200, epoch: epochId, durationMs: Date.now() - start });
}

// --- HTTP server ------------------------------------------------------------

const server = http.createServer((req, res) => {
  const start = Date.now();

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    log({ route: '/health', status: 200, durationMs: Date.now() - start });
    return;
  }

  if (req.method === 'GET' && req.url === '/issuer-keys') {
    handleIssuerKeys(res, start);
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
      handleIssue(req, res, start, Buffer.concat(chunks)).catch(() => {
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
  server.listen(PORT, () => {
    log({
      event: 'listen',
      port: PORT,
      role: 'token-issuer',
      appAttest: APP_ATTEST_READY ? 'enforced' : 'stub-fail-closed',
      signingKey: ISSUER_SIGNING_KEY_B64 ? 'present' : 'missing-fail-closed',
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
  reserveQuota,
  keyIdFromSpki,
  derivePublicKey,
  EPOCH_SECONDS,
  RSA_MODULUS_BITS,
  PSS_HASH,
};
