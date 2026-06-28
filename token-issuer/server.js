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

// Bind the App Attest clientDataHash to the blinded[] payload (see handleIssue
// step a2). ON by default: App Attest then proves the device authorized THESE
// tokens, not just that a genuine device is present. Set to 0 only during client
// bring-up, before the iOS client computes clientDataHash over the batch.
const REQUIRE_CLIENT_DATA_BINDING = process.env.REQUIRE_CLIENT_DATA_BINDING !== '0';

// The issuer signing key (PKCS#8, base64-encoded) is injected at runtime via env,
// exactly like the gateway's SEED_SECRET_KEY. It is NEVER committed. If unset, the
// issuer fails closed at startup. To rotate per epoch in production you supply the
// epoch's key (or a seed a KMS expands); the in-process fallback below derives a
// fresh ephemeral epoch key when only a single base key is provided, which is fine
// for a single replica but NOT for multi-replica (see KEY STORE note).
const ISSUER_SIGNING_KEY_B64 = process.env.ISSUER_SIGNING_KEY || '';

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

// --- Attested-key store (App Attest device registration) --------------------
//
// App Attest is two-phase: a one-time ATTESTATION registers a hardware key, and
// every later request carries an ASSERTION signed by that key. To check an
// assertion we must remember the device's public key and its last sign counter,
// keyed by the App Attest keyId.
//
// ATTESTED-KEY STORE (production): this Map is in-process and resets on restart,
// which has the same two multi-replica gaps the quota store has: a device
// registered on replica A is unknown to replica B, and a restart forgets every
// registration (forcing devices to re-attest, which the iOS client handles by
// falling back to a fresh attestation when an assertion is rejected as unknown).
// For a real multi-replica deployment, move this to the SAME shared store as the
// quota/redemption state (e.g. Redis: a hash per keyId holding the SPKI PEM + last
// counter, with the counter updated via a compare-and-set so two concurrent
// assertions cannot both pass with the same counter). The stored public key is
// device-PUBLIC material, not a secret, but the keyId is a device identifier, so
// key the store by a SALTED hash of the keyId exactly like the quota table rather
// than the raw keyId. The counter update MUST be atomic to preserve the
// strictly-increasing guarantee under concurrency.
//
// NOTE on identity: the keyId is the one device identifier this service handles.
// It is used transiently to look up the attested key and is NEVER logged (see the
// RED-only logging note at the top of this file).

const attestedKeys = new Map(); // keyId -> { publicKeyPem, signCount }

const ATTEST_STORE = {
  getAttestedKey(keyId) {
    return attestedKeys.get(keyId) || null;
  },
  setAttestedKey(keyId, publicKeyPem, signCount) {
    // Re-attestation of an EXISTING keyId must not roll the assertion counter
    // backwards: a fresh attestation reports signCount 0, but if this device has
    // already advanced its counter via assertions, resetting to 0 would re-open the
    // assertion-replay window for that key. Producing a fresh attestation needs
    // genuine hardware re-attesting its own key (a valid chain-to-Apple + a
    // challenge-bound nonce), so this is not a forgery vector, but we still keep the
    // higher counter as defense-in-depth. The public key is identical across
    // attestations of the same hardware key, so refreshing the PEM is harmless.
    const existing = attestedKeys.get(keyId);
    const keptCount = Math.max(signCount || 0, existing ? (existing.signCount || 0) : 0);
    attestedKeys.set(keyId, { publicKeyPem, signCount: keptCount });
    // Bound the map so a flood of one-time attestations cannot grow it forever.
    // This is a coarse cap; the production shared store would use a TTL instead.
    if (attestedKeys.size > 500000) {
      // Drop the oldest ~10% by insertion order (Map preserves it).
      let toDrop = Math.floor(attestedKeys.size * 0.1);
      for (const k of attestedKeys.keys()) {
        if (toDrop-- <= 0) break;
        attestedKeys.delete(k);
      }
    }
  },
  setSignCount(keyId, n) {
    const rec = attestedKeys.get(keyId);
    if (rec) rec.signCount = n;
  },
};

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
  // unmodified iOS client install on real Apple hardware. FAILS CLOSED: if App Attest
  // is unconfigured (Apple root cert / team+bundle id not supplied), the validator
  // returns { ok: false } and we reject. We never log the assertion/attestation,
  // and we never log the coarse failure reason at a level that could fingerprint a
  // device (it is an aggregate counter only).
  //
  // We pass the in-process attested-key store so an ASSERTION can be checked
  // against the device public key recorded at ATTESTATION time, and so the sign
  // counter advances. On a successful attestation we persist the returned public
  // key keyed by keyId.
  let attest;
  try {
    attest = await validateAppAttest({ keyId, attestation, assertion, clientDataHash, store: ATTEST_STORE });
  } catch {
    attest = { ok: false, reason: 'verification_exception' };
  }
  if (!attest || !attest.ok) {
    res.writeHead(401); res.end();
    log({ route: '/issue', status: 401, reason: 'attest_failed', durationMs: Date.now() - start });
    return;
  }
  // Register the device's attested public key on the one-time attestation, so its
  // later assertions can be verified. (validateAppAttest does the assertion-side
  // counter update through the store itself.)
  if (attest.mode === 'attestation') {
    ATTEST_STORE.setAttestedKey(attest.keyId, attest.publicKeyPem, attest.signCount);
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

  if (REQUIRE_CLIENT_DATA_BINDING) {
    let got;
    try { got = Buffer.from(clientDataHash, 'base64'); } catch { got = Buffer.alloc(0); }
    // Accept the current OR previous epoch's binding: the client computes the hash
    // against the epoch it last saw, which can be one behind the issuer if the
    // request crosses an epoch boundary (the issuer already publishes both epochs'
    // keys for the same reason). Both candidate hashes are constant-time compared.
    let bound = false;
    if (got.length === 32) {
      for (const e of [epochId, epochId - 1]) {
        if (crypto.timingSafeEqual(got, expectedClientDataHash(e, blinded))) { bound = true; break; }
      }
    }
    if (!bound) {
      res.writeHead(401); res.end();
      log({ route: '/issue', status: 401, reason: 'client_data_binding_failed', durationMs: Date.now() - start });
      return;
    }
  }

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
  const raw = req.headers['x-azure-fdid'];
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

const server = http.createServer((req, res) => {
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
  expectedClientDataHash,
  ATTEST_STORE,
  EPOCH_SECONDS,
  RSA_MODULUS_BITS,
  PSS_HASH,
};
