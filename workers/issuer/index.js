// Columbia token issuer on Cloudflare Workers.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Same wire contract, config and RED-only logging as token-issuer/server.js
// (see token-issuer/PROTOCOL.md). App Attest, epoch keys/blind signing and the
// counter/quota state machine are the token-issuer modules themselves; only the
// HTTP glue and the durable backend (D1 instead of Azure Tables) live here.
import crypto from 'node:crypto';
import { validateAppAttest, attestationFailureCategory } from '../../token-issuer/appattest.js';
import { createEpochKeyProvider, blindSign } from '../../token-issuer/epoch-keys.js';
import { createIssuerState, memoryDeviceBackend, StateUnavailable } from '../../token-issuer/state-store.js';

const RSA_MODULUS_BITS = 2048;
const ROUTES = ['/health', '/issuer-keys', '/issue'];
const REASONS = ['bad_json', 'missing_keyid', 'bad_batch_size', 'attest_failed', 'client_data_binding_failed', 'quota_exceeded', 'bad_blinded_type', 'bad_blinded_len', 'no_signing_key', 'blind_sign_error', 'state_unavailable', 'unhandled'];
const FAILURES = ['configuration', 'client_data', 'proof_format', 'unknown_device_key', 'state_unavailable', 'key_binding', 'counter', 'expired_epoch', 'quota', 'environment', 'app_identity', 'assertion_signature', 'certificate_chain', 'nonce_binding', 'verification'];

export function safeLogFields(fields, maxTokens = 64) {
  const safe = {};
  if (fields.route !== undefined) safe.route = ROUTES.includes(fields.route) ? fields.route : 'other';
  if (Number.isInteger(fields.status) && fields.status >= 100 && fields.status <= 599) safe.status = fields.status;
  if (Number.isFinite(fields.durationMs)) safe.durationMs = Math.max(0, Math.round(fields.durationMs));
  if (REASONS.includes(fields.reason)) safe.reason = fields.reason;
  if (['attestation', 'assertion', 'missing'].includes(fields.proofMode)) safe.proofMode = fields.proofMode;
  if (FAILURES.includes(fields.attestFailure)) safe.attestFailure = fields.attestFailure;
  for (const key of ['issued', 'count']) {
    if (Number.isInteger(fields[key]) && fields[key] >= 0 && fields[key] <= maxTokens) safe[key] = fields[key];
  }
  if (Number.isSafeInteger(fields.epoch) && fields.epoch >= 0) safe.epoch = fields.epoch;
  return safe;
}

// SHA-256( utf8(epoch) || 0x00 || blinded[0] || 0x00 || blinded[1] ... ), raw blinded bytes.
export function expectedClientDataHash(epochId, blinded) {
  const h = crypto.createHash('sha256');
  h.update(String(epochId), 'utf8');
  for (const b of blinded) {
    h.update(Buffer.from([0x00]));
    h.update(Buffer.from(b, 'base64'));
  }
  return h.digest();
}

export function boundEpoch(clientDataHash, blinded, epochId) {
  if (typeof clientDataHash !== 'string') return null;
  const got = Buffer.from(clientDataHash, 'base64');
  if (got.length !== 32) return null;
  for (const candidate of [epochId, epochId - 1]) {
    if (crypto.timingSafeEqual(got, expectedClientDataHash(candidate, blinded))) return candidate;
  }
  return null;
}

function timingSafeEqualStr(presented, expected) {
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const ha = crypto.createHash('sha256').update(presented).digest();
  const hb = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Durable device rows in D1 with the Azure backend's contract: `rev` is the
// ETag, and a write lands only if the row is unchanged since it was read. D1 has
// one serializable primary (no read replication configured), so the conditional
// INSERT/UPDATE is the atomic compare-and-swap the reservation loop needs.
// The salt fingerprint row makes a changed salt fail closed instead of silently
// orphaning every registration and quota.
// ponytail: no per-call deadline like the Azure backend; D1 enforces its own query timeout.
export function d1DeviceBackend(db, { salt } = {}) {
  if (!db || !Buffer.isBuffer(salt) || salt.length < 32) throw Error('issuer_state_salt_required');
  const saltFingerprint = crypto.createHash('sha256').update(salt).digest('hex');
  let ready;
  function initialize() {
    ready ??= (async () => {
      await db.batch([
        db.prepare('CREATE TABLE IF NOT EXISTS issuer_state (k TEXT PRIMARY KEY, state TEXT NOT NULL, rev INTEGER NOT NULL)'),
        db.prepare("INSERT INTO issuer_state (k, state, rev) VALUES ('config', ?, 1) ON CONFLICT (k) DO NOTHING").bind(saltFingerprint),
      ]);
      if (await db.prepare("SELECT state FROM issuer_state WHERE k = 'config'").first('state') !== saltFingerprint) throw new StateUnavailable();
    })().catch(() => { ready = undefined; throw new StateUnavailable(); });
    return ready;
  }
  async function read(key) {
    try {
      const row = await db.prepare('SELECT state, rev FROM issuer_state WHERE k = ?').bind(key).first();
      return row ? { etag: row.rev, value: JSON.parse(row.state) } : null;
    } catch { throw new StateUnavailable(); }
  }
  return {
    async get(key) { await initialize(); return read(key); },
    async put(key, etag, value) {
      await initialize();
      const state = JSON.stringify(value);
      try {
        const { meta } = await (etag === null
          ? db.prepare('INSERT INTO issuer_state (k, state, rev) VALUES (?, ?, 1) ON CONFLICT (k) DO NOTHING').bind(key, state)
          : db.prepare('UPDATE issuer_state SET state = ?, rev = rev + 1 WHERE k = ? AND rev = ?').bind(state, key, etag)).run();
        return meta.changes === 1;
      } catch {
        // A committed write whose ACK was lost must not reserve quota twice.
        const current = await read(key);
        if (value.commitID && current?.value.commitID === value.commitID) return true;
        throw new StateUnavailable();
      }
    },
  };
}

// Builds the issuer from Worker bindings, validating config the way server.js
// does at startup. ISSUER_DB (D1) replaces ISSUER_STATE_CONNECTION_STRING.
export function createIssuer(env, { now = Date.now } = {}) {
  const EPOCH_SECONDS = parseInt(env.EPOCH_SECONDS || String(7 * 24 * 3600), 10);
  const QUOTA = Number(env.ISSUANCE_QUOTA_PER_EPOCH || '256');
  const MAX_TOKENS = parseInt(env.MAX_TOKENS_PER_REQUEST || '64', 10);
  const MAX_BODY = parseInt(env.MAX_BODY_BYTES || '262144', 10);
  const REQUIRE_CLIENT_DATA_BINDING = env.REQUIRE_CLIENT_DATA_BINDING !== '0';
  const REQUIRE_FDID = env.REQUIRE_FDID || '';
  const FDID_HEADER = (env.FDID_HEADER || 'x-azure-fdid').toLowerCase();
  const REQUIRE_DURABLE_STATE = env.REQUIRE_DURABLE_STATE || '0';
  if (!['0', '1'].includes(REQUIRE_DURABLE_STATE)) throw new Error('issuer_durable_state_policy_invalid');
  if (REQUIRE_DURABLE_STATE === '1' && !env.ISSUER_DB) throw new Error('issuer_durable_state_required');
  const salt = env.ISSUER_DB ? Buffer.from(env.ISSUER_STATE_SALT || '', 'base64') : crypto.randomBytes(32);
  const state = createIssuerState({
    backend: env.ISSUER_DB ? d1DeviceBackend(env.ISSUER_DB, { salt }) : memoryDeviceBackend(),
    salt, quota: QUOTA,
  });
  const currentEpoch = () => Math.floor(now() / 1000 / EPOCH_SECONDS);
  const keys = createEpochKeyProvider({ legacySigningKeyB64: env.ISSUER_SIGNING_KEY || '',
    manifestJSON: env.ISSUER_EPOCH_KEYS_JSON, currentEpoch });

  const log = fields => console.log(JSON.stringify({ ts: new Date().toISOString(), ...safeLogFields(fields, MAX_TOKENS) }));
  const empty = (status, headers) => new Response(null, { status, headers });
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body),
    { status, headers: { 'Content-Type': 'application/json', ...headers } });

  function frontDoorAllowed(request) {
    const raw = request.headers.get(FDID_HEADER);
    if (!raw) return false;
    return raw.split(',').some(tok => timingSafeEqualStr(tok.trim(), REQUIRE_FDID));
  }

  async function readCapped(request) {
    const chunks = [];
    let received = 0;
    if (request.body) {
      for await (const chunk of request.body) {
        received += chunk.byteLength;
        if (received > MAX_BODY) return null;
        chunks.push(chunk);
      }
    }
    return Buffer.concat(chunks);
  }

  async function handleIssuerKeys(start) {
    const epochId = currentEpoch();
    const out = [];
    try {
      for (const id of [epochId, epochId - 1]) {
        const k = await keys.keysForEpoch(id);
        out.push({ epoch: id, keyId: k.keyId, publicKeySpki: k.spkiB64 });
      }
    } catch {
      log({ route: '/issuer-keys', status: 503, reason: 'no_signing_key', durationMs: Date.now() - start });
      return empty(503);
    }
    log({ route: '/issuer-keys', status: 200, epoch: epochId, durationMs: Date.now() - start });
    return json(200, { schemaVersion: 1, suite: 'RSABSSA-SHA384-PSS-Deterministic', epoch: epochId,
      epochSeconds: EPOCH_SECONDS, keys: out });
  }

  async function handleIssue(start, body) {
    const fail = (status, reason, extra = {}) => {
      log({ route: '/issue', status, reason, ...extra, durationMs: Date.now() - start });
      return empty(status);
    };
    let parsed;
    try { parsed = JSON.parse(body.toString('utf8')); } catch { return fail(400, 'bad_json'); }
    const { keyId, attestation, assertion, clientDataHash, blinded } = parsed || {};
    if (typeof keyId !== 'string' || !keyId.length) return fail(400, 'missing_keyid');
    if (!Array.isArray(blinded) || blinded.length < 1 || blinded.length > MAX_TOKENS) return fail(400, 'bad_batch_size');

    const blindedBufs = [];
    for (const b of blinded) {
      if (typeof b !== 'string') return fail(400, 'bad_blinded_type');
      const buf = Buffer.from(b, 'base64');
      if (buf.length !== RSA_MODULUS_BITS / 8) return fail(400, 'bad_blinded_len');
      blindedBufs.push(new Uint8Array(buf));
    }

    const epochId = currentEpoch();
    let signingEpochId = epochId;
    if (REQUIRE_CLIENT_DATA_BINDING) {
      signingEpochId = boundEpoch(clientDataHash, blinded, epochId);
      if (signingEpochId === null) return fail(401, 'client_data_binding_failed');
    }

    let signingKey;
    try { signingKey = await keys.keysForEpoch(signingEpochId); } catch { return fail(503, 'no_signing_key'); }

    let attest;
    try {
      attest = await validateAppAttest({ keyId, attestation, assertion, clientDataHash, store: state });
    } catch {
      attest = { ok: false, reason: 'verification_exception' };
    }
    if (!attest || !attest.ok) {
      const unavailable = attest?.reason === 'state_unavailable';
      const status = unavailable ? 503 : 401;
      log({ route: '/issue', status, reason: unavailable ? 'state_unavailable' : 'attest_failed',
        proofMode: attestation ? 'attestation' : assertion ? 'assertion' : 'missing',
        attestFailure: attestationFailureCategory(attest), durationMs: Date.now() - start });
      return json(status, { error: unavailable ? 'state_unavailable' : attest?.reason === 'unknown_device_key' ? 'unknown_device_key' : 'attest_failed' },
        unavailable ? { 'Retry-After': '2' } : {});
    }

    let reservation;
    try {
      reservation = await state.reserve({ keyId: attest.keyId, mode: attest.mode,
        publicKeyPem: attest.publicKeyPem, signCount: attest.signCount, epoch: epochId, count: blinded.length });
    } catch {
      log({ route: '/issue', status: 503, reason: 'state_unavailable', durationMs: Date.now() - start });
      return json(503, { error: 'state_unavailable' }, { 'Retry-After': '2' });
    }
    if (!reservation.ok) {
      const limited = reservation.reason === 'quota_exceeded';
      const retryAfter = Math.max(1, Math.ceil((epochId + 1) * EPOCH_SECONDS - now() / 1000));
      log({ route: '/issue', status: limited ? 429 : 401, reason: limited ? 'quota_exceeded' : 'attest_failed',
        proofMode: attest.mode, attestFailure: attestationFailureCategory(reservation),
        count: blinded.length, durationMs: Date.now() - start });
      return json(limited ? 429 : 401,
        { error: limited ? 'quota_exceeded' : reservation.reason === 'unknown_device_key' ? 'unknown_device_key' : 'attest_failed' },
        limited ? { 'Retry-After': String(retryAfter) } : {});
    }

    const blindSigs = [];
    try {
      for (const bm of blindedBufs) blindSigs.push(blindSign(signingKey, bm).toString('base64'));
    } catch {
      return fail(500, 'blind_sign_error');
    }
    log({ route: '/issue', status: 200, issued: blindSigs.length, epoch: epochId, durationMs: Date.now() - start });
    return json(200, { epoch: signingEpochId, keyId: signingKey.keyId, blindSigs });
  }

  return {
    state,
    async fetch(request) {
      const start = Date.now();
      const url = new URL(request.url);
      const path = url.pathname;
      // server.js matches req.url exactly, so any query string is a 404 there too.
      const route = url.search ? null : path;

      // GET /health and GET /issuer-keys are exempt: public, and fetched in-environment.
      // FDID_GATED_HOST_SUFFIX (e.g. ".workers.dev") limits the gate to the hostname Front
      // Door uses; the custom domain serves apps directly. Unset gates every host.
      const gatedHost = !env.FDID_GATED_HOST_SUFFIX || url.hostname.endsWith(env.FDID_GATED_HOST_SUFFIX);
      if (REQUIRE_FDID && gatedHost && !(request.method === 'GET' && (path === '/health' || path === '/issuer-keys')) &&
          !frontDoorAllowed(request)) {
        log({ route: path, status: 403, durationMs: Date.now() - start });
        return empty(403);
      }
      if (request.method === 'GET' && route === '/health') {
        if (env.LOG_HEALTH === '1') log({ route: '/health', status: 200, durationMs: Date.now() - start });
        return new Response('ok', { headers: { 'Content-Type': 'text/plain' } });
      }
      if (request.method === 'GET' && route === '/issuer-keys') return handleIssuerKeys(start);
      if (request.method === 'POST' && route === '/issue') {
        const ctype = String(request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
        if (ctype !== 'application/json') {
          log({ route: '/issue', status: 415, durationMs: Date.now() - start });
          return empty(415);
        }
        const body = await readCapped(request);
        if (body === null) {
          log({ route: '/issue', status: 413, durationMs: Date.now() - start });
          return empty(413);
        }
        try { return await handleIssue(start, body); } catch {
          log({ route: '/issue', status: 500, reason: 'unhandled', durationMs: Date.now() - start });
          return empty(500);
        }
      }
      return empty(404);
    },
  };
}

// One issuer per isolate, so imported keys and the D1 readiness check are shared.
let issuer;
export default {
  fetch(request, env) {
    issuer ??= createIssuer(env);
    return issuer.fetch(request);
  },
};
