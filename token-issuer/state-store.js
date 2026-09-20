// Columbia issuer state. Device identifiers never leave this module unhashed.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import crypto from 'node:crypto';

export const ISSUER_STATE_CLIENT_OPTIONS = Object.freeze({ retryOptions: Object.freeze({ maxRetries: 0 }) });

export class StateUnavailable extends Error {
  constructor() { super('issuer_state_unavailable'); this.code = 'state_unavailable'; }
}

// This deadline limits acknowledgment waiting, not Azure's ability to commit.
async function bounded(call, timeoutMs) {
  if (timeoutMs <= 0) throw new StateUnavailable();
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => call({ abortSignal: controller.signal,
        requestOptions: { timeout: Math.max(1, timeoutMs - 1000) } })),
      new Promise((_, reject) => { timer = setTimeout(() => {
        controller.abort(); reject(new StateUnavailable());
      }, timeoutMs); }),
    ]);
  } finally { clearTimeout(timer); }
}

export function memoryDeviceBackend({ maxKeys = 500000 } = {}) {
  const rows = new Map(); let revision = 0;
  return {
    async get(key) { return structuredClone(rows.get(key) || null); },
    async put(key, etag, value) {
      if ((rows.get(key)?.etag ?? null) !== etag) return false;
      if (!rows.has(key) && rows.size >= maxKeys) throw new StateUnavailable();
      rows.set(key, { etag: String(++revision), value: structuredClone(value) });
      return true;
    },
  };
}

// The client must have retryOptions.maxRetries=0. Otherwise an ambiguous commit
// can be hidden by a later SDK retry's 409/412, losing the provenance required by
// the explicit CAS loop. The server's sole production constructor enforces this.
export function azureDeviceBackend(client, { salt, timeoutMs = 5000 } = {}) {
  if (!Buffer.isBuffer(salt) || salt.length < 32) throw Error('issuer_state_salt_required');
  const partitionKey = 'issuer-state-v1';
  const saltFingerprint = crypto.createHash('sha256').update(salt).digest('hex');
  let ready;
  const remaining = deadline => Math.min(timeoutMs, deadline - Date.now());
  async function initialize(deadline) {
    if (!ready) ready = (async () => {
      try { await bounded(options => client.createTable(options), remaining(deadline)); }
      catch (error) { if (error.statusCode !== 409) throw error; }
      try { await bounded(options => client.createEntity({ partitionKey, rowKey: 'config', saltFingerprint }, options), remaining(deadline)); }
      catch (error) {
        // Read back even after an unknown create ACK. A changed salt cannot
        // silently make every registration/quota row disappear on restart.
        let config;
        try { config = await bounded(options => client.getEntity(partitionKey, 'config', options), remaining(deadline)); }
        catch { throw new StateUnavailable(); }
        if (config.saltFingerprint !== saltFingerprint) throw new StateUnavailable();
      }
    })().catch(() => { ready = undefined; throw new StateUnavailable(); });
    await ready;
  }
  async function read(key, deadline) {
    try {
      const row = await bounded(options => client.getEntity(partitionKey, key, options), remaining(deadline));
      return { etag: row.etag, value: JSON.parse(row.state) };
    } catch (error) {
      if (error.statusCode === 404 && error.code !== 'TableNotFound') return null;
      throw new StateUnavailable();
    }
  }
  return {
    async get(key, deadline) { await initialize(deadline); return read(key, deadline); },
    async put(key, etag, value, deadline) {
      await initialize(deadline);
      const entity = { partitionKey, rowKey: key, state: JSON.stringify(value) };
      if (Buffer.byteLength(entity.state, 'utf16le') > 60000) throw new StateUnavailable();
      try {
        await bounded(options => etag === null ? client.createEntity(entity, options)
          : client.updateEntity(entity, 'Replace', { ...options, etag }), remaining(deadline));
        return true;
      } catch (error) {
        // A committed write whose ACK was lost must not reserve quota twice.
        const current = await read(key, deadline);
        if (value.commitID && current?.value.commitID === value.commitID) return true;
        if ([409, 412].includes(error.statusCode)) return false;
        throw new StateUnavailable();
      }
    },
  };
}

export function createIssuerState({ backend, salt, quota = 500, operationTimeoutMs = 8000 } = {}) {
  if (!backend || !Buffer.isBuffer(salt) || salt.length < 32 || !Number.isSafeInteger(quota) || quota < 0 ||
      !Number.isSafeInteger(operationTimeoutMs) || operationTimeoutMs <= 0) throw Error('issuer_state_configuration');
  const keyFor = keyId => crypto.createHmac('sha256', salt).update(keyId).digest('hex');
  function checked(record) {
    if (!record || record.version !== 1 || typeof record.publicKeyPem !== 'string' || record.publicKeyPem.length > 4096 ||
        !Number.isSafeInteger(record.signCount) || record.signCount < 0 ||
        !Number.isSafeInteger(record.latestEpoch) || record.latestEpoch < 0 ||
        !record.quota || typeof record.quota !== 'object' || Array.isArray(record.quota) ||
        Object.keys(record.quota).length > 2 || Object.entries(record.quota).some(([epoch, count]) =>
          ![String(record.latestEpoch), String(record.latestEpoch - 1)].includes(epoch) || !Number.isSafeInteger(count) || count < 0)) {
      throw new StateUnavailable();
    }
    return record;
  }
  return {
    async getAttestedKey(keyId) {
      const record = await backend.get(keyFor(keyId), Date.now() + operationTimeoutMs);
      const value = record ? checked(record.value) : null;
      return value ? { publicKeyPem: value.publicKeyPem, signCount: value.signCount } : null;
    },
    // Verification is pure; this is the sole counter + quota mutation. A failed
    // response/signature operation never rolls a committed reservation back.
    async reserve({ keyId, mode, publicKeyPem, signCount, epoch, count }) {
      if (!['attestation', 'assertion'].includes(mode) || !Number.isSafeInteger(signCount) || signCount < 0 ||
          !Number.isSafeInteger(epoch) || epoch < 0 || !Number.isSafeInteger(count) || count < 1 ||
          typeof publicKeyPem !== 'string' || publicKeyPem.length > 4096) throw new StateUnavailable();
      const key = keyFor(keyId), commitID = crypto.randomUUID(), deadline = Date.now() + operationTimeoutMs;
      for (let attempt = 0; attempt < 4; attempt++) {
        const prior = await backend.get(key, deadline), record = prior ? checked(prior.value) : null;
        if (mode === 'assertion' && !record) return { ok: false, reason: 'unknown_device_key' };
        if (record && record.publicKeyPem !== publicKeyPem) return { ok: false, reason: 'key_mismatch' };
        if (mode === 'assertion' && signCount <= record.signCount) return { ok: false, reason: 'replayed_assertion' };
        // Clock skew at rollover must not let an older replica erase the newer
        // epoch's quota. Keep the two epochs relative to the greatest seen one.
        const latestEpoch = Math.max(epoch, record?.latestEpoch || epoch);
        if (epoch < latestEpoch - 1) return { ok: false, reason: 'expired_epoch' };
        const used = record?.quota?.[String(epoch)] || 0;
        if (!Number.isSafeInteger(used + count)) throw new StateUnavailable();
        if (quota > 0 && used + count > quota) return { ok: false, reason: 'quota_exceeded' };
        const counts = {};
        for (const id of [latestEpoch, latestEpoch - 1]) {
          if (record?.quota?.[String(id)]) counts[id] = record.quota[String(id)];
        }
        counts[epoch] = used + count;
        const value = { version: 1, commitID, publicKeyPem, signCount: Math.max(signCount, record?.signCount || 0), latestEpoch, quota: counts };
        if (await backend.put(key, prior?.etag ?? null, value, deadline)) return { ok: true };
      }
      throw new StateUnavailable();
    },
  };
}
