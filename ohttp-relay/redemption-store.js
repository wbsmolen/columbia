// Anonymous token spends. The relay stores only hashes of public keys and
// signatures; no device identifier, address, request body, or issuer credential.
const crypto = require('node:crypto');
const CLIENT_OPTIONS = Object.freeze({ retryOptions: Object.freeze({ maxRetries: 0 }) });
class RedemptionUnavailable extends Error {
  constructor() { super('redemption_state_unavailable'); this.code = 'state_unavailable'; }
}
async function bounded(call, deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new RedemptionUnavailable();
  const controller = new AbortController(); let timer;
  try {
    return await Promise.race([Promise.resolve().then(() => call({ abortSignal: controller.signal,
      requestOptions: { timeout: Math.max(1, remaining - 1000) } })),
    new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new RedemptionUnavailable()); }, remaining); })]);
  } finally { clearTimeout(timer); }
}
function memoryRedemptionStore({ maxKeys = 5000000 } = {}) {
  if (!Number.isSafeInteger(maxKeys) || maxKeys < 1) throw Error('redemption_capacity_invalid');
  const spent = new Set();
  return { async redeem(fingerprint, nullifier) {
    const key = `${fingerprint}:${nullifier}`;
    if (spent.has(key)) return false;
    if (spent.size >= maxKeys) throw new RedemptionUnavailable();
    spent.add(key); return true;
  } };
}
function azureRedemptionStore(client, { timeoutMs = 5000 } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw Error('redemption_timeout_invalid');
  let ready;
  return { async redeem(fingerprint, nullifier) {
    if (!/^[a-f0-9]{64}$/.test(fingerprint) || !/^[a-f0-9]{64}$/.test(nullifier)) throw new RedemptionUnavailable();
    const deadline = Date.now() + timeoutMs;
    if (!ready) ready = bounded(options => client.createTable(options), deadline)
      .catch(error => { if (error.statusCode !== 409) { ready = undefined; throw new RedemptionUnavailable(); } });
    await ready;
    const entity = { partitionKey: `spent-v1-${fingerprint}`, rowKey: nullifier, claimID: crypto.randomUUID() };
    try { await bounded(options => client.createEntity(entity, options), deadline); return true; }
    catch (error) {
      // create-only rows never change. An ACK lost after this exact claim can
      // acknowledge that claim; another request/replica must always be rejected.
      try {
        const row = await bounded(options => client.getEntity(entity.partitionKey, entity.rowKey, options), deadline);
        return row.claimID === entity.claimID;
      } catch { throw new RedemptionUnavailable(); }
    }
  } };
}
module.exports = { CLIENT_OPTIONS, RedemptionUnavailable, memoryRedemptionStore, azureRedemptionStore };
