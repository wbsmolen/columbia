const test = require('node:test');
const assert = require('node:assert/strict');
const { memoryRedemptionStore, azureRedemptionStore } = require('./redemption-store');
const fingerprint = 'a'.repeat(64), nullifier = 'b'.repeat(64);
function fixture() {
  const rows = new Map(); const client = {
    lostAck: false, fail: false,
    async createTable() {},
    async createEntity(entity) {
      if (client.fail) throw { statusCode: 503 };
      const key = entity.partitionKey + ':' + entity.rowKey;
      if (rows.has(key)) throw { statusCode: 409 };
      rows.set(key, structuredClone(entity));
      if (client.lostAck) { client.lostAck = false; throw { statusCode: 503 }; }
    },
    async getEntity(pk, rk) { const row = rows.get(pk + ':' + rk); if (!row) throw { statusCode: 404 }; return structuredClone(row); },
  }; return { client, rows };
}
test('replicas and restarted clients admit one spend, and a lost ACK does not reset ownership', async () => {
  const { client, rows } = fixture(), a = azureRedemptionStore(client), b = azureRedemptionStore(client);
  client.lostAck = true;
  const results = await Promise.all([a.redeem(fingerprint, nullifier), b.redeem(fingerprint, nullifier)]);
  assert.deepEqual(results.sort(), [false, true]); assert.equal(rows.size, 1);
  assert.equal(await azureRedemptionStore(client).redeem(fingerprint, nullifier), false);
});
test('unconfirmed create fails unavailable, then retries preserve spent records', async () => {
  const { client, rows } = fixture(), store = azureRedemptionStore(client);
  client.fail = true; await assert.rejects(store.redeem(fingerprint, nullifier), { code: 'state_unavailable' });
  assert.equal(rows.size, 0); client.fail = false;
  assert.equal(await store.redeem(fingerprint, nullifier), true);
  assert.equal(await store.redeem(fingerprint, nullifier), false);
});
test('memory capacity never evicts a spent token; public key material scopes the hash', async () => {
  const store = memoryRedemptionStore({ maxKeys: 1 });
  assert.equal(await store.redeem(fingerprint, nullifier), true);
  await assert.rejects(store.redeem('c'.repeat(64), nullifier), { code: 'state_unavailable' });
  assert.equal(await store.redeem(fingerprint, nullifier), false);
});
test('hung storage aborts within its operation deadline without declaring a spend successful', async () => {
  let aborted = false;
  const client = { createTable: options => new Promise(() => options.abortSignal.addEventListener('abort', () => { aborted = true; })) };
  await assert.rejects(azureRedemptionStore(client, { timeoutMs: 25 }).redeem(fingerprint, nullifier), { code: 'state_unavailable' });
  assert.equal(aborted, true);
});
