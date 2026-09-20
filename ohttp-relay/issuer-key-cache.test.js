const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createIssuerKeyCache } = require('./issuer-key-cache');
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = publicKey.export({ format: 'der', type: 'spki' });
const keyId = crypto.createHash('sha256').update(spki).digest('hex').slice(0, 32);
const doc = { schemaVersion: 1, suite: 'RSABSSA-SHA384-PSS-Deterministic', epoch: 10, epochSeconds: 10,
  keys: [{ epoch: 10, keyId, publicKeySpki: spki.toString('base64') }] };
test('empty-cache requests share one fetch; failures back off and expired keys are never extended', async () => {
  let now = 100000, calls = 0, release, fail = false;
  const cache = createIssuerKeyCache({ url: 'https://fixture.invalid', ttlMs: 1000, backoffMs: 5000, now: () => now,
    fetchKeys: async () => { calls++; if (fail) throw Error(); await new Promise(r => { release = r; }); return doc; } });
  const first = cache.get(keyId), second = cache.get(keyId); await Promise.resolve(); release();
  assert.ok(await first); assert.ok(await second); assert.equal(calls, 1);
  now = 101500; assert.ok(await cache.get(keyId)); assert.equal(calls, 1);
  now = 105000; fail = true; assert.ok(await cache.get(keyId)); assert.equal(calls, 2);
  assert.equal(await cache.get('unknown'), null); assert.equal(calls, 2);
  now = 120000; await assert.rejects(cache.get(keyId), { code: 'state_unavailable' }); assert.equal(calls, 3);
  await assert.rejects(cache.get(keyId), { code: 'state_unavailable' }); assert.equal(calls, 3);
});
test('invalid metadata cannot admit a mismatched key or stale epoch', async () => {
  for (const value of [{ ...doc, epoch: 9 }, { ...doc, keys: [{ ...doc.keys[0], keyId: 'forged' }] },
    { ...doc, epochSeconds: 0 }, { ...doc, keys: [...doc.keys, ...doc.keys] }]) {
    const cache = createIssuerKeyCache({ url: 'https://fixture.invalid', now: () => 100000, fetchKeys: async () => value });
    await assert.rejects(cache.get(keyId), { code: 'state_unavailable' });
  }
});
