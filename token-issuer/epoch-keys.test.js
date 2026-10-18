// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { webcrypto } from 'node:crypto';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { readFileSync } from 'node:fs';
import { blindSign, createEpochKeyProvider, keyIdFromSpki, parsePrivateKeyEnv } from './epoch-keys.js';

const algorithm = { name: 'RSA-PSS', modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384' };
async function makeKey() {
  const pair = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const der = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
  const node = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return {
    pkcs8: der.toString('base64'),
    pkcs1: node.export({ format: 'der', type: 'pkcs1' }).toString('base64'),
    pem8: node.export({ format: 'pem', type: 'pkcs8' }),
    pem1: node.export({ format: 'pem', type: 'pkcs1' }),
  };
}
const [a, b] = await Promise.all([makeKey(), makeKey()]);
const manifest = keys => JSON.stringify({ version: 1, keys });
const records = [{ epoch: 10, privateKey: a.pkcs8 }, { epoch: 9, privateKey: b.pem1 }];
const unavailable = { code: 'epoch_key_unavailable' };

test('legacy PEM and base64 PKCS1/8 preserve the existing wire key and shared-key behavior', async () => {
  const ids = [];
  for (const material of [a.pkcs8, a.pkcs1, a.pem8, a.pem1]) {
    const provider = createEpochKeyProvider({ legacySigningKeyB64: material, currentEpoch: () => 10 });
    assert.equal(provider.mode, 'legacy');
    const current = await provider.keysForEpoch(10), previous = await provider.keysForEpoch(9);
    assert.strictEqual(current, previous);
    assert.equal(current.keyId, keyIdFromSpki(Buffer.from(current.spkiB64, 'base64')));
    ids.push(current.keyId);
    assert.equal(parsePrivateKeyEnv(material).asymmetricKeyDetails.modulusLength, 2048);
  }
  assert.equal(new Set(ids).size, 1);
});

test('explicit current/previous keys independently complete the actual blind-RSA protocol', async () => {
  const provider = createEpochKeyProvider({ manifestJSON: manifest(records), currentEpoch: () => 10 });
  assert.equal(provider.mode, 'manifest');
  const current = await provider.keysForEpoch(10), previous = await provider.keysForEpoch(9);
  assert.notEqual(current.keyId, previous.keyId);
  const suite = RSABSSA.SHA384.PSS.Deterministic();
  for (const [key, other] of [[current, previous], [previous, current]]) {
    const prepared = suite.prepare(crypto.randomBytes(32));
    const { blindedMsg, inv } = await suite.blind(key.pub, prepared);
    const blindSignature = blindSign(key, blindedMsg);
    const signature = await suite.finalize(key.pub, prepared, blindSignature, inv);
    assert.equal(await suite.verify(key.pub, signature, prepared), true);
    assert.equal(await suite.verify(other.pub, signature, prepared), false);
  }
});

test('native blindSign reproduces the RFC 9474 vector and keeps full-length output', async () => {
  const v = JSON.parse(readFileSync(new URL('./rfc9474-vector.json', import.meta.url)));
  const big = h => BigInt('0x' + h), [p, q, d] = [big(v.p), big(v.q), big(v.d)];
  const inv = (a, m) => { let [r0, r1, s0, s1] = [a, m, 1n, 0n];
    while (r1) { const k = r0 / r1; [r0, r1, s0, s1] = [r1, r0 - k * r1, s1, s0 - k * s1]; } return (s0 % m + m) % m; };
  const b64u = n => Buffer.from(n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0'), 'hex').toString('base64url');
  const signer = crypto.createPrivateKey({ format: 'jwk', key: { kty: 'RSA', n: b64u(big(v.n)), e: b64u(big(v.e)),
    d: b64u(d), p: b64u(p), q: b64u(q), dp: b64u(d % (p - 1n)), dq: b64u(d % (q - 1n)), qi: b64u(inv(q, p)) } });
  const key = { signer, verifier: crypto.createPublicKey(signer) };
  assert.equal(blindSign(key, Buffer.from(v.blinded_msg, 'hex')).toString('hex'), v.blind_sig);

  // About 1 in 256 signatures starts with a zero byte; I2OSP must keep it.
  const s = Buffer.alloc(512); s[100] = 1; s[511] = 7;
  const m = crypto.publicEncrypt({ key: key.verifier, padding: crypto.constants.RSA_NO_PADDING }, s);
  assert.deepEqual(blindSign(key, m), s);
  // m >= n is not a valid blinded message.
  assert.throws(() => blindSign(key, Buffer.alloc(512, 0xff)));
});

test('duplicate actual RSA material is rejected even under different encodings and epoch labels', async () => {
  const provider = createEpochKeyProvider({ currentEpoch: () => 10, legacySigningKeyB64: b.pkcs8,
    manifestJSON: manifest([{ epoch: 10, privateKey: a.pem1 }, { epoch: 9, privateKey: a.pkcs8 }]) });
  await assert.rejects(provider.keysForEpoch(10), unavailable);
  await assert.rejects(provider.keysForEpoch(9), unavailable);
});

test('missing manifest entries never fall back to a configured legacy key', async () => {
  const provider = createEpochKeyProvider({ currentEpoch: () => 10, legacySigningKeyB64: b.pkcs8,
    manifestJSON: manifest([records[0]]) });
  assert.ok(await provider.keysForEpoch(10));
  await assert.rejects(provider.keysForEpoch(9), unavailable);
});

test('malformed or noncurrent manifest configuration fails closed before key use', () => {
  const invalid = [null, '', 'not-json', 'null', '[]', '{}',
    JSON.stringify({ version: 2, keys: records }), manifest([]),
    manifest([records[0], records[0]]), manifest([...records, { epoch: 8, privateKey: b.pkcs8 }]),
    manifest([{ epoch: 11, privateKey: a.pkcs8 }]), manifest([{ epoch: 8, privateKey: a.pkcs8 }]),
    manifest([{ epoch: 10.5, privateKey: a.pkcs8 }]), manifest([{ epoch: 10, privateKey: '' }]),
    ' '.repeat(32769)];
  for (const manifestJSON of invalid) {
    assert.throws(() => createEpochKeyProvider({ manifestJSON, legacySigningKeyB64: a.pkcs8,
      currentEpoch: () => 10 }), unavailable);
  }
});

test('every configured key must validate before any public or private key is served', async () => {
  const provider = createEpochKeyProvider({ currentEpoch: () => 10, legacySigningKeyB64: a.pkcs8,
    manifestJSON: manifest([records[0], { epoch: 9, privateKey: 'invalid-key-material' }]) });
  await assert.rejects(provider.keysForEpoch(10), unavailable);
  await assert.rejects(provider.keysForEpoch(9), unavailable);
  const missing = createEpochKeyProvider({ currentEpoch: () => 10 });
  await assert.rejects(missing.keysForEpoch(10), unavailable);
});

test('rollover keeps only the final overlap epoch and rejects expired cached keys', async () => {
  let now = 10;
  const provider = createEpochKeyProvider({ manifestJSON: manifest(records), currentEpoch: () => now });
  const current = await provider.keysForEpoch(10);
  await provider.keysForEpoch(9);
  now = 11;
  assert.strictEqual(await provider.keysForEpoch(10), current);
  await assert.rejects(provider.keysForEpoch(9), unavailable);
  await assert.rejects(provider.keysForEpoch(11), unavailable);
  now = 12;
  await assert.rejects(provider.keysForEpoch(10), unavailable);
});

test('a boundary crossed during asynchronous import cannot release an expired key', async () => {
  let now = 10;
  const provider = createEpochKeyProvider({ manifestJSON: manifest(records), currentEpoch: () => now });
  const pending = provider.keysForEpoch(9);
  now = 11;
  await assert.rejects(pending, unavailable);
  assert.ok(await provider.keysForEpoch(10));
});

test('concurrent imports share one immutable entry and keep exact epoch selection', async () => {
  const provider = createEpochKeyProvider({ manifestJSON: manifest(records), currentEpoch: () => 10 });
  const keys = await Promise.all(Array.from({ length: 12 }, (_, i) => provider.keysForEpoch(i % 2 ? 9 : 10)));
  for (let i = 0; i < keys.length; i++) assert.strictEqual(keys[i], keys[i % 2]);
  assert.notEqual(keys[0].keyId, keys[1].keyId);
  assert.ok(Object.isFrozen(keys[0]));
});

test('unsupported key types and sizes fail closed with a nonsecret error', async () => {
  const wrong = [
    crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey,
    crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey,
  ];
  for (const key of wrong) {
    const provider = createEpochKeyProvider({ currentEpoch: () => 10,
      legacySigningKeyB64: key.export({ format: 'pem', type: 'pkcs8' }) });
    await assert.rejects(provider.keysForEpoch(10), unavailable);
  }
});

test('invalid requested epochs and invalid clock values cannot select a key', async () => {
  let now = 10;
  const provider = createEpochKeyProvider({ legacySigningKeyB64: a.pkcs8, currentEpoch: () => now });
  for (const epoch of [-1, 8, 11, 10.1, NaN, Infinity]) await assert.rejects(provider.keysForEpoch(epoch), unavailable);
  for (now of [-1, NaN, Infinity, 10.1]) await assert.rejects(provider.keysForEpoch(10), unavailable);
});
