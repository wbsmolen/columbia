// Real HTTP issuance with synthetic App Attest certificates and ephemeral RSA.
// No Apple services, deployed endpoints, identities or persisted private keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { webcrypto } from 'node:crypto';
import { once } from 'node:events';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { makeAttestationFixture, makeAssertion } from './appattest-fixtures.js';

const suite = RSABSSA.SHA384.PSS.Deterministic();
const signingKey = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
const currentSigningKey = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
const epochSeconds = 604800;
const epoch = Math.floor(Date.now() / 1000 / epochSeconds);
const requestedEpoch = epoch - 1;
const nonce = crypto.randomBytes(32);
const prepared = suite.prepare(nonce);
const blind = await suite.blind(signingKey.publicKey, prepared);
const blinded = Buffer.from(blind.blindedMsg).toString('base64');
const challenge = Buffer.concat([Buffer.from(String(requestedEpoch)), Buffer.from([0]), Buffer.from(blind.blindedMsg)]);
const attested = makeAttestationFixture({ appId: 'ABCDE12345.com.example.app', challenge });

process.env.APPLE_APP_ATTEST_ROOT_CA_PEM_B64 = attested.rootPemB64;
process.env.APPLE_TEAM_ID = 'ABCDE12345';
process.env.APPLE_BUNDLE_ID = 'com.example.app';
process.env.APPLE_APP_ATTEST_AAGUID = 'appattest';
process.env.ISSUER_SIGNING_KEY = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', signingKey.privateKey)).toString('base64');
process.env.ISSUER_EPOCH_KEYS_JSON = JSON.stringify({ version: 1, keys: [
  { epoch, privateKey: Buffer.from(await webcrypto.subtle.exportKey('pkcs8', currentSigningKey.privateKey)).toString('base64') },
  { epoch: requestedEpoch, privateKey: process.env.ISSUER_SIGNING_KEY },
] });
process.env.EPOCH_SECONDS = String(epochSeconds);
process.env.ISSUANCE_QUOTA_PER_EPOCH = '3';
const issuer = await import('./server.js');

test('HTTP keys contract and previous-epoch issuance agree with the client envelope', async () => {
  issuer.server.listen(0, '127.0.0.1');
  await once(issuer.server, 'listening');
  const base = `http://127.0.0.1:${issuer.server.address().port}`;
  try {
    const keysResponse = await fetch(`${base}/issuer-keys`);
    assert.equal(keysResponse.status, 200);
    const doc = await keysResponse.json();
    assert.deepEqual(Object.keys(doc).sort(), ['epoch', 'epochSeconds', 'keys', 'schemaVersion', 'suite']);
    assert.equal(doc.schemaVersion, 1);
    assert.equal(doc.suite, 'RSABSSA-SHA384-PSS-Deterministic');
    assert.equal(doc.epochSeconds, epochSeconds);
    assert.equal(doc.epoch, epoch);
    assert.deepEqual(doc.keys.map(k => k.epoch), [epoch, requestedEpoch]);
    assert.notEqual(doc.keys[0].keyId, doc.keys[1].keyId, 'HTTP rollover uses distinct actual keys');
    for (const key of doc.keys) {
      assert.deepEqual(Object.keys(key).sort(), ['epoch', 'keyId', 'publicKeySpki']);
      assert.equal(issuer.keyIdFromSpki(Buffer.from(key.publicKeySpki, 'base64')), key.keyId);
    }

    const request = {
      keyId: attested.keyIdB64, attestation: attested.attestationB64,
      clientDataHash: attested.clientDataHashB64, blinded: [blinded],
    };
    const response = await fetch(`${base}/issue`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.epoch, requestedEpoch, 'sign and label the epoch bound by the client, not the later server epoch');
    assert.equal(result.keyId, doc.keys.find(k => k.epoch === requestedEpoch).keyId);
    assert.equal(result.blindSigs.length, 1);
    const signature = await suite.finalize(signingKey.publicKey, prepared, Buffer.from(result.blindSigs[0], 'base64'), blind.inv);
    assert.equal(await suite.verify(signingKey.publicKey, signature, prepared), true);

    const proof = makeAssertion({ appId: 'ABCDE12345.com.example.app', credPrivateKey: attested.credKey.privateKey,
      signCount: 1, challenge });
    const assertionRequest = { keyId: attested.keyIdB64, assertion: proof.assertionB64,
      clientDataHash: proof.clientDataHashB64, blinded: [blinded] };
    const post = body => fetch(`${base}/issue`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const competing = await Promise.all([post(assertionRequest), post(assertionRequest)]);
    assert.deepEqual(competing.map(r => r.status).sort(), [200, 401], 'concurrent actual proofs admit one counter reservation');
    assert.equal((await issuer.ISSUER_STATE.getAttestedKey(attested.keyIdB64)).signCount, 1);
    assert.equal((await post(request)).status, 200, 're-attestation consumes the last quota without resetting the counter');
    assert.equal((await issuer.ISSUER_STATE.getAttestedKey(attested.keyIdB64)).signCount, 1);

    const limited = await fetch(`${base}/issue`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
    });
    assert.equal(limited.status, 429);
    const retryAfter = Number(limited.headers.get('Retry-After'));
    assert.ok(retryAfter >= 1 && retryAfter <= epochSeconds);
  } finally {
    issuer.server.closeAllConnections();
    await new Promise(resolve => issuer.server.close(resolve));
  }
});

test('issuer log boundary discards arbitrary path, key, challenge and error details', () => {
  const privateString = 'private-test-marker';
  const safe = issuer.safeLogFields({
    route: `/${privateString}`, status: 403, durationMs: 12.3,
    reason: privateString, keyId: privateString, attestation: privateString,
    clientDataHash: privateString, error: privateString, issued: 999999,
  });
  assert.deepEqual(safe, { route: 'other', status: 403, durationMs: 12 });
  assert.ok(!JSON.stringify(safe).includes(privateString));
});

test('binding chooses exactly the current or previous epoch and rejects stale epochs', () => {
  const messages = [blinded];
  for (const e of [epoch, epoch - 1]) {
    assert.equal(issuer.boundEpoch(issuer.expectedClientDataHash(e, messages).toString('base64'), messages, epoch), e);
  }
  assert.equal(issuer.boundEpoch(issuer.expectedClientDataHash(epoch - 2, messages).toString('base64'), messages, epoch), null);
  assert.equal(issuer.boundEpoch('invalid', messages, epoch), null);
});
