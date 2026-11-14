// Worker HTTP contract, run inside workerd against local D1. Ports of
// token-issuer/issuer-http.test.js, test.js and state-config.test.js, with
// synthetic App Attest certificates and ephemeral RSA keys only.
import { test } from 'vitest';
import assert from 'node:assert/strict';
import crypto, { webcrypto } from 'node:crypto';
import { env } from 'cloudflare:workers';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { makeAttestationFixture, makeAssertion } from '../../../token-issuer/appattest-fixtures.js';
import { blindSign, keyIdFromSpki } from '../../../token-issuer/epoch-keys.js';

const suite = RSABSSA.SHA384.PSS.Deterministic();
const newKey = () => suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
const pkcs8 = async key => Buffer.from(await webcrypto.subtle.exportKey('pkcs8', key)).toString('base64');
const signingKey = await newKey(), currentSigningKey = await newKey();
const epochSeconds = 604800;
const epoch = Math.floor(Date.now() / 1000 / epochSeconds);
const requestedEpoch = epoch - 1;
const prepared = suite.prepare(crypto.randomBytes(32));
const blind = await suite.blind(signingKey.publicKey, prepared);
const blinded = Buffer.from(blind.blindedMsg).toString('base64');
const challenge = Buffer.concat([Buffer.from(String(requestedEpoch)), Buffer.from([0]), Buffer.from(blind.blindedMsg)]);
const appId = 'ABCDE12345.com.example.app';
const attested = makeAttestationFixture({ appId, challenge });

// appattest.js reads its operator config from process.env at load, as in Node.
Object.assign(process.env, { APPLE_APP_ATTEST_ROOT_CA_PEM_B64: attested.rootPemB64, APPLE_TEAM_ID: 'ABCDE12345',
  APPLE_BUNDLE_ID: 'com.example.app', APPLE_APP_ATTEST_AAGUID: 'appattest' });
const { createIssuer, expectedClientDataHash, boundEpoch, safeLogFields, default: worker } = await import('../index.js');

const legacyKey = await pkcs8(signingKey.privateKey);
const baseEnv = {
  ISSUER_DB: env.ISSUER_DB, REQUIRE_DURABLE_STATE: '1', ISSUER_STATE_SALT: Buffer.alloc(32, 9).toString('base64'),
  ISSUER_SIGNING_KEY: legacyKey, EPOCH_SECONDS: String(epochSeconds), ISSUANCE_QUOTA_PER_EPOCH: '3',
  ISSUER_EPOCH_KEYS_JSON: JSON.stringify({ version: 1, keys: [
    { epoch, privateKey: await pkcs8(currentSigningKey.privateKey) },
    { epoch: requestedEpoch, privateKey: legacyKey },
  ] }),
};
const call = (issuer, path, init = {}) => issuer.fetch(new Request(`https://issuer.test${path}`, init));
const post = (issuer, body, headers = {}) => call(issuer, '/issue', { method: 'POST',
  headers: { 'Content-Type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

test('runs inside workerd', () => assert.equal(navigator.userAgent, 'Cloudflare-Workers'));

test('HTTP keys contract and previous-epoch issuance agree with the client envelope', async () => {
  const issuer = createIssuer(baseEnv);
  const keysResponse = await call(issuer, '/issuer-keys');
  assert.equal(keysResponse.status, 200);
  assert.equal(keysResponse.headers.get('Content-Type'), 'application/json');
  const doc = await keysResponse.json();
  assert.deepEqual(Object.keys(doc), ['schemaVersion', 'suite', 'epoch', 'epochSeconds', 'keys']);
  assert.equal(doc.schemaVersion, 1);
  assert.equal(doc.suite, 'RSABSSA-SHA384-PSS-Deterministic');
  assert.equal(doc.epochSeconds, epochSeconds);
  assert.equal(doc.epoch, epoch);
  assert.deepEqual(doc.keys.map(k => k.epoch), [epoch, requestedEpoch]);
  assert.notEqual(doc.keys[0].keyId, doc.keys[1].keyId, 'HTTP rollover uses distinct actual keys');
  for (const key of doc.keys) {
    assert.deepEqual(Object.keys(key), ['epoch', 'keyId', 'publicKeySpki']);
    assert.equal(keyIdFromSpki(Buffer.from(key.publicKeySpki, 'base64')), key.keyId);
  }

  const request = { keyId: attested.keyIdB64, attestation: attested.attestationB64,
    clientDataHash: attested.clientDataHashB64, blinded: [blinded] };
  const response = await post(issuer, request);
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.deepEqual(Object.keys(result), ['epoch', 'keyId', 'blindSigs']);
  assert.equal(result.epoch, requestedEpoch, 'sign and label the epoch bound by the client, not the later server epoch');
  assert.equal(result.keyId, doc.keys.find(k => k.epoch === requestedEpoch).keyId);
  assert.equal(result.blindSigs.length, 1);
  const signature = await suite.finalize(signingKey.publicKey, prepared, Buffer.from(result.blindSigs[0], 'base64'), blind.inv);
  // What the relay does offline: RSA-PSS/SHA-384 verify against the published SPKI.
  const published = await crypto.subtle.importKey('spki', Buffer.from(doc.keys[1].publicKeySpki, 'base64'),
    { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 48 }, published, signature, prepared), true);

  const proof = makeAssertion({ appId, credPrivateKey: attested.credKey.privateKey, signCount: 1, challenge });
  const assertionRequest = { keyId: attested.keyIdB64, assertion: proof.assertionB64,
    clientDataHash: proof.clientDataHashB64, blinded: [blinded] };
  const competing = await Promise.all([post(issuer, assertionRequest), post(createIssuer(baseEnv), assertionRequest)]);
  assert.deepEqual(competing.map(r => r.status).sort(), [200, 401], 'concurrent actual proofs admit one counter reservation');
  assert.equal((await issuer.state.getAttestedKey(attested.keyIdB64)).signCount, 1);
  assert.equal((await post(issuer, request)).status, 200, 're-attestation consumes the last quota without resetting the counter');
  assert.equal((await issuer.state.getAttestedKey(attested.keyIdB64)).signCount, 1);

  const limited = await post(issuer, request);
  assert.equal(limited.status, 429);
  assert.deepEqual(await limited.json(), { error: 'quota_exceeded' });
  const retryAfter = Number(limited.headers.get('Retry-After'));
  assert.ok(retryAfter >= 1 && retryAfter <= epochSeconds);
});

test('the production key shape (legacy base64 PKCS#1) serves one stable key for both epochs', async () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const issuer = createIssuer({ ...baseEnv, ISSUER_EPOCH_KEYS_JSON: undefined,
    ISSUER_SIGNING_KEY: privateKey.export({ type: 'pkcs1', format: 'der' }).toString('base64') + '\n' });
  const response = await call(issuer, '/issuer-keys');
  assert.equal(response.status, 200);
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const key = { keyId: keyIdFromSpki(spki), publicKeySpki: spki.toString('base64') };
  // Byte-for-byte the JSON server.js writes.
  assert.equal(await response.text(), JSON.stringify({ schemaVersion: 1, suite: 'RSABSSA-SHA384-PSS-Deterministic',
    epoch, epochSeconds, keys: [{ epoch, ...key }, { epoch: epoch - 1, ...key }] }));
});

test('health, routing, content type and body limits match server.js', async () => {
  const issuer = createIssuer(baseEnv);
  const health = await call(issuer, '/health');
  assert.equal(health.status, 200);
  assert.equal(health.headers.get('Content-Type'), 'text/plain');
  assert.equal(await health.text(), 'ok');
  for (const [path, init] of [['/nope', {}], ['/health?x=1', {}], ['/issuer-keys', { method: 'POST' }],
    ['/issue', {}], ['/health', { method: 'HEAD' }]]) {
    assert.equal((await call(issuer, path, init)).status, 404, `${init.method || 'GET'} ${path}`);
  }
  assert.equal((await call(issuer, '/issue', { method: 'POST', body: '{}' })).status, 415);
  assert.equal((await call(issuer, '/issue', { method: 'POST', body: '{}', headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await post(issuer, 'x'.repeat(262145))).status, 413);
  assert.equal((await post(issuer, ' '.repeat(262144))).status, 400, 'exactly MAX_BODY_BYTES is read, then fails JSON');
  assert.equal((await post(issuer, '{}', { 'Content-Type': 'Application/JSON; charset=utf-8' })).status, 400);
});

test('/issue shape failures are status-only and precede any crypto or state', async () => {
  const issuer = createIssuer(baseEnv);
  const ok = { keyId: 'k', clientDataHash: crypto.randomBytes(32).toString('base64'), attestation: attested.attestationB64 };
  const cases = [
    ['not json', 400], ['null', 400], ['﻿{}', 400],
    [{ ...ok, blinded: [blinded], keyId: '' }, 400], [{ ...ok, blinded: [blinded], keyId: 7 }, 400],
    [{ ...ok, blinded: [] }, 400], [{ ...ok, blinded: blinded }, 400], [{ ...ok, blinded: Array(65).fill(blinded) }, 400],
    [{ ...ok, blinded: [7] }, 400], [{ ...ok, blinded: [Buffer.alloc(255).toString('base64')] }, 400],
    [{ ...ok, blinded: [blinded] }, 401], // clientDataHash is not bound to this batch
  ];
  for (const [body, status] of cases) {
    const response = await post(issuer, body);
    assert.equal(response.status, status, JSON.stringify(body).slice(0, 60));
    assert.equal(await response.text(), '');
  }
  assert.equal((await post(issuer, { ...ok, blinded: Array(64).fill(blinded) })).status, 401, '64 is the largest accepted batch');
});

test('App Attest failures return the typed JSON error', async () => {
  const issuer = createIssuer(baseEnv);
  const binding = expectedClientDataHash(epoch, [blinded]).toString('base64');
  const unknown = await post(issuer, { keyId: crypto.randomBytes(32).toString('base64'), assertion: 'AA==',
    clientDataHash: binding, blinded: [blinded] });
  assert.equal(unknown.status, 401);
  assert.deepEqual(await unknown.json(), { error: 'unknown_device_key' });
  const bad = await post(issuer, { keyId: attested.keyIdB64, attestation: attested.attestationB64,
    clientDataHash: binding, blinded: [blinded] });
  assert.equal(bad.status, 401, 'binding hash is not the nonce the fixture attested');
  assert.deepEqual(await bad.json(), { error: 'attest_failed' });
});

test('missing signing key and unavailable state fail closed', async () => {
  const keyless = createIssuer({ ...baseEnv, ISSUER_SIGNING_KEY: '', ISSUER_EPOCH_KEYS_JSON: undefined });
  assert.equal((await call(keyless, '/issuer-keys')).status, 503);
  const binding = expectedClientDataHash(epoch, [blinded]).toString('base64');
  assert.equal((await post(keyless, { keyId: 'k', assertion: 'AA==', clientDataHash: binding, blinded: [blinded] })).status, 503);

  // A different salt against the persisted fingerprint is state_unavailable, not a reset.
  assert.equal(await createIssuer(baseEnv).state.getAttestedKey('initialize'), null);
  const resalted = createIssuer({ ...baseEnv, ISSUER_STATE_SALT: Buffer.alloc(32, 1).toString('base64') });
  const response = await post(resalted, { keyId: attested.keyIdB64, attestation: attested.attestationB64,
    clientDataHash: attested.clientDataHashB64, blinded: [blinded] });
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('Retry-After'), '2');
  assert.deepEqual(await response.json(), { error: 'state_unavailable' });
});

test('front door lock gates everything except GET /health and GET /issuer-keys', async () => {
  const fdid = 'fdid-fixture';
  const issuer = createIssuer({ ...baseEnv, REQUIRE_FDID: fdid });
  assert.equal((await call(issuer, '/health')).status, 200);
  assert.equal((await call(issuer, '/issuer-keys')).status, 200);
  assert.equal((await post(issuer, 'x')).status, 403);
  assert.equal((await post(issuer, 'x', { 'X-Azure-FDID': 'wrong' })).status, 403);
  assert.equal((await post(issuer, 'x', { 'X-Azure-FDID': `other, ${fdid}` })).status, 400, 'any comma-joined value may match');
  assert.equal((await call(issuer, '/health', { method: 'POST' })).status, 403);
  assert.equal((await call(issuer, '/elsewhere')).status, 403);
  const custom = createIssuer({ ...baseEnv, REQUIRE_FDID: fdid, FDID_HEADER: 'X-Edge-Id' });
  assert.equal((await post(custom, 'x', { 'x-edge-id': fdid })).status, 400);
});

test('durable-state policy and quota configuration fail closed like server.js startup', () => {
  assert.throws(() => createIssuer({ ...baseEnv, ISSUER_DB: undefined }), /issuer_durable_state_required/);
  assert.throws(() => createIssuer({ ...baseEnv, REQUIRE_DURABLE_STATE: 'true' }), /issuer_durable_state_policy_invalid/);
  assert.throws(() => createIssuer({ ...baseEnv, ISSUANCE_QUOTA_PER_EPOCH: '0.5' }), /issuer_state_configuration/);
  assert.throws(() => createIssuer({ ...baseEnv, ISSUER_STATE_SALT: 'c2hvcnQ=' }), /issuer_state_salt_required/);
  assert.ok(createIssuer({ ...baseEnv, ISSUER_DB: undefined, REQUIRE_DURABLE_STATE: '0' }), 'memory mode for development');
});

test('the module entrypoint serves through the bound environment', async () => {
  const response = await worker.fetch(new Request('https://issuer.test/health'), baseEnv);
  assert.equal(await response.text(), 'ok');
});

test('issuer log boundary discards arbitrary path, key, challenge and error details', () => {
  const privateString = 'private-test-marker';
  const safe = safeLogFields({
    route: `/${privateString}`, status: 403, durationMs: 12.3,
    reason: privateString, keyId: privateString, attestation: privateString,
    clientDataHash: privateString, error: privateString, issued: 999999,
    proofMode: privateString, attestFailure: privateString,
  });
  assert.deepEqual(safe, { route: 'other', status: 403, durationMs: 12 });
  assert.deepEqual(safeLogFields({ reason: 'attest_failed', proofMode: 'assertion',
    attestFailure: 'unknown_device_key', detail: privateString, keyId: privateString }),
  { reason: 'attest_failed', proofMode: 'assertion', attestFailure: 'unknown_device_key' });
});

test('binding chooses exactly the current or previous epoch and rejects stale epochs', () => {
  for (const e of [epoch, epoch - 1]) {
    assert.equal(boundEpoch(expectedClientDataHash(e, [blinded]).toString('base64'), [blinded], epoch), e);
  }
  assert.equal(boundEpoch(expectedClientDataHash(epoch - 2, [blinded]).toString('base64'), [blinded], epoch), null);
  assert.equal(boundEpoch('invalid', [blinded], epoch), null);
});

test('(h) expectedClientDataHash binds the blinded batch + epoch', () => {
  const [a, b, c] = ['aaaa', 'bbbb', 'cccc'].map(s => Buffer.from(s).toString('base64'));
  const h1 = expectedClientDataHash(12345, [a, b]);
  assert.equal(h1.length, 32);
  assert.ok(h1.equals(expectedClientDataHash(12345, [a, b])));
  assert.ok(!h1.equals(expectedClientDataHash(12345, [b, a])), 'order');
  assert.ok(!h1.equals(expectedClientDataHash(12345, [a, c])), 'payload');
  assert.ok(!h1.equals(expectedClientDataHash(12346, [a, b])), 'epoch');
  assert.ok(!expectedClientDataHash(12345, [Buffer.from('aaaabbbb').toString('base64')]).equals(h1), 'separators');
});

test('(h2) expectedClientDataHash matches the pinned cross-check vector (mirrored in Swift)', () => {
  const got = expectedClientDataHash(2871, [Buffer.alloc(256, 0x11).toString('base64'), Buffer.alloc(256, 0x22).toString('base64')]);
  assert.equal(got.toString('hex'), 'b3ebf7a2a03f8b0d372681555499a9d46d3017722a493cf841d80dad23e174ed');
});

test('(a, d, e) blind / sign / finalize verifies; tampering fails; the issuer view is unlinkable', async () => {
  const pair = await newKey();
  const entry = { signer: crypto.KeyObject.from(pair.privateKey), verifier: crypto.KeyObject.from(pair.publicKey) };
  const input = suite.prepare(crypto.randomBytes(32));
  const { blindedMsg, inv } = await suite.blind(pair.publicKey, input);
  const blindSig = blindSign(entry, blindedMsg);
  const signature = await suite.finalize(pair.publicKey, input, blindSig, inv);
  assert.equal(await suite.verify(pair.publicKey, signature, input), true);

  const badSig = Buffer.from(signature); badSig[10] ^= 0xff;
  assert.equal(await suite.verify(pair.publicKey, badSig, input), false);
  const badInput = Buffer.from(input); badInput[0] ^= 0xff;
  assert.equal(await suite.verify(pair.publicKey, signature, badInput), false);
  assert.equal(await suite.verify((await newKey()).publicKey, signature, input), false, 'another key never verifies');

  assert.notDeepEqual(Buffer.from(blindedMsg), Buffer.from(input));
  assert.notDeepEqual(Buffer.from(blindSig), Buffer.from(signature));
  const again = await suite.blind(pair.publicKey, input);
  assert.notDeepEqual(Buffer.from(again.blindedMsg), Buffer.from(blindedMsg), 'blinding is randomized');
});
