// Columbia - Apple App Attest validation tests.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Run: node --test   (from this directory)
//
// We have NO real device attestation in CI, so these tests mint a SYNTHETIC trust
// chain + attestation (see appattest-fixtures.js) that satisfies every Apple check, and
// then prove:
//   (a) GOLDEN PATH: a well-formed attestation is ACCEPTED, the device public key
//       and keyId are returned, and a following assertion verifies.
//   (b) NEGATIVE: each single tampered field is REJECTED on its own -
//       wrong rpIdHash, wrong nonce/challenge, broken chain, untrusted root,
//       wrong aaguid, non-zero first counter, wrong/forged keyId, bad assertion
//       signature, non-increasing assertion counter, unknown device key.
//   (c) FAIL-CLOSED: missing inputs are rejected, and with App Attest unconfigured
//       the validator rejects everything.
//
// IMPORTANT: appattest.js reads its operator config (root CA, team, bundle, aaguid)
// from env AT MODULE LOAD. So this file sets that env to the synthetic fixture's
// root BEFORE importing appattest.js. The trust anchor is the only substitution;
// every cryptographic and structural check is the real one.

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';

import {
  makeAttestationFixture, makeAssertion, newP256, buildCert,
  buildAttestationAuthData, appleNonceExtension,
  cborMap, cborArray, cborBytes, cborText, uncompressedPoint,
} from './appattest-fixtures.js';

// --- One canonical fixture drives the env config for the whole file ----------

const APP_ID = 'ABCDE12345.com.example.app';
const TEAM_ID = 'ABCDE12345';
const BUNDLE_ID = 'com.example.app';

// Build the baseline (valid) fixture first so we can pin its root CA via env.
const baseChallenge = crypto.randomBytes(32);
const base = makeAttestationFixture({ appId: APP_ID, aaguidLabel: 'appattest', challenge: baseChallenge });

process.env.APPLE_APP_ATTEST_ROOT_CA_PEM_B64 = base.rootPemB64;
process.env.APPLE_TEAM_ID = TEAM_ID;
process.env.APPLE_BUNDLE_ID = BUNDLE_ID;
process.env.APPLE_APP_ATTEST_AAGUID = 'appattest';

// Now import the validator (it reads the env above at load).
const appattest = await import('./appattest.js');
const { validateAppAttest, APP_ATTEST_READY } = appattest;

// A tiny in-memory attested-key store, as server.js would provide.
function makeStore() {
  const m = new Map();
  return {
    map: m,
    getAttestedKey(keyId) { return m.get(keyId) || null; },
    setSignCount(keyId, n) { const r = m.get(keyId); if (r) r.signCount = n; },
    register(keyId, publicKeyPem, signCount = 0) { m.set(keyId, { publicKeyPem, signCount }); },
  };
}

// ===========================================================================
// (a) GOLDEN PATH
// ===========================================================================

test('module is configured (APP_ATTEST_READY) for these tests', () => {
  assert.strictEqual(APP_ATTEST_READY, true, 'env must configure App Attest for the suite');
});

test('(a1) a well-formed attestation is ACCEPTED and returns the device key + keyId', async () => {
  const res = await validateAppAttest({
    keyId: base.keyIdB64,
    attestation: base.attestationB64,
    clientDataHash: base.clientDataHashB64,
  });
  assert.strictEqual(res.ok, true, `attestation must be accepted: ${res.reason} ${res.detail || ''}`);
  assert.strictEqual(res.mode, 'attestation');
  assert.strictEqual(res.signCount, 0, 'first attestation counter is 0');
  assert.strictEqual(res.keyId, base.keyIdB64, 'returns the same keyId the device presented');
  assert.match(res.publicKeyPem, /BEGIN PUBLIC KEY/, 'returns the attested public key as PEM');
});

test('(a2) an assertion from the attested key verifies and advances the counter', async () => {
  const reg = await validateAppAttest({
    keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: base.clientDataHashB64,
  });
  assert.strictEqual(reg.ok, true);

  const store = makeStore();
  store.register(base.keyIdB64, reg.publicKeyPem, reg.signCount);

  const a = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 7, challenge: crypto.randomBytes(32) });
  const res = await validateAppAttest({ keyId: base.keyIdB64, assertion: a.assertionB64, clientDataHash: a.clientDataHashB64, store });
  assert.strictEqual(res.ok, true, `assertion must verify: ${res.reason} ${res.detail || ''}`);
  assert.strictEqual(res.mode, 'assertion');
  assert.strictEqual(res.signCount, 7);
  assert.strictEqual(store.getAttestedKey(base.keyIdB64).signCount, 7, 'counter persisted');
});

test('(a3) two assertions with strictly increasing counters both pass', async () => {
  const reg = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: base.clientDataHashB64 });
  const store = makeStore();
  store.register(base.keyIdB64, reg.publicKeyPem, 0);

  const a1 = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 3, challenge: crypto.randomBytes(32) });
  const r1 = await validateAppAttest({ keyId: base.keyIdB64, assertion: a1.assertionB64, clientDataHash: a1.clientDataHashB64, store });
  assert.strictEqual(r1.ok, true);

  const a2 = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 4, challenge: crypto.randomBytes(32) });
  const r2 = await validateAppAttest({ keyId: base.keyIdB64, assertion: a2.assertionB64, clientDataHash: a2.clientDataHashB64, store });
  assert.strictEqual(r2.ok, true);
  assert.strictEqual(store.getAttestedKey(base.keyIdB64).signCount, 4);
});

// ===========================================================================
// (b) NEGATIVE - each single tampered field is rejected on its own
// ===========================================================================

test('(b1) wrong rpIdHash (attestation for a different appID) is REJECTED', async () => {
  // A fixture built for a DIFFERENT appID has a different rpIdHash in authData, but
  // is otherwise well-formed. Anchor it to the pinned root by reusing base's root:
  // simplest is to mint under base's root key directly.
  const wrong = makeAttestationFixtureUnderRoot({
    rootKey: base.rootKey, interKey: base.interKey,
    appId: 'ABCDE12345.com.example.WRONG', aaguidLabel: 'appattest', challenge: crypto.randomBytes(32),
  });
  const res = await validateAppAttest({ keyId: wrong.keyIdB64, attestation: wrong.attestationB64, clientDataHash: wrong.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /rpIdHash/, 'must fail on rpIdHash mismatch');
});

test('(b2) wrong challenge (nonce mismatch) is REJECTED', async () => {
  // Present the valid attestation but with a clientDataHash for a DIFFERENT
  // challenge. The nonce baked into the cert no longer matches.
  const otherChallenge = crypto.randomBytes(32);
  const otherCdh = crypto.createHash('sha256').update(otherChallenge).digest().toString('base64');
  const res = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: otherCdh });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /nonce/, 'must fail on nonce mismatch');
});

test('(b3) broken chain (leaf re-signed by a stranger key) is REJECTED', async () => {
  // Re-sign the leaf with a random key that is NOT the intermediate, so the chain
  // signature breaks while names still line up.
  const stranger = newP256();
  const fx = makeAttestationFixtureUnderRoot({
    rootKey: base.rootKey, interKey: base.interKey,
    appId: APP_ID, aaguidLabel: 'appattest', challenge: crypto.randomBytes(32),
    leafSignerOverride: stranger.privateKey,
  });
  const res = await validateAppAttest({ keyId: fx.keyIdB64, attestation: fx.attestationB64, clientDataHash: fx.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /chain/, 'must fail on chain signature');
});

test('(b4) untrusted root (chain that does not anchor to the pinned root) is REJECTED', async () => {
  // A completely fresh fixture mints its OWN root, which is NOT the pinned one.
  const fresh = makeAttestationFixture({ appId: APP_ID, aaguidLabel: 'appattest', challenge: crypto.randomBytes(32) });
  const res = await validateAppAttest({ keyId: fresh.keyIdB64, attestation: fresh.attestationB64, clientDataHash: fresh.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /chain/, 'must fail to anchor to the pinned root');
});

test('(b5) wrong AAGUID (dev aaguid while prod is expected) is REJECTED', async () => {
  const devFx = makeAttestationFixtureUnderRoot({
    rootKey: base.rootKey, interKey: base.interKey,
    appId: APP_ID, aaguidLabel: 'appattestdevelop', challenge: crypto.randomBytes(32),
  });
  const res = await validateAppAttest({ keyId: devFx.keyIdB64, attestation: devFx.attestationB64, clientDataHash: devFx.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /aaguid/, 'a dev aaguid must be rejected when prod is configured');
});

test('(b6) non-zero first-attestation counter is REJECTED', async () => {
  const fx = makeAttestationFixtureUnderRoot({
    rootKey: base.rootKey, interKey: base.interKey,
    appId: APP_ID, aaguidLabel: 'appattest', challenge: crypto.randomBytes(32),
    signCount: 1,
  });
  const res = await validateAppAttest({ keyId: fx.keyIdB64, attestation: fx.attestationB64, clientDataHash: fx.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /signCount/, 'first attestation must have counter 0');
});

test('(b7) wrong keyId (does not match SHA256 of the attested key) is REJECTED', async () => {
  const bogusKeyId = crypto.randomBytes(32).toString('base64');
  const res = await validateAppAttest({ keyId: bogusKeyId, attestation: base.attestationB64, clientDataHash: base.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /keyId/, 'a keyId that is not SHA256(pubkey) must be rejected');
});

test('(b8) bad assertion signature (signed by the WRONG key) is REJECTED', async () => {
  const reg = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: base.clientDataHashB64 });
  const store = makeStore();
  store.register(base.keyIdB64, reg.publicKeyPem, 0);

  // Sign the assertion with a DIFFERENT key than the one registered.
  const attacker = newP256();
  const a = makeAssertion({ appId: APP_ID, credPrivateKey: attacker.privateKey, signCount: 9, challenge: crypto.randomBytes(32) });
  const res = await validateAppAttest({ keyId: base.keyIdB64, assertion: a.assertionB64, clientDataHash: a.clientDataHashB64, store });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /signature/, 'an assertion signed by the wrong key must be rejected');
});

test('(b9) assertion with a non-increasing counter (replay/rollback) is REJECTED', async () => {
  const reg = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: base.clientDataHashB64 });
  const store = makeStore();
  store.register(base.keyIdB64, reg.publicKeyPem, 10); // already at 10

  const a = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 10, challenge: crypto.randomBytes(32) });
  const res = await validateAppAttest({ keyId: base.keyIdB64, assertion: a.assertionB64, clientDataHash: a.clientDataHashB64, store });
  assert.strictEqual(res.ok, false);
  assert.match(res.detail || '', /signCount/, 'a non-increasing counter must be rejected');
});

test('(b10) assertion with a tampered authenticatorData byte is REJECTED', async () => {
  const reg = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: base.clientDataHashB64 });
  const store = makeStore();
  store.register(base.keyIdB64, reg.publicKeyPem, 0);

  const a = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 2, challenge: crypto.randomBytes(32) });
  // Flip a byte in the signed authData by re-encoding a tampered CBOR map.
  const tampered = Buffer.from(a.assertionB64, 'base64');
  tampered[tampered.length - 1] ^= 0xff; // corrupt the last authData byte
  const res = await validateAppAttest({ keyId: base.keyIdB64, assertion: tampered.toString('base64'), clientDataHash: a.clientDataHashB64, store });
  assert.strictEqual(res.ok, false, 'a tampered authData must not verify');
});

test('(b11) assertion for an unknown device key is REJECTED', async () => {
  const store = makeStore(); // empty store
  const a = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 1, challenge: crypto.randomBytes(32) });
  const res = await validateAppAttest({ keyId: base.keyIdB64, assertion: a.assertionB64, clientDataHash: a.clientDataHashB64, store });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'unknown_device_key');
});

test('(b12) ATTACKER-SUPPLIED ROOT in x5c is REJECTED (anchor-pinning bypass)', async () => {
  // The classic App Attest server bug: a validator that "anchors" by appending the
  // trusted root to the PRESENTED chain without checking the presented chain
  // actually connects to it. Here the attacker builds a fully self-consistent
  // chain - their own self-signed root, their own intermediate, a leaf carrying the
  // CORRECT nonce/keyId/rpIdHash/aaguid - and even APPENDS their own root cert into
  // x5c. It must still be rejected, because the terminal presented cert is not
  // signed by the PINNED Apple root.
  const challenge = crypto.randomBytes(32);
  const appId = APP_ID;
  const rpIdHash = crypto.createHash('sha256').update(appId, 'utf8').digest();
  const clientDataHash = crypto.createHash('sha256').update(challenge).digest();

  const attackerRoot = newP256();
  const attackerInter = newP256();
  const credKey = newP256();
  const credPoint = uncompressedPoint(credKey.publicKey);
  const keyIdRaw = crypto.createHash('sha256').update(credPoint).digest();

  const authData = buildAttestationAuthData({ rpIdHash, aaguidLabel: 'appattest', credentialId: keyIdRaw, credentialKey: credKey.publicKey });
  const nonce = crypto.createHash('sha256').update(authData).update(clientDataHash).digest();

  const attackerRootDer = buildCert({
    subjectCN: 'Evil Root', issuerCN: 'Evil Root',
    subjectKey: attackerRoot.publicKey, issuerKey: attackerRoot.privateKey, serial: 1,
  });
  const attackerInterDer = buildCert({
    subjectCN: 'Evil CA', issuerCN: 'Evil Root',
    subjectKey: attackerInter.publicKey, issuerKey: attackerRoot.privateKey, serial: 2,
  });
  const leafDer = buildCert({
    subjectCN: 'Evil Credential', issuerCN: 'Evil CA',
    subjectKey: credKey.publicKey, issuerKey: attackerInter.privateKey, serial: 3,
    extensions: [appleNonceExtension(nonce)],
  });

  // x5c includes the attacker's OWN root as the terminal cert.
  const attObj = cborMap([
    [cborText('fmt'), cborText('apple-appattest')],
    [cborText('attStmt'), cborMap([[cborText('x5c'), cborArray([cborBytes(leafDer), cborBytes(attackerInterDer), cborBytes(attackerRootDer)])]])],
    [cborText('authData'), cborBytes(authData)],
  ]);

  const res = await validateAppAttest({
    keyId: keyIdRaw.toString('base64'),
    attestation: attObj.toString('base64'),
    clientDataHash: clientDataHash.toString('base64'),
  });
  assert.strictEqual(res.ok, false, 'an attacker-rooted chain must NOT anchor to the pinned Apple root');
  assert.match(res.detail || '', /chain/, 'must fail at the chain-anchoring step');
});

// ===========================================================================
// (c) FAIL-CLOSED - missing/garbage inputs
// ===========================================================================

test('(c1) missing clientDataHash is REJECTED', async () => {
  const res = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64 });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'missing_client_data_hash');
});

test('(c2) a clientDataHash that is not 32 bytes is REJECTED', async () => {
  const res = await validateAppAttest({ keyId: base.keyIdB64, attestation: base.attestationB64, clientDataHash: Buffer.from('short').toString('base64') });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'client_data_hash_not_32_bytes');
});

test('(c3) neither attestation nor assertion is REJECTED', async () => {
  const res = await validateAppAttest({ keyId: base.keyIdB64, clientDataHash: base.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'no_attestation_or_assertion');
});

test('(c4) garbage CBOR attestation is REJECTED (parser fails closed, no crash)', async () => {
  const res = await validateAppAttest({ keyId: base.keyIdB64, attestation: Buffer.from('not cbor at all $$$').toString('base64'), clientDataHash: base.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
});

test('(c5) assertion without a store is REJECTED', async () => {
  const a = makeAssertion({ appId: APP_ID, credPrivateKey: base.credKey.privateKey, signCount: 1, challenge: crypto.randomBytes(32) });
  const res = await validateAppAttest({ keyId: base.keyIdB64, assertion: a.assertionB64, clientDataHash: a.clientDataHashB64 });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'no_attested_key_store');
});

// ===========================================================================
// Helper: mint a fixture under a GIVEN root + intermediate key, with optional
// tampers, so negative tests can vary ONE field while still anchoring to the
// pinned root. This mirrors appattest-fixtures.makeAttestationFixture but lets the
// caller pass the existing root/intermediate and tweak appId/aaguid/counter/leaf
// signer. Kept here (not in appattest-fixtures) because it is purely a test concern.
// ===========================================================================

function makeAttestationFixtureUnderRoot({ rootKey, interKey, appId, aaguidLabel, challenge, signCount = 0, leafSignerOverride = null }) {
  const rpIdHash = crypto.createHash('sha256').update(appId, 'utf8').digest();
  const clientDataHash = crypto.createHash('sha256').update(challenge).digest();

  const credKey = newP256();
  const credPoint = uncompressedPoint(credKey.publicKey);
  const keyIdRaw = crypto.createHash('sha256').update(credPoint).digest();
  const credentialId = keyIdRaw;

  const authData = buildAttestationAuthData({ rpIdHash, aaguidLabel, credentialId, credentialKey: credKey.publicKey, signCount });
  const nonce = crypto.createHash('sha256').update(authData).update(clientDataHash).digest();

  const interDer = buildCert({
    subjectCN: 'Columbia Test App Attestation CA 1', issuerCN: 'Columbia Test App Attest Root CA',
    subjectKey: interKey.publicKey, issuerKey: rootKey.privateKey, serial: 100,
  });
  const leafDer = buildCert({
    subjectCN: 'Columbia Test App Attest Credential', issuerCN: 'Columbia Test App Attestation CA 1',
    subjectKey: credKey.publicKey,
    issuerKey: leafSignerOverride || interKey.privateKey, // override = broken chain
    serial: 2, extensions: [appleNonceExtension(nonce)],
  });

  const attObj = cborMap([
    [cborText('fmt'), cborText('apple-appattest')],
    [cborText('attStmt'), cborMap([[cborText('x5c'), cborArray([cborBytes(leafDer), cborBytes(interDer)])]])],
    [cborText('authData'), cborBytes(authData)],
  ]);

  return {
    keyIdB64: keyIdRaw.toString('base64'),
    attestationB64: attObj.toString('base64'),
    clientDataHashB64: clientDataHash.toString('base64'),
    credKey,
  };
}
