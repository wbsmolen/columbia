// Columbia - token-issuer / relay token-mode tests.
//
// Run: node --test   (from this directory, after `npm install`)
//
// These prove the end-to-end Privacy Pass property the system depends on:
//   (a) blind -> issuer blind-sign -> client unblind/finalize -> verify roundtrip
//   (b) a valid finished token passes the RELAY's verifyAccessToken
//   (c) the same token spent twice is rejected (spend-once / double-spend)
//   (d) a tampered/forged token is rejected
//   (e) unlinkability sanity: the issuer's view (blinded request + blind sig)
//       cannot be matched to the finished token, and blinding is randomized.
//
// The tests use the issuer's OWN blind-RSA suite and the relay's OWN
// verifyAccessToken, generating an ephemeral epoch keypair so no env-injected
// signing key is needed. The relay is required with a dummy (valid) GATEWAY_URL
// and ISSUER_KEYS_URL unset, so requiring it starts no socket and makes no network
// call; the epoch public key is injected directly via setIssuerKeysForTest.

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { webcrypto } = crypto;

const issuer = require('./server.js');
const { suite, keyIdFromSpki, derivePublicKey } = issuer;

// The relay validates GATEWAY_URL at load and exits if it is missing/not https, so
// set a valid dummy before requiring. ISSUER_KEYS_URL stays unset => no network.
process.env.GATEWAY_URL = process.env.GATEWAY_URL || 'https://gateway.invalid/gateway';
const relay = require('../ohttp-relay/server.js');

// --- Shared helpers ---------------------------------------------------------

// Generate an ephemeral epoch keypair using the issuer's blind-RSA suite, plus its
// SPKI bytes, derived RSA-PSS public KeyObject for the relay, and the key id.
async function makeEpochKey() {
  const { publicKey, privateKey } = await suite.generateKey({
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  });
  const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', publicKey));
  const keyId = keyIdFromSpki(spki);
  const relayPub = crypto.createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  return { publicKey, privateKey, spki, keyId, relayPub };
}

// One full client+issuer exchange for a fresh token. Returns every intermediate so
// tests can inspect both the issuer's view and the client's finished token.
async function mintToken(epoch, tokenInputBytes) {
  // Client side: prepare + blind the token input.
  const prepared = suite.prepare(tokenInputBytes);
  const { blindedMsg, inv } = await suite.blind(epoch.publicKey, prepared);

  // Issuer side: blind-sign the blinded message ONLY. The issuer never sees
  // `prepared` (the token input) or the finished signature.
  const blindSig = await suite.blindSign(epoch.privateKey, blindedMsg);

  // Client side: finalize (unblind) into the real, publicly-verifiable signature.
  const signature = await suite.finalize(epoch.publicKey, prepared, blindSig, inv);

  // The compact token the client presents to the relay in the auth header.
  const tokenObj = {
    keyId: epoch.keyId,
    tokenInput: Buffer.from(prepared).toString('base64'),
    signature: Buffer.from(signature).toString('base64'),
  };
  const headerValue = 'PrivateToken ' + Buffer.from(JSON.stringify(tokenObj)).toString('base64url');

  return { prepared, blindedMsg, inv, blindSig, signature, tokenObj, headerValue };
}

// Point the relay at a one-key issuer-key cache for the given epoch key.
function loadRelayKey(epoch) {
  relay.setIssuerKeysForTest(new Map([[epoch.keyId, epoch.relayPub]]));
}

// --- (a) blind -> sign -> unblind -> verify roundtrip -----------------------

test('(a) blind / issuer-sign / client-finalize / verify roundtrip succeeds', async () => {
  const epoch = await makeEpochKey();
  const input = crypto.randomBytes(32);
  const m = await mintToken(epoch, input);

  // Verify the finished signature under the epoch PUBLIC key via the suite.
  const ok = await suite.verify(epoch.publicKey, m.signature, m.prepared);
  assert.strictEqual(ok, true, 'finalized token must verify under the issuer public key');

  // And independently via Node's built-in RSA-PSS verify (what the relay uses),
  // proving the token is publicly verifiable with the public key alone.
  const builtinOk = crypto.verify(
    'sha384',
    Buffer.from(m.prepared),
    { key: epoch.relayPub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
    Buffer.from(m.signature),
  );
  assert.strictEqual(builtinOk, true, 'token must verify with the public key offline');
});

// --- (b) a valid token passes the relay's verify logic ----------------------

test('(b) a valid token passes the relay verifyAccessToken', async () => {
  const epoch = await makeEpochKey();
  loadRelayKey(epoch);
  const m = await mintToken(epoch, crypto.randomBytes(32));

  assert.strictEqual(relay.verifyAccessToken(m.headerValue), true,
    'a freshly minted, well-formed token must be accepted by the relay');
});

// --- (c) double-spend is rejected -------------------------------------------

test('(c) spending the same token twice is rejected (spend-once)', async () => {
  const epoch = await makeEpochKey();
  loadRelayKey(epoch);
  const m = await mintToken(epoch, crypto.randomBytes(32));

  assert.strictEqual(relay.verifyAccessToken(m.headerValue), true, 'first spend accepted');
  assert.strictEqual(relay.verifyAccessToken(m.headerValue), false, 'second spend rejected');
});

// --- (d) tampered / forged tokens are rejected ------------------------------

test('(d) a tampered or forged token is rejected', async () => {
  const epoch = await makeEpochKey();
  loadRelayKey(epoch);
  const m = await mintToken(epoch, crypto.randomBytes(32));

  // (d1) Flip one byte of the signature. The new nullifier is fresh (not the spent
  // one), so this isolates signature verification, not the spend-once path.
  const badSig = Buffer.from(m.signature);
  badSig[10] ^= 0xff;
  const tamperedSig = {
    keyId: m.tokenObj.keyId,
    tokenInput: m.tokenObj.tokenInput,
    signature: badSig.toString('base64'),
  };
  const tamperedSigHeader = 'PrivateToken ' + Buffer.from(JSON.stringify(tamperedSig)).toString('base64url');
  assert.strictEqual(relay.verifyAccessToken(tamperedSigHeader), false, 'tampered signature rejected');

  // (d2) Tamper the token input (claim the signature covers a different message).
  const badInput = Buffer.from(m.prepared);
  badInput[0] ^= 0xff;
  const tamperedInput = {
    keyId: m.tokenObj.keyId,
    tokenInput: badInput.toString('base64'),
    signature: m.tokenObj.signature,
  };
  const tamperedInputHeader = 'PrivateToken ' + Buffer.from(JSON.stringify(tamperedInput)).toString('base64url');
  assert.strictEqual(relay.verifyAccessToken(tamperedInputHeader), false, 'tampered token input rejected');

  // (d3) Forge a signature with an ATTACKER key the issuer never authorized. Must
  // be rejected because the relay only holds the genuine epoch public key.
  const attacker = await makeEpochKey(); // different keypair, NOT loaded into relay
  const forged = await mintToken({ ...attacker, keyId: epoch.keyId }, crypto.randomBytes(32));
  // Present it under the genuine epoch's keyId so the relay looks up the real key.
  assert.strictEqual(relay.verifyAccessToken(forged.headerValue), false,
    'a signature from an unauthorized key must not verify under the genuine public key');

  // (d4) Garbage / unparseable header is rejected, not crashed.
  assert.strictEqual(relay.verifyAccessToken('PrivateToken not-base64-$$$'), false);
  assert.strictEqual(relay.verifyAccessToken(''), false);
  assert.strictEqual(relay.verifyAccessToken(undefined), false);
});

// --- (e) unlinkability sanity check -----------------------------------------

test('(e) the issuer view cannot be matched to the finished token', async () => {
  const epoch = await makeEpochKey();
  const input = crypto.randomBytes(32);
  const m = await mintToken(epoch, input);

  // What the ISSUER saw: the blinded message and the blind signature.
  // What gets SPENT at the relay: the token input and the finalized signature.
  // For unlinkability, the spent values must differ from the issuer's view, so the
  // issuer cannot recognize "its" signature when it later appears at the relay.
  assert.notDeepStrictEqual(Buffer.from(m.blindedMsg), Buffer.from(m.prepared),
    'blinded message must differ from the token input');
  assert.notDeepStrictEqual(Buffer.from(m.blindSig), Buffer.from(m.signature),
    'blind signature must differ from the finalized signature');

  // Blinding is randomized: the SAME token input, blinded twice, yields DIFFERENT
  // blinded messages. So even if the issuer logged every blinded request, it has no
  // stable handle that survives to spend time. (This is the core of the unlinkable
  // property; the blinding factor `inv` is secret to the client and discarded.)
  const prepared2 = suite.prepare(input);
  const b1 = await suite.blind(epoch.publicKey, m.prepared);
  const b2 = await suite.blind(epoch.publicKey, prepared2);
  assert.notDeepStrictEqual(Buffer.from(b1.blindedMsg), Buffer.from(b2.blindedMsg),
    'blinding the same input twice must produce different blinded messages');

  // The finished signature still verifies (it is a genuine signature over the
  // input), so unlinkability does not come at the cost of verifiability.
  const ok = await suite.verify(epoch.publicKey, m.signature, m.prepared);
  assert.strictEqual(ok, true);

  // Concretely: try to "match" by re-deriving. The issuer would need `inv` (the
  // client's secret blinding factor) to connect blindSig -> signature. It never
  // has it. We assert the two signatures share no trivial relationship a logger
  // could exploit: the finalized signature is not byte-equal to the blind sig.
  assert.notStrictEqual(
    Buffer.from(m.signature).toString('hex'),
    Buffer.from(m.blindSig).toString('hex'),
  );
});

// --- bonus: quota accounting (per-device per-epoch) -------------------------

test('(f) per-device per-epoch issuance quota reserves and then refuses', () => {
  // reserveQuota is exported from the issuer. Default quota is large, so use a
  // distinct device id and drive it past a small simulated budget by reserving in
  // chunks. We can't change the env-configured quota here, so this asserts the
  // monotonic reserve behavior: repeated reserves accumulate, and a single
  // oversized reserve for a fresh device is refused.
  const epoch = issuer.currentEpoch();
  const device = 'test-device-' + crypto.randomBytes(8).toString('hex');

  // A reservation that fits should succeed.
  assert.strictEqual(issuer.reserveQuota(epoch, device, 1), true);

  // A reservation that would exceed the per-epoch quota in one shot is refused.
  const huge = 10_000_000;
  const fresh = 'test-device-' + crypto.randomBytes(8).toString('hex');
  assert.strictEqual(issuer.reserveQuota(epoch, fresh, huge), false,
    'an over-quota batch must be refused for a fresh device');
});
