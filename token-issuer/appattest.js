// Columbia - Apple App Attest validation (Attester role)
//
// This module is the gate that proves an /issue request comes from a genuine,
// unmodified Lander install on real Apple hardware, before the issuer will
// blind-sign any tokens. It implements Apple's DCAppAttestService verification.
//
// HONESTY NOTICE - READ THIS:
//   The full Apple App Attest verification has several cryptographic steps
//   (cert-chain to Apple's App Attest root, nonce binding, rpId/appID hash,
//   sign-counter monotonicity). Doing them correctly requires two things this
//   open-source repo deliberately does NOT carry:
//     1. Apple's App Attest Root CA certificate (public, but pinned per operator).
//     2. The operator's Apple Team ID + app Bundle ID (the appID = teamId.bundleId).
//   Until BOTH are supplied (via env, see APPLE_* below) this module FAILS CLOSED:
//   validateAppAttest() returns false and the issuer rejects every request. There
//   is no silent-allow path. A stub check below that cannot be completed without
//   operator input throws/returns false and is labeled with a TODO.
//
// The structure here is the real, full verification flow. Each Apple-defined check
// is its own clearly-named function so an operator can supply the missing inputs
// and turn the stub into enforcement without restructuring anything. Where a step
// genuinely needs CBOR/X.509 parsing that a dependency-light first cut can't do
// safely, the function is marked STUB with a precise TODO of what to parse and
// which Apple doc section governs it.
//
// References:
//   Apple, "Validating Apps That Connect to Your Server" (App Attest server-side
//   verification: attestation object, authenticator data, nonce, rpId hash,
//   sign count, cert chain to the App Attest Root CA).
//   Apple App Attest Root CA: https://www.apple.com/certificateauthority/

// Native ES module (the package is ESM; see server.js for why).

import crypto from 'node:crypto';

// --- Operator-supplied inputs (env). Without these we cannot verify. ---------

// Apple's App Attest Root CA, PEM, base64-encoded into one env var (so it is not
// committed to this public repo). Download from Apple's certificate authority page
// and inject at runtime. TODO(operator): supply APPLE_APP_ATTEST_ROOT_CA_PEM_B64.
const APPLE_ROOT_CA_PEM_B64 = process.env.APPLE_APP_ATTEST_ROOT_CA_PEM_B64 || '';

// The app identity the attestation must match: appID = "<TeamID>.<BundleID>".
// e.g. ABCDE12345.com.example.Lander. TODO(operator): supply both.
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID || '';
const APPLE_BUNDLE_ID = process.env.APPLE_BUNDLE_ID || '';

// Apple's production App Attest environment uses the aaguid "appattest" (dev uses
// "appattestdevelop"). Operators on TestFlight/dev builds set this to the dev value.
const EXPECTED_AAGUID = process.env.APPLE_APP_ATTEST_AAGUID || 'appattest';

// Are we fully configured to ENFORCE, or do we run as a fail-closed stub? The
// issuer logs this at startup so stub mode is never silent.
const APP_ATTEST_READY = Boolean(APPLE_ROOT_CA_PEM_B64 && APPLE_TEAM_ID && APPLE_BUNDLE_ID);

// rpId for App Attest is the appID; its SHA-256 is what the authenticator data
// binds. Computed once if we have the inputs.
function appIdHash() {
  const appId = `${APPLE_TEAM_ID}.${APPLE_BUNDLE_ID}`;
  return crypto.createHash('sha256').update(appId).digest();
}

// ---------------------------------------------------------------------------
// The individual Apple-defined checks. Each returns true ONLY when the check
// genuinely passes. Anything not yet implementable without operator input is a
// STUB that returns false (fail closed) with a precise TODO.
// ---------------------------------------------------------------------------

// CHECK 1 - Certificate chain.
// Verify the attestation statement's x5c cert chain terminates at Apple's App
// Attest Root CA, and that the leaf ("credCert") is valid (dates, signature).
//
// STUB. TODO: parse the attestation CBOR (`fmt` must be "apple-appattest",
// `attStmt.x5c` is [credCert, intermediateCert]), build an X.509 chain, and verify
// it against APPLE_ROOT_CA_PEM_B64 using e.g. node's crypto.X509Certificate +
// checkIssued, or a vetted PKI lib. Per Apple step 1-2 of "Verify the attestation".
function verifyCertChain(_attestationObj) {
  if (!APPLE_ROOT_CA_PEM_B64) return false; // no root => cannot anchor => fail closed
  // TODO(operator): implement X.509 chain validation to Apple's App Attest Root CA.
  return false;
}

// CHECK 2 - Nonce binding.
// Apple's nonce = SHA-256( authenticatorData || SHA-256(clientDataHash) ). It must
// appear in the leaf cert's Apple App Attest OID extension (1.2.840.113635.100.8.2).
// This is what binds the attestation to the exact request the device signed, so a
// captured attestation can't be replayed against a different request.
//
// STUB. TODO: extract the OID 1.2.840.113635.100.8.2 octet string from credCert,
// compute the expected nonce from authenticatorData + clientDataHash, compare.
// Per Apple step 3-4.
function verifyNonce(_authenticatorData, _clientDataHash, _credCert) {
  // TODO(operator): implement nonce extraction + comparison.
  return false;
}

// CHECK 3 - Key id binding.
// The SHA-256 of the credCert's public key must equal the keyId the device
// presented. This ties the attestation to the specific hardware key.
//
// STUB. TODO: export the credCert subject public key, SHA-256 it, compare to the
// base64url-decoded keyId. Per Apple step 5.
function verifyKeyId(_credCert, _keyId) {
  // TODO(operator): implement public-key-hash == keyId comparison.
  return false;
}

// CHECK 4 - rpId (appID) hash + aaguid + counter, in the authenticator data.
//   - authData[0..32) (rpIdHash) must equal SHA-256("<TeamID>.<BundleID>").
//   - the aaguid field must be the expected App Attest environment value.
//   - on first attestation the sign counter must be 0.
//
// STUB. TODO: parse authenticatorData (rpIdHash | flags | counter | aaguid |
// credentialIdLength | credentialId), compare rpIdHash to appIdHash(), check
// aaguid == EXPECTED_AAGUID, counter == 0. Per Apple step 6-9.
function verifyAuthenticatorData(_authenticatorData, _keyId) {
  if (!APPLE_TEAM_ID || !APPLE_BUNDLE_ID) return false; // no appID => fail closed
  // appIdHash() is the value we WOULD compare rpIdHash against once parsed.
  void appIdHash();
  void EXPECTED_AAGUID;
  // TODO(operator): implement authenticator-data parsing + comparisons.
  return false;
}

// CHECK 5 - Assertion (subsequent calls).
// After the one-time attestation, each request carries an ASSERTION: a signature
// by the attested key over SHA-256(authenticatorData || clientDataHash), plus a
// sign counter that MUST strictly increase across requests from the same key (a
// replayed or rolled-back counter is rejected). This is the per-request proof.
//
// STUB. TODO: verify the assertion signature with the stored public key for keyId,
// and enforce strictly-monotonic sign counter using a per-keyId store (the same
// shared store the quota uses). Per Apple "Assert your app's validity".
function verifyAssertion(_assertion, _clientDataHash, _storedPublicKeyForKeyId) {
  // TODO(operator): implement assertion signature + monotonic counter check.
  return false;
}

// ---------------------------------------------------------------------------
// Public entry point. Returns true ONLY if every applicable check passes. While
// the module is in stub mode (operator inputs absent) this ALWAYS returns false,
// so the issuer rejects every request - fail closed, never fake success.
// ---------------------------------------------------------------------------
async function validateAppAttest({ keyId, attestation, assertion, clientDataHash } = {}) {
  // Hard gate: refuse to even attempt verification until the operator has supplied
  // Apple's root CA and the app identity. This is the explicit, non-silent stub.
  if (!APP_ATTEST_READY) {
    return false;
  }

  // clientDataHash binds the attestation/assertion to the request the device made.
  // Required in both flows.
  if (typeof clientDataHash !== 'string' || !clientDataHash.length) return false;
  const clientDataHashBuf = Buffer.from(clientDataHash, 'base64');

  // First contact for a device: full attestation. Later: lightweight assertion.
  if (attestation) {
    const attestationObj = decodeAttestation(attestation);
    if (!attestationObj) return false;
    const { authenticatorData, credCert } = attestationObj;
    if (!verifyCertChain(attestationObj)) return false;
    if (!verifyNonce(authenticatorData, clientDataHashBuf, credCert)) return false;
    if (!verifyKeyId(credCert, keyId)) return false;
    if (!verifyAuthenticatorData(authenticatorData, keyId)) return false;
    // On success an operator implementation persists the attested public key for
    // this keyId so future assertions can be checked. (Shared store, see server.js.)
    return true;
  }

  if (assertion) {
    const storedPub = lookupAttestedKey(keyId); // STUB lookup, see below
    if (!storedPub) return false;
    if (!verifyAssertion(assertion, clientDataHashBuf, storedPub)) return false;
    return true;
  }

  // Neither attestation nor assertion present => nothing to verify => reject.
  return false;
}

// Decode the CBOR attestation object into { fmt, authenticatorData, credCert, ... }.
//
// STUB. TODO: CBOR-decode the base64 attestation (a vetted CBOR lib), pull out
// `authData` and `attStmt.x5c`. Returns null in stub mode so callers fail closed.
function decodeAttestation(_attestationB64) {
  // TODO(operator): CBOR-decode the App Attest attestation object.
  return null;
}

// Look up the previously-attested public key for a keyId (populated on the first
// successful attestation). STUB. TODO: read from the shared store (the same one
// the quota/redemption state uses). Returns null in stub mode => fail closed.
function lookupAttestedKey(_keyId) {
  // TODO(operator): read attested public key for keyId from the shared store.
  return null;
}

export {
  validateAppAttest,
  APP_ATTEST_READY,
  // Exported for tests/operators wiring real implementations in.
  appIdHash,
  verifyCertChain,
  verifyNonce,
  verifyKeyId,
  verifyAuthenticatorData,
  verifyAssertion,
};
