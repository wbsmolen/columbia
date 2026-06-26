// Columbia - synthetic App Attest fixtures for tests.
//
// We have NO real device attestation in CI, and node has no built-in X.509
// builder, and the deploy image (node:20-alpine) ships no openssl CLI. So to prove
// the validator ACCEPTS a well-formed attestation - and REJECTS each tampered
// variant - we mint a synthetic trust chain and a hand-built attestation object in
// pure JavaScript here:
//
//   * a self-signed P-256 "root" CA (stands in for Apple's App Attest Root CA),
//   * a P-256 leaf "credCert" signed by that root, carrying the Apple nonce
//     extension (OID 1.2.840.113635.100.8.2),
//   * a WebAuthn-style authenticatorData with the attested EC credential key,
//   * the CBOR attestation object Apple's fmt "apple-appattest" produces.
//
// The validator under test does not know these are synthetic: it does the exact
// same chain/nonce/keyId/rpIdHash/aaguid checks it would do on a real Apple
// attestation. The ONLY substitution is the trust anchor (our root instead of
// Apple's), injected via APPLE_APP_ATTEST_ROOT_CA_PEM_B64 - which is exactly the
// operator-supplied pin in production. This is the strongest test possible without
// a physical device; a real-device fixture is still required (see PR notes).
//
// This file is a TEST helper only. It is not imported by server.js and is not
// copied into the Docker image.

import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Minimal DER encoders (just what an X.509 cert needs).
// ---------------------------------------------------------------------------

function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

function derSeq(...items) { return tlv(0x30, Buffer.concat(items)); }
function derSet(...items) { return tlv(0x31, Buffer.concat(items)); }
function derOctetString(buf) { return tlv(0x04, buf); }
function derBoolean(b) { return tlv(0x01, Buffer.from([b ? 0xff : 0x00])); }
function derContext(tagNum, constructed, content) {
  const tag = 0x80 | (constructed ? 0x20 : 0x00) | tagNum;
  return tlv(tag, content);
}

function derInteger(value) {
  // small non-negative integer (serial)
  let bytes = [];
  let v = value;
  if (v === 0) bytes = [0];
  else { while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); } }
  if (bytes[0] & 0x80) bytes.unshift(0x00); // keep positive
  return tlv(0x02, Buffer.from(bytes));
}

function derOid(dotted) {
  const parts = dotted.split('.').map((x) => parseInt(x, 10));
  const bytes = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [v & 0x7f];
    v >>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>= 7; }
    for (const b of stack) bytes.push(b);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function derUtcTime(date) {
  // YYMMDDHHMMSSZ
  const p = (n) => String(n).padStart(2, '0');
  const s = p(date.getUTCFullYear() % 100) + p(date.getUTCMonth() + 1) + p(date.getUTCDate()) +
            p(date.getUTCHours()) + p(date.getUTCMinutes()) + p(date.getUTCSeconds()) + 'Z';
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

// A minimal RDN: CN=<commonName>.
function derName(commonName) {
  const cnOid = derOid('2.5.4.3'); // commonName
  const cnVal = tlv(0x0c, Buffer.from(commonName, 'utf8')); // UTF8String
  return derSeq(derSet(derSeq(cnOid, cnVal)));
}

// ecdsa-with-SHA256 AlgorithmIdentifier: SEQUENCE { OID 1.2.840.10045.4.3.2 }.
function ecdsaWithSha256AlgId() {
  return derSeq(derOid('1.2.840.10045.4.3.2'));
}

// SubjectPublicKeyInfo for an EC P-256 public key, from a node KeyObject.
function spkiFromKey(publicKey) {
  // node exports SPKI DER directly; reuse it verbatim.
  return publicKey.export({ type: 'spki', format: 'der' });
}

// The Apple nonce extension: extnValue OCTET STRING wraps
//   SEQUENCE { [1] EXPLICIT OCTET STRING nonce }.
function appleNonceExtension(nonce32) {
  const inner = derSeq(derContext(1, true, derOctetString(nonce32)));
  return derSeq(
    derOid('1.2.840.113635.100.8.2'),
    derOctetString(inner), // extnValue
  );
}

// ---------------------------------------------------------------------------
// Cert builder. Builds a TBSCertificate, signs it with the issuer key (ECDSA
// P-256 / SHA-256), and assembles the full Certificate. Returns DER bytes.
// ---------------------------------------------------------------------------

function buildCert({ subjectCN, issuerCN, subjectKey, issuerKey, serial, extensions = [], notBefore, notAfter }) {
  const nb = notBefore || new Date(Date.now() - 3600 * 1000);
  const na = notAfter || new Date(Date.now() + 24 * 3600 * 1000);

  const version = derContext(0, true, derInteger(2)); // v3
  const tbsPieces = [
    version,
    derInteger(serial),
    ecdsaWithSha256AlgId(),
    derName(issuerCN),
    derSeq(derUtcTime(nb), derUtcTime(na)),
    derName(subjectCN),
    spkiFromKey(subjectKey),
  ];
  if (extensions.length) {
    tbsPieces.push(derContext(3, true, derSeq(...extensions))); // [3] EXPLICIT Extensions
  }
  const tbs = derSeq(...tbsPieces);

  // Sign the TBSCertificate. node emits a DER ECDSA signature, which is exactly
  // the BIT STRING content X.509 wants.
  const sig = crypto.sign('sha256', tbs, issuerKey);
  const sigBitString = tlv(0x03, Buffer.concat([Buffer.from([0x00]), sig])); // BIT STRING, 0 unused bits

  return derSeq(tbs, ecdsaWithSha256AlgId(), sigBitString);
}

function newP256() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function pemCert(der) {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

function uncompressedPoint(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

// ---------------------------------------------------------------------------
// CBOR encoders (the small subset App Attest uses).
// ---------------------------------------------------------------------------

function cborUint(n) {
  if (n < 24) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x18, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = 0x19; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = 0x1a; b.writeUInt32BE(n, 1); return b;
}
function cborNegInt(n) {
  // n is negative; encode major type 1 with value (-1 - n)
  const m = -1 - n;
  const u = cborUint(m);
  u[0] = (u[0] & 0x1f) | 0x20;
  return u;
}
function cborBytes(buf) {
  const head = cborUint(buf.length); head[0] = (head[0] & 0x1f) | 0x40;
  return Buffer.concat([head, buf]);
}
function cborText(str) {
  const b = Buffer.from(str, 'utf8');
  const head = cborUint(b.length); head[0] = (head[0] & 0x1f) | 0x60;
  return Buffer.concat([head, b]);
}
function cborArray(items) {
  const head = cborUint(items.length); head[0] = (head[0] & 0x1f) | 0x80;
  return Buffer.concat([head, ...items]);
}
// map from an ordered list of [keyBuf, valBuf] pairs
function cborMap(pairs) {
  const head = cborUint(pairs.length); head[0] = (head[0] & 0x1f) | 0xa0;
  return Buffer.concat([head, ...pairs.flatMap(([k, v]) => [k, v])]);
}

// COSE_Key for an EC2 P-256 ES256 public key.
function coseKeyFor(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  // Ordered: 1:2 (kty EC2), 3:-7 (ES256), -1:1 (P-256), -2:x, -3:y
  return cborMap([
    [cborUint(1), cborUint(2)],
    [cborUint(3), cborNegInt(-7)],
    [cborNegInt(-1), cborUint(1)],
    [cborNegInt(-2), cborBytes(x)],
    [cborNegInt(-3), cborBytes(y)],
  ]);
}

// ---------------------------------------------------------------------------
// authenticatorData builders.
// ---------------------------------------------------------------------------

function aaguidBuf(label) {
  const out = Buffer.alloc(16);
  Buffer.from(label, 'ascii').copy(out, 0, 0, 16);
  return out;
}

// Attestation authData: rpIdHash | flags(AT) | signCount(0) | aaguid | credIdLen |
// credentialId | COSE_Key.
function buildAttestationAuthData({ rpIdHash, aaguidLabel, credentialId, credentialKey, signCount = 0, flags = 0x40 }) {
  const head = Buffer.alloc(37);
  rpIdHash.copy(head, 0);
  head[32] = flags;
  head.writeUInt32BE(signCount, 33);
  const aaguid = aaguidBuf(aaguidLabel);
  const credIdLen = Buffer.alloc(2); credIdLen.writeUInt16BE(credentialId.length, 0);
  const cose = coseKeyFor(credentialKey);
  return Buffer.concat([head, aaguid, credIdLen, credentialId, cose]);
}

// Assertion authData: rpIdHash | flags | signCount  (no attestedCredentialData).
function buildAssertionAuthData({ rpIdHash, signCount, flags = 0x00 }) {
  const b = Buffer.alloc(37);
  rpIdHash.copy(b, 0);
  b[32] = flags;
  b.writeUInt32BE(signCount, 33);
  return b;
}

// ---------------------------------------------------------------------------
// Top-level fixture: a complete, valid synthetic attestation for a given appID,
// aaguid label, and a 32-byte challenge. Returns everything the tests need plus
// the building blocks so a test can tamper one field and rebuild.
// ---------------------------------------------------------------------------

function makeAttestationFixture({ appId, aaguidLabel = 'appattest', challenge }) {
  const rpIdHash = crypto.createHash('sha256').update(appId, 'utf8').digest();
  const clientDataHash = crypto.createHash('sha256').update(challenge).digest();

  // Device credential key (the hardware key App Attest would create).
  const credKey = newP256();
  const credPoint = uncompressedPoint(credKey.publicKey);
  const keyIdRaw = crypto.createHash('sha256').update(credPoint).digest(); // == credentialId
  const credentialId = keyIdRaw;

  // Root CA (stands in for Apple's App Attest Root CA).
  const rootKey = newP256();
  const rootDer = buildCert({
    subjectCN: 'Columbia Test App Attest Root CA',
    issuerCN: 'Columbia Test App Attest Root CA',
    subjectKey: rootKey.publicKey,
    issuerKey: rootKey.privateKey,
    serial: 1,
  });

  // Intermediate CA, signed by the root. Real Apple x5c carries the leaf AND an
  // intermediate ("Apple App Attestation CA 1"); modelling two certs exercises the
  // multi-hop chain walk, not just a single leaf-under-root link.
  const interKey = newP256();
  const interDer = buildCert({
    subjectCN: 'Columbia Test App Attestation CA 1',
    issuerCN: 'Columbia Test App Attest Root CA',
    subjectKey: interKey.publicKey,
    issuerKey: rootKey.privateKey,
    serial: 100,
  });

  // authData first (the nonce is computed over it).
  const authData = buildAttestationAuthData({ rpIdHash, aaguidLabel, credentialId, credentialKey: credKey.publicKey });

  // nonce = SHA-256(authData || clientDataHash), placed in the leaf cert extension.
  const nonce = crypto.createHash('sha256').update(authData).update(clientDataHash).digest();

  // Leaf credCert: subject key = the SAME device credential key; signed by the
  // INTERMEDIATE (as Apple's credCert is signed by the App Attestation CA, not the
  // root directly).
  const leafDer = buildCert({
    subjectCN: 'Columbia Test App Attest Credential',
    issuerCN: 'Columbia Test App Attestation CA 1',
    subjectKey: credKey.publicKey,
    issuerKey: interKey.privateKey,
    serial: 2,
    extensions: [appleNonceExtension(nonce)],
  });

  // CBOR attestation object: { fmt, attStmt:{ x5c:[leaf, intermediate] }, authData }.
  // Apple orders x5c leaf-first, intermediate-second; the root is the operator's pin.
  const attObj = cborMap([
    [cborText('fmt'), cborText('apple-appattest')],
    [cborText('attStmt'), cborMap([
      [cborText('x5c'), cborArray([cborBytes(leafDer), cborBytes(interDer)])],
    ])],
    [cborText('authData'), cborBytes(authData)],
  ]);

  return {
    appId,
    challenge,
    clientDataHashB64: clientDataHash.toString('base64'),
    keyIdB64: keyIdRaw.toString('base64'),
    keyIdRaw,
    rootPemB64: Buffer.from(pemCert(rootDer)).toString('base64'),
    attestationB64: attObj.toString('base64'),
    // Building blocks for negative tests:
    rootKey, interKey, credKey, credentialId, rpIdHash, authData, nonce,
    leafDer, interDer, rootDer, aaguidLabel,
    // re-exported encoders/builders so tests can rebuild a tampered variant:
    helpers: {
      buildCert, appleNonceExtension, buildAttestationAuthData, buildAssertionAuthData,
      cborMap, cborArray, cborBytes, cborText, pemCert, uncompressedPoint, aaguidBuf,
    },
  };
}

// Build a valid assertion for a registered key: signs SHA-256(authData ||
// clientDataHash) with the device key, with a chosen signCount.
function makeAssertion({ appId, credPrivateKey, signCount, challenge }) {
  const rpIdHash = crypto.createHash('sha256').update(appId, 'utf8').digest();
  const clientDataHash = crypto.createHash('sha256').update(challenge).digest();
  const authData = buildAssertionAuthData({ rpIdHash, signCount });
  const nonce = crypto.createHash('sha256').update(authData).update(clientDataHash).digest();
  const signature = crypto.sign('sha256', nonce, credPrivateKey); // DER ECDSA
  const assertionObj = cborMap([
    [cborText('signature'), cborBytes(signature)],
    [cborText('authenticatorData'), cborBytes(authData)],
  ]);
  return {
    assertionB64: assertionObj.toString('base64'),
    clientDataHashB64: clientDataHash.toString('base64'),
    authData,
  };
}

export {
  makeAttestationFixture,
  makeAssertion,
  buildCert,
  newP256,
  pemCert,
  uncompressedPoint,
  appleNonceExtension,
  buildAttestationAuthData,
  buildAssertionAuthData,
  coseKeyFor,
  cborMap, cborArray, cborBytes, cborText, cborUint, cborNegInt,
  aaguidBuf,
};
