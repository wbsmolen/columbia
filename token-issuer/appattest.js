// Columbia - Apple App Attest validation (Attester role)
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// This module is the gate that proves an /issue request comes from a genuine,
// unmodified install of the iOS client on real Apple hardware, before the issuer
// will blind-sign any tokens. It implements the server side of Apple's
// DCAppAttestService: the one-time ATTESTATION that registers a hardware-backed
// key, and the per-request ASSERTION that proves possession of that key.
//
// Reference: Apple, "Validating Apps That Connect to Your Server through App
// Attest." App Attest reuses the WebAuthn authenticator-data layout (rpIdHash |
// flags | signCount | attestedCredentialData), with an Apple-specific
// attestation format ("apple-appattest"), an Apple anonymous attestation CA, and
// the nonce carried in the leaf cert extension OID 1.2.840.113635.100.8.2.
//
// FAIL-CLOSED BY DESIGN: every check returns/throws on anything it cannot fully
// verify, and validateAppAttest() returns { ok: false } unless EVERY applicable
// check passes. If the operator has not supplied Apple's root CA and the app
// identity (team + bundle id), the module refuses to even attempt verification.
// There is no silent-allow path anywhere.
//
// DEPENDENCY POSTURE: no new runtime dependency. CBOR decoding and the ASN.1 walk
// needed to pull one extension out of the leaf cert are done with small, bounded,
// purpose-built parsers in this file (App Attest objects use only a tiny CBOR
// subset). All cryptographic work - cert-chain signature verification, ECDSA
// assertion verification, SHA-256 - uses node's built-in `crypto` only. We do NOT
// hand-roll any crypto primitive; we only hand-roll structural parsing, which is
// the safe, dependency-light part.

import crypto from 'node:crypto';

// --- Operator-supplied inputs (env). Without these we cannot verify. ---------

// Apple's App Attest Root CA, PEM, base64-encoded into one env var (so it is not
// committed to this public repo). Download from Apple's certificate authority page
// (Apple_App_Attestation_Root_CA.pem) and inject at runtime.
const APPLE_ROOT_CA_PEM_B64 = process.env.APPLE_APP_ATTEST_ROOT_CA_PEM_B64 || '';

// The app identity the attestation must match: appID = "<TeamID>.<BundleID>".
// e.g. ABCDE12345.com.example.app
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID || '';
const APPLE_BUNDLE_ID = process.env.APPLE_BUNDLE_ID || '';

// Apple's production App Attest environment uses the aaguid "appattest" (dev uses
// "appattestdevelop"). Operators on a development/TestFlight provisioning profile
// set this to the dev value. Both are 16-byte aaguids: the ASCII bytes of the
// label, zero-padded to 16 bytes.
const EXPECTED_AAGUID_LABEL = process.env.APPLE_APP_ATTEST_AAGUID || 'appattest';

// Apple's App Attest leaf certs are short-lived but the attestation is validated
// once, immediately, at registration. We accept a small clock skew (seconds) when
// checking cert validity windows so a few seconds of issuer/Apple clock drift does
// not reject a freshly minted attestation.
const CERT_CLOCK_SKEW_MS = parseInt(process.env.APP_ATTEST_CLOCK_SKEW_MS || '300000', 10);

// Are we fully configured to ENFORCE, or do we run as a fail-closed stub? The
// issuer logs this at startup so stub mode is never silent.
const APP_ATTEST_READY = Boolean(APPLE_ROOT_CA_PEM_B64 && APPLE_TEAM_ID && APPLE_BUNDLE_ID);

// Apple's App Attest credCert carries the nonce in this private extension OID.
const APPLE_NONCE_OID = '1.2.840.113635.100.8.2';

// rpId for App Attest is the appID; its SHA-256 is what the authenticator data
// binds. Computed once if we have the inputs.
function appId() {
  return `${APPLE_TEAM_ID}.${APPLE_BUNDLE_ID}`;
}
function appIdHash() {
  return crypto.createHash('sha256').update(appId(), 'utf8').digest();
}

// The expected 16-byte aaguid: ASCII label, zero-padded to 16 bytes.
function expectedAaguid() {
  const out = Buffer.alloc(16);
  Buffer.from(EXPECTED_AAGUID_LABEL, 'ascii').copy(out, 0, 0, 16);
  return out;
}

function sha256(...bufs) {
  const h = crypto.createHash('sha256');
  for (const b of bufs) h.update(b);
  return h.digest();
}

// ---------------------------------------------------------------------------
// Minimal CBOR decoder. App Attest attestation objects and assertions use only:
//   - unsigned ints (major 0), negative ints (major 1, for COSE map keys),
//   - byte strings (major 2), text strings (major 3),
//   - arrays (major 4), maps (major 5).
// We deliberately do NOT support tags, floats, indefinite-length, or anything
// else; encountering them throws, which fails the validation closed. Lengths are
// bounded by the caller's MAX_BODY, so there is no unbounded allocation here.
// ---------------------------------------------------------------------------

function cborDecodeFirst(buf) {
  const st = { buf, pos: 0 };
  const value = cborReadItem(st, 0);
  return { value, end: st.pos };
}

const CBOR_MAX_DEPTH = 16;

function cborReadItem(st, depth) {
  if (depth > CBOR_MAX_DEPTH) throw new Error('cbor: max depth exceeded');
  if (st.pos >= st.buf.length) throw new Error('cbor: truncated');
  const ib = st.buf[st.pos++];
  const major = ib >> 5;
  const minor = ib & 0x1f;
  const len = cborReadLength(st, minor);
  switch (major) {
    case 0: // unsigned int
      return len;
    case 1: // negative int: -1 - len
      return -1 - Number(len);
    case 2: { // byte string
      const n = Number(len);
      if (st.pos + n > st.buf.length) throw new Error('cbor: byte string overruns');
      const out = st.buf.subarray(st.pos, st.pos + n);
      st.pos += n;
      return Buffer.from(out);
    }
    case 3: { // text string
      const n = Number(len);
      if (st.pos + n > st.buf.length) throw new Error('cbor: text string overruns');
      const out = st.buf.toString('utf8', st.pos, st.pos + n);
      st.pos += n;
      return out;
    }
    case 4: { // array
      const n = Number(len);
      const arr = new Array(n);
      for (let i = 0; i < n; i++) arr[i] = cborReadItem(st, depth + 1);
      return arr;
    }
    case 5: { // map
      const n = Number(len);
      const m = new Map();
      for (let i = 0; i < n; i++) {
        const k = cborReadItem(st, depth + 1);
        const v = cborReadItem(st, depth + 1);
        m.set(k, v);
      }
      return m;
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

function cborReadLength(st, minor) {
  if (minor < 24) return minor;
  if (minor === 24) { // 1 byte
    if (st.pos + 1 > st.buf.length) throw new Error('cbor: truncated len8');
    return st.buf[st.pos++];
  }
  if (minor === 25) { // 2 bytes
    if (st.pos + 2 > st.buf.length) throw new Error('cbor: truncated len16');
    const v = st.buf.readUInt16BE(st.pos); st.pos += 2; return v;
  }
  if (minor === 26) { // 4 bytes
    if (st.pos + 4 > st.buf.length) throw new Error('cbor: truncated len32');
    const v = st.buf.readUInt32BE(st.pos); st.pos += 4; return v;
  }
  if (minor === 27) { // 8 bytes
    if (st.pos + 8 > st.buf.length) throw new Error('cbor: truncated len64');
    const hi = st.buf.readUInt32BE(st.pos);
    const lo = st.buf.readUInt32BE(st.pos + 4);
    st.pos += 8;
    // App Attest never legitimately uses 8-byte lengths; reject anything that
    // would not fit safely in a JS number rather than silently truncate.
    if (hi !== 0) throw new Error('cbor: length too large');
    return lo;
  }
  throw new Error('cbor: indefinite or reserved length not supported');
}

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER walk - just enough to extract one extension's OCTET STRING by
// OID from an X.509 certificate. We do NOT build a general ASN.1 parser; we walk
// the TLV tree to find the matching extension. crypto.X509Certificate on node 20
// does not expose arbitrary extensions, so this fills that one gap.
// ---------------------------------------------------------------------------

// Read one DER TLV at offset. Returns { tag, len, headerLen, contentStart }.
function derReadTLV(buf, off) {
  if (off + 1 > buf.length) throw new Error('der: truncated tag');
  const tag = buf[off];
  let p = off + 1;
  if (p >= buf.length) throw new Error('der: truncated length');
  let len = buf[p++];
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    if (nBytes === 0 || nBytes > 4) throw new Error('der: bad long-form length');
    if (p + nBytes > buf.length) throw new Error('der: truncated long length');
    len = 0;
    for (let i = 0; i < nBytes; i++) len = (len << 8) | buf[p++];
  }
  const contentStart = p;
  if (contentStart + len > buf.length) throw new Error('der: content overruns');
  return { tag, len, headerLen: contentStart - off, contentStart };
}

// Encode an OID dotted string into its DER content bytes (no tag/length), so we
// can compare against the encoded OID inside the cert without an ASN.1 library.
function encodeOid(dotted) {
  const parts = dotted.split('.').map((x) => parseInt(x, 10));
  if (parts.length < 2) throw new Error('oid: too short');
  const bytes = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [v & 0x7f];
    v >>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>= 7; }
    for (const b of stack) bytes.push(b);
  }
  return Buffer.from(bytes);
}

// Recursively scan the DER tree for an Extension SEQUENCE whose first element is
// an OID equal to `oidBytes`, and return the bytes of its extnValue OCTET STRING.
// An X.509 Extension is: SEQUENCE { OID, [BOOLEAN critical], OCTET STRING value }.
function findExtensionValue(certDer, oidDotted) {
  const oidBytes = encodeOid(oidDotted);
  const found = { value: null };

  function walk(buf, start, end, depth) {
    if (depth > 24 || found.value) return;
    let off = start;
    while (off < end && !found.value) {
      let tlv;
      try { tlv = derReadTLV(buf, off); } catch { return; }
      const tag = tlv.tag;
      const cStart = tlv.contentStart;
      const cEnd = cStart + tlv.len;

      // Is THIS a SEQUENCE that begins with our target OID? (An Extension.)
      if (tag === 0x30) {
        try {
          const inner = derReadTLV(buf, cStart);
          if (inner.tag === 0x06 && inner.len === oidBytes.length &&
              buf.subarray(inner.contentStart, inner.contentStart + inner.len).equals(oidBytes)) {
            // Walk siblings to find the OCTET STRING (skip an optional BOOLEAN).
            let sib = inner.contentStart + inner.len;
            while (sib < cEnd) {
              const s = derReadTLV(buf, sib);
              if (s.tag === 0x04) { // OCTET STRING = extnValue
                found.value = Buffer.from(buf.subarray(s.contentStart, s.contentStart + s.len));
                return;
              }
              sib = s.contentStart + s.len;
            }
          }
        } catch { /* not a matching extension; fall through to recurse */ }
      }

      // Recurse into constructed types (high bit 0x20 of the tag), and into the
      // context-tagged [3] explicit wrapper that holds X.509 v3 extensions.
      const constructed = (tag & 0x20) !== 0;
      if (constructed) walk(buf, cStart, cEnd, depth + 1);

      off = cEnd;
    }
  }

  walk(certDer, 0, certDer.length, 0);
  return found.value;
}

// The Apple nonce extension's extnValue is itself DER: an OCTET STRING wrapping
// SEQUENCE { [1] EXPLICIT OCTET STRING nonce }. Parse out the 32-byte nonce.
function parseAppleNonce(extnValueDer) {
  // extnValue content is a SEQUENCE.
  const seq = derReadTLV(extnValueDer, 0);
  if (seq.tag !== 0x30) throw new Error('nonce: outer not SEQUENCE');
  // First (and only) element is context-tag [1] constructed (0xA1).
  const ctx = derReadTLV(extnValueDer, seq.contentStart);
  if (ctx.tag !== 0xa1) throw new Error('nonce: expected [1] context tag');
  // Inside is an OCTET STRING with the 32-byte nonce.
  const oct = derReadTLV(extnValueDer, ctx.contentStart);
  if (oct.tag !== 0x04) throw new Error('nonce: inner not OCTET STRING');
  if (oct.len !== 32) throw new Error('nonce: not 32 bytes');
  return Buffer.from(extnValueDer.subarray(oct.contentStart, oct.contentStart + oct.len));
}

// ---------------------------------------------------------------------------
// authenticatorData parsing.
//   rpIdHash:  32 bytes
//   flags:      1 byte   (bit 6 = AT, attestedCredentialData present)
//   signCount:  4 bytes  big-endian
//   [attestedCredentialData, present iff AT flag]:
//      aaguid:           16 bytes
//      credIdLen:         2 bytes big-endian
//      credentialId:      credIdLen bytes  (App Attest: the keyId)
//      credentialPubKey:  COSE_Key (CBOR map) - the attested EC P-256 key
// ---------------------------------------------------------------------------

function parseAuthenticatorData(authData) {
  if (!Buffer.isBuffer(authData) || authData.length < 37) {
    throw new Error('authData: too short');
  }
  const rpIdHash = authData.subarray(0, 32);
  const flags = authData[32];
  const signCount = authData.readUInt32BE(33);
  const out = { rpIdHash: Buffer.from(rpIdHash), flags, signCount };

  const atPresent = (flags & 0x40) !== 0; // bit 6
  if (atPresent) {
    let off = 37;
    if (off + 18 > authData.length) throw new Error('authData: attestedCredentialData truncated');
    const aaguid = authData.subarray(off, off + 16); off += 16;
    const credIdLen = authData.readUInt16BE(off); off += 2;
    if (off + credIdLen > authData.length) throw new Error('authData: credentialId truncated');
    const credentialId = authData.subarray(off, off + credIdLen); off += credIdLen;
    // The remaining bytes are the COSE_Key for the credential public key.
    const { value: coseKey } = cborDecodeFirst(Buffer.from(authData.subarray(off)));
    out.aaguid = Buffer.from(aaguid);
    out.credentialId = Buffer.from(credentialId);
    out.credentialPublicKey = coseKeyToEcPublicKey(coseKey);
    out.credentialPublicKeyRawPoint = out.credentialPublicKey.rawPoint;
  }
  return out;
}

// Convert a COSE_Key (CBOR map) for an EC2 / P-256 / ES256 public key into a node
// KeyObject plus its uncompressed X9.62 point (0x04 || X || Y), which is the value
// App Attest hashes to produce the keyId.
function coseKeyToEcPublicKey(coseKey) {
  if (!(coseKey instanceof Map)) throw new Error('cose: not a map');
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);
  const crv = coseKey.get(-1);
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  if (kty !== 2) throw new Error('cose: kty must be EC2');
  if (alg !== -7) throw new Error('cose: alg must be ES256');
  if (crv !== 1) throw new Error('cose: crv must be P-256');
  if (!Buffer.isBuffer(x) || x.length !== 32) throw new Error('cose: bad x');
  if (!Buffer.isBuffer(y) || y.length !== 32) throw new Error('cose: bad y');
  const rawPoint = Buffer.concat([Buffer.from([0x04]), x, y]);
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: x.toString('base64url'),
    y: y.toString('base64url'),
  };
  const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return { keyObject, rawPoint };
}

// ---------------------------------------------------------------------------
// The individual Apple-defined checks. Each throws on failure (caught by the
// caller, which then returns ok:false), so a check never quietly "passes."
// ---------------------------------------------------------------------------

// CHECK 1 - Certificate chain. Verify x5c terminates at Apple's App Attest Root
// CA: each cert is signed by the next, the top is signed by (or equals an
// intermediate signed by) the pinned root, and every cert is within its validity
// window. Returns the leaf (credCert) X509Certificate.
function verifyCertChain(x5c, now = Date.now()) {
  if (!APPLE_ROOT_CA_PEM_B64) throw new Error('chain: no root CA configured');
  if (!Array.isArray(x5c) || x5c.length < 1) throw new Error('chain: empty x5c');

  const rootPem = Buffer.from(APPLE_ROOT_CA_PEM_B64, 'base64').toString('utf8');
  const root = new crypto.X509Certificate(rootPem);

  const certs = x5c.map((der) => {
    if (!Buffer.isBuffer(der)) throw new Error('chain: x5c entry not bytes');
    return new crypto.X509Certificate(der);
  });

  // Validity windows (with a small skew tolerance).
  for (const c of [...certs, root]) {
    const notBefore = new Date(c.validFrom).getTime();
    const notAfter = new Date(c.validTo).getTime();
    if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) throw new Error('chain: bad validity dates');
    if (now < notBefore - CERT_CLOCK_SKEW_MS) throw new Error('chain: cert not yet valid');
    if (now > notAfter + CERT_CLOCK_SKEW_MS) throw new Error('chain: cert expired');
  }

  // Build the full chain to anchor: [leaf, ...intermediates, root].
  const chain = [...certs, root];
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i];
    const issuer = chain[i + 1];
    // checkIssued confirms the issuer/subject name relationship.
    if (!child.checkIssued(issuer)) throw new Error(`chain: cert ${i} not issued by next`);
    // verify() confirms the cryptographic signature with the issuer's public key.
    if (!child.verify(issuer.publicKey)) throw new Error(`chain: cert ${i} signature invalid`);
  }
  // The root must be self-signed and be the pinned Apple root (identity by its raw
  // DER: we constructed `root` from the pinned PEM, so anchoring to it IS the pin).
  if (!root.verify(root.publicKey)) throw new Error('chain: root not self-signed');

  return certs[0]; // credCert / leaf
}

// CHECK 2 - Nonce binding. nonce = SHA-256(authData || clientDataHash). It must
// equal the 32-byte value in the credCert's Apple OID extension. This binds the
// attestation to the exact challenge the issuer gave the device.
//
// This runs ONLY after CHECK 1 has proven credCert is signed by Apple, so the
// extension contents are authentic and cannot be forged or duplicated by an
// attacker: the first-match search in findExtensionValue is safe because an
// attacker cannot mint or alter extensions on an Apple-signed leaf.
function verifyNonce(authData, clientDataHash, credCert) {
  const expected = sha256(authData, clientDataHash);
  const extnValue = findExtensionValue(Buffer.from(credCert.raw), APPLE_NONCE_OID);
  if (!extnValue) throw new Error('nonce: extension missing');
  const actual = parseAppleNonce(extnValue);
  if (!crypto.timingSafeEqual(expected, actual)) throw new Error('nonce: mismatch');
  return true;
}

// CHECK 3 - Key id binding. keyId = SHA-256(uncompressed EC public key point) of
// the credCert key MUST equal the keyId the device presented (and the credentialId
// inside authData). This ties the attestation to the specific hardware key.
function verifyKeyId(credCert, presentedKeyId, credentialPublicKeyRawPoint, credentialId) {
  // Extract the leaf cert's public key as an uncompressed P-256 point.
  const certJwk = credCert.publicKey.export({ format: 'jwk' });
  if (certJwk.kty !== 'EC' || certJwk.crv !== 'P-256') throw new Error('keyId: leaf key not P-256');
  const certPoint = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(certJwk.x, 'base64url'),
    Buffer.from(certJwk.y, 'base64url'),
  ]);
  // The credential public key in authData must be the SAME key as the cert's.
  if (!certPoint.equals(credentialPublicKeyRawPoint)) {
    throw new Error('keyId: cert key != authData credential key');
  }
  const computed = sha256(certPoint);

  // presentedKeyId is base64url (App Attest keyId is base64-encoded SHA-256).
  const presented = decodeKeyId(presentedKeyId);
  if (presented.length !== 32 || !crypto.timingSafeEqual(computed, presented)) {
    throw new Error('keyId: presented keyId != SHA256(pubkey)');
  }
  // The credentialId inside authData is the same keyId.
  if (!Buffer.isBuffer(credentialId) || credentialId.length !== 32 ||
      !crypto.timingSafeEqual(computed, credentialId)) {
    throw new Error('keyId: credentialId != SHA256(pubkey)');
  }
  return computed; // the canonical keyId (raw 32 bytes)
}

// Accept the keyId in base64 or base64url; both decode to the same 32 bytes.
function decodeKeyId(keyId) {
  if (typeof keyId !== 'string' || keyId.length === 0) throw new Error('keyId: missing');
  const b = Buffer.from(keyId, 'base64'); // base64 decode also tolerates base64url chars in node
  return b;
}

// CHECK 4 - authenticator data: rpIdHash, aaguid, and first-attestation counter.
function verifyAttestationAuthData(parsed) {
  if (!crypto.timingSafeEqual(parsed.rpIdHash, appIdHash())) {
    throw new Error('authData: rpIdHash != SHA256(appID)');
  }
  if ((parsed.flags & 0x40) === 0) throw new Error('authData: AT flag not set');
  if (!parsed.aaguid || !parsed.aaguid.equals(expectedAaguid())) {
    throw new Error('authData: aaguid mismatch');
  }
  if (parsed.signCount !== 0) throw new Error('authData: first attestation signCount must be 0');
  return true;
}

// CHECK 5 - Assertion (subsequent calls). Verify the ECDSA-P256-SHA256 signature
// by the attested key over SHA-256(authenticatorData || clientDataHash), the
// rpIdHash, and a strictly increasing sign counter. Returns the new sign counter
// so the caller can persist it.
function verifyAssertion(assertionBuf, clientDataHash, storedPublicKeyObject, storedCounter) {
  const { value: assertion } = cborDecodeFirst(assertionBuf);
  if (!(assertion instanceof Map)) throw new Error('assertion: not a CBOR map');
  const signature = assertion.get('signature');
  const authData = assertion.get('authenticatorData');
  if (!Buffer.isBuffer(signature) || !Buffer.isBuffer(authData)) {
    throw new Error('assertion: missing signature/authenticatorData');
  }

  // The signed bytes: SHA-256(authData || SHA-256(challenge)).
  const nonce = sha256(authData, clientDataHash);

  // ECDSA over SHA-256; the signature is DER-encoded (X9.62). node verifies DER
  // by default for createVerify('SHA256') on an EC key.
  const ok = crypto.verify('sha256', nonce, storedPublicKeyObject, signature);
  if (!ok) throw new Error('assertion: bad signature');

  const parsed = parseAuthenticatorData(authData);
  if (!crypto.timingSafeEqual(parsed.rpIdHash, appIdHash())) {
    throw new Error('assertion: rpIdHash != SHA256(appID)');
  }
  // Strictly increasing counter: a replayed or rolled-back counter is rejected.
  if (!(parsed.signCount > storedCounter)) {
    throw new Error('assertion: signCount not strictly increasing');
  }
  return parsed.signCount;
}

// ---------------------------------------------------------------------------
// CBOR attestation object decode -> { fmt, x5c, authData }.
// ---------------------------------------------------------------------------
function decodeAttestation(attestationBuf) {
  const { value } = cborDecodeFirst(attestationBuf);
  if (!(value instanceof Map)) throw new Error('attestation: not a CBOR map');
  const fmt = value.get('fmt');
  const attStmt = value.get('attStmt');
  const authData = value.get('authData');
  if (fmt !== 'apple-appattest') throw new Error('attestation: fmt must be apple-appattest');
  if (!(attStmt instanceof Map)) throw new Error('attestation: attStmt missing');
  const x5c = attStmt.get('x5c');
  if (!Array.isArray(x5c) || x5c.length < 1) throw new Error('attestation: x5c missing');
  if (!Buffer.isBuffer(authData)) throw new Error('attestation: authData missing');
  return { fmt, x5c, authData };
}

// ---------------------------------------------------------------------------
// Public entry point.
//
// ATTESTATION (one-time registration): pass { keyId, attestation, clientDataHash }.
//   On success returns { ok: true, mode: 'attestation', keyId (base64),
//   publicKeyPem, signCount } so the caller persists the device public key keyed
//   by keyId for future assertions.
//
// ASSERTION (per issuance): pass { keyId, assertion, clientDataHash } and a
//   `store` with getAttestedKey(keyId) / setSignCount(keyId, n). On success
//   returns { ok: true, mode: 'assertion', signCount }.
//
// Returns { ok: false, reason } on any failure. While the module is unconfigured
// (operator inputs absent) this ALWAYS returns { ok: false } - fail closed.
// ---------------------------------------------------------------------------
async function validateAppAttest({ keyId, attestation, assertion, clientDataHash, store } = {}) {
  if (!APP_ATTEST_READY) {
    return { ok: false, reason: 'app_attest_not_configured' };
  }
  if (typeof clientDataHash !== 'string' || !clientDataHash.length) {
    return { ok: false, reason: 'missing_client_data_hash' };
  }
  let clientDataHashBuf;
  try {
    clientDataHashBuf = Buffer.from(clientDataHash, 'base64');
    if (clientDataHashBuf.length !== 32) {
      return { ok: false, reason: 'client_data_hash_not_32_bytes' };
    }
  } catch {
    return { ok: false, reason: 'bad_client_data_hash' };
  }

  try {
    // First contact for a device: full attestation.
    if (attestation) {
      const attestationBuf = Buffer.from(attestation, 'base64');
      const { x5c, authData } = decodeAttestation(attestationBuf);

      const credCert = verifyCertChain(x5c);                        // CHECK 1
      verifyNonce(authData, clientDataHashBuf, credCert);           // CHECK 2
      const parsed = parseAuthenticatorData(authData);
      const canonicalKeyId = verifyKeyId(                           // CHECK 3
        credCert,
        keyId,
        parsed.credentialPublicKeyRawPoint,
        parsed.credentialId,
      );
      verifyAttestationAuthData(parsed);                            // CHECK 4

      // Hand back the attested public key so the caller can store it keyed by
      // keyId. We return a PEM (SPKI) so the store is a plain serializable string.
      const publicKeyPem = parsed.credentialPublicKey.keyObject.export({
        type: 'spki',
        format: 'pem',
      });
      const keyIdB64 = canonicalKeyId.toString('base64');

      // Cross-check the canonical keyId equals the one presented (already enforced
      // in CHECK 3, but make the returned identity unambiguous).
      return {
        ok: true,
        mode: 'attestation',
        keyId: keyIdB64,
        publicKeyPem,
        signCount: parsed.signCount, // 0
      };
    }

    // Subsequent calls: lightweight assertion against the stored key.
    if (assertion) {
      if (!store || typeof store.getAttestedKey !== 'function' ||
          typeof store.setSignCount !== 'function') {
        return { ok: false, reason: 'no_attested_key_store' };
      }
      // Normalize the keyId the SAME way the attestation path stored it (canonical
      // base64), so a base64 vs base64url spelling difference between the
      // registration and a later assertion can't cause a spurious store miss.
      const storeKeyId = decodeKeyId(keyId).toString('base64');
      const record = store.getAttestedKey(storeKeyId);
      if (!record || !record.publicKeyPem) {
        return { ok: false, reason: 'unknown_device_key' };
      }
      const pub = crypto.createPublicKey({ key: record.publicKeyPem, format: 'pem' });
      const assertionBuf = Buffer.from(assertion, 'base64');
      const newCount = verifyAssertion(                            // CHECK 5
        assertionBuf,
        clientDataHashBuf,
        pub,
        record.signCount || 0,
      );
      store.setSignCount(storeKeyId, newCount);
      return { ok: true, mode: 'assertion', signCount: newCount };
    }

    return { ok: false, reason: 'no_attestation_or_assertion' };
  } catch (err) {
    // Any thrown check fails the whole validation closed. We deliberately surface
    // only a coarse reason string, never the attestation/assertion bytes.
    return { ok: false, reason: 'verification_failed', detail: err && err.message };
  }
}

export {
  validateAppAttest,
  APP_ATTEST_READY,
  // Exported for tests / operators wiring real implementations in.
  appId,
  appIdHash,
  expectedAaguid,
  verifyCertChain,
  verifyNonce,
  verifyKeyId,
  verifyAttestationAuthData,
  verifyAssertion,
  parseAuthenticatorData,
  decodeAttestation,
  cborDecodeFirst,
  findExtensionValue,
  parseAppleNonce,
  encodeOid,
};
