// Columbia issuer key selection. Private material is supplied by the operator.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import crypto, { webcrypto } from 'node:crypto';

const ALGORITHM = { name: 'RSA-PSS', hash: 'SHA-384' };
const MAX_MANIFEST_BYTES = 32768;

export class EpochKeyUnavailable extends Error {
  constructor() { super('issuer_epoch_key_unavailable'); this.code = 'epoch_key_unavailable'; }
}

// Preserve the existing PEM / base64 DER, PKCS#1 / PKCS#8 operator contract.
export function parsePrivateKeyEnv(envValue) {
  if (typeof envValue !== 'string' || !envValue.trim()) throw new EpochKeyUnavailable();
  const value = envValue.trim();
  if (value.includes('-----BEGIN')) return crypto.createPrivateKey({ key: value, format: 'pem' });
  const der = Buffer.from(value, 'base64');
  try { return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }); }
  catch { return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs1' }); }
}

export async function derivePublicKey(priv, algorithm = ALGORITHM) {
  const jwk = await webcrypto.subtle.exportKey('jwk', priv);
  return webcrypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, ext: true },
    algorithm, true, ['verify']);
}

export function keyIdFromSpki(spkiBytes) {
  return crypto.createHash('sha256').update(spkiBytes).digest('hex').slice(0, 32);
}

async function importKey(material) {
  try {
    const nodeKey = parsePrivateKeyEnv(material);
    if (!['rsa', 'rsa-pss'].includes(nodeKey.asymmetricKeyType) ||
        nodeKey.asymmetricKeyDetails?.modulusLength !== 2048) throw new EpochKeyUnavailable();
    const jwk = nodeKey.export({ format: 'jwk' });
    const priv = await webcrypto.subtle.importKey('jwk', jwk, ALGORITHM, true, ['sign']);
    const pub = await derivePublicKey(priv);
    const spki = Buffer.from(await webcrypto.subtle.exportKey('spki', pub));
    // Compare actual RSA material, not PEM/DER spelling or a truncated wire ID.
    const fingerprint = crypto.createHash('sha256').update(jwk.n).update('\0').update(jwk.e).digest('hex');
    return { fingerprint, entry: Object.freeze({ priv, pub, spkiB64: spki.toString('base64'), keyId: keyIdFromSpki(spki) }) };
  } catch { throw new EpochKeyUnavailable(); }
}

/**
 * Explicit manifests supply at most the current and previous epoch. A lookup
 * checks the live epoch even after import, so cached keys cannot outlive their
 * overlap window. Missing entries never fall back to the legacy shared key.
 * Legacy mode deliberately retains the existing single-key behavior; it does
 * not provide cryptographic epoch expiry while the same key remains published.
 */
export function createEpochKeyProvider({ legacySigningKeyB64 = '', manifestJSON, currentEpoch } = {}) {
  if (typeof currentEpoch !== 'function') throw new EpochKeyUnavailable();
  const readEpoch = () => {
    const epoch = currentEpoch();
    if (!Number.isSafeInteger(epoch) || epoch < 0) throw new EpochKeyUnavailable();
    return epoch;
  };
  const isLive = epoch => {
    const now = readEpoch();
    return Number.isSafeInteger(epoch) && epoch >= 0 && (epoch === now || epoch === now - 1);
  };
  // Unset is the only opt-out. An explicitly empty/malformed manifest is an
  // operator error, not authorization to reuse the legacy key.
  const explicit = manifestJSON !== undefined;
  let records;
  if (explicit) {
    try {
      if (typeof manifestJSON !== 'string' || Buffer.byteLength(manifestJSON) > MAX_MANIFEST_BYTES) throw new EpochKeyUnavailable();
      const manifest = JSON.parse(manifestJSON), now = readEpoch();
      if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.keys) ||
          manifest.keys.length < 1 || manifest.keys.length > 2) throw new EpochKeyUnavailable();
      const epochs = new Set();
      records = manifest.keys.map(record => {
        if (!record || !Number.isSafeInteger(record.epoch) || record.epoch < 0 ||
            ![now, now - 1].includes(record.epoch) || epochs.has(record.epoch) ||
            typeof record.privateKey !== 'string' || !record.privateKey.trim()) throw new EpochKeyUnavailable();
        epochs.add(record.epoch);
        return { epoch: record.epoch, privateKey: record.privateKey };
      });
    } catch { throw new EpochKeyUnavailable(); }
  }

  // One bounded import per configured key, shared by concurrent requests. All
  // manifest keys must validate before any one of them can be used or published.
  let imported;
  function load() {
    if (!imported) imported = explicit ? Promise.all(records.map(async record => ({
      epoch: record.epoch, ...(await importKey(record.privateKey)),
    }))).then(keys => {
      if (new Set(keys.map(key => key.fingerprint)).size !== keys.length) throw new EpochKeyUnavailable();
      return new Map(keys.map(key => [key.epoch, key.entry]));
    }) : importKey(legacySigningKeyB64).then(key => key.entry);
    return imported;
  }

  return Object.freeze({
    mode: explicit ? 'manifest' : 'legacy',
    async keysForEpoch(epoch) {
      if (!isLive(epoch)) throw new EpochKeyUnavailable();
      const keys = await load();
      if (!isLive(epoch)) throw new EpochKeyUnavailable();
      const entry = explicit ? keys.get(epoch) : keys;
      if (!entry) throw new EpochKeyUnavailable();
      return entry;
    },
  });
}
