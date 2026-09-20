// Bounded public-key refresh. A cached key can outlive a failed refresh only
// through its declared current/previous epoch acceptance window.
const crypto = require('node:crypto');
const https = require('node:https');
const { RedemptionUnavailable } = require('./redemption-store');
function fetchDocument(url, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(url); if (u.protocol !== 'https:') throw Error(); } catch { reject(new RedemptionUnavailable()); return; }
    let timer;
    const finish = (error, value) => { clearTimeout(timer); error ? reject(error) : resolve(value); };
    const request = https.get(u, { timeout: timeoutMs }, response => {
      const chunks = []; let bytes = 0;
      response.on('data', chunk => { bytes += chunk.length; if (bytes > 65536) response.destroy(new RedemptionUnavailable()); else chunks.push(chunk); });
      response.on('error', error => finish(error));
      response.on('end', () => { try { if (response.statusCode !== 200) throw Error(); finish(null, JSON.parse(Buffer.concat(chunks))); } catch { finish(new RedemptionUnavailable()); } });
    });
    request.on('timeout', () => request.destroy(new RedemptionUnavailable())); request.on('error', error => finish(error));
    timer = setTimeout(() => request.destroy(new RedemptionUnavailable()), timeoutMs);
  });
}
function createIssuerKeyCache({ url, ttlMs = 300000, backoffMs = 5000, now = Date.now, fetchKeys = fetchDocument } = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || !Number.isSafeInteger(backoffMs) || backoffMs < 1) throw Error('issuer_cache_configuration');
  let keys = new Map(), refreshedAt = 0, nextAttempt = 0, pending;
  function parse(doc) {
    if (doc?.schemaVersion !== 1 || doc.suite !== 'RSABSSA-SHA384-PSS-Deterministic' ||
        !Number.isSafeInteger(doc.epochSeconds) || doc.epochSeconds < 1 || doc.epochSeconds > 31557600 ||
        !Array.isArray(doc.keys) || doc.keys.length < 1 || doc.keys.length > 2) throw new RedemptionUnavailable();
    const epoch = Math.floor(now() / 1000 / doc.epochSeconds), next = new Map(), epochs = new Set();
    if (doc.epoch !== epoch) throw new RedemptionUnavailable();
    for (const entry of doc.keys) {
      if (![epoch, epoch - 1].includes(entry.epoch) || epochs.has(entry.epoch) || typeof entry.publicKeySpki !== 'string' || entry.publicKeySpki.length > 2048) throw new RedemptionUnavailable();
      epochs.add(entry.epoch);
      const publicKey = crypto.createPublicKey({ key: Buffer.from(entry.publicKeySpki, 'base64'), format: 'der', type: 'spki' });
      if (!['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType) || publicKey.asymmetricKeyDetails.modulusLength !== 2048) throw new RedemptionUnavailable();
      const fingerprint = crypto.createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex');
      if (entry.keyId !== fingerprint.slice(0, 32)) throw new RedemptionUnavailable();
      const expiresAt = (entry.epoch + 2) * doc.epochSeconds * 1000;
      const prior = next.get(entry.keyId);
      next.set(entry.keyId, { publicKey, fingerprint, expiresAt: Math.max(expiresAt, prior?.expiresAt || 0) });
    }
    if (!epochs.has(epoch)) throw new RedemptionUnavailable();
    return next;
  }
  async function refresh() {
    if (pending) return pending;
    if (!url || now() < nextAttempt) return;
    nextAttempt = now() + backoffMs;
    pending = (async () => { try { const doc = await fetchKeys(url); keys = parse(doc); refreshedAt = now(); }
      catch { /* callers may use a still-valid cached key; never extend expiry */ }
    })().finally(() => { pending = undefined; });
    return pending;
  }
  return {
    async get(keyId) {
      let entry = keys.get(keyId);
      if (!entry || now() >= entry.expiresAt || now() - refreshedAt >= ttlMs) await refresh();
      entry = keys.get(keyId);
      if (entry && now() < entry.expiresAt) return entry;
      if (![...keys.values()].some(key => now() < key.expiresAt)) throw new RedemptionUnavailable();
      return null;
    },
    // Test injection is explicit, finite-lived, and never used by production.
    setForTest(map, expiresAt = now() + 60000) {
      keys = new Map([...map].map(([id, publicKey]) => [id, { publicKey, expiresAt,
        fingerprint: crypto.createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex') }]));
      refreshedAt = now(); nextAttempt = now() + backoffMs;
    },
  };
}
module.exports = { createIssuerKeyCache };
