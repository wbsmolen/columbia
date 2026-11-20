import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes128Gcm } from '@hpke/core'
import { decapsulate, encapsulateResponse, ConfigMismatch, DecapsulationFailed } from '../shared/ohttp.js'

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() })
const encode = s => new TextEncoder().encode(s)
const concat = (...parts) => Uint8Array.from(parts.flatMap(p => [...new Uint8Array(p)]))

async function request() {
  const keys = await suite.kem.generateKeyPair()
  const header = Uint8Array.of(128, 0, 32, 0, 1, 0, 1)
  const info = concat(encode('message/bhttp request'), [0], header)
  const sender = await suite.createSenderContext({ recipientPublicKey: keys.publicKey, info })
  const plaintext = Uint8Array.of(0, 1, 2, 127, 128, 255)
  const ciphertext = await sender.seal(plaintext)
  return { keys, sender, plaintext, body: concat(header, sender.enc, ciphertext) }
}

// Client-side RFC 9458 response decoding, independent of the gateway helper.
async function openResponse(sender, wire) {
  const secret = await sender.export(encode('message/bhttp response'), 16)
  const salt = concat(sender.enc, wire.slice(0, 16))
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
  const derive = (label, length) => crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: encode(label) }, ikm, length * 8)
  const key = await crypto.subtle.importKey('raw', await derive('key', 16), 'AES-GCM', false, ['decrypt'])
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: await derive('nonce', 12) }, key, wire.slice(16)))
}

test('OHTTP request and response interoperate with the client HPKE context', async () => {
  const { keys, sender, plaintext, body } = await request()
  const result = await decapsulate(keys.privateKey, 128, body)
  assert.deepEqual(result.plaintext, plaintext)
  const response = encode('binary HTTP response payload')
  const wire = await encapsulateResponse(result.ctx, response)
  assert.deepEqual(await openResponse(sender, wire), response)
  wire[wire.length - 1] ^= 1
  await assert.rejects(openResponse(sender, wire))
})

test('OHTTP rejects wrong key ID, unsupported suite, truncation and tampering', async () => {
  const { keys, body } = await request()
  await assert.rejects(decapsulate(keys.privateKey, 129, body), ConfigMismatch)
  await assert.rejects(decapsulate(keys.privateKey, 128, body.slice(0, 38)), DecapsulationFailed)
  const suiteMismatch = body.slice(); suiteMismatch[6] = 2
  await assert.rejects(decapsulate(keys.privateKey, 128, suiteMismatch), DecapsulationFailed)
  const tampered = body.slice(); tampered[tampered.length - 1] ^= 1
  await assert.rejects(decapsulate(keys.privateKey, 128, tampered), DecapsulationFailed)
})

test('independent concurrent OHTTP requests preserve their own contexts', async () => {
  await Promise.all(Array.from({ length: 16 }, async (_, i) => {
    const { keys, sender, body } = await request()
    const { ctx } = await decapsulate(keys.privateKey, 128, body)
    const response = encode(`response ${i}`)
    assert.deepEqual(await openResponse(sender, await encapsulateResponse(ctx, response)), response)
  }))
})

// CVE-2025-64767: one sender must never reuse its sequence nonce when seals overlap.
test('HPKE serializes concurrent seals on a shared sender context', async () => {
  const keys = await suite.kem.generateKeyPair()
  const sender = await suite.createSenderContext({ recipientPublicKey: keys.publicKey })
  const recipient = await suite.createRecipientContext({ recipientKey: keys.privateKey, enc: sender.enc })
  const plaintext = encode('same plaintext makes nonce reuse observable')
  const ciphertexts = await Promise.all(Array.from({ length: 32 }, () => sender.seal(plaintext)))
  assert.equal(new Set(ciphertexts.map(ct => Buffer.from(ct).toString('hex'))).size, 32)
  for (const ct of ciphertexts) assert.deepEqual(new Uint8Array(await recipient.open(ct)), plaintext)
})
