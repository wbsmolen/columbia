// Oblivious HTTP gateway side (RFC 9458) for the one config Lander's client
// uses: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes128Gcm } from '@hpke/core'

export const KEM_X25519 = 0x0020, KDF_SHA256 = 0x0001, AEAD_AES128GCM = 0x0001
const NENC = 32, NK = 16, NN = 12
const REQ_LABEL = new TextEncoder().encode('message/bhttp request')
const RES_LABEL = new TextEncoder().encode('message/bhttp response')

export class ConfigMismatch extends Error {}
export class DecapsulationFailed extends Error {}

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() })

export function hexToBytes(hex) {
  const h = hex.trim()
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16)
  return out
}

export async function importPrivateKey(hex) {
  return suite.kem.importKey('raw', hexToBytes(hex).buffer, false)
}

// Returns { plaintext, ctx } or throws ConfigMismatch / DecapsulationFailed.
export async function decapsulate(privateKey, keyId, body) {
  if (body.length < 7 + NENC) throw new DecapsulationFailed('short')
  const hdr = body.subarray(0, 7)
  const id = hdr[0], kem = (hdr[1] << 8) | hdr[2], kdf = (hdr[3] << 8) | hdr[4], aead = (hdr[5] << 8) | hdr[6]
  if (id !== keyId || kem !== KEM_X25519) throw new ConfigMismatch('config')
  if (kdf !== KDF_SHA256 || aead !== AEAD_AES128GCM) throw new DecapsulationFailed('suite')
  const enc = body.slice(7, 7 + NENC)
  const ct = body.slice(7 + NENC)
  const info = new Uint8Array(REQ_LABEL.length + 1 + 7)
  info.set(REQ_LABEL, 0); info[REQ_LABEL.length] = 0; info.set(hdr, REQ_LABEL.length + 1)
  let recipient, plaintext
  try {
    recipient = await suite.createRecipientContext({ recipientKey: privateKey, enc: enc.buffer, info: info.buffer })
    plaintext = new Uint8Array(await recipient.open(ct.buffer))
  } catch {
    throw new DecapsulationFailed('open')
  }
  return { plaintext, ctx: { recipient, enc } }
}

export async function encapsulateResponse({ recipient, enc }, response) {
  const secret = new Uint8Array(await recipient.export(RES_LABEL.buffer, Math.max(NN, NK)))
  const nonce = crypto.getRandomValues(new Uint8Array(Math.max(NN, NK)))
  const salt = new Uint8Array(enc.length + nonce.length)
  salt.set(enc, 0); salt.set(nonce, enc.length)
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
  const keyBits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('key') }, ikm, NK * 8)
  const nonceBits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('nonce') }, ikm, NN * 8)
  const aeadKey = await crypto.subtle.importKey('raw', keyBits, 'AES-GCM', false, ['encrypt'])
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(nonceBits) }, aeadKey, response))
  const out = new Uint8Array(nonce.length + ct.length)
  out.set(nonce, 0); out.set(ct, nonce.length)
  return out
}
