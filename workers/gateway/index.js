// Columbia OHTTP gateway on Cloudflare Workers. Behaviour mirrors the vendored
// privacy-gateway-server-go (ohttp-gateway/): same key (derived from the same
// seed, X25519 config 0x80), same /ohttp-configs bytes, same outer/inner status
// mapping. Reachable only through the relay's service binding (no public route).
import { decodeRequest, encodeResponse } from '../shared/bhttp.js'
import { importPrivateKey, decapsulate, encapsulateResponse, ConfigMismatch, hexToBytes } from '../shared/ohttp.js'

const PAYLOAD_ERROR = [400, 'Issues with payload marshalling (BHTTP or Protobuf)']
const FORBIDDEN = [403, 'Target forbidden on gateway (request was blocked by gateway)']
const INTERNAL = [500, 'The request failed to be processed after decapsulation']
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length'])
const STRIP_RESPONSE = new Set(['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive'])
const UPSTREAM_TIMEOUT_MS = 30000

let keyPromise
const config = (env) => {
  keyPromise ??= importPrivateKey(env.OHTTP_SK_HEX)
  return keyPromise
}

function log(fields) { console.log(JSON.stringify({ svc: 'gateway', ...fields })) }

async function sha256(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))) }
async function relayAuthorized(request, env) {
  if (!env.RELAY_GATEWAY_SECRET) return true
  const a = await sha256(request.headers.get('x-columbia-relay-auth') || ''), b = await sha256(env.RELAY_GATEWAY_SECRET)
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

async function targetResponse(req, env) {
  const allowed = new Set((env.ALLOWED_TARGET_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean))
  if (allowed.size && !allowed.has(req.authority)) return { error: FORBIDDEN, reason: 'forbidden' }
  let scheme = req.scheme || 'https', host = req.authority
  const rewrites = env.TARGET_REWRITES ? JSON.parse(env.TARGET_REWRITES) : null
  if (rewrites && rewrites[host]) ({ Scheme: scheme, Host: host } = rewrites[host])
  const headers = new Headers()
  for (const [name, value] of req.headers) if (!HOP.has(name.toLowerCase())) headers.append(name, value)
  const init = { method: req.method, headers, redirect: 'follow', signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) }
  if (req.body.length && req.method !== 'GET' && req.method !== 'HEAD') init.body = req.body
  let resp
  try {
    resp = await fetch(`${scheme}://${host}${req.path}`, init)
  } catch (e) {
    return { error: INTERNAL, reason: 'upstream_error', code: e?.name }
  }
  const body = new Uint8Array(await resp.arrayBuffer())
  const outHeaders = []
  for (const [name, value] of resp.headers) {
    const n = name.toLowerCase()
    if (STRIP_RESPONSE.has(n) || n === 'set-cookie') continue
    outHeaders.push([n, value])
  }
  for (const cookie of resp.headers.getSetCookie?.() || []) outHeaders.push(['set-cookie', cookie])
  return { status: resp.status, headers: outHeaders, body }
}

async function handleGateway(request, env, start) {
  if (request.method !== 'POST') return new Response('Bad Request', { status: 400 })
  if (!(await relayAuthorized(request, env))) return new Response('Unauthorized', { status: 401 })
  if ((request.headers.get('content-type') || '') !== 'message/ohttp-req') return new Response('Bad Request', { status: 400 })
  const body = new Uint8Array(await request.arrayBuffer())
  let decapsulated
  try {
    decapsulated = await decapsulate(await config(env), Number(env.OHTTP_KEY_ID), body)
  } catch (e) {
    const status = e instanceof ConfigMismatch ? 401 : 400
    log({ route: '/gateway', status, reason: e instanceof ConfigMismatch ? 'config_mismatch' : 'decapsulation_failed', durationMs: Date.now() - start })
    return new Response(status === 401 ? 'Unauthorized' : 'Bad Request', { status })
  }
  let inner, reason, code, upstreamStatus
  try {
    const req = decodeRequest(decapsulated.plaintext)
    const result = await targetResponse(req, env)
    if (result.error) {
      ;({ reason, code } = result)
      inner = encodeResponse(result.error[0], [], new TextEncoder().encode(result.error[1]))
    } else {
      upstreamStatus = result.status
      inner = encodeResponse(result.status, result.headers, result.body)
    }
  } catch {
    reason = 'payload_error'
    inner = encodeResponse(PAYLOAD_ERROR[0], [], new TextEncoder().encode(PAYLOAD_ERROR[1]))
  }
  const sealed = await encapsulateResponse(decapsulated.ctx, inner)
  log({ route: '/gateway', status: 200, upstreamStatus, reason, code, durationMs: Date.now() - start })
  return new Response(sealed, { status: 200, headers: { 'content-type': 'message/ohttp-res' } })
}

export default {
  async fetch(request, env) {
    const start = Date.now()
    const { pathname } = new URL(request.url)
    if (pathname === '/health' && request.method === 'GET') return new Response('ok')
    if (pathname === '/ohttp-configs' && request.method === 'GET') {
      return new Response(hexToBytes(env.OHTTP_CONFIG_HEX), {
        headers: { 'content-type': 'application/ohttp-keys', 'cache-control': 'max-age=43200' }
      })
    }
    if (pathname === '/gateway') return handleGateway(request, env, start)
    return new Response('Not Found', { status: 404 })
  }
}
