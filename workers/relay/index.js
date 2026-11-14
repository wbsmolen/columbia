// Columbia OHTTP relay on Cloudflare Workers. Mirrors ohttp-relay/server.js:
// GET /health, GET /ohttp-configs (passthrough), POST /relay forwarded to the
// gateway Worker through a service binding. The relay sees the client's IP but
// never the plaintext; the gateway sees the plaintext but never the IP.
const MAX_BODY = 65536
const MAX_RESP_BYTES = 5000000
const GW_TIMEOUT_MS = 15000

function log(fields) { console.log(JSON.stringify({ svc: 'relay', ...fields })) }

function fdidAllowed(request, env) {
  // While Azure Front Door fronts this Worker, only accept requests it forwards.
  if (!env.REQUIRE_FDID) return true
  return request.headers.get('x-azure-fdid') === env.REQUIRE_FDID
}

async function rateLimited(request, env) {
  if (!env.RELAY_RATE_LIMITER) return false
  const ip = request.headers.get(env.TRUSTED_CLIENT_IP_HEADER || 'cf-connecting-ip') || request.headers.get('cf-connecting-ip') || 'unknown'
  const { success } = await env.RELAY_RATE_LIMITER.limit({ key: ip })
  return !success
}

async function forward(env, path, init, route, start) {
  let resp
  try {
    resp = await env.GATEWAY.fetch(`https://gateway.internal${path}`, { ...init, signal: AbortSignal.timeout(GW_TIMEOUT_MS) })
  } catch (e) {
    const timeout = e?.name === 'TimeoutError'
    log({ route, status: timeout ? 504 : 502, reason: timeout ? 'gw_timeout' : 'gw_error', code: e?.name, durationMs: Date.now() - start })
    return new Response(null, { status: timeout ? 504 : 502 })
  }
  const body = await resp.arrayBuffer()
  if (body.byteLength > MAX_RESP_BYTES) {
    log({ route, status: 502, reason: 'resp_too_large', durationMs: Date.now() - start })
    return new Response(null, { status: 502 })
  }
  const headers = {}
  const ct = resp.headers.get('content-type'), cc = resp.headers.get('cache-control')
  if (ct) headers['content-type'] = ct
  if (cc && route === '/ohttp-configs') headers['cache-control'] = cc
  log({ route, status: resp.status, durationMs: Date.now() - start })
  return new Response(body, { status: resp.status, headers })
}

export default {
  async fetch(request, env) {
    const start = Date.now()
    const { pathname } = new URL(request.url)
    if (request.method === 'GET' && pathname === '/health') return new Response('ok')
    if (!fdidAllowed(request, env)) return new Response(null, { status: 403 })
    if (request.method === 'GET' && pathname === '/ohttp-configs') {
      return forward(env, '/ohttp-configs', { method: 'GET' }, '/ohttp-configs', start)
    }
    if (!(request.method === 'POST' && pathname === '/relay')) return new Response(null, { status: 404 })
    const ctype = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase()
    if (ctype !== 'message/ohttp-req') {
      log({ route: '/relay', status: 415, reason: 'content_type', durationMs: Date.now() - start })
      return new Response(null, { status: 415 })
    }
    if (await rateLimited(request, env)) {
      log({ route: '/relay', status: 429, reason: 'rate_limit', durationMs: Date.now() - start })
      return new Response(null, { status: 429 })
    }
    const declared = Number(request.headers.get('content-length') || 0)
    if (declared > MAX_BODY) {
      log({ route: '/relay', status: 413, reason: 'request_too_large', durationMs: Date.now() - start })
      return new Response(null, { status: 413 })
    }
    const body = await request.arrayBuffer()
    if (body.byteLength > MAX_BODY) {
      log({ route: '/relay', status: 413, reason: 'request_too_large', durationMs: Date.now() - start })
      return new Response(null, { status: 413 })
    }
    const headers = { 'content-type': 'message/ohttp-req' }
    if (env.RELAY_GATEWAY_SECRET) headers['x-columbia-relay-auth'] = env.RELAY_GATEWAY_SECRET
    const resp = await forward(env, '/gateway', { method: 'POST', headers, body }, '/relay', start)
    if (resp.status === 200) return new Response(resp.body, { status: 200, headers: { 'content-type': 'message/ohttp-res' } })
    return resp
  }
}
