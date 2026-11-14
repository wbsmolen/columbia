// Columbia commons cache on Cloudflare Workers, ported from commons-cache/server.js.
// Same routes, validation, upstream template, SWR semantics and response headers.
// The cache is per isolate (in memory); the Cache API is not available on
// workers.dev, and a per-isolate LRU matches the single Azure replica's design.
const SORT_RE = /^[a-z]+$/
const IMGUR_ID_RE = /^[A-Za-z0-9]{1,15}$/
const ALLOWED_CONTENT_TYPES = new Set(['application/rss+xml', 'application/atom+xml', 'application/xml', 'text/xml', 'application/json'])
const ROUTES = ['/health', '/v1/commons', '/v1/comments', '/v1/imgur', '/v1/probe']
const MAX_ENTRIES = 5000
const MAX_BODY_BYTES = 5000000

const cache = new Map()
const inflight = new Map()
const bootedAt = Date.now()

const cfg = (env) => ({
  ttl: Number(env.COMMONS_TTL_MS || 60000),
  swr: Number(env.COMMONS_SWR_MS || 300000),
  base: (env.UPSTREAM_BASE || 'https://oauth.reddit.com').replace(/\/+$/, ''),
  template: env.UPSTREAM_PATH_TEMPLATE || '/r/{id}/{sort}?raw_json=1&limit=25&sr_detail=true',
  commentsTemplate: env.COMMENTS_PATH_TEMPLATE || '/comments/{id}?sort={sort}&raw_json=1',
  ua: env.UPSTREAM_UA || 'columbia-commons/1.0 (+https://example.com)',
  forwardAuth: /^(1|true|yes|on)$/i.test(env.FORWARD_UPSTREAM_AUTH || ''),
  imgurBase: (env.IMGUR_BASE || 'https://api.imgur.com').replace(/\/+$/, ''),
  imgurClientId: env.IMGUR_CLIENT_ID || '546c25a59c58ad7',
})

function log(fields) {
  const safe = { svc: 'commons', route: ROUTES.includes(fields.route) ? fields.route : 'other' }
  for (const k of ['status', 'durationMs', 'cache', 'phase', 'reason', 'upstreamStatus']) if (fields[k] !== undefined) safe[k] = fields[k]
  console.log(JSON.stringify(safe))
}

function upstreamFailure(status, error) {
  if (error?.name === 'TimeoutError') return 'timeout'
  if (error?.code === 'BODY_TOO_LARGE') return 'too_large'
  if (error instanceof SyntaxError) return 'invalid_body'
  if (status === 403) return 'upstream_403'
  if (status === 429) return 'upstream_429'
  if (status === 404) return 'not_found'
  if (status >= 500) return 'upstream_5xx'
  if (status >= 400) return 'upstream_4xx'
  if (status >= 300) return 'redirect'
  return error ? 'network' : 'other'
}

const safeContentType = (raw) => {
  const media = String(raw || '').split(';')[0].trim().toLowerCase()
  return ALLOWED_CONTENT_TYPES.has(media) ? media : 'application/octet-stream'
}

function cacheSet(key, val) {
  cache.delete(key)
  cache.set(key, val)
  while (cache.size > MAX_ENTRIES) cache.delete(cache.keys().next().value)
}

async function readBounded(res) {
  const buf = new Uint8Array(await res.arrayBuffer())
  if (buf.length > MAX_BODY_BYTES) throw Object.assign(new Error('body limit'), { code: 'BODY_TOO_LARGE' })
  return buf
}

async function fetchUpstream(c, url, auth) {
  const started = Date.now()
  const headers = { 'User-Agent': c.ua, Accept: 'application/json, text/plain, */*', 'Accept-Language': 'en-US,en;q=0.9' }
  if (c.forwardAuth && auth) headers.Authorization = auth
  try {
    const res = await fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(10000) })
    if (res.status !== 200) {
      await res.body?.cancel().catch(() => {})
      return { status: res.status, error: true, ms: Date.now() - started, reason: upstreamFailure(res.status) }
    }
    const body = await readBounded(res)
    return { status: 200, body, contentType: res.headers.get('content-type') || 'application/json', ms: Date.now() - started }
  } catch (error) {
    return { status: 0, error: true, ms: Date.now() - started, reason: upstreamFailure(0, error) }
  }
}

const upstreamUrl = (c, id, sort, template) => {
  const path = template.replace(/\{id\}/g, encodeURIComponent(id)).replace(/\{sort\}/g, encodeURIComponent(sort))
  return `${c.base}${path.startsWith('/') ? '' : '/'}${path}`
}

// Shared SWR + coalescing logic for feeds and imgur, as in the Node service.
async function cached(c, ctx, key, fetcher, route) {
  const now = Date.now()
  const entry = cache.get(key)
  if (entry) {
    const age = now - entry.fetchedAt
    if (age < c.ttl) return { ...entry, cacheState: 'HIT' }
    if (age < c.ttl + c.swr) {
      if (!entry.revalidating) {
        entry.revalidating = true
        ctx.waitUntil(fetcher().then((up) => {
          if (up.status === 200 && !up.error) cacheSet(key, { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: 200, revalidating: false })
          else log({ route, phase: 'revalidate', reason: up.reason, upstreamStatus: up.status, durationMs: up.ms })
        }).catch(() => log({ route, phase: 'revalidate', reason: 'network' })).finally(() => { entry.revalidating = false }))
      }
      return { ...entry, cacheState: 'STALE' }
    }
  }
  let promise = inflight.get(key)
  const isLeader = !promise
  if (isLeader) { promise = fetcher().finally(() => inflight.delete(key)); inflight.set(key, promise) }
  const up = await promise
  if (up.status === 200 && !up.error) {
    const val = { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: 200 }
    if (isLeader) cacheSet(key, { ...val, revalidating: false })
    return { ...val, cacheState: isLeader ? 'MISS' : 'COALESCED' }
  }
  return { cacheState: 'MISS', upstreamStatus: up.status, upstreamError: true, reason: up.reason }
}

async function fetchImgurJson(c, path, shape) {
  const started = Date.now()
  try {
    const res = await fetch(`${c.imgurBase}${path}`, {
      headers: { 'User-Agent': c.ua, Accept: 'application/json', Authorization: `Client-ID ${c.imgurClientId}` },
      redirect: 'manual', signal: AbortSignal.timeout(10000),
    })
    if (res.status !== 200) {
      await res.body?.cancel().catch(() => {})
      return { status: res.status, error: true, ms: Date.now() - started, reason: upstreamFailure(res.status) }
    }
    const out = shape(JSON.parse(new TextDecoder().decode(await readBounded(res))))
    if (!out) return { status: 200, error: true, ms: Date.now() - started, reason: 'invalid_body' }
    const body = new TextEncoder().encode(JSON.stringify(out))
    if (body.length > MAX_BODY_BYTES) return { status: 200, error: true, ms: Date.now() - started, reason: 'too_large' }
    return { status: 200, body, contentType: 'application/json', ms: Date.now() - started }
  } catch (error) {
    return { status: 0, error: true, ms: Date.now() - started, reason: upstreamFailure(0, error) }
  }
}
const httpsUrl = (u) => typeof u === 'string' && u.startsWith('https://')
const imgurAlbum = (c, id) => fetchImgurJson(c, `/3/album/${encodeURIComponent(id)}/images`, (j) => ({
  images: (Array.isArray(j.data) ? j.data : []).map((i) => ({ url: i.link, type: i.type, w: i.width, h: i.height })).filter((x) => httpsUrl(x.url)),
}))
const imgurImage = (c, id) => fetchImgurJson(c, `/3/image/${encodeURIComponent(id)}`, (j) => {
  const d = j.data
  if (!d || typeof d !== 'object') return null
  const animated = d.animated === true
  const mp4 = animated && httpsUrl(d.mp4) ? d.mp4 : null
  const url = mp4 || d.link
  if (!httpsUrl(url)) return null
  return { image: { url, type: mp4 ? 'video/mp4' : d.type, w: d.width, h: d.height, animated } }
})

async function encodeForClient(request, body) {
  if (!/\bgzip\b/i.test(request.headers.get('accept-encoding') || '')) return { body, headers: { Vary: 'Accept-Encoding' } }
  const gz = new Uint8Array(await new Response(new Blob([body]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer())
  return { body: gz, headers: { 'Content-Encoding': 'gzip', 'Content-Length': String(gz.length), Vary: 'Accept-Encoding' } }
}

async function sha256(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))) }
async function frontDoorAllowed(request, env) {
  if (!env.REQUIRE_FDID) return true
  const raw = request.headers.get('x-azure-fdid')
  if (!raw) return false
  const want = await sha256(env.REQUIRE_FDID)
  for (const tok of raw.split(',')) {
    const got = await sha256(tok.trim())
    let diff = 0
    for (let i = 0; i < got.length; i++) diff |= got[i] ^ want[i]
    if (diff === 0) return true
  }
  return false
}

const json = (status, obj, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...extra } })

async function serveCached(request, c, out) {
  if (out.upstreamError) {
    return json(502, { error: 'upstream unavailable' }, { 'X-Cache': out.cacheState, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' })
  }
  const ageS = out.fetchedAt ? Math.max(0, Math.floor((Date.now() - out.fetchedAt) / 1000)) : 0
  const encoded = await encodeForClient(request, out.body)
  return new Response(encoded.body, {
    status: 200,
    // encodeBody 'manual': the body is already gzip; don't let the runtime re-encode it.
    encodeBody: encoded.headers['Content-Encoding'] ? 'manual' : 'automatic',
    headers: {
      ...encoded.headers,
      'Content-Type': safeContentType(out.contentType),
      'X-Cache': out.cacheState,
      'X-Upstream-Status': String(out.upstreamStatus || 200),
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': `public, max-age=${Math.floor(c.ttl / 1000)}, stale-while-revalidate=${Math.floor(c.swr / 1000)}`,
      Age: String(ageS),
    },
  })
}

export default {
  async fetch(request, env, ctx) {
    const started = Date.now()
    const c = cfg(env)
    const u = new URL(request.url)
    const route = u.pathname
    // Front Door reaches this Worker on workers.dev; the custom domain and the
    // gateway's service binding serve apps directly.
    const viaWorkersDev = u.hostname.endsWith('.workers.dev')
    if (env.REQUIRE_FDID && viaWorkersDev && !(request.method === 'GET' && route === '/health') && !(await frontDoorAllowed(request, env))) {
      log({ route, status: 403, durationMs: Date.now() - started })
      return new Response(null, { status: 403 })
    }
    let resp, cacheState = '-', reason, upstreamStatus
    if (route === '/health') {
      resp = json(200, { status: 'ok', service: 'commons-cache', ts: new Date().toISOString(), uptimeS: Math.round((Date.now() - bootedAt) / 1000), cacheKeys: cache.size })
    } else if (route === '/v1/probe') {
      const up = await fetchUpstream(c, upstreamUrl(c, 'example', 'latest', c.template))
      resp = new Response(JSON.stringify({ note: 'upstream-surface reachability from this host: status, size, and latency', results: { commons: { status: up.status, bytes: up.body?.length || 0, ms: up.ms } } }, null, 2), { headers: { 'Content-Type': 'application/json' } })
    } else if (route === '/v1/commons' || route === '/v1/comments') {
      const kind = route === '/v1/comments' ? 'comments' : 'commons'
      const id = (u.searchParams.get('id') || '').replace(/[^A-Za-z0-9_]/g, '')
      const sort = (u.searchParams.get('sort') || 'latest').toLowerCase()
      if (!id || !SORT_RE.test(sort)) {
        resp = json(400, { error: `require ?id=<${kind === 'comments' ? 'item' : 'feed'}-id>&sort=<sort>` })
      } else {
        const auth = c.forwardAuth ? request.headers.get('authorization') || undefined : undefined
        const key = kind === 'commons' ? `${id}/${sort}` : `${kind}:${id}/${sort}`
        const url = upstreamUrl(c, id, sort, kind === 'comments' ? c.commentsTemplate : c.template)
        const out = await cached(c, ctx, key, () => fetchUpstream(c, url, auth), route)
        ;({ cacheState, reason, upstreamStatus } = out)
        resp = await serveCached(request, c, out)
      }
    } else if (route === '/v1/imgur') {
      const id = (u.searchParams.get('id') || '').trim()
      const image = (u.searchParams.get('image') || '').trim()
      const valid = (id && !image && IMGUR_ID_RE.test(id)) || (image && !id && IMGUR_ID_RE.test(image))
      if (!valid) {
        resp = json(400, { error: 'require ?id=<imgur album id> or ?image=<imgur image id>' })
      } else {
        const out = id ? await cached(c, ctx, `imgur/${id}`, () => imgurAlbum(c, id), route)
          : await cached(c, ctx, `imgur-image/${image}`, () => imgurImage(c, image), route)
        ;({ cacheState, reason, upstreamStatus } = out)
        resp = await serveCached(request, c, out)
      }
    } else {
      resp = json(404, { error: 'not found', routes: ['/health', '/v1/probe', '/v1/commons?id=&sort=', '/v1/imgur?id=|image=', '/v1/comments?id=&sort='] })
    }
    log({ route, status: resp.status, cache: cacheState, reason: resp.status >= 500 ? reason : undefined, upstreamStatus: resp.status >= 500 ? upstreamStatus : undefined, durationMs: Date.now() - started })
    return resp
  },
}
