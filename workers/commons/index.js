// Columbia commons cache on Cloudflare Workers, ported from commons-cache/server.js.
// Same routes, validation, upstream template, SWR semantics and response headers.
// Two tiers: a per-isolate LRU (L1) and, when COMMONS_KV is bound, a KV copy every
// isolate and colo shares (L2), so one Reddit read per key per TTL serves everyone,
// not one per isolate. Every guest read Lander makes spends ONE Reddit bucket
// (1000 requests / 600 s for the app's client ID), so the commons also watches that
// bucket's headers and, when it runs low, serves the copy it has instead of spending
// what readers with no copy need (STALE-BUDGET).
const SORT_RE = /^[a-z]+$/
const IMGUR_ID_RE = /^[A-Za-z0-9]{1,15}$/
const ALLOWED_CONTENT_TYPES = new Set(['application/rss+xml', 'application/atom+xml', 'application/xml', 'text/xml', 'application/json'])
const ROUTES = ['/health', '/v1/commons', '/v1/comments', '/v1/page', '/v1/imgur', '/v1/probe', '/v1/read']
// A later listing page is keyed by the post it follows (Reddit's `after`).
const AFTER_RE = /^t3_[a-z0-9]{1,13}$/
const MAX_ENTRIES = 5000
const MAX_BODY_BYTES = 5000000
// /v1/read/<reddit path>?<query>: any other public read the app makes as the guest,
// shared by every reader of the same path and query. Lowercased paths; no search and no
// user pages (their keys would name what someone looked for).
const READ_PATHS = [
  /^\/(hot|new|top|rising|best|controversial)$/,
  /^\/r\/[a-z0-9_+]{1,400}(\/(hot|new|top|rising|best|controversial))?$/,
  /^\/r\/[a-z0-9_]{1,21}\/about(\/rules)?$/,
  /^\/r\/[a-z0-9_]{1,21}\/wiki\/[a-z0-9_/-]{1,100}$/,
  /^\/comments\/[a-z0-9]{1,13}$/,
  /^\/by_id\/t3_[a-z0-9]{1,13}(,t3_[a-z0-9]{1,13}){0,99}$/,
  /^\/duplicates\/[a-z0-9]{1,13}$/,
  /^\/api\/morechildren$/,
  /^\/subreddits\/popular$/,
]
const READ_PARAMS = new Set(['limit', 'after', 'before', 'count', 'sr_detail', 'raw_json', 't', 'g', 'sort', 'comment', 'context', 'depth', 'api_type', 'link_id', 'children', 'limit_children', 'show'])
const READ_VALUE_RE = /^[A-Za-z0-9_,.-]{1,2000}$/
// Community info, rules and wiki pages change rarely.
const SLOW_READ_RE = /\/about(\/rules)?$|\/wiki\/|^\/subreddits\//

const cache = new Map()
const inflight = new Map()
const FLIGHT_MAX_MS = 20000 // above the 10 s Reddit/imgur and 15 s egress fetch timeouts
const bootedAt = Date.now()

const cfg = (env) => ({
  ttl: Number(env.COMMONS_TTL_MS || 60000),
  swr: Number(env.COMMONS_SWR_MS || 300000),
  base: (env.UPSTREAM_BASE || 'https://oauth.reddit.com').replace(/\/+$/, ''),
  template: env.UPSTREAM_PATH_TEMPLATE || '/r/{id}/{sort}?raw_json=1&limit=25&sr_detail=true',
  commentsTemplate: env.COMMENTS_PATH_TEMPLATE || '/comments/{id}?sort={sort}&raw_json=1',
  // Every reader of a shared page 1 follows the same cursor, so later pages share too.
  pageTemplate: env.PAGE_PATH_TEMPLATE || '/r/{id}/{sort}?raw_json=1&limit=100&sr_detail=true&after={after}',
  ua: env.UPSTREAM_UA || 'columbia-commons/1.0 (+https://example.com)',
  forwardAuth: /^(1|true|yes|on)$/i.test(env.FORWARD_UPSTREAM_AUTH || ''),
  imgurBase: (env.IMGUR_BASE || 'https://api.imgur.com').replace(/\/+$/, ''),
  imgurClientId: env.IMGUR_CLIENT_ID || '546c25a59c58ad7',
  // On an upstream 429/5xx (or a low budget) a copy this young stands in for the error.
  staleIfError: Number(env.COMMONS_STALE_IF_ERROR_MS || 6 * 60 * 60 * 1000),
  slowTtl: Number(env.COMMONS_SLOW_TTL_MS || 60 * 60 * 1000),
  // `fresh=1` (a person's refresh) takes a copy at most this old, else reads Reddit.
  freshMs: Number(env.COMMONS_FRESH_MS || 30000),
  // Below this many requests left in a bucket's window, a copy is served instead.
  budgetFloor: Number(env.COMMONS_BUDGET_FLOOR || 150),
  tokenUrl: env.REDDIT_TOKEN_URL || 'https://www.reddit.com/api/v1/access_token',
})

function log(fields) {
  const route = String(fields.route || '').startsWith('/v1/read/') ? '/v1/read' : fields.route
  const safe = { svc: 'commons', route: ROUTES.includes(route) ? route : 'other' }
  for (const k of ['status', 'durationMs', 'cache', 'phase', 'reason', 'upstreamStatus', 'cred', 'remaining']) if (fields[k] !== undefined) safe[k] = fields[k]
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

// ponytail: per-isolate like the SWR cache, so a fresh isolate has no copy; the
// Cache API on the custom domain would share copies across isolates if that matters.
const refused = (status) => status === 429 || status >= 500 || status === 0
function lastGood(c, entry) {
  return entry && Date.now() - entry.fetchedAt <= c.staleIfError ? entry : null
}

// --- Shared tier (KV). Keys are hashed, so a listing of the namespace names nothing,
// and bodies are stored gzip (Reddit JSON shrinks ~6x). Reads use KV's edge cache for
// 60 s, so a copy written in one colo reaches the others within a minute.
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const kvKey = async (key) => `c1:${hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key)))}`
const pipe = async (body, stream) => new Uint8Array(await new Response(new Blob([body]).stream().pipeThrough(stream)).arrayBuffer())

async function sharedGet(env, key) {
  if (!env.COMMONS_KV) return null
  try {
    const { value, metadata } = await env.COMMONS_KV.getWithMetadata(await kvKey(key), { type: 'arrayBuffer', cacheTtl: 60 })
    if (!value || !metadata || typeof metadata.fetchedAt !== 'number') return null
    const body = metadata.gz ? await pipe(value, new DecompressionStream('gzip')) : new Uint8Array(value)
    return { body, contentType: safeContentType(metadata.contentType), fetchedAt: metadata.fetchedAt, upstreamStatus: 200 }
  } catch (e) {
    log({ route: 'kv', phase: 'kv_get', reason: e?.name || 'error' })
    return null
  }
}

async function sharedPut(c, env, key, entry) {
  if (!env.COMMONS_KV) return
  try {
    const gz = await pipe(entry.body, new CompressionStream('gzip'))
    await env.COMMONS_KV.put(await kvKey(key), gz, {
      expirationTtl: Math.max(60, Math.ceil(c.staleIfError / 1000)),
      metadata: { fetchedAt: entry.fetchedAt, contentType: entry.contentType, gz: 1 },
    })
  } catch (e) {
    // KV allows one write per key per second; a racing colo already wrote this copy.
    log({ route: 'kv', phase: 'kv_put', reason: e?.name || 'error' })
  }
}

// A good read lands in both tiers; the KV write never delays the reader.
function keep(c, env, ctx, key, val) {
  const entry = { ...val, revalidating: false }
  cacheSet(key, entry)
  ctx.waitUntil(sharedPut(c, env, key, entry))
}

// --- The bucket. Reddit reports each credential's window on every answer
// (x-ratelimit-remaining / -reset). Per isolate: settled numbers, never promises.
const budgets = { own: { remaining: Infinity, resetAt: 0 }, guest: { remaining: Infinity, resetAt: 0 } }
function noteBudget(slot, res) {
  if (!slot) return
  const now = Date.now()
  const reset = Number(res.headers.get('x-ratelimit-reset'))
  if (res.status === 429) {
    slot.remaining = 0
    slot.resetAt = now + (Number.isFinite(reset) && reset > 0 ? reset : 60) * 1000
    return
  }
  const remaining = Number(res.headers.get('x-ratelimit-remaining'))
  if (res.headers.has('x-ratelimit-remaining') && Number.isFinite(remaining) && Number.isFinite(reset)) {
    slot.remaining = remaining
    slot.resetAt = now + reset * 1000
  }
}
const slotLow = (c, slot, now) => now < slot.resetAt && slot.remaining < c.budgetFloor
// Low when every credential this commons could spend is low.
function budgetLow(c, env, now = Date.now()) {
  if (env.REDDIT_CLIENT_ID && !slotLow(c, budgets.own, now) && !ownMintBlocked(now)) return false
  return slotLow(c, budgets.guest, now)
}

// --- Columbia's own Reddit credential (optional). With REDDIT_CLIENT_ID (and, for a
// web/script app, REDDIT_CLIENT_SECRET) set as wrangler secrets, misses spend Columbia's
// own bucket instead of the app's shared guest bucket; the caller's guest bearer is the
// fallback when the own bucket refuses. The token lives only in this isolate's memory.
let ownToken = null // { token, exp } once minted (a settled value)
let ownMintingSince = 0
let ownMintBackoffUntil = 0
const ownMintBlocked = (now) => now < ownMintBackoffUntil

async function ownBearer(c, env) {
  if (!env.REDDIT_CLIENT_ID) return null
  const now = Date.now()
  if (ownToken && ownToken.exp - 60000 > now) return ownToken.token
  // Another request in this isolate is minting: this read uses the guest bearer.
  if (ownMintBlocked(now) || now - ownMintingSince < 10000) return null
  ownMintingSince = now
  try {
    const secret = env.REDDIT_CLIENT_SECRET || ''
    const form = secret
      ? 'grant_type=client_credentials'
      : 'grant_type=https%3A%2F%2Foauth.reddit.com%2Fgrants%2Finstalled_client&device_id=DO_NOT_TRACK_THIS_DEVICE'
    const res = await fetch(c.tokenUrl, {
      method: 'POST',
      headers: { Authorization: `Basic ${btoa(`${env.REDDIT_CLIENT_ID}:${secret}`)}`, 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': c.ua },
      body: form, redirect: 'manual', signal: AbortSignal.timeout(10000),
    })
    const j = res.status === 200 ? await res.json().catch(() => null) : null
    if (!j?.access_token) {
      await res.body?.cancel().catch(() => {})
      ownMintBackoffUntil = Date.now() + 5 * 60 * 1000
      log({ route: 'token', phase: 'mint', reason: 'refused', upstreamStatus: res.status })
      return null
    }
    ownToken = { token: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 }
    return ownToken.token
  } catch (e) {
    ownMintBackoffUntil = Date.now() + 60 * 1000
    log({ route: 'token', phase: 'mint', reason: upstreamFailure(0, e) })
    return null
  } finally {
    ownMintingSince = 0
  }
}

// One Reddit read: Columbia's own bearer when it has one and its bucket isn't low,
// else (or when the own bucket refuses) the caller's guest bearer.
async function fetchReddit(c, env, url, callerAuth) {
  const own = await ownBearer(c, env)
  if (own && !slotLow(c, budgets.own, Date.now())) {
    const up = await fetchUpstream(c, url, `Bearer ${own}`, budgets.own)
    if (up.status === 401) ownToken = null
    up.cred = 'own'
    if (!(up.status === 429 || up.status === 401) || !callerAuth) return up
  }
  const up = await fetchUpstream(c, url, callerAuth, callerAuth ? budgets.guest : null)
  up.cred = callerAuth ? 'guest' : 'none'
  return up
}

async function readBounded(res) {
  const buf = new Uint8Array(await res.arrayBuffer())
  if (buf.length > MAX_BODY_BYTES) throw Object.assign(new Error('body limit'), { code: 'BODY_TOO_LARGE' })
  return buf
}

async function fetchUpstream(c, url, auth, slot) {
  const started = Date.now()
  const headers = { 'User-Agent': c.ua, Accept: 'application/json, text/plain, */*', 'Accept-Language': 'en-US,en;q=0.9' }
  if (auth) headers.Authorization = auth
  try {
    const res = await fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(10000) })
    noteBudget(slot, res)
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

const upstreamUrl = (c, id, sort, template, after = '') => {
  const path = template.replace(/\{id\}/g, encodeURIComponent(id)).replace(/\{sort\}/g, encodeURIComponent(sort)).replace(/\{after\}/g, encodeURIComponent(after))
  return `${c.base}${path.startsWith('/') ? '' : '/'}${path}`
}

// Shared SWR + coalescing logic for feeds and imgur, as in the Node service, over both
// tiers. `read.ttl` overrides the fresh window (slow reads); `read.fresh` (a person's
// refresh) takes only a copy younger than `freshMs`, else reads Reddit, and still gets
// the last good copy when Reddit refuses.
async function cached(c, env, ctx, read, route) {
  const { key, fetcher } = read
  const ttl = read.ttl || c.ttl
  const freshFor = read.fresh ? Math.min(c.freshMs, ttl) : ttl
  const now = Date.now()
  let entry = cache.get(key)
  // L1 is missing or not fresh enough: another isolate or colo may hold a newer copy.
  if (!entry || now - entry.fetchedAt >= freshFor) {
    const shared = await sharedGet(env, key)
    if (shared && (!entry || shared.fetchedAt > entry.fetchedAt)) {
      entry = { ...shared, revalidating: false }
      cacheSet(key, entry)
      if (now - entry.fetchedAt < freshFor) return { ...entry, cacheState: 'HIT-SHARED' }
    }
  }
  if (entry) {
    const age = now - entry.fetchedAt
    if (age < freshFor) return { ...entry, cacheState: 'HIT' }
    // The bucket is nearly spent: the copy in hand beats spending what readers with
    // no copy need, and beats a refusal.
    if (age <= c.staleIfError && budgetLow(c, env, now)) return { ...entry, cacheState: 'STALE-BUDGET' }
    if (!read.fresh && age < ttl + c.swr) {
      if (!entry.revalidating) {
        entry.revalidating = true
        ctx.waitUntil(fetcher().then((up) => {
          if (up.status === 200 && !up.error) keep(c, env, ctx, key, { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: 200 })
          else log({ route, phase: 'revalidate', reason: up.reason, upstreamStatus: up.status, durationMs: up.ms, cred: up.cred })
        }).catch(() => log({ route, phase: 'revalidate', reason: 'network' })).finally(() => { entry.revalidating = false }))
      }
      return { ...entry, cacheState: 'STALE' }
    }
  }
  // Coalescing across requests: a Workers promise settles only in the request that created it.
  // When that request ends first (the client gave up), awaiting its flight throws "can never
  // settle" and the flight never clears, so every later read of the key failed until the
  // isolate restarted. A follower drops such a flight, and any flight older than the fetch
  // timeouts, and fetches for itself.
  let flight = inflight.get(key)
  if (flight && now - flight.at > FLIGHT_MAX_MS) flight = null
  let isLeader = !flight
  if (isLeader) {
    const mine = { at: now }
    mine.promise = fetcher().finally(() => { if (inflight.get(key) === mine) inflight.delete(key) })
    inflight.set(key, mine)
    flight = mine
  }
  let up
  try {
    up = await flight.promise
  } catch (error) {
    if (isLeader) throw error
    if (inflight.get(key) === flight) inflight.delete(key)
    isLeader = true
    up = await fetcher()
  }
  if (up.status === 200 && !up.error) {
    const val = { body: up.body, contentType: safeContentType(up.contentType), fetchedAt: Date.now(), upstreamStatus: 200 }
    if (isLeader) keep(c, env, ctx, key, val)
    return { ...val, cacheState: isLeader ? 'MISS' : 'COALESCED', cred: up.cred }
  }
  const stale = refused(up.status) && lastGood(c, entry)
  if (stale) return { ...stale, cacheState: 'STALE-ERROR', upstreamStatus: up.status, reason: up.reason, cred: up.cred }
  return { cacheState: 'MISS', upstreamStatus: up.status, upstreamError: true, reason: up.reason, cred: up.cred }
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
    // A deleted post or image (upstream 404) is the client's answer, not an outage.
    const notFound = out.reason === 'not_found'
    return json(notFound ? 404 : 502, { error: notFound ? 'not found' : 'upstream unavailable' }, { 'X-Cache': out.cacheState, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' })
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

// Reddit rate-limits Cloudflare's shared egress IPs, so while EGRESS_COMMONS_ORIGIN is
// set, app traffic on the custom domain is proxied to a commons with its own egress.
let egressDownUntil = 0
async function viaEgressCommons(request, env, ctx, c, u, key) {
  const headers = new Headers()
  for (const h of ['authorization', 'accept', 'accept-encoding', 'accept-language', 'user-agent']) {
    const v = request.headers.get(h)
    if (v) headers.set(h, v)
  }
  headers.set('x-azure-fdid', env.REQUIRE_FDID || '')
  headers.set('x-azure-socketip', request.headers.get('cf-connecting-ip') || '')
  const resp = await fetch(`${env.EGRESS_COMMONS_ORIGIN}${u.pathname}${u.search}`, { method: request.method, headers, signal: AbortSignal.timeout(15000) })
  // Anything that isn't commons answering (503, a platform error page) means the
  // egress is down: null sends the request to this Worker's own commons, which has
  // its own stale-if-error. Cloudflare swaps an origin's 502 body for HTML, so a 502
  // is still commons answering.
  if (resp.status === 503 || (resp.status !== 502 && resp.status >= 400 && (resp.headers.get('content-type') || '').includes('text/html'))) return null
  // Commons answered but its Reddit fetch failed: the last good copy beats the error.
  const stale = key && refused(resp.status) && lastGood(c, cache.get(key))
  if (stale) {
    await resp.body?.cancel().catch(() => {})
    log({ route: u.pathname, status: 200, cache: 'STALE-ERROR', phase: 'egress', upstreamStatus: resp.status })
    return serveCached(request, c, { ...stale, cacheState: 'STALE-ERROR', upstreamStatus: resp.status })
  }
  // Answer the way commons does so clients see the same JSON.
  if (resp.status === 502) return json(502, { error: 'upstream unavailable' }, { 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' })
  // fetch() already decompressed the egress's gzip, so the body is plain while the
  // headers still say gzip. 'automatic' re-encodes it to match; 'manual' sent plain
  // JSON labelled gzip, which URLSession can't read (seen from 2.3.15 and the watch).
  const out = new Headers(resp.headers)
  out.delete('content-length')
  if (!key || resp.status !== 200) return new Response(resp.body, { status: resp.status, headers: out })
  // Keep a good read as the last good copy, aged by commons' own Age header.
  const body = new Uint8Array(await resp.arrayBuffer())
  if (body.length <= MAX_BODY_BYTES) {
    const ageMs = (Number(resp.headers.get('age')) || 0) * 1000
    keep(c, env, ctx, key, { body, contentType: safeContentType(resp.headers.get('content-type')), fetchedAt: Date.now() - ageMs, upstreamStatus: 200 })
  }
  return new Response(body, { status: 200, headers: out })
}

// A valid read's cache key and upstream fetcher, shared by the egress and own paths;
// { error } for a bad query, null for any other route.
function parseRead(c, env, u, request) {
  const route = u.pathname
  const fresh = u.searchParams.get('fresh') === '1'
  const auth = c.forwardAuth ? request.headers.get('authorization') || undefined : undefined
  if (route.startsWith('/v1/read/')) {
    const path = route.slice('/v1/read'.length).toLowerCase()
    if (!READ_PATHS.some((re) => re.test(path))) return { error: 'not a shared read path' }
    const params = []
    const seen = new Set()
    for (const [name, value] of u.searchParams) {
      if (name === 'fresh') continue
      if (!READ_PARAMS.has(name) || seen.has(name) || !READ_VALUE_RE.test(value)) return { error: `not a shared read parameter: ${name.slice(0, 40)}` }
      seen.add(name)
      params.push([name, value])
    }
    // One key per read, whatever order the client wrote its query in.
    params.sort(([a], [b]) => (a < b ? -1 : 1))
    const qs = new URLSearchParams(params).toString()
    const url = `${c.base}${path}${qs ? `?${qs}` : ''}`
    return { key: `read:${path}?${qs}`, fetcher: () => fetchReddit(c, env, url, auth), ttl: SLOW_READ_RE.test(path) ? c.slowTtl : 0, fresh }
  }
  if (route === '/v1/commons' || route === '/v1/comments' || route === '/v1/page') {
    const kind = route === '/v1/comments' ? 'comments' : route === '/v1/page' ? 'page' : 'commons'
    const id = (u.searchParams.get('id') || '').replace(/[^A-Za-z0-9_]/g, '')
    const sort = (u.searchParams.get('sort') || 'latest').toLowerCase()
    const after = kind === 'page' ? u.searchParams.get('after') || '' : ''
    if (!id || !SORT_RE.test(sort) || (kind === 'page' && !AFTER_RE.test(after))) {
      return { error: `require ?id=<${kind === 'comments' ? 'item' : 'feed'}-id>&sort=<sort>${kind === 'page' ? '&after=<t3_id>' : ''}` }
    }
    const key = kind === 'commons' ? `${id}/${sort}` : kind === 'page' ? `page:${id}/${sort}/${after}` : `${kind}:${id}/${sort}`
    const template = kind === 'comments' ? c.commentsTemplate : kind === 'page' ? c.pageTemplate : c.template
    const url = upstreamUrl(c, id, sort, template, after)
    return { key, fetcher: () => fetchReddit(c, env, url, auth), fresh }
  }
  if (route === '/v1/imgur') {
    const id = (u.searchParams.get('id') || '').trim()
    const image = (u.searchParams.get('image') || '').trim()
    const valid = (id && !image && IMGUR_ID_RE.test(id)) || (image && !id && IMGUR_ID_RE.test(image))
    if (!valid) return { error: 'require ?id=<imgur album id> or ?image=<imgur image id>' }
    return id ? { key: `imgur/${id}`, fetcher: () => imgurAlbum(c, id) } : { key: `imgur-image/${image}`, fetcher: () => imgurImage(c, image) }
  }
  return null
}

export default {
  async fetch(request, env, ctx) {
    const started = Date.now()
    const c = cfg(env)
    const u = new URL(request.url)
    const read = parseRead(c, env, u, request)
    // Reads only, so any egress failure can fall back to this Worker's own commons
    // (more Reddit 429s from Cloudflare IPs, but no outage). The breaker skips a dead
    // egress for a minute per isolate.
    if (env.EGRESS_COMMONS_ORIGIN && !u.hostname.endsWith('.workers.dev') && u.pathname !== '/health' && Date.now() >= egressDownUntil) {
      try {
        const viaEgress = await viaEgressCommons(request, env, ctx, c, u, read?.key)
        if (viaEgress) return viaEgress
        log({ route: u.pathname, reason: 'egress_unavailable' })
      } catch (e) { log({ route: u.pathname, reason: 'egress_error', code: e?.name }) }
      egressDownUntil = Date.now() + 60000
    }
    const route = u.pathname
    // Front Door reaches this Worker on workers.dev; the custom domain and the
    // gateway's service binding serve apps directly.
    const viaWorkersDev = u.hostname.endsWith('.workers.dev')
    if (env.REQUIRE_FDID && viaWorkersDev && !(request.method === 'GET' && route === '/health') && !(await frontDoorAllowed(request, env))) {
      log({ route, status: 403, durationMs: Date.now() - started })
      return new Response(null, { status: 403 })
    }
    let resp, cacheState = '-', reason, upstreamStatus, cred
    if (route === '/health') {
      resp = json(200, {
        status: 'ok', service: 'commons-cache', ts: new Date().toISOString(), uptimeS: Math.round((Date.now() - bootedAt) / 1000), cacheKeys: cache.size,
        sharedCache: Boolean(env.COMMONS_KV), ownCredential: Boolean(env.REDDIT_CLIENT_ID), ownToken: Boolean(ownToken), budgetLow: budgetLow(c, env),
      })
    } else if (route === '/v1/probe') {
      const up = await fetchUpstream(c, upstreamUrl(c, 'example', 'latest', c.template))
      resp = new Response(JSON.stringify({ note: 'upstream-surface reachability from this host: status, size, and latency', results: { commons: { status: up.status, bytes: up.body?.length || 0, ms: up.ms } } }, null, 2), { headers: { 'Content-Type': 'application/json' } })
    } else if (read?.error) {
      resp = json(400, { error: read.error })
    } else if (read) {
      const out = await cached(c, env, ctx, read, route)
      ;({ cacheState, reason, upstreamStatus, cred } = out)
      resp = await serveCached(request, c, out)
    } else {
      resp = json(404, { error: 'not found', routes: ['/health', '/v1/probe', '/v1/commons?id=&sort=', '/v1/imgur?id=|image=', '/v1/comments?id=&sort=', '/v1/page?id=&sort=&after=', '/v1/read/<path>?<query>'] })
    }
    log({ route, status: resp.status, cache: cacheState, reason, upstreamStatus: reason ? upstreamStatus : undefined, cred, remaining: Number.isFinite(budgets.guest.remaining) ? budgets.guest.remaining : undefined, durationMs: Date.now() - started })
    return resp
  },
}
