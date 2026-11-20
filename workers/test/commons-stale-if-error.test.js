// Stale-if-error: when Reddit (or the egress commons) refuses a read with 429/5xx,
// the last good copy up to 6 h old (COMMONS_STALE_IF_ERROR_MS) answers 200 with X-Cache: STALE-ERROR.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import commons from '../commons/index.js'

const ctx = { waitUntil() {} }
const HOUR = 3600 * 1000
const realFetch = globalThis.fetch
const realNow = Date.now
let now, reddit, egress

beforeEach(() => {
  now = realNow()
  Date.now = () => now
  globalThis.fetch = async (url) => {
    const [status, body, headers] = String(url).startsWith('https://egress.test/') ? egress : reddit
    return new Response(body, { status, headers })
  }
})
afterEach(() => { Date.now = realNow; globalThis.fetch = realFetch })

const own = (path) => commons.fetch(new Request(`https://commons.landerapp.xyz${path}`), {}, ctx)
const viaEgress = (path) => commons.fetch(new Request(`https://commons.landerapp.xyz${path}`), { EGRESS_COMMONS_ORIGIN: 'https://egress.test' }, ctx)
const atom = { 'content-type': 'application/atom+xml' }

test('a refused Reddit read serves the last good copy, never one older than 6 h', async () => {
  reddit = [200, 'good-1', atom]
  assert.equal((await own('/v1/commons?id=stale1&sort=hot')).headers.get('x-cache'), 'MISS')
  now += 11 * 60 * 1000 // past TTL + SWR, so every read goes upstream
  for (const status of [429, 502, 503]) {
    reddit = [status, 'reddit error', { 'content-type': 'text/html' }]
    const resp = await own('/v1/commons?id=stale1&sort=hot')
    assert.equal(resp.status, 200, `upstream ${status}`)
    assert.equal(resp.headers.get('x-cache'), 'STALE-ERROR')
    assert.equal(resp.headers.get('content-type'), 'application/atom+xml')
    assert.equal(await resp.text(), 'good-1')
  }
  now += 6 * HOUR
  reddit = [429, 'reddit error', {}]
  const old = await own('/v1/commons?id=stale1&sort=hot')
  assert.equal(old.status, 502, 'a copy over 6 h old is not served')
  assert.equal(old.headers.get('cache-control'), 'no-store')
})

test('a 404 stays a 404 even with a good copy', async () => {
  reddit = [200, '{"post":1}', {}]
  await own('/v1/comments?id=gone2&sort=best')
  now += 11 * 60 * 1000
  reddit = [404, '', {}]
  assert.equal((await own('/v1/comments?id=gone2&sort=best')).status, 404)
})

test('a fresh 200 replaces the copy', async () => {
  reddit = [200, 'v1', {}]
  await own('/v1/page?id=popular&sort=hot&after=t3_x1')
  now += 11 * 60 * 1000
  reddit = [200, 'v2', {}]
  assert.equal(await (await own('/v1/page?id=popular&sort=hot&after=t3_x1')).text(), 'v2')
  now += 11 * 60 * 1000
  reddit = [429, '', {}]
  const resp = await own('/v1/page?id=popular&sort=hot&after=t3_x1')
  assert.equal(resp.headers.get('x-cache'), 'STALE-ERROR')
  assert.equal(await resp.text(), 'v2')
})

// Last: an egress 503 trips the per-isolate breaker.
test('the egress path keeps its good reads and serves them when commons fails', async () => {
  egress = [200, 'egress-1', { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': '8', age: '30' }]
  const first = await viaEgress('/v1/commons?id=stale3&sort=hot')
  assert.equal(await first.text(), 'egress-1')
  assert.equal(first.headers.get('content-length'), null, 'gzip fix: length dropped, runtime re-encodes')
  egress = [200, 'egress-2', { 'content-type': 'application/json', age: '3600' }]
  await viaEgress('/v1/commons?id=stale3&sort=hot')
  for (const status of [429, 502]) {
    egress = [status, '{"error":"upstream unavailable"}', { 'content-type': 'application/json' }]
    const resp = await viaEgress('/v1/commons?id=stale3&sort=hot')
    assert.equal(resp.status, 200, `egress ${status}`)
    assert.equal(resp.headers.get('x-cache'), 'STALE-ERROR')
    assert.equal(await resp.text(), 'egress-2', 'the newer good copy replaced the first')
  }
  egress = [404, '{"error":"not found"}', { 'content-type': 'application/json' }]
  assert.equal((await viaEgress('/v1/commons?id=stale3&sort=hot')).status, 404)
  // No copy for this key: today's 502.
  egress = [502, '<html>', { 'content-type': 'text/html' }]
  const none = await viaEgress('/v1/commons?id=nocopy&sort=hot')
  assert.equal(none.status, 502)
  assert.equal((await none.json()).error, 'upstream unavailable')
  // A dead egress (503) falls back to this Worker's own fetch; Reddit refuses that too.
  egress = [503, '', {}]
  reddit = [429, '', {}]
  const fallback = await viaEgress('/v1/commons?id=stale3&sort=hot')
  assert.equal(fallback.headers.get('x-cache'), 'STALE-ERROR')
  assert.equal(await fallback.text(), 'egress-2')
  // The egress copy is aged by its Age header (1 h at fetch): 5 h later it's too old.
  now += 5 * HOUR + 1000
  assert.equal((await viaEgress('/v1/commons?id=stale3&sort=hot')).status, 502)
})
