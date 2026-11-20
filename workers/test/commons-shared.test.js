// The shared tier (KV), the bucket governor, /v1/read, fresh=1 and Columbia's own
// credential. Each `isolate()` is a fresh module instance (its own L1, budget and
// token), so two of them over one fake KV behave like two isolates or colos.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'

let seq = 0
const isolate = async () => (await import(`../commons/index.js?isolate=${++seq}`)).default
const realFetch = globalThis.fetch
const realNow = Date.now
let now, calls, answer

function fakeKV() {
  const m = new Map()
  return {
    m,
    async getWithMetadata(k) {
      const v = m.get(k)
      return v ? { value: v.value.slice().buffer, metadata: v.metadata } : { value: null, metadata: null }
    },
    async put(k, value, opts) { m.set(k, { value: new Uint8Array(value), metadata: opts.metadata, ttl: opts.expirationTtl }) },
  }
}
const newCtx = () => ({ pending: [], waitUntil(p) { this.pending.push(p) } })
const settle = (ctx) => Promise.all(ctx.pending)

beforeEach(() => {
  now = realNow()
  Date.now = () => now
  calls = []
  answer = () => [200, '{"kind":"Listing"}', { 'content-type': 'application/json; charset=UTF-8' }]
  globalThis.fetch = async (url, init = {}) => {
    const headers = new Headers(init.headers)
    calls.push({ url: String(url), auth: headers.get('authorization'), method: init.method || 'GET', body: init.body })
    const [status, body, h] = answer(String(url), headers)
    return new Response(body, { status, headers: h })
  }
})
afterEach(() => { Date.now = realNow; globalThis.fetch = realFetch })

const get = (w, env, ctx, path, auth = 'Bearer guest') =>
  w.fetch(new Request(`https://commons.internal${path}`, { headers: auth ? { authorization: auth } : {} }), { FORWARD_UPSTREAM_AUTH: 'true', ...env }, ctx)

test('a copy one isolate fetched serves another isolate without a Reddit read', async () => {
  const kv = fakeKV()
  const a = await isolate(), b = await isolate()
  const ctx = newCtx()
  const first = await get(a, { COMMONS_KV: kv }, ctx, '/v1/commons?id=apple&sort=hot')
  assert.equal(first.headers.get('x-cache'), 'MISS')
  await settle(ctx)
  assert.equal(calls.length, 1)
  const [[k, stored]] = [...kv.m]
  assert.match(k, /^c1:[0-9a-f]{64}$/, 'the key names nothing')
  assert.equal(stored.metadata.gz, 1)
  assert.ok(stored.ttl >= 6 * 3600, 'kept for the stale-if-error window')
  const second = await get(b, { COMMONS_KV: kv }, newCtx(), '/v1/commons?id=apple&sort=hot')
  assert.equal(second.headers.get('x-cache'), 'HIT-SHARED')
  assert.equal(await second.text(), '{"kind":"Listing"}')
  assert.equal(calls.length, 1, 'no second Reddit read')
  // L1 has it now.
  assert.equal((await get(b, { COMMONS_KV: kv }, newCtx(), '/v1/commons?id=apple&sort=hot')).headers.get('x-cache'), 'HIT')
})

test('a refused read in a cold isolate serves the shared copy', async () => {
  const kv = fakeKV()
  const a = await isolate(), b = await isolate()
  const ctx = newCtx()
  await get(a, { COMMONS_KV: kv }, ctx, '/v1/comments?id=abc&sort=best')
  await settle(ctx)
  now += 60 * 60 * 1000
  answer = () => [429, '', { 'x-ratelimit-reset': '200' }]
  const resp = await get(b, { COMMONS_KV: kv }, newCtx(), '/v1/comments?id=abc&sort=best')
  assert.equal(resp.status, 200)
  assert.equal(resp.headers.get('x-cache'), 'STALE-ERROR')
})

test('a low guest bucket serves copies instead of spending it, and still reads what nobody has', async () => {
  const w = await isolate()
  answer = () => [200, '{"v":1}', { 'content-type': 'application/json', 'x-ratelimit-remaining': '900', 'x-ratelimit-reset': '400' }]
  await get(w, {}, newCtx(), '/v1/commons?id=pics&sort=hot')
  now += 6 * 60 * 1000 // past TTL, inside SWR
  answer = () => [200, '{"v":2}', { 'content-type': 'application/json', 'x-ratelimit-remaining': '40', 'x-ratelimit-reset': '300' }]
  await get(w, {}, newCtx(), '/v1/commons?id=news&sort=hot') // learns the bucket is low
  const before = calls.length
  const stale = await get(w, {}, newCtx(), '/v1/commons?id=pics&sort=hot')
  assert.equal(stale.headers.get('x-cache'), 'STALE-BUDGET')
  assert.equal(await stale.text(), '{"v":1}')
  assert.equal(calls.length, before, 'no revalidation while low')
  const fresh = await get(w, {}, newCtx(), '/v1/commons?id=pics&sort=hot&fresh=1')
  assert.equal(fresh.headers.get('x-cache'), 'STALE-BUDGET', "a refresh doesn't spend a low bucket either")
  const miss = await get(w, {}, newCtx(), '/v1/commons?id=gaming&sort=hot')
  assert.equal(miss.headers.get('x-cache'), 'MISS', 'a key with no copy still reads Reddit')
  // The window resets: copies revalidate again.
  now += 301 * 1000
  answer = () => [200, '{"v":3}', { 'content-type': 'application/json', 'x-ratelimit-remaining': '990', 'x-ratelimit-reset': '599' }]
  assert.equal((await get(w, {}, newCtx(), '/v1/commons?id=pics&sort=hot&fresh=1')).headers.get('x-cache'), 'MISS')
})

test('a guest 429 marks the bucket spent until its reset', async () => {
  const w = await isolate()
  await get(w, {}, newCtx(), '/v1/commons?id=a1&sort=hot')
  now += 6 * 60 * 1000
  answer = () => [429, '', { 'x-ratelimit-reset': '120' }]
  assert.equal((await get(w, {}, newCtx(), '/v1/commons?id=a2&sort=hot')).status, 502)
  const before = calls.length
  assert.equal((await get(w, {}, newCtx(), '/v1/commons?id=a1&sort=hot')).headers.get('x-cache'), 'STALE-BUDGET')
  assert.equal(calls.length, before)
})

test('/v1/read shares any public read, keyed regardless of query order', async () => {
  const w = await isolate()
  const one = await get(w, {}, newCtx(), '/v1/read/r/AskReddit/about?raw_json=1')
  assert.equal(one.status, 200)
  assert.deepEqual(calls.map((c) => c.url), ['https://oauth.reddit.com/r/askreddit/about?raw_json=1'])
  assert.equal(calls[0].auth, 'Bearer guest')
  await get(w, {}, newCtx(), '/v1/read/hot?sr_detail=true&limit=25&raw_json=1')
  assert.equal(calls[1].url, 'https://oauth.reddit.com/hot?limit=25&raw_json=1&sr_detail=true')
  const reordered = await get(w, {}, newCtx(), '/v1/read/hot?raw_json=1&limit=25&sr_detail=true')
  assert.equal(reordered.headers.get('x-cache'), 'HIT')
  await get(w, {}, newCtx(), '/v1/read/api/morechildren?api_type=json&link_id=t3_abc&children=d1,d2,d3&sort=confidence&raw_json=1')
  assert.equal(calls[2].url, 'https://oauth.reddit.com/api/morechildren?api_type=json&children=d1%2Cd2%2Cd3&link_id=t3_abc&raw_json=1&sort=confidence')
  // Community info stays fresh for an hour, not 5 minutes.
  now += 30 * 60 * 1000
  assert.equal((await get(w, {}, newCtx(), '/v1/read/r/askreddit/about?raw_json=1')).headers.get('x-cache'), 'HIT')
  for (const bad of ['/v1/read/search?q=x', '/v1/read/user/someone/about', '/v1/read/api/v1/me', '/v1/read/r/pics/hot?q=1',
    '/v1/read/r/pics/hot?limit=1&limit=2', '/v1/read/r/pics/hot?after=a%20b', '/v1/read/comments/abc/x']) {
    assert.equal((await get(w, {}, newCtx(), bad)).status, 400, bad)
  }
  assert.equal(calls.length, 3)
})

test('fresh=1 takes a copy up to 30 s old, else reads Reddit, and keeps the copy when refused', async () => {
  const w = await isolate()
  await get(w, {}, newCtx(), '/v1/read/r/pics/hot?limit=25')
  now += 20 * 1000
  assert.equal((await get(w, {}, newCtx(), '/v1/read/r/pics/hot?limit=25&fresh=1')).headers.get('x-cache'), 'HIT')
  now += 20 * 1000
  answer = () => [200, '{"v":"new"}', { 'content-type': 'application/json' }]
  const fresh = await get(w, {}, newCtx(), '/v1/read/r/pics/hot?fresh=1&limit=25')
  assert.equal(fresh.headers.get('x-cache'), 'MISS')
  assert.equal(await fresh.text(), '{"v":"new"}')
  assert.equal(calls.length, 2)
  now += 60 * 1000
  answer = () => [503, '', {}]
  const kept = await get(w, {}, newCtx(), '/v1/read/r/pics/hot?limit=25&fresh=1')
  assert.equal(kept.headers.get('x-cache'), 'STALE-ERROR')
  assert.equal(await kept.text(), '{"v":"new"}')
})

test("with its own credential the commons spends its own bucket, and the guest's only when refused", async () => {
  const w = await isolate()
  const env = { REDDIT_CLIENT_ID: 'cid', REDDIT_CLIENT_SECRET: 'sec' }
  answer = (url) => url.includes('access_token')
    ? [200, JSON.stringify({ access_token: 'own-token', expires_in: 86400 }), { 'content-type': 'application/json' }]
    : [200, '{"k":1}', { 'content-type': 'application/json', 'x-ratelimit-remaining': '999', 'x-ratelimit-reset': '599' }]
  await get(w, env, newCtx(), '/v1/commons?id=one&sort=hot')
  assert.equal(calls[0].url, 'https://www.reddit.com/api/v1/access_token')
  assert.equal(calls[0].method, 'POST')
  assert.equal(calls[0].auth, `Basic ${btoa('cid:sec')}`)
  assert.equal(calls[0].body, 'grant_type=client_credentials')
  assert.equal(calls[1].auth, 'Bearer own-token', "the caller's guest bearer is not spent")
  await get(w, env, newCtx(), '/v1/commons?id=two&sort=hot')
  assert.equal(calls.length, 3, 'one mint per isolate')
  // The own bucket refuses: the caller's guest bearer gets the read.
  answer = (url, h) => h.get('authorization') === 'Bearer own-token' ? [429, '', { 'x-ratelimit-reset': '100' }] : [200, '{"k":3}', { 'content-type': 'application/json' }]
  const resp = await get(w, env, newCtx(), '/v1/commons?id=three&sort=hot')
  assert.equal(resp.status, 200)
  assert.deepEqual(calls.slice(3).map((c) => c.auth), ['Bearer own-token', 'Bearer guest'])
  // While the own bucket is spent, reads go straight to the guest.
  await get(w, env, newCtx(), '/v1/commons?id=four&sort=hot')
  assert.deepEqual(calls.slice(5).map((c) => c.auth), ['Bearer guest'])
})

test('a refused mint falls back to the guest bearer and backs off', async () => {
  const w = await isolate()
  const env = { REDDIT_CLIENT_ID: 'cid' }
  answer = (url) => url.includes('access_token') ? [401, '', {}] : [200, '{}', { 'content-type': 'application/json' }]
  const resp = await get(w, env, newCtx(), '/v1/commons?id=m1&sort=hot')
  assert.equal(resp.status, 200)
  assert.match(calls[0].body, /installed_client/, 'no secret: an installed-app grant')
  assert.equal(calls[1].auth, 'Bearer guest')
  await get(w, env, newCtx(), '/v1/commons?id=m2&sort=hot')
  assert.equal(calls.filter((c) => c.url.includes('access_token')).length, 1, 'no re-mint during the backoff')
})

test('/health reports the tiers without secrets', async () => {
  const w = await isolate()
  const body = await (await get(w, { COMMONS_KV: fakeKV(), REDDIT_CLIENT_ID: 'cid', REDDIT_CLIENT_SECRET: 'sec' }, newCtx(), '/health', null)).json()
  assert.equal(body.sharedCache, true)
  assert.equal(body.ownCredential, true)
  assert.ok(!JSON.stringify(body).includes('sec'))
})
