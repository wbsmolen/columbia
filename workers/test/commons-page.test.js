// /v1/page: a later listing page, keyed by the post it follows, shared by every
// reader of that cursor. Clients learn an older deployment lacks it from the
// unknown-route 404, whose body lists the routes.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import commons from '../commons/index.js'

const ctx = { waitUntil() {} }
const get = (path, headers = {}) => commons.fetch(new Request(`https://commons.landerapp.xyz${path}`, { headers }), {}, ctx)

test('a cursor page is fetched once under the page template and served to every reader', async () => {
  const realFetch = globalThis.fetch
  const fetched = []
  globalThis.fetch = async (url) => {
    fetched.push(String(url))
    return new Response('{"kind":"Listing"}', { status: 200, headers: { 'content-type': 'application/json' } })
  }
  try {
    const first = await get('/v1/page?id=popular&sort=hot&after=t3_p1')
    assert.equal(first.status, 200)
    assert.equal(first.headers.get('x-cache'), 'MISS')
    assert.deepEqual(fetched, ['https://oauth.reddit.com/r/popular/hot?raw_json=1&limit=100&sr_detail=true&after=t3_p1'])
    const second = await get('/v1/page?id=popular&sort=hot&after=t3_p1', { authorization: 'Bearer other' })
    assert.equal(second.headers.get('x-cache'), 'HIT')
    await get('/v1/page?id=popular&sort=hot&after=t3_p2')
    assert.equal(fetched.length, 2, 'another cursor is another page')
    for (const bad of ['', 't1_abc', 'T3_abc', 't3_abc&limit=1']) {
      const resp = await get(`/v1/page?id=popular&sort=hot&after=${encodeURIComponent(bad)}`)
      assert.equal(resp.status, 400, `after=${bad}`)
    }
    assert.equal(fetched.length, 2, 'a rejected cursor never reaches Reddit')
  } finally { globalThis.fetch = realFetch }
})

test('an unknown route still answers 404 with the route list', async () => {
  const resp = await get('/v1/nope')
  assert.equal(resp.status, 404)
  const body = await resp.json()
  assert.ok(body.routes.includes('/v1/page?id=&sort=&after='))
})
