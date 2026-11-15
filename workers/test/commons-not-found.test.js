// A deleted post or image is a 404 to the client, not a 5xx outage.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import commons from '../commons/index.js'

const ctx = { waitUntil() {} }

test('upstream 404 answers 404; other upstream failures stay 502, no-store, no leak', async () => {
  const realFetch = globalThis.fetch
  globalThis.fetch = async (url) => {
    const status = /gone/.test(String(url)) ? 404 : 500
    return new Response('upstream secret text', { status })
  }
  try {
    for (const [path, status] of [
      ['/v1/comments?id=gone1&sort=best', 404],
      ['/v1/commons?id=gonesub&sort=hot', 404],
      ['/v1/imgur?image=goneimg', 404],
      ['/v1/comments?id=broken1&sort=best', 502],
      ['/v1/imgur?id=brokenalbum', 502],
    ]) {
      const resp = await commons.fetch(new Request(`https://commons.landerapp.xyz${path}`), {}, ctx)
      assert.equal(resp.status, status, path)
      assert.equal(resp.headers.get('cache-control'), 'no-store', path)
      const body = await resp.text()
      assert.ok(!/secret/.test(body), `${path}: upstream body never leaks`)
      assert.equal(JSON.parse(body).error, status === 404 ? 'not found' : 'upstream unavailable', path)
    }
  } finally { globalThis.fetch = realFetch }
})
