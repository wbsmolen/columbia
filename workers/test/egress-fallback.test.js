// The relay and commons Workers must keep serving when the egress origin dies.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import relay, { egressUnavailable } from '../relay/index.js'

const sealed = () => new Request('https://relay.landerapp.xyz/relay', {
  method: 'POST', headers: { 'content-type': 'message/ohttp-req' }, body: new Uint8Array([1, 2, 3]),
})

test('egressUnavailable: 502/503 and HTML error pages, not relay answers', () => {
  assert.equal(egressUnavailable(new Response(null, { status: 502 })), true)
  assert.equal(egressUnavailable(new Response(null, { status: 503 })), true)
  assert.equal(egressUnavailable(new Response('<html>', { status: 403, headers: { 'content-type': 'text/html' } })), true)
  assert.equal(egressUnavailable(new Response(null, { status: 401 })), false)
  assert.equal(egressUnavailable(new Response(null, { status: 504 })), false)
  assert.equal(egressUnavailable(new Response('x', { status: 200, headers: { 'content-type': 'message/ohttp-res' } })), false)
})

test('a dead egress falls back to the gateway binding, then the breaker skips it', async () => {
  const realFetch = globalThis.fetch
  let egressCalls = 0, gatewayCalls = 0
  globalThis.fetch = async () => { egressCalls++; throw new TypeError('connect failed') }
  const env = {
    EGRESS_RELAY_ORIGIN: 'https://egress.invalid',
    GATEWAY: { fetch: async () => { gatewayCalls++; return new Response('ok', { status: 200, headers: { 'content-type': 'message/ohttp-res' } }) } },
  }
  try {
    const first = await relay.fetch(sealed(), env)
    assert.equal(first.status, 200)
    const second = await relay.fetch(sealed(), env)
    assert.equal(second.status, 200)
    assert.equal(egressCalls, 1, 'breaker skips the egress after one failure')
    assert.equal(gatewayCalls, 2)
  } finally { globalThis.fetch = realFetch }
})
