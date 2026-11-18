// Coalescing never strands a read on another request's flight: a follower drops a flight
// that throws (Workers: its request ended, so it can never settle) or that is older than
// the fetch timeouts, and fetches for itself.
import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import commons from '../commons/index.js'

const ctx = { waitUntil() {} }
const realFetch = globalThis.fetch, realNow = Date.now
afterEach(() => { Date.now = realNow; globalThis.fetch = realFetch })
const read = (path) => commons.fetch(new Request(`https://commons.landerapp.xyz${path}`), {}, ctx)
const atom = { 'content-type': 'application/atom+xml' }

test('a flight older than the fetch timeouts is not awaited', async () => {
  let now = realNow()
  Date.now = () => now
  globalThis.fetch = () => new Promise(() => {}) // the first request's fetch never settles
  read('/v1/commons?id=flight1&sort=hot')
  await new Promise((r) => setTimeout(r, 10))
  now += 21000
  globalThis.fetch = async () => new Response('fresh', { status: 200, headers: atom })
  const resp = await read('/v1/commons?id=flight1&sort=hot')
  assert.equal(resp.status, 200)
  assert.equal(resp.headers.get('x-cache'), 'MISS')
  assert.equal(await resp.text(), 'fresh')
})

test('a follower whose flight throws fetches for itself', async () => {
  // Node has no cross-request promises, so make the shared flight itself reject: the leader's
  // fetch fails and the next Date.now (in fetchUpstream's catch) throws once.
  let fail, boom = false
  Date.now = () => { if (boom) { boom = false; throw new Error('can never settle') } return realNow() }
  globalThis.fetch = () => new Promise((_, reject) => { fail = reject })
  const leader = read('/v1/commons?id=flight2&sort=hot').catch((e) => e)
  await new Promise((r) => setTimeout(r, 10))
  const follower = read('/v1/commons?id=flight2&sort=hot')
  await new Promise((r) => setTimeout(r, 10))
  globalThis.fetch = async () => new Response('own', { status: 200, headers: atom })
  boom = true
  fail(new Error('network'))
  const resp = await follower
  assert.equal(resp.status, 200)
  assert.equal(await resp.text(), 'own')
  assert.match(String((await leader)?.message), /can never settle/)
})
