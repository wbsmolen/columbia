// Columbia - commons-cache self-test (Node built-ins only, no framework).
//
//   node test.mjs
//
// Drives the real server.js in-process against a local mock upstream. Because the
// test imports server.js (require.main !== module), the SSRF guard and auto-listen
// stay dormant, letting us point UPSTREAM_BASE at a loopback mock. It asserts:
//   (a) a MISS fetches upstream and forwards the Authorization header (FORWARD_UPSTREAM_AUTH=true)
//   (b) a HIT serves cached bytes WITHOUT hitting upstream and WITHOUT any Authorization
//   (c) a different Authorization on the same (id, sort) shares the one cache entry
//   (d) a JSON body/content-type passes through byte-for-byte
//   (e) RSS mode still works (backward compatible)

import http from 'node:http';
import assert from 'node:assert/strict';

const JSON_PAYLOAD = JSON.stringify({ ok: true, id: 'jsonsub', items: [1, 2, 3] });
const RSS_PAYLOAD = '<rss><channel><title>mock</title></channel></rss>';

// --- mock upstream: records every hit + the Authorization it saw, routes by id ---
let upstreamHits = 0;
let lastAuth;
const mock = http.createServer((req, res) => {
  upstreamHits++;
  lastAuth = req.headers['authorization'];
  const respond = () => {
    if (req.url.includes('rsssub')) {
      res.writeHead(200, { 'Content-Type': 'application/rss+xml' });
      res.end(RSS_PAYLOAD);
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON_PAYLOAD);
    }
  };
  // 'slowsub' responds after a delay so concurrent requests overlap the in-flight
  // fetch; exercises cold-miss single-flight (test f).
  if (req.url.includes('slowsub')) setTimeout(respond, 100); else respond();
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const mockPort = mock.address().port;

// --- configure + load the real server (env MUST be set before import) ---
process.env.UPSTREAM_BASE = `http://127.0.0.1:${mockPort}`;
process.env.UPSTREAM_PATH_TEMPLATE = '/{id}/{sort}';
process.env.FORWARD_UPSTREAM_AUTH = 'true';
process.env.COMMONS_TTL_MS = '60000'; // keep HITs fresh through the whole test

const { server } = (await import('./server.js')).default;
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

async function get(path, headers = {}) {
  const res = await fetch(base + path, { headers });
  return {
    status: res.status,
    xcache: res.headers.get('x-cache'),
    ctype: res.headers.get('content-type'),
    ustatus: res.headers.get('x-upstream-status'),
    body: await res.text(),
  };
}

let failed = false;
try {
  // (a) MISS fetches upstream once and forwards Authorization
  let r = await get('/v1/commons?id=jsonsub&sort=hot', { Authorization: 'Bearer AAA' });
  assert.equal(r.status, 200, 'a: 200');
  assert.equal(r.xcache, 'MISS', 'a: X-Cache MISS');
  assert.equal(upstreamHits, 1, 'a: MISS hits upstream exactly once');
  assert.equal(lastAuth, 'Bearer AAA', 'a: Authorization forwarded to upstream on MISS');
  assert.equal(r.ustatus, '200', 'a: X-Upstream-Status present');

  // (d) JSON passes through byte-for-byte with a JSON content-type
  assert.match(r.ctype, /^application\/json/, 'd: JSON content-type');
  assert.equal(r.body, JSON_PAYLOAD, 'd: JSON body byte-for-byte');

  // (b) HIT serves cached bytes with NO upstream fetch and NO Authorization required
  r = await get('/v1/commons?id=jsonsub&sort=hot'); // deliberately no auth header
  assert.equal(r.status, 200, 'b: 200 without auth');
  assert.equal(r.xcache, 'HIT', 'b: X-Cache HIT');
  assert.equal(upstreamHits, 1, 'b: HIT does NOT hit upstream');
  assert.equal(r.body, JSON_PAYLOAD, 'b: HIT serves identical cached bytes');

  // (c) a different Authorization on the same (id, sort) shares the one cache entry
  r = await get('/v1/commons?id=jsonsub&sort=hot', { Authorization: 'Bearer BBB' });
  assert.equal(r.xcache, 'HIT', 'c: different auth still HITs');
  assert.equal(upstreamHits, 1, 'c: different auth shares one entry, no new fetch');
  assert.equal(r.body, JSON_PAYLOAD, 'c: shared cached bytes across auth values');

  // (e) RSS mode still works (new id -> new MISS, RSS content-type passes through)
  r = await get('/v1/commons?id=rsssub&sort=hot', { Authorization: 'Bearer AAA' });
  assert.equal(r.status, 200, 'e: 200');
  assert.equal(r.xcache, 'MISS', 'e: X-Cache MISS');
  assert.equal(upstreamHits, 2, 'e: RSS MISS hits upstream');
  assert.match(r.ctype, /^application\/rss\+xml/, 'e: RSS content-type');
  assert.equal(r.body, RSS_PAYLOAD, 'e: RSS body byte-for-byte');

  // (f) COLD-MISS SINGLE-FLIGHT: N concurrent requests for one cold key coalesce
  // to ONE upstream fetch: thundering-herd protection for the shared credential.
  const before = upstreamHits;
  const results = await Promise.all(Array.from({ length: 12 }, () =>
    get('/v1/commons?id=slowsub&sort=hot', { Authorization: 'Bearer AAA' })));
  assert.equal(upstreamHits - before, 1, 'f: 12 concurrent cold reads = ONE upstream fetch (single-flight)');
  assert.ok(results.every((x) => x.status === 200 && x.body === JSON_PAYLOAD), 'f: every coalesced request still gets the body');
  assert.equal(results.filter((x) => x.xcache === 'MISS').length, 1, 'f: exactly one MISS (the leader)');
  assert.equal(results.filter((x) => x.xcache === 'COALESCED').length, 11, 'f: the other 11 COALESCED onto it');

  console.log('PASS: all commons-cache self-tests passed (a-f)');
} catch (err) {
  failed = true;
  console.error('FAIL:', err.message);
} finally {
  server.close();
  mock.close();
  process.exit(failed ? 1 : 0);
}
