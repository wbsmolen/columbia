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
//   (f) cold single-flight: concurrent misses coalesce onto one upstream fetch
//   (g-j) /v1/imgur: album normalization (https-only, imgur {data:[…]} -> {images:[…]}),
//         cache HIT with no re-fetch, id-validation/SSRF 400, and upstream-failure 502 with no leak
//   (k-o) /v1/imgur?image=: single-image normalization, animated -> mp4 preference, id/param
//         validation 400, upstream 429 -> 502 logged as upstream_429, cold single-flight

import http from 'node:http';
import assert from 'node:assert/strict';

const JSON_PAYLOAD = JSON.stringify({ ok: true, id: 'jsonsub', items: [1, 2, 3] });
const RSS_PAYLOAD = '<rss><channel><title>mock</title></channel></rss>';

// --- mock upstream: records every hit + the Authorization it saw, routes by id ---
let upstreamHits = 0;
let lastAuth;
let releaseSlowResponse;
let slowRequestsReceived = 0;
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
  // Hold the cold response until all test callers have reached the cache. A
  // fixed delay races connection scheduling on busy machines.
  if (req.url.includes('slowsub')) {
    releaseSlowResponse = respond;
    if (slowRequestsReceived === 12) setImmediate(respond);
  } else respond();
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const mockPort = mock.address().port;

// --- configure + load the real server (env MUST be set before import) ---
process.env.UPSTREAM_BASE = `http://127.0.0.1:${mockPort}`;
process.env.UPSTREAM_PATH_TEMPLATE = '/{id}/{sort}';
process.env.FORWARD_UPSTREAM_AUTH = 'true';
process.env.COMMONS_TTL_MS = '60000'; // keep HITs fresh through the whole test

// --- mock imgur API: the /v1/imgur route fetches IMGUR_BASE/3/album/{id}/images,
//     separate from UPSTREAM_BASE. 'failalbum' returns a non-200 to exercise the
//     fixed-502-no-leak path; 'goodalbum' returns imgur's {data:[{link,...}]} shape. ---
let imgurHits = 0;
const imgurMock = http.createServer((req, res) => {
  imgurHits++;
  if (req.url.includes('/3/album/failalbum/images')) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, status: 500, data: { error: 'imgur boom' } }));
    return;
  }
  if (req.url.startsWith('/3/image/')) {
    const id = req.url.slice('/3/image/'.length);
    if (id === 'ratelimited') {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, status: 429, data: { error: 'imgur throttled you' } }));
      return;
    }
    const still = { id, link: `https://i.imgur.com/${id}.jpeg`, type: 'image/jpeg', width: 640, height: 480, animated: false };
    const anim = { id, link: `https://i.imgur.com/${id}.gif`, type: 'image/gif', width: 320, height: 240, animated: true, mp4: `https://i.imgur.com/${id}.mp4` };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, status: 200, data: id === 'animimg' ? anim : still }));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: true, status: 200, data: [
    { link: 'https://i.imgur.com/a1.jpeg', type: 'image/jpeg', width: 800, height: 600 },
    { link: 'https://i.imgur.com/a2.png', type: 'image/png', width: 100, height: 100 },
    { link: 'http://i.imgur.com/insecure.gif', type: 'image/gif', width: 50, height: 50 }, // dropped: https-only
  ] }));
});
await new Promise((r) => imgurMock.listen(0, '127.0.0.1', r));
process.env.IMGUR_BASE = `http://127.0.0.1:${imgurMock.address().port}`;

const { server, readBoundedBody, safeLogFields, upstreamFailure } = (await import('./server.js')).default;
server.prependListener('request', (req) => {
  if (req.url === '/v1/commons?id=slowsub&sort=hot') {
    slowRequestsReceived++;
    if (slowRequestsReceived === 12 && releaseSlowResponse) setImmediate(releaseSlowResponse);
  }
});
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
  // Streaming limits stop allocation before an unbounded response completes,
  // including when Content-Length is absent or dishonest.
  let cancelled = false, chunksRead = 0;
  const oversized = new Response(new ReadableStream({
    pull(controller) { chunksRead++; controller.enqueue(new Uint8Array([1, 2])); },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(readBoundedBody(oversized, 3), error => error.code === 'BODY_TOO_LARGE');
  assert.ok(cancelled, 'oversized upstream stream cancelled');
  assert.ok(chunksRead <= 3, 'did not buffer an unlimited upstream');
  assert.equal((await readBoundedBody(new Response('abc'), 3)).toString(), 'abc');
  assert.deepEqual(safeLogFields({ route: '/private/person', method: 'SECRET', status: 404,
    error: 'token', reason: 'network', body: 'private' }),
    { route: 'other', method: 'other', status: 404, reason: 'network' });
  assert.equal(upstreamFailure(429), 'upstream_429');
  assert.equal(upstreamFailure(403), 'upstream_403');
  assert.equal(upstreamFailure(0, { name: 'TimeoutError', message: 'private' }), 'timeout');

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
  let barrierTimeout;
  let results;
  try {
    results = await Promise.race([
      Promise.all(Array.from({ length: 12 }, () =>
        get('/v1/commons?id=slowsub&sort=hot', { Authorization: 'Bearer AAA' }))),
      new Promise((_, reject) => { barrierTimeout = setTimeout(() => reject(new Error('cold callers did not reach the cache')), 5000); }),
    ]);
  } finally { clearTimeout(barrierTimeout); }
  assert.equal(upstreamHits - before, 1, 'f: 12 concurrent cold reads = ONE upstream fetch (single-flight)');
  assert.ok(results.every((x) => x.status === 200 && x.body === JSON_PAYLOAD), 'f: every coalesced request still gets the body');
  assert.equal(results.filter((x) => x.xcache === 'MISS').length, 1, 'f: exactly one MISS (the leader)');
  assert.equal(results.filter((x) => x.xcache === 'COALESCED').length, 11, 'f: the other 11 COALESCED onto it');

  // (g) imgur MISS: fetch imgur once and normalize {data:[{link,type,width,height}]}
  //     -> {images:[{url,type,w,h}]}, keeping https-only urls in order.
  r = await get('/v1/imgur?id=goodalbum');
  assert.equal(r.status, 200, 'g: 200');
  assert.equal(r.xcache, 'MISS', 'g: X-Cache MISS');
  assert.equal(imgurHits, 1, 'g: MISS hits imgur exactly once');
  const alb = JSON.parse(r.body);
  assert.equal(alb.images.length, 2, 'g: 3 imgur items -> 2 https images (http dropped)');
  assert.deepEqual(alb.images[0], { url: 'https://i.imgur.com/a1.jpeg', type: 'image/jpeg', w: 800, h: 600 }, 'g: link/type/width/height mapped to url/type/w/h');
  assert.equal(alb.images[1].url, 'https://i.imgur.com/a2.png', 'g: second https image kept, in order');
  assert.ok(!alb.images.some((i) => String(i.url).startsWith('http://')), 'g: non-https image filtered out');

  // (h) imgur HIT: a second read serves cached bytes with no second imgur fetch.
  r = await get('/v1/imgur?id=goodalbum');
  assert.equal(r.status, 200, 'h: 200');
  assert.equal(r.xcache, 'HIT', 'h: X-Cache HIT');
  assert.equal(imgurHits, 1, 'h: HIT does NOT re-fetch imgur');

  // (i) imgur id validation is the SSRF guard (id is interpolated into the imgur
  //     path): a malformed id is 400'd BEFORE any upstream fetch.
  r = await get('/v1/imgur?id=bad!id');
  assert.equal(r.status, 400, 'i: malformed id -> 400');
  assert.equal(imgurHits, 1, 'i: rejected id never touches imgur');

  // (j) imgur upstream failure -> fixed 502 that never leaks imgur status/body/error.
  r = await get('/v1/imgur?id=failalbum');
  assert.equal(r.status, 502, 'j: upstream non-200 -> 502');
  assert.ok(!/imgur boom/.test(r.body), 'j: imgur error text never leaks downstream');

  // (k) imgur single image MISS: fetch /3/image/{id} once, normalize {data:{link,...}}
  //     -> {image:{url,type,w,h,animated}}.
  let before2 = imgurHits;
  r = await get('/v1/imgur?image=stillimg');
  assert.equal(r.status, 200, 'k: 200');
  assert.equal(r.xcache, 'MISS', 'k: X-Cache MISS');
  assert.equal(imgurHits - before2, 1, 'k: MISS hits imgur exactly once');
  assert.deepEqual(JSON.parse(r.body), { image: { url: 'https://i.imgur.com/stillimg.jpeg', type: 'image/jpeg', w: 640, h: 480, animated: false } }, 'k: image normalized');

  // (l) animated image prefers imgur's mp4 over the gif link.
  r = await get('/v1/imgur?image=animimg');
  assert.equal(r.status, 200, 'l: 200');
  assert.deepEqual(JSON.parse(r.body), { image: { url: 'https://i.imgur.com/animimg.mp4', type: 'video/mp4', w: 320, h: 240, animated: true } }, 'l: animated -> mp4');

  // (m) image id validation / param shape: bad id, both params, neither -> 400 before any fetch.
  before2 = imgurHits;
  for (const q of ['?image=bad!id', '?id=goodalbum&image=stillimg', '']) {
    r = await get('/v1/imgur' + q);
    assert.equal(r.status, 400, `m: ${q || '(none)'} -> 400`);
    assert.ok(JSON.parse(r.body).error, 'm: 400 keeps the { error } shape');
  }
  assert.equal(imgurHits, before2, 'm: rejected requests never touch imgur');

  // (n) upstream 429 -> fixed 502, no leak, logged with reason upstream_429 only.
  const lines = [];
  const realWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, ...rest) => { lines.push(String(chunk)); return realWrite(chunk, ...rest); };
  try { r = await get('/v1/imgur?image=ratelimited'); } finally { process.stdout.write = realWrite; }
  assert.equal(r.status, 502, 'n: upstream 429 -> 502');
  assert.ok(!/throttled/.test(r.body), 'n: imgur error text never leaks downstream');
  const logged = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((l) => l && l.route === '/v1/imgur' && l.status === 502);
  assert.ok(logged, 'n: 502 was logged');
  assert.equal(logged.reason, 'upstream_429', 'n: reason is the fixed category');
  assert.ok(!lines.some((l) => /throttled|ratelimited/.test(l)), 'n: neither imgur body nor the id reaches the log');
  assert.equal(upstreamFailure(404), 'not_found');

  // (o) image cold single-flight: concurrent cold reads of one image = one imgur fetch;
  //     a follow-up read is a HIT.
  before2 = imgurHits;
  const imgs = await Promise.all(Array.from({ length: 12 }, () => get('/v1/imgur?image=coldimg')));
  assert.ok(imgs.every((x) => x.status === 200), 'o: every concurrent reader gets a 200');
  assert.equal(imgurHits - before2, 1, 'o: 12 concurrent cold reads = ONE imgur fetch');
  r = await get('/v1/imgur?image=coldimg');
  assert.equal(r.xcache, 'HIT', 'o: subsequent read is a HIT');
  assert.equal(imgurHits - before2, 1, 'o: HIT does NOT re-fetch imgur');

  console.log('PASS: all commons-cache self-tests passed (a-o)');
} catch (err) {
  failed = true;
  console.error('FAIL:', err.message);
} finally {
  server.close();
  mock.close();
  imgurMock.close();
  process.exit(failed ? 1 : 0);
}
