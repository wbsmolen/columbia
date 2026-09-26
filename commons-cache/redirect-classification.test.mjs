import assert from 'node:assert/strict';
import test from 'node:test';
import commons from './server.js';

const { redirectTargetClass, safeLogFields, fetchUpstream, getCachedFeed, server, cache } = commons;
const requestedUrl = 'https://public.example.test/feed/sub/hot';

test('redirects are classified without returning a Location', () => {
  for (const [status, location, expected] of [
    [302, '/different/path?private=secret', 'same_origin'],
    [301, 'https://elsewhere.example.test/private?secret=token', 'other_origin_https'],
    [307, 'http://169.254.169.254/latest/meta-data/', 'unsafe_scheme'],
    [308, null, 'missing'],
    [302, 'http://[', 'invalid'],
  ]) {
    const response = new Response(null, { status, headers: location ? { Location: location } : {} });
    const category = redirectTargetClass(requestedUrl, response);
    assert.equal(category, expected);
    assert.deepEqual(safeLogFields({ reason: 'redirect', upstreamStatus: status, redirectTarget: category, location }),
      { reason: 'redirect', upstreamStatus: status, redirectTarget: expected });
  }
});

test('only finite HTTP statuses and fixed categories enter logs', () => {
  assert.deepEqual(safeLogFields({ upstreamStatus: 0, redirectTarget: 'https://private.example.test' }), {});
  assert.deepEqual(safeLogFields({ upstreamStatus: 600, redirectTarget: 'private' }), {});
  assert.equal(redirectTargetClass(requestedUrl, new Response(null, { status: 200 })), undefined);
});

test('upstream fetch rejects redirects without following or exposing Location', async () => {
  const originalFetch = globalThis.fetch;
  const attempted = [];
  globalThis.fetch = async (url, options) => {
    attempted.push({ url, redirect: options.redirect });
    return new Response(null, {
      status: 302,
      headers: { Location: 'http://169.254.169.254/latest/meta-data/?secret=private' },
    });
  };
  try {
    const result = await fetchUpstream(requestedUrl);
    assert.deepEqual(attempted, [{ url: requestedUrl, redirect: 'manual' }]);
    assert.equal(result.error, true);
    assert.equal(result.status, 302);
    assert.equal(result.reason, 'redirect');
    assert.equal(result.redirectTarget, 'unsafe_scheme');
    assert.equal(Object.keys(result).some((key) => /location|url|host/i.test(key)), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Commons miss carries only bounded redirect diagnostics to its caller', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (_url, options) => {
    calls += 1;
    assert.equal(options.redirect, 'manual');
    return new Response(null, { status: 301, headers: { Location: '/private?secret=private' } });
  };
  try {
    const result = await getCachedFeed('redirectfixture', 'latest');
    assert.equal(calls, 1);
    assert.deepEqual({
      upstreamError: result.upstreamError,
      upstreamStatus: result.upstreamStatus,
      reason: result.reason,
      redirectTarget: result.redirectTarget,
    }, {
      upstreamError: true,
      upstreamStatus: 301,
      reason: 'redirect',
      redirectTarget: 'same_origin',
    });
    assert.equal(Object.keys(result).some((key) => /location|url|host/i.test(key)), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('HTTP Commons response remains a fixed 502 while its log is classified', async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const captured = [];
  globalThis.fetch = async () => new Response(null, {
    status: 307,
    headers: { Location: 'http://169.254.169.254/private?secret=private' },
  });
  process.stdout.write = (chunk, ...args) => {
    captured.push(String(chunk));
    return originalWrite.call(process.stdout, chunk, ...args);
  };
  try {
    const response = await new Promise((resolve) => {
      const out = { status: null, headers: null, body: '' };
      const res = {
        writeHead(status, headers) { out.status = status; out.headers = headers; },
        end(body = '') { out.body = String(body); resolve(out); },
      };
      server.emit('request', {
        method: 'GET',
        url: '/v1/commons?id=redirecthttpfixture&sort=latest',
        headers: { authorization: 'Bearer PRIVATE' },
      }, res);
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(response.status, 502);
    assert.equal(response.headers['X-Cache'], 'MISS');
    assert.deepEqual(JSON.parse(response.body), { error: 'upstream unavailable' });
    assert.ok(!/169\.254|PRIVATE|private|secret|307/.test(JSON.stringify(response)));
    const row = captured.map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .find((line) => line?.route === '/v1/commons' && line.status === 502);
    assert.equal(row?.reason, 'redirect');
    assert.equal(row?.upstreamStatus, 307);
    assert.equal(row?.redirectTarget, 'unsafe_scheme');
    assert.ok(!/169\.254|PRIVATE|private|secret/.test(captured.join('')));
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
  }
});

test('failed background revalidation is visible without changing a stale 200', async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const captured = [];
  const cacheKey = 'revalidationfixture/latest';
  cache.set(cacheKey, {
    body: Buffer.from('cached public response'),
    contentType: 'application/json',
    fetchedAt: Date.now() - 120_000,
    upstreamStatus: 200,
    revalidating: false,
  });
  globalThis.fetch = async () => new Response(null, {
    status: 301,
    headers: { Location: 'https://other.example.test/private?secret=private' },
  });
  process.stdout.write = (chunk, ...args) => {
    captured.push(String(chunk));
    return originalWrite.call(process.stdout, chunk, ...args);
  };
  try {
    const stale = await getCachedFeed('revalidationfixture', 'latest');
    assert.equal(stale.cacheState, 'STALE');
    assert.equal(stale.body.toString(), 'cached public response');
    await new Promise((resolve) => setImmediate(resolve));
    const row = captured.map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .find((line) => line?.route === '/v1/commons' && line.phase === 'revalidate');
    assert.equal(row?.status, undefined, 'background failure is not a client 502');
    assert.equal(row?.reason, 'redirect');
    assert.equal(row?.upstreamStatus, 301);
    assert.equal(row?.redirectTarget, 'other_origin_https');
    assert.ok(!/other\.example|PRIVATE|private|secret/.test(captured.join('')));
  } finally {
    cache.delete(cacheKey);
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
  }
});
