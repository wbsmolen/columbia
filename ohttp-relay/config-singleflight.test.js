const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const { once } = require('node:events');

const existing = fs.readFileSync(path.join(__dirname, 'test.mjs'), 'utf8');
const key = existing.match(/const KEY = `([\s\S]*?)`;/)?.[1];
const cert = existing.match(/const CERT = `([\s\S]*?)`;/)?.[1];
assert.ok(key && cert, 'Existing loopback certificate fixture is required');
const turn = () => new Promise(resolve => setImmediate(resolve));
async function within(predicate, message) {
  const deadline = performance.now() + 2000;
  while (!predicate()) {
    if (performance.now() > deadline) throw Error(message);
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

async function fixture(t, overrides = {}) {
  const logs = [], configs = [], clientPromises = [], clients = new Set();
  let gatewayPosts = 0, incomingConfigs = 0, sharedAgent, gateway, relay;
  const originalWrite = process.stdout.write, Agent = https.Agent;
  const events = ['uncaughtException', 'unhandledRejection'];
  const addedListeners = [];
  const environmentKeys = new Set(['GATEWAY_URL', 'GATEWAY_CONFIGS_URL', 'CLIENT_AUTH_MODE',
    'REDEMPTION_CONNECTION_STRING', 'ISSUER_KEYS_URL', 'RELAY_GATEWAY_SECRET', 'REQUIRE_FDID',
    'TRUSTED_CLIENT_IP_HEADER', 'NODE_TLS_REJECT_UNAUTHORIZED', 'MAX_INFLIGHT', 'RATE_LIMIT_RPM',
    'RATE_WINDOW_MS', 'GW_TIMEOUT_MS', 'MAX_BODY_BYTES', 'MAX_RESP_BYTES', 'CONFIG_TTL_MS',
    ...Object.keys(overrides)]);
  const environment = new Map([...environmentKeys].map(name => [name, process.env[name]]));
  t.after(async () => {
    try {
      for (const client of clients) client.destroy();
      sharedAgent?.destroy();
      relay?.server?.closeAllConnections(); gateway?.closeAllConnections();
      await Promise.allSettled(clientPromises);
      await Promise.all([relay?.server, gateway].filter(Boolean)
        .map(server => new Promise(resolve => server.close(resolve))));
    } finally {
      process.stdout.write = originalWrite;
      https.Agent = Agent;
      for (const [name, value] of environment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      for (const [event, listener] of addedListeners) process.removeListener(event, listener);
    }
  });
  gateway = https.createServer({ key, cert }, (req, res) => {
    for (const name of ['x-azure-socketip', 'x-forwarded-for', 'authorization']) {
      assert.equal(req.headers[name], undefined, 'Client headers must never reach the gateway');
    }
    if (req.method === 'GET' && req.url === '/ohttp-configs') {
      const entry = { req, res, closed: false };
      req.socket.once('close', () => { entry.closed = true; });
      configs.push(entry);
    } else if (req.method === 'POST' && req.url === '/gateway') {
      gatewayPosts += 1;
      req.resume();
      res.writeHead(200, { 'Content-Type': 'message/ohttp-res' });
      res.end('opaque-response-fixture');
    } else { res.writeHead(404); res.end(); }
  });
  gateway.listen(0, '127.0.0.1');
  await once(gateway, 'listening');
  const endpoint = `https://127.0.0.1:${gateway.address().port}`;
  Object.assign(process.env, { GATEWAY_URL: endpoint + '/gateway', GATEWAY_CONFIGS_URL: endpoint + '/ohttp-configs',
    CLIENT_AUTH_MODE: 'off', REDEMPTION_CONNECTION_STRING: '', ISSUER_KEYS_URL: '', RELAY_GATEWAY_SECRET: '',
    REQUIRE_FDID: '', TRUSTED_CLIENT_IP_HEADER: 'x-azure-socketip', NODE_TLS_REJECT_UNAUTHORIZED: '0' });
  for (const name of ['MAX_INFLIGHT', 'RATE_LIMIT_RPM', 'RATE_WINDOW_MS', 'GW_TIMEOUT_MS',
    'MAX_BODY_BYTES', 'MAX_RESP_BYTES', 'CONFIG_TTL_MS']) delete process.env[name];
  Object.assign(process.env, overrides);
  process.stdout.write = function(chunk, ...args) {
    try {
      const entry = JSON.parse(String(chunk));
      if (entry.route) {
        logs.push(entry);
        if (typeof args.at(-1) === 'function') queueMicrotask(args.at(-1));
        return true;
      }
    } catch {}
    return originalWrite.call(this, chunk, ...args);
  };
  https.Agent = new Proxy(Agent, { construct(target, args) {
    const agent = Reflect.construct(target, args);
    if (args[0]?.maxSockets === 128) sharedAgent = agent;
    return agent;
  } });
  const listeners = Object.fromEntries(events.map(event => [event, new Set(process.listeners(event))]));
  try {
    const modulePath = require.resolve('./server.js');
    delete require.cache[modulePath];
    relay = require(modulePath);
  } finally {
    https.Agent = Agent;
    for (const event of events) for (const listener of process.listeners(event)) {
      if (!listeners[event].has(listener)) addedListeners.push([event, listener]);
    }
  }
  assert.ok(sharedAgent, 'Observe the actual source-created shared agent');
  const agentCount = field => Object.values(sharedAgent[field]).reduce((sum, entries) => sum + entries.length, 0);
  relay.server.on('request', req => {
    if (req.method === 'GET' && req.url === '/ohttp-configs') incomingConfigs += 1;
  });
  relay.server.listen(0, '127.0.0.1');
  await once(relay.server, 'listening');
  function request(route = '/ohttp-configs', body, identity = '192.0.2.1') {
    let request;
    const promise = new Promise((resolve, reject) => {
      const headers = { 'x-azure-socketip': identity, authorization: 'fixture-only-client-auth' };
      if (body !== undefined) Object.assign(headers, { 'Content-Type': 'message/ohttp-req',
        'Content-Length': Buffer.byteLength(body) });
      request = http.request({ host: '127.0.0.1', port: relay.server.address().port, path: route,
        method: body === undefined ? 'GET' : 'POST', headers, agent: false }, res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('error', reject);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers,
          body: Buffer.concat(chunks).toString() }));
      });
      clients.add(request);
      request.on('close', () => clients.delete(request));
      request.on('error', reject);
      request.end(body);
    });
    promise.catch(() => {});
    clientPromises.push(promise);
    return { request, promise };
  }
  function reply(index, status = 200, body = 'public-keys') {
    assert.ok(configs[index], 'Expected the gateway config request');
    configs[index].res.writeHead(status, { 'Content-Type': 'application/ohttp-keys' });
    configs[index].res.end(body);
  }
  async function joined(count, expectedDispatches = 1) {
    try { await within(() => incomingConfigs === count && configs.length >= 1, 'Config callers failed to arrive'); }
    catch (error) { throw Error(`${error.message}: incoming=${incomingConfigs};gateway=${configs.length};active=${agentCount('sockets')};queued=${agentCount('requests')}`); }
    await turn();
    assert.equal(agentCount('sockets'), expectedDispatches, 'Cold callers must share one gateway socket');
    assert.equal(agentCount('requests'), 0, 'Cold callers must not build an agent queue');
    assert.equal(configs.length, expectedDispatches, 'Concurrent callers must share the actual gateway GET');
  }
  return { logs, configs, request, reply, joined, gatewayPosts: () => gatewayPosts,
    incomingConfigs: () => incomingConfigs };
}

test('cold configs share one fetch and leave the pool available to an opaque POST', async t => {
  const f = await fixture(t);
  const readers = Array.from({ length: 128 }, () => f.request());
  await within(() => f.incomingConfigs() === 128, 'The initial callers must reach the relay');
  readers.push(f.request());
  await f.joined(129);
  const post = f.request('/relay', 'opaque-request-fixture', '198.51.100.2');
  const delivered = await post.promise;
  assert.equal(delivered.status, 200);
  assert.equal(delivered.body, 'opaque-response-fixture');
  assert.equal(f.gatewayPosts(), 1, 'Potential writes must never replay');
  f.reply(0);
  const responses = await Promise.all(readers.map(reader => reader.promise));
  for (const response of responses) {
    assert.equal(response.status, 200); assert.equal(response.body, 'public-keys');
    assert.equal(response.headers['content-type'], 'application/ohttp-keys');
  }
  const cached = await f.request().promise;
  assert.equal(cached.body, 'public-keys');
  assert.equal(f.configs.length, 1, 'A completed public config is cached');
  await turn();
  assert.equal(f.logs.filter(log => log.route === '/ohttp-configs' && log.status === 200).length, 130);
  assert.ok(!/192\.0\.2\.1|198\.51\.100\.2|x-azure-socketip|fixture-only-client-auth|opaque-request-fixture/.test(JSON.stringify(f.logs)));
});

test('one config caller disconnects without canceling another caller', async t => {
  const f = await fixture(t), first = f.request(), second = f.request();
  await f.joined(2);
  first.request.destroy();
  await within(() => f.logs.some(log => log.status === 499), 'Disconnected caller needs its own outcome');
  assert.equal(f.configs[0].closed, false, 'A remaining caller still owns the shared fetch');
  f.reply(0);
  const response = await second.promise;
  assert.equal(response.status, 200); assert.equal(response.body, 'public-keys');
  await turn();
  const outcomes = f.logs.filter(log => log.route === '/ohttp-configs');
  assert.deepEqual(outcomes.map(log => log.status).sort(), [200, 499]);
  assert.equal(outcomes.find(log => log.status === 499).reason, 'client_disconnect');
});

test('last config caller disconnect aborts the shared fetch and a later caller can retry', async t => {
  const f = await fixture(t), first = f.request(), second = f.request();
  await f.joined(2);
  first.request.destroy(); second.request.destroy();
  await within(() => f.configs[0].closed, 'Last disconnect must cancel outbound gateway work');
  assert.equal(f.logs.filter(log => log.status === 499).length, 2);
  const next = f.request();
  await within(() => f.configs.length === 2, 'An abandoned shared fetch must not stick');
  f.reply(1, 200, 'fresh-public-keys');
  assert.equal((await next.promise).body, 'fresh-public-keys');
});

test('shared gateway errors are not cached and the next caller retries once', async t => {
  const f = await fixture(t), first = f.request(), second = f.request();
  await f.joined(2);
  f.reply(0, 503, 'gateway-unavailable');
  const errors = await Promise.all([first.promise, second.promise]);
  assert.deepEqual(errors.map(response => response.status), [503, 503]);
  assert.ok(errors.every(response => response.body === 'gateway-unavailable'));
  const retry = f.request();
  await within(() => f.configs.length === 2, 'An error must not populate config cache');
  f.reply(1);
  assert.equal((await retry.promise).body, 'public-keys');
  assert.equal((await f.request().promise).body, 'public-keys');
  assert.equal(f.configs.length, 2);
});

test('coalesced config reads retain response-body and gateway-idle bounds', async t => {
  const f = await fixture(t, { MAX_RESP_BYTES: '32', GW_TIMEOUT_MS: '250' });
  let first = f.request(), second = f.request();
  await f.joined(2);
  f.reply(0, 200, 'x'.repeat(33));
  assert.deepEqual((await Promise.all([first.promise, second.promise])).map(value => value.status), [502, 502]);
  first = f.request(); second = f.request();
  await within(() => f.incomingConfigs() === 4 && f.configs.length === 2, 'Body failure must allow a new flight');
  assert.deepEqual((await Promise.all([first.promise, second.promise])).map(value => value.status), [502, 502]);
  assert.equal(f.logs.filter(log => log.reason === 'resp_too_large').length, 2);
  assert.equal(f.logs.filter(log => log.reason === 'gw_error' && log.code === 'ETIMEDOUT').length, 2);
  const retry = f.request();
  await within(() => f.configs.length === 3, 'Timeout must not stick or cache');
  f.reply(2);
  assert.equal((await retry.promise).body, 'public-keys');
});
