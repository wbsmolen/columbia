// Columbia - ohttp-relay self-test (Node built-ins only, no framework).
//
//   node test.mjs
//
// Drives the real server.js in-process against a local mock GATEWAY (https with a
// baked-in self-signed cert, because server.js refuses a non-https GATEWAY_URL).
// Because the test imports server.js (require.main !== module) the auto-listen
// stays dormant; we listen on an ephemeral port ourselves. It asserts:
//   (a) happy path: POST /relay forwards to the gateway and returns its response
//   (b) keep-alive race: the gateway RSTs a REUSED pooled socket -> the relay
//       reports 502 without replaying a potentially completed inner write
//   (c) mid-response gateway error -> relay answers 502 and does NOT crash
//   (d) after (c) the in-flight slot was released: with MAX_INFLIGHT=1 a further
//       request still succeeds (a leaked slot would 429 it)

import https from 'node:https';
import http from 'node:http';
import assert from 'node:assert/strict';

// Test-only self-signed key pair for the mock gateway (CN=127.0.0.1, 100y).
const KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWrJdp4ySCaaVK
TIvXI39CWkV5orlUFAWewcvFLNPU0P7G831Eukoofv9RROIevHKmDRlqLINOr+MP
BXcP43HGLD4hgr9ojEr92uUXJpmioZqsneA+j48yrWZy2jYHp24Ta/viMazLnDxf
1lXxW758tWrro1WyFVI44FgCAOgMJ4n0hFf2jWNe6BbNZ286vWbLTdg/gMYLog0s
L0ncm6EiQ+GYok4l0btAEsWRBcnwWr1Ks4Rh2mhSuQjltmI3ipCTsFkErSyukd7x
q20MiXDmejoUPzXPYxYO6vTd/O7FSfkZ/bbKk4lAVLjWeau2CK5unLXn0E+Fo98A
UxpT70fRAgMBAAECggEAEX//Vd/w5Xq0QULNMYwQvzl5qWlE/2AkdyUoNdoqKJKi
+lf2Eci36+YybQ8W+dd15yhxNnELgTogYeSZqJ9rcnK/2957OQwavuf9ve3lH1da
MxEpqx/r1f9Bt0InnmcdN5MZdP6ErhJ973gbCHJorGTjovLtNPe8/Kr5MayePgNC
1tdxUleZMleamM5V7AeBjS89QQG5eSo4qTTaLC2Mvf/udHQMpyfmitlmBblCS5p5
E8GcOpFa9PdYl9FZzyjN3YHqlSj61vxcHoF1ohuu3e+dIK6b1Y7PB+HtaRq3Ymno
xZgRludPs6770x0t+lS8YApFe+PtRjVlsfSNwVdnWQKBgQD4/VN6Bj7eeln3FBqR
a82T3GmB7DjoyETO2MamOtoze2whddBPOu0SrI9yzB9xadIUTVFcLbokfpTxa89y
lPM4zbSTfJjRme/x17NuDjvMdP5zT6DuvxNZF3ndg88RcqexrYPbRGg/gmgsTdzd
tzrPLtra9pQ4stzs1F0WUdmfJQKBgQDct+0UYimxSpTV1tIdTkHnK1N8MUKeR9vy
MCopDp0icU95lTMSYuBcQWKNxhuzgPZoJW7/65lBfUB0w5QCLcM11S8QKN05/r+h
TVtMeRO8LkeptzzofYJJedPiI2EWyzRe+aAD30CzwooHp0Fx/jHqCo/HuDeNlKrr
NO8CdLIsPQKBgQDo6UfCGL+Mq9UmXGbx6271xrPndgpSLqy29W71po3gpK6kqil/
Q/bqhgL19t3e4IdEuILIAHpkkwhOwXPfklfmpf4qDN6DC0W56/WLmML1Yed4BF/d
lV3K9DvqK9dyUdduTIrQfLAr4JgEAZ3+xNy9W+4b75b9Zstkus6NB2nUBQKBgC7Q
I8yK9WTQ+LhSE8Z7bqblHZPdrs97Vj8L0CVdIB7KAZ0789UWe5eVlp2TQxTTaW+1
YNGO2rZ1JlKdmKrNofWs/Ypj4GgIjAReL9sMYw8qkbCBWL3GwPdsi3APKOx4tObf
8vxfQY3e2P++jbbrvxJwowYtIDs7KPUyCO9waMnRAoGBAN97mgqTd0yP20P86kQJ
gXODaZAsMEqqy0AMyKZxoYANAWBqPOgr+vU7ftfrfVZJH8D4vnprLrQh6v+b3H1K
xIbpR4CzfwoMjqbVJNOeruw+tq1vxiqtaATtogHIfhHNpNITZxiKrWpbOtySrBix
d8Amv3RMa9xSl3rYCd2iBld0
-----END PRIVATE KEY-----`;
const CERT = `-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUGbBEOflRLDKkprh3fKp6sFHOMiAwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MDgwMjE4MzU0NFoYDzIxMjYw
NzA5MTgzNTQ0WjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDWrJdp4ySCaaVKTIvXI39CWkV5orlUFAWewcvFLNPU
0P7G831Eukoofv9RROIevHKmDRlqLINOr+MPBXcP43HGLD4hgr9ojEr92uUXJpmi
oZqsneA+j48yrWZy2jYHp24Ta/viMazLnDxf1lXxW758tWrro1WyFVI44FgCAOgM
J4n0hFf2jWNe6BbNZ286vWbLTdg/gMYLog0sL0ncm6EiQ+GYok4l0btAEsWRBcnw
Wr1Ks4Rh2mhSuQjltmI3ipCTsFkErSyukd7xq20MiXDmejoUPzXPYxYO6vTd/O7F
SfkZ/bbKk4lAVLjWeau2CK5unLXn0E+Fo98AUxpT70fRAgMBAAGjUzBRMB0GA1Ud
DgQWBBQvCI8G4MyfsZZSz3/WVpPnJU3udDAfBgNVHSMEGDAWgBQvCI8G4MyfsZZS
z3/WVpPnJU3udDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCm
7eCD868yBK055KMraiw58Qx7bTf/TscCgRbmuWscacocH642RpD5PcWPp59Gvall
674JwdbA6GsUadnkv6W6gEVV2le/+/WQjLyN5RbXrQP6Z2t5VMN8I6J63OeKwW9D
V4/twOt0KmvPuk9gb5+kPgmKw4cT1HImI6AJKaudkfHo9aLKh2tvwKlqrYa8EEmd
yHa/+czEq10+nAbo+HOtiWLMksbzigPrPtCPaInfIdFpI4sjejf3+OSDssR6h5I/
IE3ma8OIfQK4MF3j/HURcSgSPevpO5c1xnmlwwg4f0bD0MCHUO9LaRI2tZzdjU4k
1fkVDNflwAy+IrpGMsPC
-----END CERTIFICATE-----`;

// --- mock gateway: counts hits; per-request behavior scripted via a queue -----
let gwHits = 0;
const gwScript = []; // shift()ed per request; default answers 200
function gwOk(req, res) {
  res.writeHead(200, { 'Content-Type': 'message/ohttp-res' });
  res.end('gw-response');
}
const mockGw = https.createServer({ key: KEY, cert: CERT }, (req, res) => {
  gwHits++;
  (gwScript.length ? gwScript.shift() : gwOk)(req, res);
});
await new Promise((r) => mockGw.listen(0, '127.0.0.1', r));

// Environment must be in place BEFORE server.js is imported (config is read at
// module load). MAX_INFLIGHT=1 makes a leaked in-flight slot immediately fatal
// to the next request. The TLS override only trusts our own in-process mock.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
process.env.GATEWAY_URL = `https://127.0.0.1:${mockGw.address().port}/gateway`;
process.env.RATE_LIMIT_RPM = '0';
process.env.MAX_INFLIGHT = '1';
process.env.MAX_RESP_BYTES = '32';
process.env.GW_TIMEOUT_MS = '250';

const relay = (await import('./server.js')).default;
await new Promise((r) => relay.server.listen(0, '127.0.0.1', r));
const relayPort = relay.server.address().port;

function post() { return request('/relay', 'POST', 'opaque-ciphertext'); }
function configs() { return request('/ohttp-configs'); }

function request(path, method = 'GET', content) {
  const body = content === undefined ? undefined : Buffer.from(content);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: relayPort,
        path,
        method,
        headers: body === undefined ? {} : { 'Content-Type': 'message/ohttp-req', 'Content-Length': body.length },
      },
      (res) => {
        const cc = [];
        res.on('data', (d) => cc.push(d));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(cc).toString() }));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

async function within(promise, message) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), 2000);
    })]);
  } finally { clearTimeout(timer); }
}

const logs = [];
const relayLogs = [];
const originalWrite = process.stdout.write;
process.stdout.write = function(chunk, ...args) {
  try {
    const entry = JSON.parse(String(chunk));
    logs.push(entry);
    if (entry.route === '/relay') relayLogs.push(entry);
  } catch {}
  return originalWrite.call(this, chunk, ...args);
};

let failed = false;
try {
  // (a) happy path; also warms the keep-alive pool so (b) runs on a REUSED socket.
  let r = await post();
  assert.equal(r.status, 200, 'a: 200 from gateway');
  assert.equal(r.body, 'gw-response', 'a: gateway body relayed');
  assert.equal(gwHits, 1, 'a: exactly one gateway hit');

  // (b) The gateway received the request and may already have committed its
  //     opaque inner write before losing the response. Never replay it.
  gwScript.push((req) => { req.socket.destroy(); });
  r = await post();
  assert.equal(r.status, 502, 'b: ambiguous reset is surfaced without replay');
  assert.equal(gwHits, 2, 'b: exactly one dispatch despite reused socket reset');
  assert.deepEqual(relay.safeLogFields({ route: '/private/person?token=secret', message: 'private', stack: 'private', code: 'private', status: 403 }), { route: 'other', status: 403, code: 'other' });
  assert.equal(relay.safeLogFields({ route: '/relay', reason: 'capacity' }).reason, 'capacity');
  assert.equal(relay.safeLogFields({ route: '/relay', reason: 'rate_limit' }).reason, 'rate_limit');

  // (c) gateway dies MID-response body. Pre-fix this was an unhandled 'error'
  //     event on the response stream that killed the whole relay process.
  const logsBeforeReset = relayLogs.length;
  gwScript.push((req, res) => {
    res.writeHead(200, { 'Content-Type': 'message/ohttp-res', 'Content-Length': 99999 });
    res.write('partial');
    setTimeout(() => res.destroy(), 20);
  });
  r = await post();
  assert.equal(r.status, 502, 'c: mid-response gateway error -> 502');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(relayLogs.length - logsBeforeReset, 1, 'c: one outcome despite request/response teardown events');

  // (d) relay still alive AND the in-flight slot from (c) was released
  //     (MAX_INFLIGHT=1: a leaked slot would turn this into a 429).
  r = await post();
  assert.equal(r.status, 200, 'd: slot released, relay still serving');

  // (e) A client that disconnects after dispatch must cancel the pending
  //     gateway request, not merely free a slot while the work keeps running.
  let receivedResolve, closedResolve;
  const received = new Promise(resolve => { receivedResolve = resolve; });
  const gatewayClosed = new Promise(resolve => { closedResolve = resolve; });
  gwScript.push((req) => {
    req.socket.once('close', closedResolve);
    receivedResolve();
  });
  const abandoned = http.request({ host: '127.0.0.1', port: relayPort,
    path: '/relay', method: 'POST', headers: { 'Content-Type': 'message/ohttp-req' } });
  abandoned.on('error', () => {});
  abandoned.end('opaque-ciphertext');
  await within(received, 'e: mock gateway did not receive the request');
  const hitsAtDisconnect = gwHits;
  const logsAtDisconnect = relayLogs.length;
  abandoned.destroy();
  await within(gatewayClosed, 'e: disconnected relay left gateway work alive');
  assert.equal(gwHits, hitsAtDisconnect, 'e: client disconnect must not replay ciphertext');
  assert.equal(relayLogs.length - logsAtDisconnect, 1, 'e: cancellation produces one outcome');
  assert.equal(relayLogs.at(-1).reason, 'client_disconnect');
  assert.equal(relayLogs.at(-1).status, 499);
  r = await post();
  assert.equal(r.status, 200, 'e: cancellation releases the relay slot');

  // (f) An incomplete inbound upload must never dispatch ciphertext and must
  //     release its slot exactly once, including the pre-gateway abort path.
  let acceptedResolve, uploadClosedResolve;
  const accepted = new Promise(resolve => { acceptedResolve = resolve; });
  const uploadClosed = new Promise(resolve => { uploadClosedResolve = resolve; });
  relay.server.once('request', (req, res) => {
    res.once('close', uploadClosedResolve);
    acceptedResolve();
  });
  const upload = http.request({ host: '127.0.0.1', port: relayPort,
    path: '/relay', method: 'POST', headers: { 'Content-Type': 'message/ohttp-req', 'Content-Length': 100 } });
  upload.on('error', () => {});
  upload.write('partial');
  await within(accepted, 'f: relay did not receive partial upload');
  const hitsAtUpload = gwHits;
  const logsAtUpload = relayLogs.length;
  upload.destroy();
  await within(uploadClosed, 'f: relay did not close abandoned upload');
  assert.equal(gwHits, hitsAtUpload, 'f: incomplete ciphertext must not be dispatched');
  assert.equal(relayLogs.length - logsAtUpload, 1, 'f: upload abort produces one outcome');
  assert.equal(relayLogs.at(-1).reason, 'client_disconnect');
  r = await post();
  assert.equal(r.status, 200, 'f: aborted upload releases the relay slot');

  // (g) Both relay endpoints handle oversized bodies, partial resets, and timeouts
  //     with one bounded failure outcome. Config response errors used to be unhandled.
  for (const [route, send] of [['/relay', post], ['/ohttp-configs', configs]]) {
    for (const [reason, script] of [
      ['resp_too_large', (req, res) => { res.writeHead(200); res.end('x'.repeat(33)); }],
      ['gres_error', (req, res) => {
        res.writeHead(200, { 'Content-Length': 30 });
        res.write('partial');
        setTimeout(() => req.socket.destroy(), 25);
      }],
      ['gw_error', () => {}],
    ]) {
      const logsBefore = logs.length;
      const hitsBefore = gwHits;
      gwScript.push(script);
      r = await within(send(), `g: ${route} ${reason} did not terminate`);
      assert.equal(r.status, 502, `g: ${route} ${reason} -> 502`);
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(gwHits - hitsBefore, 1, 'g: gateway failure never replays a request');
      assert.equal(logs.length - logsBefore, 1, 'g: gateway failure logs one outcome');
      assert.equal(logs.at(-1).route, route);
      assert.equal(logs.at(-1).reason, reason);
      if (reason === 'gw_error') assert.equal(logs.at(-1).code, 'ETIMEDOUT');
    }
  }

  // (h) A disconnected public-config caller also cancels outbound work.
  let configReceivedResolve, configClosedResolve;
  const configReceived = new Promise(resolve => { configReceivedResolve = resolve; });
  const configClosed = new Promise(resolve => { configClosedResolve = resolve; });
  gwScript.push(req => {
    req.socket.once('close', configClosedResolve);
    configReceivedResolve();
  });
  const abandonedConfig = http.get({ host: '127.0.0.1', port: relayPort, path: '/ohttp-configs' });
  abandonedConfig.on('error', () => {});
  await within(configReceived, 'h: gateway did not receive config request');
  const logsBeforeConfigClose = logs.length;
  abandonedConfig.destroy();
  await within(configClosed, 'h: disconnected config caller left gateway work alive');
  assert.equal(logs.length - logsBeforeConfigClose, 1, 'h: config cancellation produces one outcome');
  assert.equal(logs.at(-1).route, '/ohttp-configs');
  assert.equal(logs.at(-1).reason, 'client_disconnect');
  assert.equal(logs.at(-1).status, 499);

  // (i) A fully received public config is cached, including its content type.
  //     None of the preceding failed responses may populate that cache.
  gwScript.push((req, res) => {
    assert.equal(req.method, 'GET');
    assert.equal(req.url, '/ohttp-configs');
    res.writeHead(200, { 'Content-Type': 'application/ohttp-keys' });
    res.end('public-keys');
  });
  r = await configs();
  assert.equal(r.status, 200, 'i: config endpoint recovers after gateway failures');
  assert.equal(r.body, 'public-keys');
  assert.equal(r.headers['content-type'], 'application/ohttp-keys');
  const hitsAtCache = gwHits;
  r = await configs();
  assert.equal(r.body, 'public-keys');
  assert.equal(gwHits, hitsAtCache, 'i: cache hit does not fetch the gateway again');

  console.log('PASS: all ohttp-relay self-tests passed (a-i)');
} catch (err) {
  failed = true;
  console.error('FAIL:', err.message);
} finally {
  process.stdout.write = originalWrite;
  relay.server.close();
  mockGw.close();
  process.exit(failed ? 1 : 0);
}
