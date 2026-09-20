const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
process.env.GATEWAY_URL = 'https://offline.invalid/gateway';
process.env.CLIENT_AUTH_MODE = 'token';
process.env.RATE_LIMIT_RPM = '0';
process.env.MAX_INFLIGHT = '1';
const relay = require('./server');
test('disconnect retains capacity until authentication settles, then unavailable state returns503', async () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  relay.setIssuerKeysForTest(new Map([['fixture', pair.publicKey]]));
  const input = crypto.randomBytes(32), signature = crypto.sign('sha384', input,
    { key: pair.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 });
  const token = 'PrivateToken ' + Buffer.from(JSON.stringify({ keyId: 'fixture', tokenInput: input.toString('base64'), signature: signature.toString('base64') })).toString('base64url');
  let entered, finish, calls = 0;
  const enteredPromise = new Promise(r => { entered = r; });
  relay.setRedemptionStoreForTest({ redeem: async () => {
    calls++;
    if (calls > 1) return false;
    entered(); return new Promise(r => { finish = r; });
  } });
  await new Promise(r => relay.server.listen(0, '127.0.0.1', r));
  const port = relay.server.address().port;
  function request(value = token) { return http.request({ hostname: '127.0.0.1', port, method: 'POST', path: '/relay',
    headers: { 'Content-Type': 'message/ohttp-req', 'x-columbia-token': value } }); }
  const status = value => new Promise((resolve, reject) => { const req = request(value); req.on('error', reject); req.on('response', res => { res.resume(); res.on('end', () => resolve(res)); }); req.end('opaque'); });
  try {
    const serverClosed = new Promise(resolve => relay.server.once('request', (_, res) => res.once('close', resolve)));
    const first = request(); first.on('error', () => {}); first.end('opaque');
    await enteredPromise;
    first.destroy(); await serverClosed;
    assert.equal((await status()).statusCode, 429, 'closed socket must not free still-running auth admission');
    assert.equal(calls, 1);
    finish(true);
    // A 429 is acceptable until the asynchronous close/auth settlement has run.
    let recovered;
    for (let i = 0; i < 20; i++) { recovered = await status('malformed'); if (recovered.statusCode !== 429) break; await new Promise(r => setTimeout(r, 5)); }
    assert.equal(recovered.statusCode, 401);
    relay.setRedemptionStoreForTest({ async redeem() { throw Error('offline unavailable'); } });
    const failure = await status(); assert.equal(failure.statusCode, 503); assert.equal(failure.headers['retry-after'], '2');
    assert.equal((await status('malformed')).statusCode, 401, 'failed auth releases capacity');
  } finally { relay.server.closeAllConnections(); await new Promise(r => relay.server.close(r)); }
});
