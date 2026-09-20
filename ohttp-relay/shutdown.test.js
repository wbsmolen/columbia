const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const http = require('node:http');
test('shutdown waits for disconnected authentication ownership then exits cleanly', { timeout: 10000 }, async t => {
  const source = `
    process.env.GATEWAY_URL='https://offline.invalid/gateway';process.env.CLIENT_AUTH_MODE='token';
    const crypto=require('node:crypto'),relay=require('./server');
    process.on('SIGTERM',relay.beginShutdown);
    const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048});relay.setIssuerKeysForTest(new Map([['fixture',pair.publicKey]]));
    const input=crypto.randomBytes(32),signature=crypto.sign('sha384',input,{key:pair.privateKey,padding:crypto.constants.RSA_PKCS1_PSS_PADDING,saltLength:48});
    const token=Buffer.from(JSON.stringify({keyId:'fixture',tokenInput:input.toString('base64'),signature:signature.toString('base64')})).toString('base64url');
    relay.setRedemptionStoreForTest({redeem:async()=>{process.send({event:'entered'});return new Promise(r=>process.once('message',()=>r(false)));}});
    relay.server.once('request',(_,res)=>res.once('close',()=>process.send({event:'closed'})));
    relay.server.listen(0,'127.0.0.1',()=>process.send({event:'ready',port:relay.server.address().port,token}));`;
  const child = spawn(process.execPath, ['-e', source], { cwd: __dirname, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  t.signal.addEventListener('abort', () => child.kill('SIGKILL'), { once: true });
  const messages = [], waiters = new Map();
  child.on('message', value => { messages.push(value); waiters.get(value.event)?.(value); });
  const event = name => messages.find(v => v.event === name) || new Promise(resolve => waiters.set(name, resolve));
  const exited = once(child, 'exit');
  try {
    const ready = await event('ready');
    const req = http.request({ hostname: '127.0.0.1', port: ready.port, path: '/relay', method: 'POST',
      headers: { 'Content-Type': 'message/ohttp-req', 'x-columbia-token': ready.token } });
    req.on('error', () => {}); req.end('opaque');
    await event('entered'); req.destroy(); await event('closed'); child.kill('SIGTERM');
    await new Promise(resolve => setTimeout(resolve, 60));
    assert.equal(child.exitCode, null, 'HTTP close cannot finish shutdown while authorization still owns work');
    child.send('finish'); assert.deepEqual(await exited, [0, null]);
  } finally { if (child.exitCode === null) child.kill('SIGKILL'); }
});
