import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
test('issuer shutdown waits for disconnected assertion lookup before clean exit', { timeout: 10000 }, async t => {
  const source = `
    import crypto from 'node:crypto';
    import { makeAttestationFixture,makeAssertion } from './appattest-fixtures.js';
    const appId='ABCDE12345.com.example.app',epoch=Math.floor(Date.now()/1000/604800),blinded=crypto.randomBytes(256);
    const challenge=Buffer.concat([Buffer.from(String(epoch)),Buffer.from([0]),blinded]);
    const fixture=makeAttestationFixture({appId,challenge});
    Object.assign(process.env,{APPLE_APP_ATTEST_ROOT_CA_PEM_B64:fixture.rootPemB64,APPLE_TEAM_ID:'ABCDE12345',APPLE_BUNDLE_ID:'com.example.app',APPLE_APP_ATTEST_AAGUID:'appattest',
      ISSUER_SIGNING_KEY:crypto.generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'pem',type:'pkcs8'})});
    const issuer=await import('./server.js');process.on('SIGTERM',issuer.beginShutdown);
    issuer.ISSUER_STATE.getAttestedKey=async()=>{process.send({event:'entered'});return new Promise(r=>process.once('message',()=>r(null)));};
    const proof=makeAssertion({appId,credPrivateKey:fixture.credKey.privateKey,signCount:1,challenge});
    const body=JSON.stringify({keyId:fixture.keyIdB64,assertion:proof.assertionB64,clientDataHash:proof.clientDataHashB64,blinded:[blinded.toString('base64')]});
    issuer.server.once('request',(_,res)=>res.once('close',()=>process.send({event:'closed'})));
    issuer.server.listen(0,'127.0.0.1',()=>process.send({event:'ready',port:issuer.server.address().port,body}));`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], {
    cwd: fileURLToPath(new URL('.', import.meta.url)), stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  t.signal.addEventListener('abort', () => child.kill('SIGKILL'), { once: true });
  const messages = [], waiters = new Map();
  child.on('message', value => { messages.push(value); waiters.get(value.event)?.(value); });
  const event = name => messages.find(v => v.event === name) || new Promise(resolve => waiters.set(name, resolve));
  const exited = once(child, 'exit');
  try {
    const ready = await event('ready');
    const req = http.request({ hostname: '127.0.0.1', port: ready.port, path: '/issue', method: 'POST',
      headers: { 'Content-Type': 'application/json' } });
    req.on('error', () => {}); req.end(ready.body);
    await event('entered'); req.destroy(); await event('closed'); child.kill('SIGTERM');
    await new Promise(resolve => setTimeout(resolve, 60));
    assert.equal(child.exitCode, null, 'HTTP close cannot abandon an assertion lookup');
    child.send('finish'); assert.deepEqual(await exited, [0, null]);
  } finally { if (child.exitCode === null) child.kill('SIGKILL'); }
});
