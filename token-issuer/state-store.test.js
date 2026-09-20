import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { TableClient } from '@azure/data-tables';
import { createHttpHeaders } from '@azure/core-rest-pipeline';
import { memoryDeviceBackend, azureDeviceBackend, createIssuerState, ISSUER_STATE_CLIENT_OPTIONS } from './state-store.js';

const salt = Buffer.alloc(32, 7);
const registration = { keyId: 'canonical-key', mode: 'attestation', publicKeyPem: 'public-key-fixture', signCount: 0, epoch: 10, count: 2 };
const assertion = (signCount, count = 2) => ({ ...registration, mode: 'assertion', signCount, count });

test('competing issuer replicas reserve a counter and quota atomically', async () => {
  const backend = memoryDeviceBackend(), a = createIssuerState({ backend, salt, quota: 6 }), b = createIssuerState({ backend, salt, quota: 6 });
  assert.deepEqual(await a.reserve(registration), { ok: true });
  const results = await Promise.all([a.reserve(assertion(1)), b.reserve(assertion(1))]);
  assert.equal(results.filter(v => v.ok).length, 1);
  assert.equal(results.find(v => !v.ok).reason, 'replayed_assertion');
  assert.equal((await b.getAttestedKey(registration.keyId)).signCount, 1);
  assert.equal((await b.reserve(assertion(2))).ok, true);
  assert.deepEqual(await a.reserve(assertion(3)), { ok: false, reason: 'quota_exceeded' });
  assert.equal((await a.getAttestedKey(registration.keyId)).signCount, 2, 'rejected quota cannot consume the counter');
});

test('re-registration preserves counters and quotas; memory capacity never drops a live registration', async () => {
  const backend = memoryDeviceBackend({ maxKeys: 1 }), a = createIssuerState({ backend, salt, quota: 7 });
  await a.reserve(registration); await a.reserve(assertion(4)); await a.reserve(registration);
  assert.equal((await a.getAttestedKey(registration.keyId)).signCount, 4);
  assert.equal((await a.reserve(assertion(5))).reason, 'quota_exceeded');
  assert.equal((await a.reserve({ ...registration, publicKeyPem: 'replacement' })).reason, 'key_mismatch');
  await assert.rejects(a.reserve({ ...registration, keyId: 'different' }), { code: 'state_unavailable' });
  assert.equal((await a.getAttestedKey(registration.keyId)).signCount, 4);
  assert.equal((await a.reserve({ ...assertion(5), epoch: 11 })).ok, true);
  assert.equal((await a.reserve({ ...assertion(6), epoch: 10 })).reason, 'quota_exceeded');
});

test('an older replica cannot erase a newer epoch quota at rollover', async () => {
  const a = createIssuerState({ backend: memoryDeviceBackend(), salt, quota: 4 });
  await a.reserve(registration);
  await a.reserve({ ...assertion(1, 4), epoch: 11 });
  assert.equal((await a.reserve(assertion(2))).ok, true);
  assert.equal((await a.reserve({ ...assertion(3), epoch: 11 })).reason, 'quota_exceeded');
  assert.equal((await a.reserve({ ...assertion(3), epoch: 12 })).ok, true);
  assert.equal((await a.reserve(assertion(4))).reason, 'expired_epoch');
});

function fakeAzure() {
  const rows = new Map(); let revision = 0;
  const client = {
    lostAck: false, failBefore: false,
    async createTable() {},
    async getEntity(pk, key) { if (!rows.has(key)) throw { statusCode: 404 }; return structuredClone(rows.get(key)); },
    async createEntity(entity) {
      if (client.failBefore) throw { statusCode: 503 };
      if (rows.has(entity.rowKey)) throw { statusCode: 409 };
      rows.set(entity.rowKey, { ...entity, etag: String(++revision) });
      if (entity.rowKey !== 'config' && client.lostAck) { client.lostAck = false; throw { statusCode: 503 }; }
    },
    async updateEntity(entity, mode, options) {
      if (client.failBefore) throw { statusCode: 503 };
      if (rows.get(entity.rowKey)?.etag !== options.etag) throw { statusCode: 412 };
      rows.set(entity.rowKey, { ...entity, etag: String(++revision) });
      if (client.lostAck) { client.lostAck = false; throw { statusCode: 503 }; }
    },
    rows,
  };
  return client;
}

test('Azure lost-ACK create/update does not double reserve; restart preserves state; changed salt fails closed', async () => {
  const client = fakeAzure();
  const make = (keySalt = salt) => createIssuerState({ backend: azureDeviceBackend(client, { salt: keySalt }), salt: keySalt, quota: 6 });
  const a = make(); client.lostAck = true;
  assert.equal((await a.reserve(registration)).ok, true);
  client.lostAck = true;
  assert.equal((await a.reserve(assertion(1))).ok, true);
  const restarted = make(); assert.equal((await restarted.getAttestedKey(registration.keyId)).signCount, 1);
  assert.equal((await restarted.reserve(assertion(2))).ok, true);
  assert.equal((await a.reserve(assertion(3))).reason, 'quota_exceeded');
  const serialized = JSON.stringify([...client.rows]); assert.ok(!serialized.includes(registration.keyId));
  await assert.rejects(make(crypto.randomBytes(32)).getAttestedKey(registration.keyId), { code: 'state_unavailable' });
});

test('uncommitted storage errors are unavailable; configuration can retry without accepting a request', async () => {
  const client = fakeAzure(); client.failBefore = true;
  const a = createIssuerState({ backend: azureDeviceBackend(client, { salt }), salt });
  await assert.rejects(a.reserve(registration), { code: 'state_unavailable' });
  client.failBefore = false; assert.equal((await a.reserve(registration)).ok, true);
  client.failBefore = true; await assert.rejects(a.reserve(assertion(1)), { code: 'state_unavailable' });
  client.failBefore = false; assert.equal((await a.getAttestedKey(registration.keyId)).signCount, 0);
  const get = client.getEntity;
  client.getEntity = async (pk, key) => {
    if (key !== 'config') throw { statusCode: 404, code: 'TableNotFound' };
    return get(pk, key);
  };
  await assert.rejects(a.getAttestedKey(registration.keyId), { code: 'state_unavailable' },
    'a deleted/unavailable table is not an unknown device registration');
});

test('initial table failure stays typed unavailable for assertion lookup and can recover', async () => {
  const client = fakeAzure(); let failed = false;
  client.createTable = async () => { if (!failed) { failed = true; throw { statusCode: 503, code: 'ServerBusy' }; } };
  const a = createIssuerState({ backend: azureDeviceBackend(client, { salt }), salt });
  await assert.rejects(a.getAttestedKey(registration.keyId), { code: 'state_unavailable' });
  assert.equal(await a.getAttestedKey(registration.keyId), null);
  assert.equal((await a.reserve(registration)).ok, true);
});

test('invalid quotas and present corrupt rows fail closed without replacing registration', async () => {
  for (const quota of [NaN, -1, Infinity, 0.5]) {
    assert.throws(() => createIssuerState({ backend: memoryDeviceBackend(), salt, quota }), /issuer_state_configuration/);
  }
  for (const value of [null, false, 0, undefined, { version: 2 }]) {
    let writes = 0;
    const a = createIssuerState({ salt, backend: { async get() { return { etag: 'exists', value }; }, async put() { writes++; } } });
    await assert.rejects(a.getAttestedKey(registration.keyId), { code: 'state_unavailable' });
    await assert.rejects(a.reserve(registration), { code: 'state_unavailable' });
    assert.equal(writes, 0);
  }
});

test('real SDK preserves an ambiguous write ACK after a peer advances the reservation', async () => {
  const client = fakeAzure(); let attempts = 0;
  const transport = { async sendRequest(request) {
    attempts++;
    const entity = JSON.parse(request.body), current = client.rows.get(entity.RowKey);
    const response = (status, code) => ({ request, status,
      headers: createHttpHeaders({ 'Content-Type': 'application/json' }),
      bodyAsText: JSON.stringify({ 'odata.error': { code, message: { lang: 'en-US', value: 'offline fixture' } } }) });
    if (current?.etag !== request.headers.get('if-match')) return response(412, 'UpdateConditionNotSatisfied');
    // A's write commits, its ACK is lost, and B advances the same row before
    // A's readback. A transparent SDK retry must not turn the 503 into a 412
    // that the explicit CAS loop could interpret as an uncommitted attempt.
    const peer = JSON.parse(entity.state);
    peer.commitID = 'peer-fixture'; peer.signCount = 1; peer.quota['10'] += 2;
    client.rows.set(entity.RowKey, { partitionKey: entity.PartitionKey, rowKey: entity.RowKey,
      state: JSON.stringify(peer), etag: 'peer-etag' });
    return response(503, 'ServerBusy');
  } };
  const sdk = new TableClient('https://offline.invalid', 'IssuerState', {
    ...ISSUER_STATE_CLIENT_OPTIONS, httpClient: transport });
  client.updateEntity = (...args) => sdk.updateEntity(...args);
  const state = createIssuerState({ backend: azureDeviceBackend(client, { salt }), salt, quota: 100 });
  await state.reserve(registration);
  await assert.rejects(state.reserve(registration), { code: 'state_unavailable' });
  const stored = JSON.parse([...client.rows.values()].find(row => row.state).state);
  assert.equal(attempts, 1);
  assert.equal(stored.quota['10'], 6, 'one A reservation and one peer reservation, with no duplicate A charge');
  assert.equal(stored.signCount, 1);
});

test('a hung Azure operation observes the shared deadline and leaves state unavailable', async () => {
  let aborted = false;
  const client = fakeAzure();
  client.createTable = options => new Promise(() => {
    options.abortSignal.addEventListener('abort', () => { aborted = true; }, { once: true });
  });
  const state = createIssuerState({ backend: azureDeviceBackend(client, { salt }), salt, operationTimeoutMs: 25 });
  await assert.rejects(state.getAttestedKey(registration.keyId), { code: 'state_unavailable' });
  assert.equal(aborted, true);
  assert.equal(client.rows.size, 0);
});

test('server configuration cannot truncate a fractional quota into disabled enforcement', async () => {
  const { spawnSync } = await import('node:child_process');
  const run = spawnSync(process.execPath, ['--input-type=module', '-e', "await import('./server.js')"], {
    cwd: new URL('.', import.meta.url), encoding: 'utf8', env: { ...process.env, ISSUANCE_QUOTA_PER_EPOCH: '0.5' },
  });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /issuer_state_configuration/);
});
