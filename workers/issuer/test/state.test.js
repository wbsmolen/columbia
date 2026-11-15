// D1 device backend under the shared reservation state machine. Port of
// token-issuer/state-store.test.js with D1 in place of Azure Tables.
import { test } from 'vitest';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { env } from 'cloudflare:workers';
import { createIssuerState } from '../../../token-issuer/state-store.js';
import { d1DeviceBackend } from '../index.js';

const salt = Buffer.alloc(32, 7);
const registration = { keyId: 'canonical-key', mode: 'attestation', publicKeyPem: 'public-key-fixture', signCount: 0, epoch: 10, count: 2 };
const assertion = (signCount, count = 2) => ({ ...registration, mode: 'assertion', signCount, count });
const unavailable = { code: 'state_unavailable' };

// Wraps the binding so a write can fail before committing or commit and then
// lose its ACK, and so N concurrent reads can be held until all have read.
function flaky(db) {
  const faults = { failBefore: false, lostAck: false, holdReads: 0 };
  const held = [];
  const wrap = statement => ({
    statement,
    bind: (...args) => wrap(statement.bind(...args)),
    async first(...args) {
      const row = await statement.first(...args);
      if (faults.holdReads) await new Promise(resolve => {
        held.push(resolve);
        if (held.length === faults.holdReads) { faults.holdReads = 0; held.splice(0).forEach(release => release()); }
      });
      return row;
    },
    async run() {
      if (faults.failBefore) throw new Error('D1_ERROR: fixture');
      const result = await statement.run();
      if (faults.lostAck) { faults.lostAck = false; throw new Error('D1_ERROR: fixture'); }
      return result;
    },
  });
  return { faults, prepare: sql => wrap(db.prepare(sql)), batch: list => db.batch(list.map(s => s.statement)) };
}
const make = (db = env.ISSUER_DB, { keySalt = salt, quota = 6 } = {}) =>
  createIssuerState({ backend: d1DeviceBackend(db, { salt: keySalt }), salt: keySalt, quota });

test('a stale or duplicate write loses the compare-and-swap', async () => {
  const backend = d1DeviceBackend(env.ISSUER_DB, { salt });
  assert.equal(await backend.put('cas', null, { n: 1 }), true);
  assert.equal(await backend.put('cas', null, { n: 2 }), false, 'create over an existing row');
  const row = await backend.get('cas');
  assert.equal(await backend.put('cas', row.etag, { n: 3 }), true);
  assert.equal(await backend.put('cas', row.etag, { n: 4 }), false, 'update from a stale read');
  assert.deepEqual((await backend.get('cas')).value, { n: 3 });
});

test('competing issuer isolates reserve a counter and quota atomically', async () => {
  const db = flaky(env.ISSUER_DB), a = make(db), b = make(db);
  assert.deepEqual(await a.reserve(registration), { ok: true });
  await b.getAttestedKey(registration.keyId);
  db.faults.holdReads = 2; // both read signCount 0 before either writes
  const results = await Promise.all([a.reserve(assertion(1)), b.reserve(assertion(1))]);
  assert.equal(results.filter(v => v.ok).length, 1);
  assert.equal(results.find(v => !v.ok).reason, 'replayed_assertion');
  assert.equal((await b.getAttestedKey(registration.keyId)).signCount, 1);
  assert.equal((await b.reserve(assertion(2))).ok, true);
  assert.deepEqual(await a.reserve(assertion(3)), { ok: false, reason: 'quota_exceeded' });
  assert.equal((await a.getAttestedKey(registration.keyId)).signCount, 2, 'rejected quota cannot consume the counter');
});

test('re-registration preserves counters and quotas', async () => {
  const a = make(env.ISSUER_DB, { quota: 7 }), reg = { ...registration, keyId: 'rereg' }, as = n => ({ ...assertion(n), keyId: 'rereg' });
  await a.reserve(reg); await a.reserve(as(4)); await a.reserve(reg);
  assert.equal((await a.getAttestedKey('rereg')).signCount, 4);
  assert.equal((await a.reserve(as(5))).reason, 'quota_exceeded');
  assert.equal((await a.reserve({ ...reg, publicKeyPem: 'replacement' })).reason, 'key_mismatch');
  assert.equal((await a.reserve({ ...as(5), epoch: 11 })).ok, true);
  assert.equal((await a.reserve({ ...as(6), epoch: 10 })).reason, 'quota_exceeded');
});

test('an older isolate cannot erase a newer epoch quota at rollover', async () => {
  const a = make(env.ISSUER_DB, { quota: 4 }), reg = { ...registration, keyId: 'rollover' }, as = (n, c) => ({ ...assertion(n, c), keyId: 'rollover' });
  await a.reserve(reg);
  await a.reserve({ ...as(1, 4), epoch: 11 });
  assert.equal((await a.reserve(as(2))).ok, true);
  assert.equal((await a.reserve({ ...as(3), epoch: 11 })).reason, 'quota_exceeded');
  assert.equal((await a.reserve({ ...as(3), epoch: 12 })).ok, true);
  assert.equal((await a.reserve(as(4))).reason, 'expired_epoch');
});

test('lost-ACK insert/update does not double reserve; restart preserves state; changed salt fails closed', async () => {
  const db = flaky(env.ISSUER_DB), reg = { ...registration, keyId: 'lost-ack' }, as = n => ({ ...assertion(n), keyId: 'lost-ack' });
  const a = make(db);
  db.faults.lostAck = true;
  assert.equal((await a.reserve(reg)).ok, true);
  db.faults.lostAck = true;
  assert.equal((await a.reserve(as(1))).ok, true);
  const restarted = make();
  assert.equal((await restarted.getAttestedKey('lost-ack')).signCount, 1);
  assert.equal((await restarted.reserve(as(2))).ok, true);
  assert.equal((await a.reserve(as(3))).reason, 'quota_exceeded', 'two lost ACKs + one write charged exactly 6');
  const { results } = await env.ISSUER_DB.prepare('SELECT k, state FROM issuer_state').all();
  assert.ok(!JSON.stringify(results).includes('lost-ack'), 'device ids are stored only as salted HMACs');
  await assert.rejects(make(env.ISSUER_DB, { keySalt: crypto.randomBytes(32) }).getAttestedKey('lost-ack'), unavailable);
});

test('uncommitted storage errors are unavailable and leave state unchanged', async () => {
  const db = flaky(env.ISSUER_DB), reg = { ...registration, keyId: 'uncommitted' };
  const a = make(db);
  db.faults.failBefore = true;
  await assert.rejects(a.reserve(reg), unavailable);
  db.faults.failBefore = false;
  assert.equal((await a.reserve(reg)).ok, true);
  db.faults.failBefore = true;
  await assert.rejects(a.reserve({ ...assertion(1), keyId: 'uncommitted' }), unavailable);
  db.faults.failBefore = false;
  assert.equal((await a.getAttestedKey('uncommitted')).signCount, 0);
});

test('initialization failure stays typed unavailable and can recover', async () => {
  let failed = false;
  const db = { prepare: sql => env.ISSUER_DB.prepare(sql),
    batch: list => { if (!failed) { failed = true; throw new Error('D1_ERROR: fixture'); } return env.ISSUER_DB.batch(list); } };
  const a = make(db);
  await assert.rejects(a.getAttestedKey('init'), unavailable);
  assert.equal(await a.getAttestedKey('init'), null);
});

test('present corrupt rows fail closed without replacing registration', async () => {
  const a = make();
  await a.getAttestedKey('init');
  const key = crypto.createHmac('sha256', salt).update('corrupt').digest('hex');
  for (const state of ['not json', 'null', '{"version":2}']) {
    await env.ISSUER_DB.prepare('INSERT OR REPLACE INTO issuer_state (k, state, rev) VALUES (?, ?, 1)').bind(key, state).run();
    await assert.rejects(a.getAttestedKey('corrupt'), unavailable);
    await assert.rejects(a.reserve({ ...registration, keyId: 'corrupt' }), unavailable);
    assert.equal(await env.ISSUER_DB.prepare('SELECT state FROM issuer_state WHERE k = ?').bind(key).first('state'), state);
  }
});

test('a missing D1 binding or short salt is a configuration error', () => {
  assert.throws(() => d1DeviceBackend(undefined, { salt }), /issuer_state_salt_required/);
  assert.throws(() => d1DeviceBackend(env.ISSUER_DB, { salt: Buffer.alloc(16) }), /issuer_state_salt_required/);
});
