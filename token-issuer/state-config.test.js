import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('explicit durable policy prevents a production issuer from silently starting in memory', () => {
  const base = { ...process.env, ISSUER_STATE_CONNECTION_STRING: '', ISSUER_STATE_SALT: '' };
  const start = overrides => spawnSync(process.execPath, ['--input-type=module', '-e', "await import('./server.js')"], {
    cwd: fileURLToPath(new URL('.', import.meta.url)), env: { ...base, ...overrides }, encoding: 'utf8', timeout: 10000,
  });
  const required = start({ REQUIRE_DURABLE_STATE: '1' });
  assert.notEqual(required.status, 0);
  assert.match(required.stderr, /issuer_durable_state_required/);
  const invalid = start({ REQUIRE_DURABLE_STATE: 'true' });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /issuer_durable_state_policy_invalid/);
  const development = start({ REQUIRE_DURABLE_STATE: '0' });
  assert.equal(development.status, 0, development.stderr);
  // Valid Azure configuration constructs the durable backend without connecting;
  // runtime storage availability remains a typed 503 rather than memory fallback.
  const durable = start({ REQUIRE_DURABLE_STATE: '1',
    ISSUER_STATE_CONNECTION_STRING: 'DefaultEndpointsProtocol=https;AccountName=qualification;AccountKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;EndpointSuffix=core.windows.net',
    ISSUER_STATE_SALT: Buffer.alloc(32, 1).toString('base64') });
  assert.equal(durable.status, 0, durable.stderr);
});
