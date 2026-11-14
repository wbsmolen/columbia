import { fileURLToPath } from 'node:url';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

const here = path => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: './wrangler.toml' } })],
  resolve: {
    alias: {
      'node:test': here('./test/node-test-shim.js'),
      // token-issuer suites import it from their own directory; use this package's copy.
      '@cloudflare/blindrsa-ts': here('./node_modules/@cloudflare/blindrsa-ts/lib/src/index.js'),
    },
  },
  test: {
    include: ['test/*.test.js', '../../token-issuer/appattest.test.js', '../../token-issuer/epoch-keys.test.js'],
  },
});
