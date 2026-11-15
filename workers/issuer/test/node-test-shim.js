// Lets the runtime-neutral token-issuer suites (written for node:test) run
// unchanged inside workerd under vitest.
import { test } from 'vitest';
export default test;
export { test };
