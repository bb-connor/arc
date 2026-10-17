import assert from 'node:assert/strict';
import test from 'node:test';

import { receiptHexToJson } from '../dist/index.js';

test('receiptHexToJson decodes prefixed hexadecimal input to text', () => {
  assert.equal(receiptHexToJson('0x7b2261223a317d'), '{"a":1}');
});

test('receiptHexToJson rejects malformed input', () => {
  assert.throws(() => receiptHexToJson('abc'), /even number/);
  assert.throws(() => receiptHexToJson('zz'), /hexadecimal/);
  assert.throws(() => receiptHexToJson('ff'), TypeError);
});
