'use strict';

const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const test = require('node:test');

const workspace = createRequire(path.join(__dirname, '../../../sdks/typescript/package.json'));
const braces = workspace('braces');

const nested = (open, close, depth) => open.repeat(depth) + 'a,b' + close.repeat(depth);

test('the installed braces is the Chio repair', () => {
  assert.equal(workspace('braces/package.json').version, '3.0.4-chio.1');
});

test('ordinary patterns compile and expand unchanged', () => {
  assert.deepEqual(braces('a/{b,c}/d'), ['a/(b|c)/d']);
  assert.deepEqual(braces.expand('a/{b,{c,d}}/e'), ['a/b/e', 'a/c/e', 'a/d/e']);
  assert.equal(braces.expand(nested('{', '}', 99)).length, 2);
});

test('nesting beyond the depth limit is a SyntaxError, not stack exhaustion', () => {
  for (const [open, close] of [['{', '}'], ['(', ')']]) {
    for (const operation of [braces, braces.expand, braces.compile, braces.parse]) {
      assert.throws(() => operation(nested(open, close, 4000)), SyntaxError);
    }
  }
});
