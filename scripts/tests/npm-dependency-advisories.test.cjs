// Qualify the installed registry fixes without executing injected shell input.
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const test = require('node:test');

const requireTooling = createRequire(path.resolve(
  process.env.CHIO_TOOLING_TEST_ROOT || 'sdks/typescript', 'package.json'));
const shellQuote = requireTooling('shell-quote');
const sharp = requireTooling('sharp');

test('shell-quote refuses line terminators after comment tokens', () => {
  // GHSA-pqg4-j6r4-53mv: the comment hides the opening quote of a later
  // string, allowing its line terminator to expose shell syntax.
  for (const terminator of ['\n', '\r', '\u2028', '\u2029']) {
    assert.throws(
      () => shellQuote.quote(['echo', 'ok', { comment: 'x' }, `a${terminator}id;#`]),
      TypeError);
    const parsed = shellQuote.parse('echo http://example.com/#fragment');
    assert.throws(() => shellQuote.quote(parsed.concat(`a${terminator}id;#`)), TypeError);
  }
});

test('shell-quote preserves ordinary quoting and multiline arguments without comments', () => {
  const tokens = ['echo', 'a b', "a'b", 'literal;syntax', 'first\nsecond'];
  assert.deepEqual(shellQuote.parse(shellQuote.quote(tokens)), tokens);
  assert.equal(shellQuote.quote(['echo', { comment: 'x' }, 'ordinary']), 'echo #x ordinary');
});

test('sharp uses repaired librsvg and decodes SVG through its native loader', async () => {
  // GHSA-wq5f-xc86-pv6w is fixed in the bundled librsvg 2.63.2. Check the
  // loaded runtime as well as the package lock, then exercise the SVG path.
  const version = sharp.versions.rsvg;
  assert.match(version, /^\d+\.\d+\.\d+$/);
  const [major, minor, patch] = version.split('.').map(Number);
  assert.ok(major > 2 || (major === 2 && (minor > 63 || (minor === 63 && patch >= 2))), version);
  const image = Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1" fill="#123456"/></svg>');
  const { data, info } = await sharp(image).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  assert.equal(info.width, 1);
  assert.equal(info.height, 1);
  assert.equal(info.channels, 4);
  assert.deepEqual([...data], [0x12, 0x34, 0x56, 0xff]);
});
