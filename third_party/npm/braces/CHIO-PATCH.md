# braces 3.0.3 nesting depth repair

Path fork of braces 3.0.3 (MIT), repairing GHSA-vfj7-8cjw-p6xm
(CVE-2026-93687, upstream issue micromatch/braces#70). `sdks/typescript`
reaches braces through micromatch 4.0.8 in Metro and Expo's `metro-file-map`,
part of the required peers of `@chio-protocol/mobile`.

## Provenance

- Archive: `https://registry.npmjs.org/braces/-/braces-3.0.3.tgz`,
  SHA-512 `yQbXgO/OSZVD2IsiLlro+7Hf6Q18EJrKSEsdoMzKePKXct3gvD8oLcOQdIzGupr5Fj+EDe8gO/lxc1BzfMpxvA==`
  (registry integrity), SHA-256
  `1cd18e862c8640b4568b1425a7df4ee030ff201d45b2da8f9f222d2987494ffc`.
- Patched archive: `braces-3.0.4-chio.1.tgz`, SHA-256
  `b06dc2a67dc1a6bc72e94729353a54832923b09968c1a06fc44b9c7689165673`.
- All 10 published files are retained.

## Delta

1. The parser throws `SyntaxError` when brace or parenthesis nesting exceeds
   `MAX_DEPTH` (100). The compile, expand and stringify walkers recurse once per
   nesting level of the parsed tree, so a pattern under the 10,000 character
   limit could nest deeply enough to exhaust the call stack and end the
   process with an uncaught `RangeError`.
2. `package.json` version is `3.0.4-chio.1`.

## Tests

`CHIO-PATCH.test.cjs` checks that ordinary and 99-level patterns compile and
expand, and that 4,000-level brace and parenthesis nesting raises
`SyntaxError` from `braces`, `parse`, `compile` and `expand`. Against the
registry archive, the depth test fails with `RangeError`.
