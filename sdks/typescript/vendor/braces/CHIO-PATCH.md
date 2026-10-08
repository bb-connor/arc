# Owned braces source repair

This private workspace preserves the upstream name, version 3.0.3, public
entry points, options and MIT license. It is a modified local source package,
not a newly fixed upstream release.

The npm archive at
<https://registry.npmjs.org/braces/-/braces-3.0.3.tgz> has SHA-256
`1cd18e862c8640b4568b1425a7df4ee030ff201d45b2da8f9f222d2987494ffc`.
Its JavaScript source matches upstream commit
`74b2db2938fad48a2ea54a9c8bf27a37a62c350d`.

GHSA-vfj7-8cjw-p6xm remains unfixed in the latest published upstream package
as checked October 7, 2026. The upstream report is
<https://github.com/micromatch/braces/issues/70>.

`CHIO-PATCH.patch` records the complete source and manifest delta. Parsing
rejects more than 100 nested brace/parenthesis blocks before recursive
processing. Compile, expand and stringify also bound direct caller-supplied
AST recursion, covering callers that bypass the string parser. Escaped,
quoted and bracket-literal braces retain their existing treatment. Excessive
nesting produces the controlled `RangeError` message `Maximum nesting depth
exceeded`; it does not consume the native call stack to its limit. This
intentionally bounds accepted nesting depth and does not promise unlimited
expansion output.

The private manifest removes upstream development dependencies and scripts
from the installed runtime package. Runtime dependencies are unchanged.
`CHIO-SOURCE-HASHES.sha256` records every installed runtime payload file.

`scripts/check-vendored-javascript.cjs` verifies these hashes and the actual
npm resolution, then exercises ordinary lists/ranges, escaped/quoted input,
the supported depth boundary, deep malformed strings and direct deep ASTs.
The original registry bytes pass the positive control and fail all six
targeted depth regressions. Source review and regression evidence close this
finding only for this exact owned workspace implementation.
