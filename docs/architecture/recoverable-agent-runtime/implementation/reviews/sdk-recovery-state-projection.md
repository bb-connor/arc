# SDK recovery state projection

The maintained Python host outcome now preserves the native effect, control and
release discriminants independently, and returns the exact fixed error code for
a typed transport error. Previously, selecting an advisory category erased these
distinctions. Existing categories, import paths and legacy construction remain
compatible. The added output fields are an intentional additive API change.

CrewAI tools and LangGraph checkpoints expose only these closed state values and
the existing opaque identifiers. Raw results, receipts, credentials and arbitrary
upstream diagnostics remain excluded. The projection grants no execution or
retry authority. TypeScript transport already preserved the native states; its
production implementation is unchanged.

Independent spec and quality reviews approved this bounded repair. The final
15-path source manifest has SHA-256
`f5229968b24565689fad61359a3fe4eded6a7d60a0a6dad113d2b5c7863157b5`.
The quality review has SHA-256
`395a27f937cc8c501a63efc13d958f2d4bd596173bbb40b9678aeb363149f482`.
Every maintained preimage was checked before installation.

## Verification on installed source

- Full Python SDK and recovery framework tests: 1,435 passed, zero failures.
- TypeScript recovery transport tests: 288 passed, zero failures or pending cases.
- TypeScript `tsc --noEmit`: passed.
- Final runs recorded zero attempted network operations and unchanged source.
- The candidate wheel includes the new module and preserves legacy class exports.
  All 259 package files match the reviewed source and isolated installation.
  Actual wheel imports passed state, session, error and compatibility controls.

The first maintained TypeScript run had a misconfigured audit-log destination.
Its test result alone was insufficient evidence. The corrected, separately saved
run passed with an empty type-check log and zero attempted connections. Earlier
candidate failures and runner configuration corrections are also preserved.

Exact records are under
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/sdk-recovery-states/`:
`source-freeze.json`, both independent reviews, `maintained-sdk-and-framework.json`,
`maintained-typescript-configured-checks.json`, and `package/smoke-result.json`.
The parameterized state combinations verify transport and projection, not that
every combination is reachable through native execution.

H-SDK-01 remains open. Current native control-plane/CLI projection, native product
host acceptance and provider campaign obligations are separate. This source and
local package repair does not qualify the runtime or hosted PR.
