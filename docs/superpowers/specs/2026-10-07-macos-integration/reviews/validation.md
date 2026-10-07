# Document validation scope

Validated on 2026-10-07. This record concerns the specification package, its synthetic schemas/examples and document checks. No product build, signed Mac installation, extension activation, runtime acceptance or release qualification is claimed.

## Checks executed

- `python3 docs/superpowers/specs/2026-10-07-macos-integration/verify.py --write-traceability --self-test`: passed. The package contains 41 Markdown documents, 323 normative requirements with acceptance/plan mappings, six schemas, 66 synthetic fixtures, 22 correlated request/response pairs and 15 validator self-checks. The output explicitly reports `runtime_qualification: false`.
- Embedded fenced examples: all 34 Python blocks parse with `ast.parse`, all 13 JSON blocks decode, and all eight Bash blocks pass `bash -n`. Parsing checks syntax only; future commands and product examples were not thereby executed.
- `cargo fmt --all -- --check`: passed against the assembled worktree. This documentation change introduces no Rust product source.
- Focused pure example checks were exercised during plan authoring: M0/M6 Python and Rust helpers, M4 host-side Rust oracle controls, and M3 guest descriptor C syntax/source-lock refusal helpers. These checks establish only the illustrated local logic, not integration, guest provenance, installed isolation or a qualified profile.
- Independent [contract review](contracts-review.md) and [platform review](platform-review.md): all six initial findings corrected and reinspected; no remaining P1/P2 findings in either reviewed scope.

The package command for subsequent checks is:

`python3 docs/superpowers/specs/2026-10-07-macos-integration/verify.py --self-test`

Dependency setup is in [contracts](../contracts/README.md). All normative AT procedures remain `specified_not_executed`. Whole-repository build/test/clippy, signed application execution, Apple entitlement approval, provider activation, VM boot, native kernel qualification and public release were not performed. Hosted review and check results belong to the live PR at its current commit and must be read there after every push.
