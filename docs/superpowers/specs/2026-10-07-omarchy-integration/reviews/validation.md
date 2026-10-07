# Documentation validation record

Date: 2026-10-07. Scope: this proposed research/specification/plan package.
No plugin, controller, native adapter, confinement runtime or release was installed
or implemented by this change. All AT-* runtime cases remain proposed.

## Checks

| Check | Result and scope |
| --- | --- |
| Package verifier with self-test | Passed: 17 specs, 209 requirement/acceptance mappings, 6 schemas, 47 fixtures, 156 response substitutions and 4 validator mutants; documents/synthetic shapes only |
| Source research | Omarchy release/development source, public Pi/native source crosswalk, OMCP and Linux/systemd/Arch primary references inspected and pinned where available |
| Proposed plugin manifest | Passed the inspected upstream structural validator using temporary placeholder entry files; no QML behavior qualified |
| Independent review | All identified P2 issues addressed and re-reviewed; [finding record](independent-review.md) |
| Runner example regression | Eight extracted-sample component tests passed on macOS arm64; no Linux runtime conclusion |
| Python/JSON syntax | 24 proposed Python plan snippets and the validator parsed; 58 JSON documents parsed |
| `cargo fmt --all -- --check` | Passed |
| `cargo build --workspace` | Failed on pre-existing finding-worker product imports and missing method |
| `cargo test --workspace` | Failed during compilation on the same finding-worker product surface; no workspace test-pass claim |
| `cargo clippy --workspace -- -D warnings` | Failed during compilation on the same finding-worker product surface |

The Rust failures are outside this documentation diff. No Rust, Cargo manifest or
lockfile changes are included. The checked-out baseline failed with unresolved
imports from `chio_finding_worker` in
`crates/products/chio-finding-worker/src/main.rs` and
`crates/products/chio-finding-market-canary/src/main.rs`, plus missing
`FindingHostedProfile::load_worker_executor`. Build/test/clippy exited 101;
format checking exited 0. These failures were not repaired as part of the Omarchy
research proposal.

## Reproducible document command

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --write-traceability --self-test
git diff --check
```

Use Python 3.11+ with jsonschema 4.21.1. The verifier checks all numbered requirement
rows against their acceptance definitions, generated traceability, local Markdown
links/anchors, six JSON schemas, positive/negative fixtures and cross-method
response substitutions. Its mutation checks remove an acceptance heading,
duplicate a requirement, break a link and corrupt a positive fixture.

The committed [document-validation.json](document-validation.json) is the final
structural-check output. It is deliberately not a `release-evidence` artifact,
native receipt or proof that a named acceptance case executed. Hosted CI and
release publication are not asserted by this record.
