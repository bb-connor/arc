# Documentation validation record

Date: 2026-10-07. Scope: this proposed research/specification/plan package.
No plugin, controller, native adapter, confinement runtime or release was installed
or implemented by this change. All AT-* runtime cases remain proposed.

## Checks

| Check | Result and scope |
| --- | --- |
| Package verifier with self-test | Passed: 17 specs, 209 requirement/acceptance mappings, 6 schemas, 77 fixtures, 156 response substitutions and 28 validator mutants; documents/synthetic shapes only |
| Source research | Omarchy release/development source, public Pi/native source crosswalk, OMCP and Linux/systemd/Arch primary references inspected and pinned where available |
| Proposed plugin manifest | Passed the inspected upstream structural validator using temporary placeholder entry files; no QML behavior qualified |
| Independent review | All identified P2 issues addressed and re-reviewed; [finding record](independent-review.md) |
| Runner example regression | 24 persistent extracted-sample component tests passed on macOS arm64: launch refusal, bounded process cleanup, phase parser and package inventory; no Linux runtime conclusion |
| Python/JSON syntax | 24 Python snippets and the validator/regression script parsed; 5 JSON snippets decoded, 8 Bash snippets passed syntax checks; 88 JSON documents parsed |
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
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --write-traceability --self-test --write-validation
git diff --check
```

Use Python 3.11+ with the pinned [format-validation dependencies](../contracts/requirements-validation.txt); see the [isolated setup](../contracts/README.md). The verifier checks all numbered requirement
rows against their acceptance definitions, generated traceability, local Markdown
links/anchors, six JSON schemas, positive/negative fixtures and cross-method
response substitutions. It decodes all package JSON, rejects duplicate keys and
non-JSON constants, checks positive/negative requests for all 13 methods, and
classifies selected, unsupported and mismatched Hello versions. Its mutation
checks also cover malformed source pins/validation records, stale counts/content,
missing per-method negatives, wrong Hello outcomes and absent date-time checking.

The committed [document-validation.json](document-validation.json) is the final
structural-check output with a digest of package paths and content; normal
validation rejects stale records. Self-test results are reported separately by
the command and must pass before `--write-validation` can refresh the record. It is deliberately not a `release-evidence` artifact,
native receipt or proof that a named acceptance case executed. Hosted CI and
release publication are not asserted by this record.

## Review repair verification

All eight first-round hosted findings are addressed: the proposed package contains
the navigation opener and desktop/menu registration, launch failures retain named
prerequisite evidence, P0 through P7 parse, all package JSON is validated, task
evidence retains its native owner, unsupported Hello versions can negotiate a
typed refusal, each known method has negative request coverage, and date-time
validation has its required dependency. Strict string-end cases reject trailing
newlines in protocol/native/UUID/digest identifiers.

Re-run the retained extracted regressions from the repository root:

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/distribution-review-regressions.py
bash scripts/check-chio-proof-room-release-truth.sh
```

Both commands pass locally. The release-copy wording failure in plan 01 was
corrected by enumerating the controls whose navigation behavior must be checked.
The component suite does not execute the future Linux qualifier, build an Arch
package or close any proposed runtime acceptance.
