# Process-host formatting and dependency-patch repair

The September 16 follow-up review reproduced two CI blockers at
`94e0da1fb758c6759dd78439a6d34d3358ba638a`. Both reproduce locally before this
repair. The candidate remains a draft and M5 acceptance remains incomplete.

## Changes

- Apply the workflow's direct Rust formatter to `process_host.rs` and its
  modules. This formats `run_evidence/native.rs`, `swarm/plan.rs` and `swarm.rs`.
- Retain the exact dependency repair as a zero-context patch, removing the
  space-only context markers that failed the accumulated candidate's whitespace
  gate. Document the required `git apply --unidiff-zero` invocation.

No runtime logic, dependency versions, audit criteria, deadlines, workflow
authority or execution-image pins change.

## Verification

All owning formatter checks pass:

```sh
rustfmt --edition 2021 --check crates/products/chio-cli/src/cli/process_host.rs
rustfmt --edition 2021 --check crates/products/chio-cli/src/cli/receipt_verify.rs
rustfmt --edition 2021 --check crates/products/chio-cli/src/cli/process_response_verify.rs crates/products/chio-cli/tests/process_response_verify.rs
cargo fmt -p chio-cli -- --check
cargo fmt --all -- --check
```

The old patch and its new representation were independently applied to fresh
copies of `src/lib.rs` extracted from the same checksum-verified
`enumflags2_derive-0.7.12.crate` archive. The new patch passes both the check and
apply forms of `git apply --unidiff-zero --whitespace=error-all`. Its result is
byte-identical to both the old patch's result and the retained previously
reviewed repaired source.

| Artifact | SHA-256 |
| --- | --- |
| Original crate archive | `67c78a4d8fdf9953a5c9d458f9efe940fd97a0cab0941c075a813ac594733827` |
| New patch representation | `d1cbdfdd755c67e9f7d65db24fa5526db7034f63e4569a019f615f3b1b3c8d3e` |
| Repaired source from either patch | `efe17e60fb3c1748e08492e7d782790b970d5586144a6da9515ff8525cadef40` |

Before/after command logs, exit codes, patch application results and extracted
source copies are retained under
`output/process-security-20260915/ci-hygiene-followup-94e0da1fb/`. The accumulated
candidate whitespace check is recorded there after the repair commit.

The full Linux foundation run remains frozen at `94e0da1fb`. Its build,
workspace formatting, generated security vectors, strict workspace Clippy and
proof coverage passed; workspace tests are executing without a terminal result
at this repair checkpoint. The follow-up inventories remain queued behind it.
These local CI repairs do not establish completion of either the hosted
process recovery lane or the cognition-market PostgreSQL qualification.
