# Local execution evidence

Source checkout: `/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.
Base: `8c8677470b6ff40491c0f66ac6aba31093be30bf`.
Reviewed implementation: `a8b5f11d3e`. Emergency-stop fix: `f965330c2a`.
Final fixture source: `c2015692b5d8f4a8027c6ef6f7f4c4b97b5480df`.
Host: aarch64 Linux, Rust 1.94.1, `CARGO_INCREMENTAL=0`.

The [execution record](../../2026-09-29-native-clock-test-ownership-execution.md)
is the task-level acceptance record. This directory retains actual successes,
failures and interrupted diagnostics. Filenames containing `green` or `final`
do not establish success; consult the terminal summaries and exit codes.

## Navigation and limits

- [Verification index](verification-index.json): terminal test commands and counts,
  additional checks, source scope and unperformed qualification.
- [Native reconciliation](native-qualification.json): 143 selected names, each with
  a passing latest result. The full campaign was 140 passed/3 failed, exit 101.
  Focused repairs were 7 passed/1 failed; the final runtime case subsequently
  passed. This is composite local evidence, not one passing final full campaign.
- [Native executable record](native-campaign-executable.json): the running build17
  executable was renamed intact before rebuilding review fixes. Subprocess tests
  continued using that same candidate. The scratch binary is not distributed.
- [Review](final-review.md): one fresh review, two Important findings, both fixed
  and qualified as recorded in the execution report; no deferred Minor findings.
- [Ledger](progress.md): chronological implementation evidence and all nine rulings,
  including costs if wrong and verification scope decisions.
- [Kernel body preservation](kernel-test-body-preservation.json) and
  [compiled inventory](kernel-inventory-preservation.json): all 845 original
  scenario bodies and 1,491 original compiled cases retained, plus the new
  emergency-stop regression. Source/body comparisons ignore formatting, imports
  and optional trailing commas. The original source snapshot, relocation maps,
  test inventories and comparison scripts are retained for inspection.
- [Identity pins](shared-identity-pins.json): 43 identifier/canonical payload hash
  pins. These are identifier identity checks; production payload behavior is
  covered by the selected owning suites. [Relocations](declaration-relocations.json)
  record the declaration moves.
- [Build results](build-results.json): compiler diagnostics and terminal
  `build-finished` records, including failed attempts. Matching human-readable
  build logs are retained. Large intermediate Cargo artifact rows were omitted.
- [Checksums](sha256.json): SHA256 of every other file in this evidence directory.

Earlier SQLite/identifier runs used the selected owners before final caller/IPC
and fixture repairs. Those selected production owners did not change in the
finishing repairs. Native full campaign uses build17; focused repairs use build20;
runtime diagnostic and final runs use builds21/22 respectively. Build22's only
subsequent Rust change was formatting. The final kernel run includes the
emergency-stop repair. Strict package Clippy preceded the last fixture history
query correction; the kernel test-target Clippy and final formatting/hygiene/
assertion checks passed afterward. See the execution report for exact boundaries.

`native-flow-tests.log` and `native-flow-superseded.log` are interrupted campaigns,
not successful runs. `kernel-superseded.log` retains six fixture clock-domain
failures. `runtime-expiry-stale-observation.log` retains the intermediate history
query failure after the intended production expiry and rollback assertions.
`emergency-stop-red.log` fails the stop-latch assertion, and its green counterpart
and the final 1,492-case kernel suite establish the repair. Historical diagnostic
logs retain their original names even where an anticipated green run failed.
`format-last-final.log` records the last fixture formatting differences; the
subsequent `format-complete-final.log` is a successful check with empty output.
Verbatim libtest logs retain their terminal blank lines. The authored-file Git
whitespace check excludes these raw logs; no captured output was trimmed.

## Reproduction scope

Compile the selected targets from the repository root using:

```sh
CARGO_INCREMENTAL=0 cargo test --locked \
  -p chio-control-plane -p chio-kernel -p chio-core-types -p chio-security-types \
  -p chio-fincred -p chio-settle -p chio-runtime-core -p chio-runtime \
  -p chio-runtime-proof-parity -p chio-active-response-authority -p chio-store-sqlite \
  --lib --test durable_admission_sqlite --test caller_execution_ledger \
  --no-run --message-format=json
```

The result JSON files record the actual direct-binary invocations and durations.
`run-targets.py` documents the grouped selections, but its `binaries.json` paths
belong to the original checkout. Regenerate executable paths from Cargo's
`compiler-artifact` output before reuse in another checkout. No binary is archived.

PQ-only execution (36 selectors), the full final workspace, native x86_64,
AWS-LC audits, hosted workflows, publication/install closure, broker transaction
performance and M5/operational acceptance remain separately queued. No push,
merge, publication or activation occurred in this batch.
