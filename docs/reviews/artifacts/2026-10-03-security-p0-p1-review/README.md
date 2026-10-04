# Security P0/P1 review evidence

Review base: `a99437b3ea8ef7ea03c7d2926049b27cb140b3c5` on
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.

The five accepted repairs are locally qualified. This archive preserves every
terminal command, including failed setup, compile, regression and owner runs.
It does not convert those failures into a clean original campaign.

## Accepted owner evidence

| Command record | Terminal result and scope |
| --- | --- |
| `security-owner-libraries` | Exit 101. API-protect: 255 passed. MCP: 126 passed, 7 fixture failures. SQLite: 1,930 passed, 15 fixture failures, 3 ignored. All production repairs were present. |
| `mcp-siem-owner-recheck` | Exit 0. MCP: all 133 tests passed after fixture initialization matched HTTP. SIEM: all 155 tests passed, including one documentation test, both paging HTTP backends and the corrected timeout assertion. |
| `storage-final-regressions` | Exit 0. All 20 retained export/query and destructive-retention cases passed, including final source/lineage ambiguity variants, allocator ceilings, native page boundary, dependency race and verified ceiling. |
| `storage-authority-fixtures-recheck` | Exit 0. All 32 DPoP and approval custody cases passed, including the new wire-only proof positive control and both sync/async missing-proof refusals. |
| `budget-owner-recheck` | Exit 0. All 146 budget library cases passed after threshold binding and private-directory fixture corrections. |
| `schema-owner-recheck` | Exit 0. All 15 schema cases passed after the store-opening fixture supplied the required private directory. |
| `threshold-lifecycle-recheck` | Exit 0. All 10 integration tests sharing the corrected threshold fixture passed. |
| `release-identity-controls-with-tool` | Exit 0. Nine local release-identity cases passed using real cosign 2.4.1. This is fixture evidence, not hosted Fulcio/Rekor or release publication. |
| `frost-independent-vectors` | Exit 0. All 20 independent FROST vector checks passed. |

`failure-reconciliation.json` maps every one of the 22 failed MCP/SQLite tests
to an exact-name passing rerun. The original SQLite campaign was not repeated
in full after test-only fixture corrections. Three cases remain ignored:

- `receipt_store::tests::scale_proof::append_scale_proof_is_batch_bounded_across_history_sizes`
- `receipt_store::tests::scale_recovery::million_receipts_preserve_integrity_queries_retention_and_restore`
- `serving_owner::tests::serving_owner_child_process` (a subprocess helper)

The ignored scale cases are not performance or million-receipt acceptance.

## Source gates and review

- `strict-clippy`: all targets for all four changed production crates passed
  with `-D warnings`. `final-storage-clippy` rechecked all SQLite targets after
  the last fixture edit and passed. Cargo's unused patch notices remain in logs.
- `final-format` and `final-hygiene`: passed on final source.
- `budget-fixture-negative`: passed with the existing 1,254-assertion debt
  unchanged. The subsequent schema fixture edit adds no assertion.
- `security-clocks`: passed with existing debt unchanged; no production clock
  edits followed. This does not claim the historical debt is eliminated.
- `dependency-budget`: passed, with no new denied packages. Percent encoding
  uses the already locked dependency version.
- `trust-boundaries-reviewed`: passed after explicitly reviewing only the
  changed SQL contracts in the two receipt-integrity adapters. The initial
  inventory failure remains archived. No blanket baseline refresh was used.
- [Independent review](independent-review.md): one completed source review and
  follow-ups; two other attempts remain incomplete. No whole-workspace audit,
  hosted CI, merge, release or operational acceptance is claimed.

## Failure history

The `store-red`, `regressions-red` and `paging-red` commands failed compilation
while new fixtures were being constructed. Corrected fixtures then reproduced
the actual failures in `regressions-red-compiled`, `archive-ddl-red` and
`paging-red-compiled`. The first repair passed `regressions-green`; the additional
archive/filter and path variants failed in `projection-variants-red` and drove
the final repairs. That intermediate green result is not the final verdict.

`release-identity-controls` initially lacked cosign. `siem-owner` failed its stale
timeout assertion. The broad owner and the separate storage diagnostic commands
preserve the old fixture failures. Their repaired suites above are distinct
terminal records. No production admission check was relaxed for these fixtures.

## Provenance and reproduction

Each `<label>.json` records the exact argv, exit status, elapsed time, source base
and SHA-256 of the uncompressed `<label>.log.gz`. The source-diff and untracked
source hash fields were added to the runner during the campaign; earlier records
without those fields are not claimed to contain them. Start snapshots can
precede later fixture-only edits. `source-hashes.json` pins the final changed
source, tests, lockfile and trust-contract bytes independently of report edits.

`commands.json` indexes the records. `qualification.json` states the acceptance
boundary. `publication-preflight.json` retains the refreshed origin reachability
of all 28 selected security tips. `publication.json` records the successful
source push, exact remote match and clean tracked state. Unrelated experiments and preexisting
untracked `output/` evidence are outside the publication set.

`run-command.py` retains the runner. It used Rust/Cargo 1.94.1 on Linux aarch64,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`,
`CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`, and
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`. Command arguments record each
suite's thread count. No fixture signing keys or raw release-fixture directory
are included. Logs are gzip-compressed without changing their contents.
