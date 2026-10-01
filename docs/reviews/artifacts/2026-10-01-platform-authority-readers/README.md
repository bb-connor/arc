# Platform authority reader qualification

Source base: `377ee5b773eff424d12182682b411867b4d643be`. The owning commit
contains this record and the final source hashes. Scope is all 31 pinned platform
readers plus their shared owners and direct consumers, on local Linux/aarch64.

## Accepted evidence

- [13-package campaign](platform-tests-final.log): terminal exit **101**, with
  1,065 passes, one new enterprise fixture failure and two ignored tests. The
  fixture selected an empty reserve ledger; its existing valid counterparty-bound
  payout variant supplies the required auxiliary receipt. The complete
  [enterprise package rerun](enterprise-final.log) passes **63 tests**, exit zero.
  The failed campaign is preserved and is not relabeled green.
- [PostgreSQL integration](postgres-final.log): terminal exit zero, one sequenced
  production-store campaign exercising tenant isolation, exact replay, role and
  lease recovery, durable state integrity and checkpoint readback. The native
  checkpoint control writes and reads `(1_u64 << 53) + 1`. The isolated local
  [runtime identity](postgres-runtime.json) pins the Docker image and endpoint;
  the test resets only this task's new database. The task-owned container was
  stopped and removed after the passing campaign.
- [Accepted test summary](test-summary.json): all enterprise results from the
  combined campaign are replaced by the complete package rerun, then PostgreSQL
  and [three focused custody tests](custody-final.log) are added. The composite
  total is **1,070 Rust harness passes, zero failures, two ignored**, across
  **34 test binaries and 13 doctest groups**. The custody command deliberately
  filters 1,183 unrelated control-plane tests. No single
  all-green combined 13-package command is claimed.
- [All-target Clippy](clippy-accepted.log): all 13 selected packages pass with
  `-D warnings`, terminal exit zero. This includes the final custody and test
  ordering fixes. The earlier lint failures remain in their original logs.
- [Direct consumers](direct-consumers-final.log): all 13 selected direct consumer
  packages compile with the final error and parser APIs, terminal exit zero.
  The later private custody lint fix and unchanged test-module move are covered
  by the final Clippy and focused custody commands.
- [Source inventory](trust-closeout.log), [file hygiene](hygiene-final.log),
  [negative assertions](negative-final.log), [clock gate](clocks-final.log) and
  [formatting](format-final.log) pass. The two subsequent touched files pass
  [follow-up formatting](format-followup.log), and the unchanged relocated API
  test module passes [its formatting check](format-test-order.log). The clock gate covers the three migrated
  platform production files. Its [three calibration tests](clock-calibration.log)
  pass. No source limits, weak-assertion allowances or clock exceptions increased.
  [Wire declarations](wire-final.log) match the existing schema lock.
  The negative baseline remains 1,257 assertions at 1,175 sites; the scoped clock
  census remains 154 sites, with no new ambient calls in the added owners.
- [Independent review](review.md): one read-only review, five findings, five
  implemented resolutions and production-linked controls. No second independent
  review is implied by the focused post-fix qualification.

Two ignored tests remain deliberate: the dedicated TLS PostgreSQL runtime/worker
lease API and a test that regenerates the checked-in cognition-market golden.
The local database campaign does not qualify that separate TLS test. Native
Firecracker execution, live-provider behavior, alternate devices/backends,
full-workspace tests/clippy, hosted CI, M5 and release acceptance are separate.

## Retained earlier attempts

Each command has same-name JSON metadata with the exact command, environment,
duration and terminal exit. Failed logs are preserved verbatim. Logs are raw
command evidence and excluded from source/documentation whitespace checks.

| Attempt | Terminal outcome and disposition |
| --- | --- |
| `task1-red`, `http-red`, `task2-red`, `worker-original-red` | Exit 101: original duplicate/oversize or worker normalization controls exposed acceptance before the corresponding fixes. |
| `task1-input-green`, `http-input-green` | Exit zero: focused controls pass after their boundary repairs. |
| `task2-budgets-red` | Exit zero: implementation was already present by execution. Despite the label, this is a green control and not a reproduced pre-fix failure. |
| `evidence-packages` | Exit 101: stale flattened-error expectations and the initial deep-graph fixture were corrected to native causes and valid digest IDs. |
| `evidence-packages-2` | Exit 101: an accidentally renamed test helper parameter was corrected. |
| `durable-compile`, `durable-compile-2` | Exit 101: exhaustive port mappings and a `const fn` invalidated by source-bearing error ownership were repaired. |
| `durable-tests` | Exit zero: the initial durable package campaign; superseded by the final accepted evidence. |
| `platform-tests` | Exit 101: new authority-test imports corrected to their public owners. |
| `platform-tests-2` | Exit 101: the new clock positive fixture lacked its HTTP tool grant; four prior transaction assertions still expected flattened strings. Fixtures and precise cause assertions were repaired. |
| `review-regressions` | Exit 101: the new enterprise regression needed its fully qualified public error type. |
| `direct-consumers` | Exit 101: downstream HTTP clock-error matches required explicit source-preserving mappings. The final consumer campaign passes. |
| `clippy-final` | Exit 101: the dependency control-plane signing reader retained a direct slice forbidden by its existing indexing lint. Checked buffer access repairs this without a lint exemption; the retry and focused custody tests qualify the fix. |
| `clippy-retry` | Exit 101: an existing API-protect test module preceded production items. Its unchanged body was moved to the file end; no lint allowance was added. |
| `hygiene` | Exit one: three existing test files exceeded their caps after regression additions. Tests now live in owned child modules; caps were not increased. |
| `postgres-integration` | Exit zero: initial database campaign before the added full-width timestamp control. Superseded by `postgres-final`. |

[Qualification metadata](qualification.json), [source hashes](source-hashes.json)
and [executable hashes](binary-hashes.json) identify the accepted source and
artifacts. The metadata lists the small changes after the combined campaign and
their focused qualification; the owning commit is the final candidate identity.

## Reader inventory and next batch

[Reviewed readers](reviewed-readers.json) records all 31 original paths;
[supporting owners](supporting-owners.json) covers shared decoders, errors and
fallible evidence traversal. The [remaining census](remaining-readers.json)
contains **67** baseline files, down from 98. Counts are semantic review debt,
not vulnerability totals or threat closure.

The next batch is all **22 economy readers** in [next-readers.json](next-readers.json),
with 45 other baseline readers and the independent roadmap gates still queued.
[Starting branch tips](published-starting-tips.json) records remote containment
of the 24 selected security branches. Separate WIP snapshots remain unintegrated
and carry no new qualification claim.
