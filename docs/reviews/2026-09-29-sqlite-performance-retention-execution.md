# SQLite authorization performance and retention diagnostic execution

Date: September 29, 2026. Worktree: `/tmp/arc-security-launch`, branch
`packet/3-retention-accounting`. Base: `a3669c03d1`; reviewed implementation:
`8aa3cf1785`. Local aarch64 Linux, Rust 1.94.1. Retention diagnostic review repair:
`b9d6af6fb0`.

Packet 9.3/9.5 is implemented and measured locally. Historical retention issue
1045 remains open. Its original-scale slow-sync diagnostic reached the preset
budget while progressing, so this record does not claim a reproduction, root
cause, complete 256-case pass or production receipt liveness repair.

## Delivered code

- Sixteen hot reader functions in budget, durable admission and capability-set
  suspension use cached SQLite bytecode. The owning budget, shared serving and
  security connections explicitly bound the cache at 64 statements. Rows,
  tenant bindings, signatures, history, authority fences and replay checks still
  run inside their original transaction. Schema, migration and reporting SQL
  stays outside this conversion. No authorization decision cache or connection
  strategy migration was added.
- Reversal, release and settlement retain the hold already validated inside
  their existing write transaction. Capture state, identity, amount, authority,
  accounting compare-and-set and replay checks remain intact. The required
  mutation-event lifecycle projection read remains separate.
- Real SQLite observations prove four repeated usage reads compile once while
  rebinding parameters and observing another connection's committed update.
  Tracing proves each of the three hold mutations performs one validation read
  and exact replay preserves accounting. Both regressions failed before repair:
  four compilations versus one, and two validation reads versus one.
- Benchmarks add usage-read and reversal-pair measurements and explicit optional
  population controls, retaining default 20,000 rows and 2,000 suspension sets.
  Composite benchmark and checked-accounting fixtures now create private owner
  directories explicitly; production permission refusal remains unchanged.
- The original retention property has a named module, explicit diagnostic case
  selection and operation/phase progress. Normal execution remains 24 cases;
  `CHIO_RETENTION_CASES=1..256` selects a deliberate diagnostic. The original
  three saved proptest counterexamples retain their explicit file ownership.
  Explicit teardown phases and real weak-owner assertions now ensure completion
  is reported only after the original, archive and reopened writers finish.

## Paired measurements

Both executables used the development profile with incremental compilation
disabled, 1,000 initial rows, 512 capability identifiers and 128 suspension
sets. Criterion used ten samples, 200 ms warmup and one second requested
measurement time per case. Each complete run had no competing build or test
from this batch. Initial population uses real public store calls. Before ran
in 98.21 seconds and after in 100.60 seconds. Full commands, executable hashes,
estimates and intervals are in the [artifacts](artifacts/2026-09-29-sqlite-performance-retention/).

| Operation | Before mean (ms) | After mean (ms) | Change | 95% change interval |
| --- | ---: | ---: | ---: | --- |
| Existing admission read (control) | 0.1229 | 0.1189 | -3.21% | -4.43% to -2.43% |
| Existing admission write (control) | 3.2877 | 3.4942 | +6.28% | +1.73% to +10.88% |
| Composed authorization stores | 70.9946 | 67.2049 | -5.34% | -9.12% to -1.87% |
| Budget charge/release pair | 9.0564 | 9.1789 | +1.35% | -7.06% to +10.60% |
| Budget charge/reversal pair | 8.5368 | 8.5917 | +0.64% | -7.10% to +7.96% |
| Budget usage read | 0.0715 | 0.0613 | -14.29% | -15.71% to -11.84% |
| Suspension allow read | 20.8283 | 14.6272 | -29.77% | -30.15% to -29.39% |
| Suspension deny read | 20.6688 | 14.6486 | -29.13% | -29.72% to -28.19% |

Write-pair intervals include zero: no latency improvement is established for
those mutations despite the verified reduction in reads. The unchanged older
admission write measured 6.28% slower and its read 3.21% faster; preserve this
control variability. The composed fixture uses the current durable admission
store plus suspension, budget and signed receipt persistence, but excludes the
kernel's complete guard, policy, broker and external tool path. These numbers
are local estimates, not universal acceleration or production/release scaling
qualification. No release rebuild or full-workspace campaign was run.

## Retention evidence and remaining gap

[Issue 1045](https://github.com/bb-connor/arc/issues/1045) and the original MSRV
job 91320792529/run 30682002563 were read without modifying the issue. The
canceled job used `PROPTEST_CASES=256` and checkout `95ff6dc`; its store source
matches branch head `72f469b0fa5bfea5eaaa93c4f854a356bcc62ae9`. It reports the
retention property over 60 seconds at 05:10:04 and cancellation at 07:38:52.
The related head property completes at 05:18:48. Neither a random seed nor a
blocked stack is present. Historical text calling this a livelock is a
hypothesis, not a demonstrated ownership cause.

The current original property ran with 256 requested generated cases, seed
20260926 and a wrapper adding 3 ms before each real fsync/fdatasync. The watchdog
budget was 900 seconds overall and 45 seconds without phase progress. It
completed 242 cases and began case 242, then reached the **overall** limit at
900.80 seconds during that case's health phase. The child was terminated with
SIGTERM (exit -15); the diagnostic runner returned 1. No no-progress timeout
occurred. This is partial workload evidence. It is not a successful test,
acknowledged cancellation of accepted writes, or evidence of the old stall's
cause. Other focused checks ran concurrently with this diagnostic, so its
wall time is not an isolated throughput measurement.

The process snapshot retains thread wait states. Kernel-stack access failed
with permission denied, and GDB attachment was denied by the environment.
Neither is a recovered blocked stack. The historical binary and unknown seed
were not reproduced. Receipt production ownership was unchanged by this batch.

The 256-case diagnostic binary preceded the explicit saved-seed path fix; it
therefore exercised generated cases only. A final property run separately
replayed all three saved counterexamples plus one generated case and passed.
The deterministic writer/rotation/timeout/VFS tests also passed. This composite
evidence does not complete the 256-case slow-sync gate. The diagnostic review
correction is qualified separately below; it does not retroactively change the
interrupted run.

## Focused verification

| Boundary | Terminal result |
| --- | --- |
| Budget tests | 144 unique passed: 142 initial passes and two repaired fixture failures; the full five-test checked-accounting group passed after repair |
| Serving owner | 91 ordinary tests passed; its isolated subprocess case separately passed |
| Admission integrity, recovery, schema, clock, joint budget and replay | 53 passed |
| Security connection recovery | 7 passed |
| Capability-set suspension, tenant and restart bindings | 4 passed |
| Deterministic retention ownership, timeout and VFS | 4 passed |
| Saved retention counterexamples | 3 saved plus 1 generated case passed |
| Diagnostic completion boundary | Actual property RED then GREEN; 4 cases, 12 teardown phases, 1 test passed in 9.84 s |
| Strict Clippy | Library, suspension and retention integration targets, authorization benchmark passed |
| Formatting and source checks | Modified package and explicitly discovered test modules, diff hygiene, Rust file hygiene and trust-boundary gate passed |
| Original-scale slow-sync workload | Incomplete: 242/256 generated cases, overall watchdog timeout; not a pass |

Full logs preserve intermediate compile/fixture/assertion failures. The initial
composite benchmark refused a group-writable fixture directory; the corrected
complete baseline is the comparison source. The initial budget failures had
the same fixture issue. Their valid production denial was retained.

The [fresh review](artifacts/2026-09-29-sqlite-performance-retention/final-review.md)
found no production defect and one diagnostic completion-order issue. The
[ledger](artifacts/2026-09-29-sqlite-performance-retention/progress.md) records its
fix, every scope ruling and cost. No compatibility layer was added. Nothing was
pushed, merged, published or activated. Preexisting `output/` is preserved.

## Next implementation batch

Continue item 6 with retention lifecycle observability: arrange supported stack
capture before another original-scale attempt, distinguish teardown from
writer/rotation progress, and connect lifecycle traces to actual commit,
external-effect and receipt boundaries. Repair demonstrated ownership faults
with deterministic regressions; do not relabel the old issue as fixed from a
local pass. Resolve the larger temporal-model boundary after that linkage.
The remaining MCP remote/edge/adapter and API Protect decoder contracts,
structured refusal causes and exact negative assertions remain the next
product/protocol authority batch in item 2. Release/default-population storage
qualification and broader connection migration retain their separate gates.
