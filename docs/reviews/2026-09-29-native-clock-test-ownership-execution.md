# Native clock, kernel test and declaration ownership execution

Date: September 29, 2026. Checkout: `/tmp/arc-security-launch`, branch
`packet/3-retention-accounting`. Base: `8c8677470b6ff40491c0f66ac6aba31093be30bf`.
Reviewed implementation candidate: `a8b5f11d3e`; emergency-stop repair: `f965330c2a`;
final fixture repairs: `c2015692b5`.
This is local aarch64 Linux evidence.

The three approved workstreams are implemented. The single fresh review found
an emergency-stop clock dependency and a fixture boundary error; the fix pass
covers both. Native qualification combines the completed campaign and focused
reruns of repaired cases and emergency-stop consumers, as detailed below.

## Delivered boundaries

1. **Deterministic native authority time.** Fixtures pin `1800000000000` Unix
   milliseconds and explicitly advance time for expiry. Kernel, SQLite authority,
   source replay, runtime, broker, caller executor and subprocess/reopen fixtures
   use their configured clocks. The fixed epoch exposed independent production
   wall-clock reads: kernel issuance/evaluation/recovery, admission transactions,
   native capture, broker readback/IPC and caller execution now use the correct
   owner and a monotonic/wall-time fence. Existing skew, lease, nonce, approval,
   declassification and capture windows remain unchanged. Default-off expiry
   cutpoints advance the actual injected clock; production still decides whether
   the original authority expired. No fabricated rejection or extended TTL.
2. **Kernel test ownership.** Forty-four hand-maintained root includes became
   responsibility-named modules with narrow shared fixtures. Receipt and
   revocation stores moved into fixture owners; mutable database internals and
   treaty signing keys remain private. Runtime, nonce and durable-admission
   scenario groups have separate children. The 40,754-line root allowance is
   retired. Mechanical, visibility and formatting commits are separate from
   clock behavior changes. All 845 original test bodies and 1,491 original
   compiled tests survive. The final review adds one emergency-stop regression,
   for 1,492 kernel tests.
3. **Shared identifier ownership.** Sixty-four declaration relocations consolidate
   all six duplicated byte domains and 37 duplicated schema values. Producers
   and verifiers import from the existing dependency owner or shared contract
   crate. Forty-three identity/canonical-payload/SHA256 pins cover the moved
   identifiers; all 1,098 wire values are unchanged. These simple payload pins
   protect identifier identity, not every production payload shape. Existing
   canonical serialization, native lifecycle and replay suites cover their
   respective production behavior. No new compatibility aliases.

## Local qualification

| Boundary | Terminal result |
| --- | --- |
| Kernel owning library | 1,492 passed; all 1,491 original cases preserved plus the emergency-stop regression |
| Source body preservation | 845 unchanged original scenario bodies plus one new regression, excluding formatting and import-only changes |
| Native flow, nonce, capture, caller and subprocess campaign | Full run: 140 passed/3 fixture failures, 12 threads; all 143 selected cases have a passing latest result after focused repairs |
| SQLite admission clock/replay/migration/factor families | 179 passed |
| Caller ledger integration | 11 passed, including fixed-epoch execution, expiry, replay and clock faults |
| Caller connection recovery | 4 passed |
| Durable SQLite shared treaty fixture | 1 passed |
| Identifier and owning suites | 377 unique passed; 2 active-response-authority tests ignored |
| Strict Clippy | Passed for 16 modified packages, libraries and two changed integration targets; kernel library/test targets also passed with admission and finding-market test features |
| Formatting | Passed for all modified packages |
| Portable shared contracts | `core-types` and `security-types` no-default-features check passed on `wasm32-unknown-unknown` |
| Source gates | Wire, domain, clock, hygiene, negative assertion, trust boundary and compiler hardening gates passed |
| Selector gates | Flow security 69 inventories and response recovery contract passed; 182 default-feature selectors resolve |

The identifier count is 59 core canonical + 1 fincred + 24 security types +
252 settlement + 11 runtime core + 8 proof parity + 22 active-response-authority.
The separately repeated core identity test is included in the 59 and is not
counted twice. The 36 PQ selectors retain their cfg/source bodies but were not
compiled in this default-feature inventory.

The 179 SQLite and 377 identifier runs preceded the final caller-ledger/IPC and
expiry-cutpoint changes. Their selected production owners are unchanged by those
finishing changes; the final native campaign and caller targets cover those
changed paths. No full-workspace, native x86_64, AWS-LC, hosted, release or M5
qualification is claimed. Nothing was pushed, merged, published or activated.
Preexisting `output/` is preserved.

## Failure evidence and decisions

The [artifact ledger](artifacts/2026-09-29-native-clock-test-ownership/progress.md)
records every scope decision and its cost if wrong. The
[fresh review](artifacts/2026-09-29-native-clock-test-ownership/final-review.md)
records two Important findings and no Critical/Minor findings. The emergency
stop now latches before reading time; clock failure produces absent timestamp
metadata and cannot resume execution after time recovers. Its unavailable,
wall-regression and monotonic-regression test failed before the fix and passes
after it; the whole kernel target passes with the added regression. The
fixed-epoch RED, capability-not-yet-valid denial, broker readback/IPC and caller
ledger clock failures are retained. Superseded native campaigns exited `-2`;
they are interrupted evidence, not passes. The intermediate kernel run was
1,485 passed/6 failed because a private fixture swapped monotonic domains after
issuance; only that fixture now resets its fence, with an assertion that no
runtime is attached. Production fences never reset.

The deadline checkpoint deliberately denies after capture. Its test asserts
physical quota capture before the exclusive deadline, no capture at the deadline,
valid signed denials and zero tool invocations. Real lifecycle tests separately
exercise execution and exact receipt replay. A future-clock fixture fault was
corrected to preserve its valid monotonic domain so it reaches the intended
wall-time rejection rather than an unrelated fixture overflow.

The completed native campaign exposed three fixture failures: a broker peer
read deadline spanning real capture, an obsolete sleep bound in the runtime
expiry cutpoint, and the same obsolete bound in output classification. Broker
control/read deadlines are now bounded host scheduling limits (30s client,
120s peer preopened execution read), independent of signed authority windows.
The expiry callbacks require a future original deadline and advance time
synchronously. The runtime fixture's report age is inclusive (60000ms), giving
an exclusive deadline at 60001ms. A lease created at the same frozen instant
would expire first at 60000ms; that correctly produced `Fenced` in the intermediate
repair run. The expiry case now advances setup by 2ms before creating the lease,
so the runtime evidence expires first without changing either duration. Its
subsequent history/reopen queries also use the current fixture clock; the
intermediate stale-observation failure is retained.

The [native qualification inventory](artifacts/2026-09-29-native-clock-test-ownership/native-qualification.json)
reconciles all 143 selected names against terminal logs, in execution order:

| Run | Result | Selected boundary |
| --- | --- | --- |
| Full native campaign, build 17 | 140 passed, 3 failed; exit 101; 1381.15s | All 143 native cases, with 12 threads |
| Focused repair selection, build 20 | 7 passed, 1 failed; exit 101; 108.45s | All three expiry cutpoints, output-lease expiry, broker normal/misbinding/lost-reply behavior and three emergency-stop consumers |
| Runtime expiry diagnostic, build 21 | 1 failed; exit 101 | Expiry denial/rollback succeeded, then the fixture's old observation time failed |
| Final runtime expiry, build 22 | 1 passed; exit 0; 8.78s | Runtime expiry, physical rollback, retained history and reopen |
| Latest result per selected native case | **143 passed, 0 failed, 0 missing** | Composite qualification across those runs |

The full campaign's running executable was preserved by renaming it before
rebuilding the focused repairs, so its subprocess cases continued to execute
the same candidate. The [executable record](artifacts/2026-09-29-native-clock-test-ownership/native-campaign-executable.json)
retains that observation. All failed/interrupted campaigns and intermediate
repair failures remain evidence. No second full native campaign was repeated
after these narrow fixes; this is local boundary qualification, not
exact-candidate whole-workspace CI. The [artifact index](artifacts/2026-09-29-native-clock-test-ownership/README.md)
records build/command scope, limitations and checksums. Both Important review
findings are fixed and locally qualified; there are no deferred Minor findings.

## Remaining work and next batch

Current ratchets: 106 size allowances, 140 ambient-clock occurrences at 135 keys,
1,260 weak assertions at 1,177 sites, 163 duplicated schema values and 32 domain
shape exceptions. These inventories include fixtures and historical source
anchors; they are not counts of confirmed exploitable defects. The five ranked
Packet 7 owners are delivered; the wider module queue remains.

Execute Packet 9.3/9.5 and the retention stall investigation next: measure populated
SQLite authorization paths, introduce statement caching only where measured,
set explicit cache capacities and remove the redundant reversal hold read while
preserving fences/transactions. Reproduce historical stall #1045 at its original
workload with blocked-stack and ownership evidence, repair the demonstrated
cause, then retain a deterministic regression and bounded original-scale result.
Existing exact financial aggregation, typed columns and query-index work remain
in place. Passing the already-enabled retention property alone does not explain
or close the historical stall. Broader connection-pool migration, lifecycle model
refinement, product/protocol boundary closure and candidate/operational acceptance
remain in the [remaining-work queue](2026-09-28-remaining-security-work.md).
