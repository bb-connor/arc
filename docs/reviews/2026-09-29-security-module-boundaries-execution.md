# Security module boundaries and confinement helper

This batch implements the four production ownership cuts from Packet 7 and the
H11 helper extraction. Work is on `packet/3-retention-accounting` in
`/tmp/arc-security-launch`, starting at `d51afb4a5ffc1caafb63540b8651d19ac767b95e`.
It does not establish hosted qualification, merge, publication, native x86_64
confinement acceptance, or M5 completion.

All five implementation tasks are complete, including the final review fixes.
Terminal logs, compiler privacy probes, inventory comparisons and investigated
failures are retained in
[the evidence directory](artifacts/2026-09-29-security-module-boundaries/README.md).

## Delivered boundaries

| Task | Implementation | Boundary preserved |
| --- | --- | --- |
| Security ports | Named identifier, canonical body, classification, flow, event, response, effect, scheduler and outbox modules; explicit facade exports | Identifier and proof fields remain private; `no_std` uses explicit allocation traits and feature-scoped imports. |
| Broker service | Authorization, registration, execution, failure, digest, sensitive wire and IPC owners | Credentials, bounded parser state, prepared endpoints and response custody stay within their owners. |
| SQLite security state | Named schema, codec, event/correlation, lineage, dispatch, scheduler, response, containment and outbox owners | Connections and lifecycle custody remain private; existing SQL text, table ownership and enforcing principals are retained. |
| Control-plane composition | Named adapter, effect, active-response, admission, correlation, recovery, worker and orchestration owners | Validated execution and admission payload types remain beneath the responsible owner. Tests that inspect private state are descendants of that owner. |
| Minimal confinement helper | `chio-cage-plan` owns shared contracts; `chio-cage-init` owns bootstrap; `chio-cage` retains parent supervision | Parent and child share plan validation and descriptor transfer. Pre-exec safety and seccomp default-denial checks remain at the existing boundaries. |

The first four mechanical cuts, the visibility pass and formatting are separate
commits. The privacy pass removes 142 unnecessary helper-function visibilities.
Formatting makes the newly named modules visible to the repository formatter.
The hygiene baseline is updated through `--ratchet`.

The port, broker and store facades now contain 293, 260 and 604 lines. The event
consumer, adapter and scheduler worker facades contain 151, 153 and 181 lines.
The large kernel test owner remains outside this batch.

## Helper graph and artifact

The normal `x86_64-unknown-linux-musl` helper graph has **72 packages**, compared
with the former broad cage graph's 260. Its ceiling is 72. Retired pending runtime,
network, regex and tracing dependencies are unconditional denials. The existing
JSON protocol codec is the documented exception. The broker graph is 481:
two shared packages were added and upstream `nono` was removed.

`nono-chio` is now `0.53.0-chio.3`. It retains descriptor-only Landlock rules and
deny-all TCP handling. Its ABI probe is extracted from the reviewed upstream
implementation; the unused capability container and upstream runtime dependency
are removed. The hashed upstream source is retained only as provenance. Both
workspace lockfiles and all discovered helper build recipes select the new crate.

The available aarch64 musl dev artifact is 3,244,864 bytes, SHA-256
`a3559a9586b24dfcedd8c76c81f41b2b5bf664be119d634407c6ddd39e0bf896`.
It is a static AArch64 ELF `EXEC`, without an interpreter, dynamic section,
`DT_NEEDED`, RPATH or RUNPATH. This is host artifact evidence, not a release
artifact or native x86_64 enforcement run.

## Verification

The selected final runs total **700 passing tests and rustdocs**. This counts
each listed target/selection once; repeated diagnostic runs are not added.

| Selection | Passed |
| --- | ---: |
| Security types, all-feature unit/integration plus rustdocs | 70 |
| Broker unit cases excluding the separate process campaign | 171 |
| SQLite security-state library and two integration targets | 170 |
| Focused control-plane cases and three native ledger cases | 264 |
| Cage, shared plan, helper, helper entrypoint and Landlock wrapper | 25 |

Passing evidence includes 171 broker unit tests (the ten-case
process campaign is excluded), 106 SQLite security-state unit tests, all 67
security-types unit/integration tests plus three rustdocs, strict `no_std` Clippy,
17 cage unit tests with one native-x86-only case ignored, five shared-plan tests,
one helper unit test and the new helper entrypoint integration test.
The final focused control-plane selection passes 261 cases with one existing ignored
case, the native ledger selection passes three cases, and SQLite's security-state
and response-dispatch integration targets pass 33 and 31 cases. Strict Clippy
passes for all seven changed packages' libraries and tests. The extracted
Landlock wrapper's directory-grant test also passes.

The final independent review identified three additional ownership gaps in the
initial cuts: broker authority results, retained credential custody, and reserved
response-plan construction remained at common ancestors. All three are fixed in
`68acb34aca`. Actual transport/orchestration compiler probes first accepted each
unauthorized access, then rejected the private authority fields, private audit
type, custody-lock method and reserved-plan field. The final broker and
control-plane suites and strict Clippy pass after the fixes. One new response
test verifies successful reconstruction and five corrupt or rebound inputs.
No second review was dispatched and no minor findings were deferred.

A final packaging search also found the release workflow selecting the old
helper package. `938b76c311` fixes it and adds a source-gate regression that
rejects the old release command. The gate was observed failing before the
workflow fix, then passing; the hostile gate suite also passes.

All original terminal test-name multisets are preserved: control plane 1,179,
SQLite 1,890, broker 181, and the cage's original 24 cases distributed across
cage (18), plan (5) and helper (1). Fully qualified selectors were migrated in
qualification scripts. Subprocess tests derive their current module path while
removing the crate prefix used by `module_path!()`.
The control-plane inventory now contains 1,180 cases with the added reconstruction
test. The helper entrypoint integration test is separately added.

The Linux all-target source inventory contains 79 cases, including the new helper
entrypoint case, with inventory digest
`42a48ab3aa04f35e4f12075c8eb73c8a7ef3da2cd4356fcdcd6efb3b0fe0a90c`.
Source inventory is distinct from actually running the native enforcement suite.

Gate evidence retains 355 classified constructors, 85 tenant tables, 170 SQL
principal contracts, 142 clock occurrences and all 1,263 baselined negative
assertions at 1,180 sites. Relocation scripts compare SQL/principal hashes and
normalized occurrence counts rather than promoting newly discovered debt.
Wire/schema and domain inventories are refreshed without introducing identifiers.

## Failures investigated

Two tests also fail in the saved pre-batch binary:

- The ledger corruption test expects an obsolete serde diagnostic. It now checks
  the concrete `SqliteServingOwnerError::Invalid` variant and exact current
  diagnostic, including the registered signed-JSON error code for malformed shape.
- The active-defense crash fixture sets `panic_once` but never consumes it. The
  fixture now injects its requested panic only on the response worker thread.

The parallel control-plane campaign was stopped after diagnosing expiry of
ten-second native-dispatch policy evidence during slow debug-profile transactions.
The same capture case passes individually in both the old and new binaries.
The stopped run is retained as incomplete/failing evidence. No policy lifetime
or production expiry check was relaxed. Full parallel native-flow qualification
remains open and requires deterministic fixture clocks and focused replay.

## Execution rulings

1. Inline implementation with one final reviewer respects the requested usage
   limit. Cost if wrong: fewer independent inspections during individual cuts.
2. Mechanical moves use preserved test inventories and compiler checks rather
   than artificial red tests. New graph gates receive hostile calibration. Cost
   if wrong: unchanged behavior depends on the existing coverage and item review.
3. Scope is the four proposed production owners plus helper. Kernel tests remain
   the next Packet 7 owner. Cost: Packet 7 as a whole stays open.
4. Focused owners replace a full workspace rebuild. Native x86 and hosted evidence
   stay separate. Cost if wrong: unrelated consumer integration could remain.
5. Shared plans reuse `chio-core-types` canonical encoding. Cost: the helper keeps
   that graph until a separately reviewed codec extraction; signed bytes keep one
   implementation.
6. The reviewed ABI algorithm is copied into the small wrapper. Cost: future
   upstream ABI changes require explicit review of that copy.
7. The old upstream tree remains a hashed source reference, absent from runtime.
   Cost: provenance maintenance remains; there is no compatibility code path.
8. Stop the slow parallel native-flow campaign once policy expiry is diagnosed;
   use focused owner cases and exact repaired regressions for this mechanical
   batch. Cost if wrong: an unexercised integration regression could remain. The
   incomplete campaign is not a passing qualification result.
9. The reviewer did not qualify native x86 confinement, the full native-flow
   timing campaign, other platforms/features, the full workspace, hosted CI,
   publication or operations. Keep those gates open. Cost if wrong: deployment
   failures outside the measured platform and focused suites remain possible.
10. Existing public wire carriers such as `TrustedExecutionContext` remain
    runtime-validated inputs, outside these private proof/custody cuts. Cost if
    wrong: those boundaries continue to depend on their validators.

## Next batch

Finish Packet 7's kernel test ownership cut; consolidate authoritative security
schema/domain declarations with exact canonical fixtures; and give native-flow
fixtures a shared deterministic clock so capture, restart, expiry and lost-ack
coverage can run without host-load-dependent policy expiry. Keep the remaining
product/protocol reader, error, arithmetic and clock queue, hosted/native
qualification and genuine dependency source audits distinct.
