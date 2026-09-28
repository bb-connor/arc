# Shared clock and response assurance execution

September 27, 2026. Base `0fbe22e0f0`, branch
`packet/3-retention-accounting`, isolated checkout `/tmp/arc-security-launch`.
This record covers the shared-time and response-lifecycle implementation batch.
It does not qualify a release or close the repository-wide clock migration.

## Implementation

`chio-security-types::clock` now owns the fallible clock contract, distinct
`UnixMillis` and `MonotonicInstant` values, checked conversions, regression
fences, explicit future-skew validation and a fixed authority deadline. Native
sampling and fence publication share one lock. Browser readings are validated
before conversion. A deadline keeps its original monotonic cap through connect,
partial reads, writes and retries; an unavailable or regressing clock refuses
work without substituting epoch zero.

The portable kernel, keyring, guard cache/limiter/breaker, security-state store,
response executor, capability issuance, broker administration, watermark issuer,
Finding admission/retraction, financial verifier and FROST coordinator consume
that contract. Their platform and composition adapters were updated together.
The three original unrelated clock traits are removed. Test clock fixtures use
explicit units. Seconds outside the representable millisecond domain now deny at
the portable adapter boundary; the C++ regression checks both sides of that
conversion boundary. A failed initial limiter clock cannot produce a burst when
it recovers.

Response dispatch, plan, record, state-machine and executor rejections retain
registered rule codes through scheduler retry state, operator diagnostics and
signed receipt construction. Nested executor errors preserve their source.
Authority-envelope decoding returns a privately constructed verified request,
uses the production canonical/signature/freshness checks and rechecks freshness
under the replay-reservation lock, immediately before mutation. The signed
receipt regression verifies the retained reason and rejects tampering. Four weak assertion exceptions were
retired, reducing the baseline from 1287 to 1283; no size cap or exception budget
was raised.

Two production-entry fuzz targets are enrolled in the manifest, target mapping,
scheduled workflow, ClusterFuzzLite and OSS-Fuzz selection. Ten checked-in seeds
reach authenticated envelope mutations, full-width timestamp overflow, live
apply, rollback conflict/recovery, exact expiry and committed-store restart.
The lifecycle target also checks dry-run refusal, unchanged committed state on
refusal and preservation of other owners' contributions in all five simulated
ports. The property runner adds 64 reproducible stateful sequences.

## Verification evidence

Raw local evidence is retained at `/tmp/chio-clock-lifecycle-20260927`. Cargo
owners were serialized, using the existing external target, locked dependencies,
`umask 022`, two build jobs and one test thread. No subagents or workspace-wide
build, test or lint run was used.

The sanitizer runs are bounded local smoke campaigns, using
`nightly-2026-04-21`, AddressSanitizer, development code generation and enabled
debug/overflow assertions on aarch64:

| Target | Budget / elapsed | Executed inputs | Final corpus | Result |
| --- | --- | --- | --- | --- |
| `response_authority_protocol` | 60 s / 61.31 s | 852 | 153 | Exit 0, no crash artifacts |
| `response_lifecycle` | 60 s / 63.53 s | 15 | 13 | Exit 0, no crash artifacts |

The lifecycle driver is expensive in this instrumented development profile;
15 inputs are smoke evidence, not a sustained campaign. Both targets also run
valid deep fixtures as Rust regressions. `campaigns/summary.json` records exact
commands, seeds, manifests, lockfiles, binary hashes and source inputs. A focused
standalone manifest uses the checked-in drivers and actual production crates,
omitting unrelated fuzz targets. Its resolved graph is recorded separately from
`fuzz/Cargo.lock`; it does not qualify the full omnibus fuzz workspace.

GNU ld spent several minutes in the authority binary's final link. The exact rustc invocation
was retained and replayed with only `-C link-arg=-fuse-ld=lld`; the target compiled
and linked in 3.45 seconds with the already compiled sanitizer dependencies.
`authority-link-command.json` and `authority-lld-build.log` preserve that recipe
and terminal exit 0. Interrupted Cargo builds and the first campaign wrapper's
link-wait timeout remain non-passing evidence. The resumed campaign completed.

The final owning compile (`owners-compile-clean.log`) passed without warnings.
The final selected run passed 182 cases in 11 nonempty suites, including authority
freshness, portable C++ conversion, lifecycle properties, scheduler persistence,
broker production surfaces, three dispatch suites, SQLite restart/state and
active-defense conformance. Across the owning runs, 607 distinct cases passed;
`test-coverage-summary.json` excludes repeated and filtered cases. Two keyring
binary targets also compile and run empty harnesses; they add no test coverage.
The final run resolves both earlier failed contract expectations.

`browser-wasm-terminal.log` records a successful
`cargo check --locked -p chio-kernel-browser --target wasm32-unknown-unknown --lib`.
This checks the browser adapter and its portable dependencies, not execution in
a browser. The platform adapter explicitly imports `std` for its thread-local
fence; the shared clock types and portable kernel remain `no_std + alloc`.

Touched Rust formatting, source hygiene, negative assertions, accounting and
clock inventories, corpus metadata and fuzz selection all pass. The lifecycle
trace gate's three corrupted fixtures are refused. Final source fingerprints
are retained alongside the logs. No exception budget or assertion baseline was
increased.

The four Kani harnesses verify the actual production clock fence, fixed-deadline
and skew arithmetic, terminal edges and clean-rollback predicate with full-width
`u64` inputs, unwind 4 and overflow/unwinding assertions enabled. The early local
driver imported those source files directly. Final verification
uses the actual crate and `scripts/run-kani-manifest.sh --crate
chio-security-types`: `kani-crate.log` records all four passing under their
60-second command bounds. No hosted result is claimed. Crate verification caught
the need to retain Serde derives under `cfg(kani)`; this verifier-only correction
preserves the normal compiled behavior exercised by the earlier sanitizer
binaries. All four new manifest entries explicitly keep unwinding checks enabled.

The finite lifecycle model explores 87,810 distinct states, depth 33, for two
actions, two targets, two workers and four clock values. All eight deliberately
broken variants violate their intended invariant. Runtime traces come from
committed production mutation history, including the intermediate Expiring
write. The trace checker validates generation order, acknowledgement ordering,
transition continuity and restoration before a clean lift. Three deliberately
corrupted traces calibrate its refusal paths. Source hook hashes and runtime
trace hashes bind the evidence to its inputs. The final run in
`tlc-terminal/summary.json` passes the positive model, eight expected invariant
violations and all five production trace scenarios. This is exercised correspondence,
not a mechanized Rust/TLA refinement or independent external-effect journal.

The revocation temporal lane now has a bounded, terminal finite check: the
40-state origin/receiver projection, 3,488-state original-action epoch quotient,
three-state non-vacuity witness and expected unfair counterexample. The original
4-authority/8-capability, length-24 SMT timeout remains unverified; the reduced
claim excludes receipt authorization safety and relies on explicit propagation
fairness. The reduction argument and exact bounds are in
[the formal record](../../formal/response-lifecycle.md). The former timeout and
later bounded SMT timeout remain preserved as incomplete evidence.

## Failure disposition and remaining work

Owning compile logs retain the migrated fixture/import failures. The final
consumer check found and repaired the broker daemon's missing clock-error arm;
its diagnostic now retains the registered clock reason. The wasm check exposed
the browser fence's missing platform `std` macro scope; the explicit import and
qualified macro fix passed the repeated target check. The initial
lifecycle seeds had invalid transition ordering; a second run revealed that the
observer omitted an intermediate committed expiry state. The seeds and observer
were corrected without weakening production invariants. The scheduler regression
was updated from its retired generic reason to the registered exact rejection.
The C++ assertion was updated to the new checked conversion contract, including
its largest accepted value and three rejected values. The initial financial test
filter selected zero tests; its corrected run selected and passed 11. The first
sanitizer build was terminated after review found a private-module target path;
a feature-gated public entry fixes that wiring without exposing the verifier
constructor. That interrupted build is retained and is not passing evidence.

Correction 4A and Q5 remain partial. The new gate pins 208 remaining direct clock
reads or independent clock traits, including test fixtures. This is not a count
of production defects. Kernel replay/session helpers, SQLite evidence timestamps
and the transaction-scoped `FindingStatusCommitClock` still require migration.
[The clock contract](../security/trusted-time.md) and checked-in inventory retain
that queue. Correction 1D also retains the broader source-chain and mutation
inventory outside the dispatch/executor paths exercised here.

Native x86_64 enforcement, the historical retention stall, stable-candidate scale
campaigns, broader arithmetic classification, hosted exact-source qualification,
independent review, merge and operator acceptance remain separate open gates.
No historical green result is relabeled as qualification of this changed source.
