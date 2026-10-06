# PR #1173 code review and repairs

This is a chronological review record. Earlier candidate counts, draft states
and acceptance judgments remain historical. The current local result appears
in the final section and in [SECOND-REVIEW.md](SECOND-REVIEW.md); hosted acceptance
must name the replacement PR commit.

This review follows the executable changes in the verifiable-work session,
including native admission and settlement, delegated continuations, federation,
protocol adapters, the funded-work and comparison programs, and the evidence
tooling. The W1-W4 design plans remain plans. Their acceptance criteria are not
treated as implemented functionality.

The initial candidate was `c3b423557727129f374f7711e498f1e4bce756e0`.
It contained 575 source or tooling paths among 2,879 changed paths against its
original merge base. Integration with the current security and retention branch
is part of this review. The retained records distinguish historical failures,
focused repaired runs, and the final source-bound native qualification.

## Confirmed findings

| Priority | Defect | Repair and regression boundary |
| --- | --- | --- |
| P1 | The native security participant reader rejected supported admission schema 36, blocking ordinary native operations. | Accept the supported successor schema without changing the native catalog digest; reject unsupported versions and verify the live catalog. |
| P2 | An already resolved checked-output denial could be stranded when output authority expired before recovery. | Resume its exact retained zero-charge obligation without fresh output release; retain frozen transform, decision, pricing, digest and settlement checks. Allow replay still requires live guards. |
| P2 | Unknown-payment release could use a backdated caller timestamp to accept expired consent. | Qualify fresh consent against owner time and reject decisions before issuance; already accepted obligations remain recoverable. |
| P2 | Combined native admission omitted an earlier receiver-side governance deadline. | Intersect both signed presentation windows into the native dispatch deadline. |
| P2 | The example HTTPS server accepted unbounded request headers before authentication. | Bound the complete header block before the HTTP parser, require explicit framing and close semantics, and retain bounded bodies. Test oversized single and aggregate TLS headers. |
| P2 | Buyer accounting counted released reservations as still reserved. | Exclude released reservations and assert exact available, reserved and spent balances. |
| P2 | Future and reversed issue times defeated the comparison receiver's maximum token lifetime. | Use checked time arithmetic and reject invalid issuance windows before dispatch. |
| P2 | Missing or malformed comparison amounts silently became zero. | Reject absent, null, fractional, negative and nonnumeric amounts in both profiles. |
| P2 | Federation experiment heartbeats could install a fresh root with missing or stale revocation subjects. | Require an origin-signed complete subject snapshot bound to the exact root before publishing or accepting each epoch; reject conflicting, incomplete and mixed batches atomically. |
| P2 | Second-rounded federation timestamps could already be stale under the current millisecond authority clock. | Use the exact publish time under the existing freshness policy. |
| P2 | The experiment counted rejected or mismatched root acknowledgements as delivery. | Accept only the exact acknowledged epoch. |
| P2 | The admission timing wrapper omitted the store's atomic trust-floor method, denying valid network calls. | Forward the atomic operation and the related retained-source lookups unchanged; test predecessor rejection without mutation and a valid successor. |
| P2 | Hosted live C++ conformance lacked the enforcing host fixture required by the current CLI. | Prepare and qualify the existing native fixture and build the real-enforcement CLI before the five live consumers. Hosted x86 evidence remains necessary. |
| P2 | New A2A v1 tests used the old parsed-value ingress API and failed to compile against the security base. | Serialize the test requests and exercise the bounded original-byte API. |
| P2 | Caller custody treated a configured single-approval authority as selected for every call, rejecting unused sources and threshold-only calls. | Read original requirements and matching cumulative grants, retain the verified typed threshold proposal for new reservations, and still require and validate actual selected single-approval custody. |
| P2 | The three-owner experiment still relied on the old implicit approval roster and did not bind the current policy and tenant context. | Configure each approval roster explicitly, keep capability issuance local to the receiver, and bind the intent through the kernel before the external approver signs it. |

Integration also repairs schema-migration fixtures, shared-clock fixture wiring,
module size violations, schema registration, and security-reader inventory drift.
The named reader witnesses are finite lexical regression tripwires. Their source
checks supplement the owning Rust tests; they do not prove authentication or
whole-program dataflow. No raw-input baseline is promoted merely to pass a gate.

The caller repair preserves committed historical frames. Previously affected
threshold reservations with a configured single-approval source could not
publish a valid caller frame. An old live `ReadyToDispatch` reservation keeps
its existing refusal and expiry/compensation path; the repair does not invent
missing historical selection evidence or rewrite its commitment. Legacy
threshold commands and exact replay retain their two-attachment representation.

The pinned ERC-8183 capture is stored as deterministic gzip. Its decompressed
41,976 bytes and original SHA-256 are unchanged. The artifact checker validates
that pin, rejects invalid metadata and confined-path violations, and limits
decompression before accepting the source.

## Hosted integration follow-up

The hosted run at `93a2552c3a6eb15ac2756129f199f5714390e794` exercised additional
consumers after the security-base merge. Its failures remain historical evidence;
the subsequent repairs do not change that run's result. Its terminal snapshot
contains 47 successful, 23 failed, 10 skipped, and two cancelled jobs. Installed
native consumer recovery passed, while its aggregate process gate correctly
failed on the separate host-test and worker failures. Source comparisons in
`test-integration-attribution.json`, `inherited-ci-inputs.json`, and the native
HTTP fixture record distinguish inherited integration defects from session code.

- Process crash recovery now configures an explicit approval roster and signs
  the kernel-bound intent before the first dispatch. Reopening still loads the
  original persisted request. Unbound intents, changed arguments, and unlisted
  approvers deny before either effect log exists. All 91 process tests and
  warning-denied Clippy passed.
- The threshold suite reuses the existing admission-checking test server through
  an explicit module import. Its exact inventory includes five already-existing
  session-scope tests. The original 42-versus-47 inventory failure remains
  recorded; corrected threshold, session-report, and receipt-isolation inventories
  passed 47, 16, and 6 tests respectively, without removing any expected case.
- SDK and PostgreSQL workflows prepare the existing enforcing host fixture.
  SDK parity restores the enforcing CLI after the HTTP example build and before
  all five native C++ consumers. Seventeen checker tests protect those sequences.
  PostgreSQL's direct database connection and proxy subprocess still need an
  approved native transport boundary; fixture preparation does not establish that
  adapter's compatibility.
- CLI signing fixtures use private files from their first write. The Drogon
  example uses temporary private signing custody outside group-writable checkout
  ancestors. Cleanup retains the sidecar receipt database and its WAL companions
  after services stop, including after an assertion failure. A retention error
  fails cleanup and preserves the private source for recovery. The sidecar
  receives an explicit private signing seed, and both allowed requests carry
  capabilities. The export reads the canonical receipt store, retains complete
  signed kernel rows, and checks the HTTP projections against their response IDs
  and exact POST bytes. The full
  Drogon, proof-package, and runtime-policy gates passed. Initial failures from
  unsafe checkout ancestry, missing signing custody, anonymous GET assumptions,
  and the legacy receipt query remain retained alongside the corrected runs.
- The verdict matrix issues a valid nonce, advances the shared injected clock,
  and requires an actual expiry error. Its three targets passed 47 tests and
  warning-denied Clippy. Standalone lockfiles follow the current local dependency
  graph; retained registry versions and checksums are unchanged. Two stale vector
  manifest entries were corrected without changing vector JSON; all 109 hashes
  now match. Fuzz inventories retain all 34 targets, including the previously
  omitted threshold target. Both response-security corpora now run through their
  existing assertion-bearing drivers in the default smoke suite. The locked
  fuzz replay passed all 38 tests (10 unit and 28 smoke tests).
- Native HTTP fixtures authenticate their exact loopback proxy, refuse missing
  and incorrect proxy credentials, and check malformed initialization before
  session creation. Existing sessions also deny fresh admission after issuer-pin
  drift. An explicitly repinned node first succeeds, then observes cross-node
  revocation. An invocation marker checks that neither denial dispatches a tool.
  These scenarios require the qualified Linux x86_64 fixture; local aarch64 source
  review is not native runtime qualification. Both changed CLI test targets
  compile and pass warning-denied Clippy on aarch64; their native execution
  remains a supported-host CI requirement.
- The older programmable-sovereignty artifact has an explicit historical
  validation mode. It authenticates immutable measured-source and assembly
  identities while checking the retained manuscript, results, and outputs. One
  original aggregate-digest defect has a documented one-field erratum. Fifteen
  tamper/provenance tests passed; strict current-source validation still rejects
  the evolved checkout. No historical measurement was reassigned to new code.

Independent automated reviews found no further P0/P1/P2 issue in the reviewed
process, historical-artifact, workflow, lockfile, or native HTTP fixture repairs.
These reviews do not supply missing supported-host execution or human approval.

## Evidence and limits

`MUTATION-TRIAGE.md` records the exact hosted survivor review. No current-source
security defect was established by the surviving mutations. The federation
report is advisory; the runtime campaign was cancelled with three mutations
unfinished. The retained archive preserves those outcomes and original diffs.
Eleven added regressions and stronger existing assertions passed in four targets
(88 tests total): exact verified evidence requirements, matching malformed
receiver records with valid signatures, persisted unused continuation state after
refusal, and exact object/array/mixed nesting limits. Production guard logic did
not change in response to this triage.


`logs.json` inventories retained diagnostic streams with uncompressed hashes.
Initial failures and partial campaigns remain present. The HTTPS summary covers
19 scenarios. The federation summary is a small debug network smoke with real
loopback peers, denial cases, duplicate races, and revocation/cut recovery; it is
not a performance benchmark or independent operation.

The current source-bound native qualification is maintained at
`docs/research/dynamic-delegation/evidence/qualification.json`. The final integrated run passed all 21 terminal commands against 37,265 source
files and retained 48 output artifacts, including actual parent SIGKILL and
stable child collection replay. Historical native inventories and benchmark
results retain their original revisions. The six
chain-dependent tests ignored by the default funded-work suite are explicitly
opt-in tests. A separate configured run passed all six; the default suite's
original six skips remain recorded. Ganache used its JavaScript fallback on
this aarch64 host. This run makes no native-binding performance claim.

The initial JavaScript work-claim campaign had 148 passes and 25 failures before
fixture startup because the command omitted `CHIO_W0_PYTHON`. The corrected run
selected the locked checker and freshly built binary explicitly and passed all
25 affected tests. The six funded-fit tests also passed. This setup failure is
preserved rather than removed from the campaign history.

The broad library campaign at the first repair revision retained 1,526 kernel
passes and two failures that exposed the caller selection problem. SQLite
retained 1,961 passes, two child-process failures, and three default skips. A
concurrent build unlinked the running SQLite executable, so those two failures
were `ENOENT` while spawning `current_exe`, not failed recovery assertions.
Both affected tests then passed from an immutable copy of the original running
binary. Its hash is retained in `store-binary-retention.json`. The two optional campaigns with one million receipts each remain skipped.
The third skip is the child helper that the passing parent test invokes
explicitly. The failed broad campaign is
preserved, with corrected runs recorded separately. On the repaired source,
all 1,532 kernel library tests passed. Focused final checks also passed: 22
caller tests, one actual durable approval test, six cumulative-budget tests,
and 16 physical SQLite threshold tests. The final test binaries were copied
to immutable paths before execution; their hashes are retained in
`custody-test-binaries.json`. A separate automated review of the resulting
approval repair found no further P0/P1/P2 issue. The three-owner fixture then exposed
three setup failures under the current explicit approval API. After repairing
its receiver and approver configuration and intent binding, all five tests
passed, including every parent-finalization crash cut and mutation control.
Its targeted Clippy check passed, and a separate automated review found no
additional issue.

To reproduce the additional chain checks after installing the contract lockfile
and the hash-locked Python requirements, set `CHIO_FUNDED_PYTHON` to that Python
interpreter and `CHIO_W0_BINARY` to the built `chio-federated-work` executable:

```sh
cargo test --locked --manifest-path examples/federated-work/Cargo.toml -- --ignored --test-threads=1
CHIO_W0_PYTHON="$CHIO_FUNDED_PYTHON" node --test --test-concurrency=1 contracts/scripts/work-claim-*.test.mjs
node --test contracts/scripts/funded-work-fit.test.mjs
python3 -B docs/papers/verifiable-work/tools/qualify_dynamic.py --record
```

This review does not establish external operation, production deployment,
release qualification of the complete workspace, or the whitepaper's open
economic and foundational claims. `publish_ready` and `breakthrough_established`
remain false. Exact-head hosted status must be read from the PR after the repair
commit is pushed; local aarch64 checks cannot qualify the x86 enforcing fixture.

At the earlier `14477aaa` candidate, the AWS-LC audit, dependency advisories,
Kani compiler compatibility and confined PostgreSQL qualification remained open.
The readiness work below supersedes that local status without reclassifying the
earlier hosted failures.

## Production-readiness integration

The candidate integrates the audited prerequisite from `main` at
`4f3c967f04af40b5025b9222e8db95a3aee0b5f4` and the PR base at
`75d6796702eebecbaa2a016da778c87ab8d0c2d6`. This work was implemented and reviewed
inline without subagents. The retained `readiness-*` streams record these local
results; they are not hosted or release acceptance.

- The complete AWS-LC gate passes: authenticated fork reconstruction, six
  deployment resolutions, default/FIPS lint inventories, Cargo Vet, three DES
  parity regressions, AES initialization and FIPS wrong-key rejection. The
  upstream review is non-implying because the registry wrapper has known
  defects. Deployment requires the corrected exact fork and the composite gate.
  No new Vet exemption was introduced; 730 existing exemptions remain.
- Wasmtime 48.0.5 uses Rust 1.95. Cargo Audit and OSV pass the existing policy.
  Braces and node-forge private tooling repairs reconstruct the exact registry
  archive plus pinned upstream changes. The monitor queries the original
  package identities and rejects additional advisories. Braces' complete
  upstream suite retains 42 pre-existing Bash-compatibility failures, compared
  with 50 before repair. Forge's RSA suite passes 101 tests with four pending.
- The repaired Kani 0.68 compiler retains its pinned release and upstream
  signature-assertion fix. Real installation controls require successful proof
  and rejection of reachable unsupported catch-unwind. All 32 selected public
  core and 21 other PR harnesses pass. The bounded Merkle input domain includes
  the former fixture mutations without the solver's redundant heap expansion.
  An actual off-by-one verifier mutation fails the independent oracle; the
  restored verifier passes all 963 checks. Model-only quote errors avoid
  unrelated recursive destructor expansion without changing runtime code.
- The receiver lease-reference predicate has isolated regression coverage for
  each identity and expiry substitution. An actual OR-to-AND mutation fails;
  restored tests pass. The historical cancelled mutation campaign remains
  cancelled. CI time budgets now cover the unchanged proof/fuzz selections.
- PostgreSQL composes through the existing prepared broker and native proxy.
  The trusted host owns TLS and database credentials; the kernel constructs the
  caller binding from the original capability. Strict role routes, bounded JSON,
  duplicate rejection and timeout errors preserve conservative effect handling.
  The committed-claim cut point withholds the real reply until the orchestrator
  kills the kernel. Adapter, payload, Python, TypeScript and contract controls
  pass locally. Real Linux x86 confinement and both PostgreSQL trajectories
  remain required hosted evidence.
- The formal source review follows moved implementation helpers, including
  deadlines and initialized-record validation. All 230 mirror entries match,
  and the generated coverage contains 66 rows and 182 artifacts. These are
  declared abstraction anchors, with their limits recorded in
  `docs/formal/PR1173-SOURCE-REVIEW.md`; they do not establish Rust refinement.
- The formal workflow now enrolls the registered open-market and security-types
  crates in both its trigger and lane classifier. The existing wiring test
  exercises the actual shell classifier for every PR crate discovered from the
  harness manifest and workspace. Removing the security-types route fails the
  control. The scope job executes this contract before classifying changes.
- The security evidence image pins Rust 1.95 and its component archives, source
  lock and toolchain. A dedicated x86 build qualifies the actual image without
  publishing it. Local aarch64 execution cannot supply that result.

The final local source-bound qualification passed all 21 commands against
37,265 source files and retained 48 outputs, including actual parent loss and
child collection recovery. Its source snapshot matches the integrated candidate.
Final acceptance still requires terminal exact-candidate x86 CI and a clean
matching local/remote/PR head. The PR remains draft. No merge, publication or
deployment is implied.

### First integrated hosted attempt

At `eddd3e18c63c26b680f5c9bb2d47ef8f6c999050`, the complete x86 Cargo Vet
gate and Cargo Audit/OSV monitor passed. Three subsequent failures required
repairs; their raw hosted logs remain in the `readiness-eddd-*` archives.

- Alpine had retired the pinned OpenSSL and Python releases. The replacement
  closure retains all 225 package identities and pins OpenSSL 3.5.9, Python
  3.12.15 and the September certificate package and bundle. The reviewed musl
  and Alpine release changes come from the already pinned Rust 1.95 base.
  Package signatures, the certificate archive digest and the complete installed
  inventory comparison remain required. An ARM-native resolver checked this
  exact x86 database with install scripts disabled; that check does not qualify
  native image execution. The historical APK archive manifest remains evidence
  for its original September image, not this replacement closure.
- All 34 caller-execution tests passed, then the workflow rejected its obsolete
  33-test expectation. Its inventory now includes the existing v34 migration
  regression. Local continuation also exposed a fixture that installed a
  second-resolution clock after observing real milliseconds. Freezing the
  fixture before its first authority read and advancing to exact nonce expiry
  preserves the production regression guard. The corrected nine-test target,
  session ownership, signing forwarding, all 20 boot-receipt tests and target
  Clippy pass. All nine FIPS contract controls and the full security CI contract
  mutation suite pass with the reviewed workflow identity.
- Native filesystem, identity, deadline and cleanup enforcement passed, as did
  the real TLS PostgreSQL public worker role/fence API. The process scenario
  then timed out before broker readiness. Rust's default test renderer prefixes
  the first marker with the test name. An actual Rust test subprocess reproduces
  that timeout; terse output passes the same strict reader. The existing helper
  now selects terse output, retaining its exact test filter and startup barrier.
  Ownership and committed-reply-loss trajectories still require a hosted rerun.

Source `5c6b04b079` passed all 21 local qualification commands. After the
broker-readiness correction, source `441cfe24ab` passed the complete profile
again: 21 terminal checks, 37,265 source files and 48 outputs, with no source
drift. Both historical successful runs and the original failures remain
attributable to their own source inputs. Hosted acceptance requires the next
exact PR candidate, including the native PostgreSQL trajectories and image.

### Unfiltered advisory closure

At `41c33618d7f349a66d18a562ac980fd5b9fd32a5`, the complete x86 AWS-LC/Cargo
Vet composite and the security execution-image build pass. The actual image
build accepts the exact 225-package inventory, pinned Rust components and
locked workspace fetch; it does not publish or activate the image. Cargo Audit
and OSV also pass their existing policy, including original-source authentication,
upstream advisory monitoring and all three installed npm repair regressions.

Review of that run's unfiltered OSV artifact finds one inherited accepted
advisory: `GHSA-866g-f22w-33x8` in the standalone AI SDK peer-test lock. The
waiver's claim that remediation requires AI SDK 6 is stale. Aligning this lock
with the workspace's AI SDK 5.0.210 and provider-utils 3.0.28 selects the upstream
response-size repair without changing the published peer range. The waiver is
removed. A trial of the latest AI SDK 5 release introduced affected Undici 5
dependencies and is retained as a failed scan; the selected graph instead uses
the existing compatible workspace dependency line.

The standalone package's build, type check and all 42 tests pass. The complete
Python/npm OSV selection, run with an empty configuration to disable every
waiver, reports zero findings. An initial invocation omitted that empty config
file and failed; its diagnostic is retained separately. Source `d6dbdf1c5d`
then passes all 21 local qualification commands against 37,264 source files,
retaining 48 outputs and unchanged before/after source hashes. The review
manifest authenticates 199 diagnostic streams. Every hosted success remains
attributed to its actual candidate; final acceptance requires terminal checks
on the final pushed PR revision.

### Hosted bootstrap boundaries

Candidate `41c33618d7` also passes the complete native x86 crypto-floor job.
The PostgreSQL lane passes native enforcement, the real TLS worker/fence API
and the repaired broker readiness barrier. It then fails before provisioning:
the example omitted the kernel-required aggregate invocation budget. Source
`c96b8b1fed` binds initialization and process-tree limits to the same existing
100-call value. A real CLI probe reproduces the original rejection and confirms
that the corrected initializer passes that boundary; its deliberately invalid
policy prevents host provisioning. This is configuration evidence, not native
execution qualification. Both full PostgreSQL trajectories remain required.

The Kani manifest lane fails before proofs because the cold release setup lacks
compiler-private Rust components. The explicit toolchain override bypasses the
pinned upstream source's component list. Source `62118f904e` provisions that
exact nightly and its four build components before reconstruction. The new
failure regression first fails on the missing provisioning step, then passes
with the repair and requires no compiler replacement or acceptance marker after
prerequisite failure. An actual empty `RUSTUP_HOME` installation resolves
`rustc_abi`, `rustc_driver`, `rustc_public_bridge` and `tempfile`. The existing
compiler still proves the positive control and rejects reachable unsupported
catch-unwind. Version and workflow controls pass. No proof is weakened or
removed; both hosted sweeps remain required.

The qualification started on `c96b8b1fed` was intentionally interrupted with
exit 143 to include the newly observed Kani repair. Its partial outputs remain
in the normal evidence history and are not a successful qualification. The
replacement profile uses frozen source `62118f904e`. The review manifest now
authenticates 216 diagnostic streams, including the two hosted failures, the
real budget probe, cold-toolchain controls and the interrupted campaign.

Frozen source `62118f904e` passes all 21 terminal qualification commands against
37,264 source files, retaining 48 outputs with unchanged source hashes. The
funded suite reports 92 passed and six explicitly ignored; the separate native
parent-loss and four child-payment interruption cases pass. The completed prior
x86 runtime mutation campaign tests 77 mutants: 69 caught and eight unviable,
with no survivors. All 218 retained diagnostic streams authenticate correctly.
A separate inline review of the final prerequisite and budget repairs finds no
additional P0/P1/P2 issue. The PostgreSQL end-to-end scenarios, both Kani sweeps
and terminal CI must still pass on the replacement pushed candidate.

### Verified broker response consumption

Candidate `2e296de197` passes the native x86 execution-image build, the complete
AWS-LC source/deployment/Vet gate, and the full crypto-floor workflow. Its actual
advisory artifacts contain zero Rust vulnerabilities and zero unfiltered OSV
result groups. The cold Kani installation succeeds, and all 21 selected non-core
PR harnesses pass. These successes remain attributed to this candidate.

The PostgreSQL lane passes native enforcement and initialization, then its
consumer rejects the first allowed result. `BrokerMcpConnection` already
consumes the transport's MCP wrapper and verifies the signed broker completion
before returning `BrokerExecuteResponse` directly. The qualifier incorrectly
expects a second wrapper. The shared prepared-resource LangGraph decoder and
its synthetic fixture had the same mismatch. Source `9a78f5c855` aligns both
consumers with the existing Rust contract, preserving the original response
and receipt artifact. Direct-value regressions fail before the repair; five
PostgreSQL tests and all 34 shared-resource tests pass afterward. Extra wrappers,
incomplete broker evidence, kernel denials and resource errors remain refused.
No Rust verification, native policy, credential custody or retry behavior changes.

The same candidate's changed-target fuzz job fails when its hosted runner
receives a shutdown signal during compilation. Target execution never starts;
this is retained as an infrastructure failure, not a completed fuzz campaign.
The review manifest authenticates 231 diagnostic streams. Both complete
PostgreSQL trajectories and the full selected CI still require terminal results
on the replacement candidate, including a fresh fuzz campaign.

Frozen source `9a78f5c855` passes all 21 terminal qualification commands against
37,265 source files, retaining 48 outputs with unchanged before/after source
hashes. The funded suite reports 92 passed and six explicitly ignored. Native
parent SIGKILL, evolving funded work and the four child-payment interruption
cases pass. A separate inline review of the consumer correction finds no
additional P0/P1/P2 issue; the hosted acceptance boundary above remains open.

## Native lifetime and fuzz handoff follow-up

Candidate `2ae8ee2979921dba7585bdcb4b2629bc6f96e563` passes the source-backed
AWS-LC/deployment gate, Cargo Audit and unfiltered OSV, native x86 image, all
32 core and 21 non-core Kani PR harnesses, the crypto floor, Lean, native
protocol, installed consumer recovery and the aggregate native MCP recovery
gate. Its runtime mutation campaign tests 77 mutations: 69 caught and eight
unviable. Those results remain bound to that candidate. Its first fuzz attempt
receives a runner shutdown during compilation; its debug rerun is separate.

The PostgreSQL trajectory reaches first assignment, exact replay, release and
pending inspection, then denies the replacement assignment. Diagnostic source
`414857027caa2a9d84745dd5364071c4c78405d3` retains explicitly selected public
operator responses and signed receipts. Artifact `11335632271` authenticates
with SHA-256
`0bd107e9c9c0e493e26aba4871c00ad89e21c1e5382d05e32576774477962505`.
The actual receipt verifier accepts the operator-5 denial signature, signer pin
and action hash. The denial occurs in native dispatch capture after launch.
No private host log, database credential or signing seed is exported.

A repeated real-kernel/SQLite probe passes with a fixed clock. An advancing
clock reproduces dispatch-policy expiry on the fourth egress operation. The
store refuses the expired policy; a curve-arithmetic-only optimization does not
repair that result and is not adopted. Both unsuccessful probes and their
source patches are retained. A second hash-only diagnostic campaign at
`76801dd3a3fe09cfd0b89ea4094b4a8d03400e2c` is cancelled while queued, with zero
executed steps, after the local reproduction and current security-lane review
supply the required diagnosis. It provides no native qualification evidence.

The active security lane already addressed this boundary in
`49a21b1a7e9dc76e96edb3b2bbd53488005034ef`. The repair is reused here: qualify
the enforcing PostgreSQL CLI with the existing `docker-release` profile, and
retain a bounded, invocation-owned launch thread through child shutdown and
terminal receipt persistence. Linux ties parent-death protection to the
creating thread, as specified by the
[Linux manual](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
A Tokio blocking worker can retire while its child remains live. The imported
owner keeps that thread alive without weakening the signal, dispatch deadline,
confinement profile or custody checks. It refuses preparation when its 64-thread
capacity is exhausted. This branch retains its existing Rust PostgreSQL resource
adapter and original-capability payload mapping.

The original pooled-thread behavior fails the child-survival regression.
The imported owner passes all 200 broker library tests with the repository's
serialized native-test configuration, including runtime retirement,
cancellation, preparation failure and capacity release. The initial parallel
debug campaign remains failed: 195 passed and five native deadline failures.
Strict all-target broker Clippy and workspace formatting pass. Nineteen native
workflow controls require the production build and staging of that same binary;
removing the profile or copying the debug binary fails. Local operator commands
use the same profile.

Fuzz review finds that the pinned upstream action clones a clean repository and
does not forward the step's target-selection environment into its nested build.
The CFLite builder also omits the mapped FROST round-two executable. The repaired
workflow builds and validates all 34 mapped executables, then selects the
exported binaries immediately before fuzzing. Both modes retain unaffected
executables until that validation; the runner creates the export directory so
it can remove unselected executables after the root builder exits. Eight
behavioral and handoff tests pass after their failing controls. Unknown,
duplicated and empty selections, missing executables, non-executable files and
symlink substitutions fail before pruning. Corpora and runtime support files
remain intact. The configured 60/120-second total sampling budgets are unchanged.
The generated-file handoff tried in local commit `f6d96879bb` was superseded by
export selection before publication; it is not the final implementation.

The source-backed repair checkpoint is
`6434f8c9e1d192efedd3244ce4dc37f5acc6226c`. Its refreshed native qualification
and final exact-candidate hosted acceptance are recorded separately below.
The current log manifest authenticates 269 retained streams; no earlier failed,
cancelled or interrupted campaign is relabeled as passing.

The separate fuzz rerun at `2ae8ee2979` finishes successfully in job
`111688251606`, run `37278705710`, attempt two. All 33 previously exported
targets execute with no reported crash. Attempt one remains interrupted.
This success does not cover the replacement workflow or restored 34th target;
those require the replacement candidate campaign. The log manifest now
authenticates 271 retained streams.

Frozen source `6434f8c9e1d192efedd3244ce4dc37f5acc6226c` passes all 21
terminal qualification commands against 37,269 source files, retaining 48
outputs with unchanged before/after source hashes. Funded work reports
92 passed and six explicitly ignored. Parent SIGKILL, evolving funded work and
all four child-payment interruption cases pass. A separate inline review of
the launch owner, its cancellation and failure paths, both fuzz export modes,
production binary staging and public artifact allowlist finds no additional
P0/P1/P2 issue. The manifest authenticates 272 retained streams. Final hosted
acceptance for the pushed evidence candidate remains required and is recorded
in the PR without mutating that candidate. This is author self-review, with
no independent approval implied.


## External review of the replacement candidate

The externally triggered review of `5dc7921d3c6437db40a01ceea20a9fdb1396ba31`
([review 5415870805](https://github.com/bb-connor/arc/pull/1173#pullrequestreview-5415870805))
found two P1 signature-verification defects and one P2 protocol projection
defect. This supersedes the earlier author review's no-additional-findings
judgment for these boundaries. The user marked the PR ready for review; that
state is preserved. No subagent was used for the repairs or their self-review.

Actual identity-point Ed25519 forgeries reproduce counterparty-authorized hold
release, receiver consent acceptance, signed unknown terminal evidence,
detached bilateral co-signing and both DSSE profiles. Adjacent directory tests
also reproduce weak trusted-issuer and passport acceptance, plus endorsement
of a weak revocation-oracle key. Capture-waiver tests reproduce weak consent
and observer-key configuration. The repair uses the existing strict signature
verifier at every affected authority boundary and rejects weak configured
payment/oracle keys. Removed directory tombstones still suppress all authority
without requiring a valid endorsement from an evicted peer. No generic crypto
compatibility API, public signature algorithm, receipt preimage or schema is
changed.

A2A v1 now carries the existing JSON-RPC response through error projection,
preserving its request ID, code, message, data and typed local error. Only
successful task results receive v1 projection. Owner mismatch and missing-task
regressions compare the original protocol behavior. The first new missing-task
assertion incorrectly expected `InvalidRequest`; the correct lower-layer cause
is `ToolNotFound`. The corrected test fails against the original implementation.
The initial 109-pass/one-failure run is retained as a failed test campaign,
separate from the corrected rerun. The next run exposed a legacy-route typo in
the comparison fixture (`tasks/get` instead of this implementation's `task/get`,
and the corresponding cancel route); that 109-pass/one-failure attempt is also
retained. The final comparison checks the typed error on both responses before
comparing their wire values. Likewise, the initial waiver test's missing
`chio_core::Result` alias is a test compilation error, not a reproduced attack.

The two CFLite attempts on `5dc7921d3c` failed during inventory build before any
sampling. In attempt two, container exit 137 preceded runner shutdown; the
last runner lease renewal was still valid. The diagnostics do not establish an
OOM cause. Both failed outcomes and logs are retained. Cargo concurrency is now
explicitly bounded to two jobs inside both nested builders by default, with an
operator override. The actual shell handoff tests observe that budget at the
compiler boundary and preserve the complete 34-target export, target-specific
features, ASan and the existing total sampling budgets. Replacement-SHA hosted
execution remains necessary; these local controls are not fuzz coverage.


The subsequent same-class audit also reproduced weak-key enrollment through
`KernelTrustExchange`, acceptance of a weak FROST artifact trust root, and
forged fanout deposit signatures. The repair covers these remaining public-key
verification sites in both federation crates. FROST artifact roots now reject
weak Ed25519 material for all three authority roles before installation; the
threshold group's native FROST verifier and signing protocol are unchanged.
The deposit verifier remains bound to the existing canonical preimage. These
additional failures are retained in `readiness-review-adjacent-authority-red.log.gz`.
The preceding 502-test protocol/federation pass and strict Clippy pass precede
this extension and are not attributed to the final source.

The final authority repair passes 505 protocol/federation/Iroh tests with
strict all-target Clippy. The kernel repair passes 1,580 tests and strict
all-target Clippy after 52 weak negative assertions were replaced by exact
rejection checks. Their diagnostic observations are retained separately from
acceptance. The negative-assertion baseline remains unchanged at 1,254.
Trust-boundary inventory review follows the two bounded PostgreSQL readers and
the renamed legacy owner. The co-signing witness now requires strict verification;
a permissive-verifier substitution fails its calibration. All 15 witness tests
and the inventory gate pass. The 230 formal mirrors and 66-row, 182-artifact
coverage check pass, as does workspace formatting.

A second external static review, 5416240083, reports further lifecycle, CI and
evidence findings against the same earlier candidate. These are not covered by
the preceding passes. The closure plan is
`docs/superpowers/plans/2026-10-05-pr1173-review-closure.md`; final source freeze
and hosted acceptance remain open until its findings are resolved.


## October 5 replacement source qualification

Frozen source `2ce480588721ce206c740ff1a601c4d2a9c9889a` passes all 21
terminal commands against 37,305 source files with 48 retained outputs and
unchanged before/after source hashes. The current source-bound record is
`docs/research/dynamic-delegation/evidence/qualification.json`. It includes
15 delegation lifecycle tests, five three-owner composition tests, 29 durable
admission tests, the full runtime/swarm selections, and 96 funded tests with six
explicit opt-in skips. Actual parent SIGKILL, evolving funded work and all four
earned-child payment cases pass, followed by all 18 artifact-tool tests.

The complete previous campaign and the interrupted attempt before the authorized
workflow-definition correction remain under the evidence history directory.
The interruption is not counted as a successful qualification. The additional
review disposition records repaired boundaries and bounded disagreements.
Final hosted main CI, research workspaces, native x86, fuzz, Kani, supply-chain
and PostgreSQL acceptance still require the replacement commit. The security
agent owns the separate signed Linux evidence package. The PR is ready for
review by the user's choice; this result does not establish merge, deployment
or publication readiness.


## October 5 final source checkpoint

Frozen source `efd0bc4d8c47a1e5a5bdf0e83aa731d7925aaa4a` passes all 21 terminal commands against
37,307 unchanged source files and 48 retained outputs. The artifact-tool
suite passes all 20 tests. Actual parent SIGKILL, evolving funded work and
all four earned-child cases pass. Earlier complete and interrupted campaigns
retain their original outputs under the evidence history directory.

The follow-up repairs pass 9 outcome-ledger tests, 8 API-protect tests,
6 control-plane initialization tests, all 41 exact return-context selections
and the complete 52-test threat target, with strict affected Clippy and
formatting. The initial structural diagnostic has 95 passes and five failures
among 100 terminal gates. All five failures have passing targeted rechecks;
the failed campaign remains failed. The real composite AWS-LC gate passes
locally, including root and standalone Cargo Vet and default/FIPS regressions.

Several historical hosted jobs never acquired a runner. The native-host
aggregate correctly fails when its binaries job is abandoned and consumers
are skipped. These cancellations and failures supply no missing execution
evidence. Final-SHA hosted qualification and the security-agent-owned signed
Linux evidence package remain required. No merge, deployment or publication
readiness is established by this local checkpoint.


## October 5 broker and workflow follow-up

Source `b7bdfb6ce67c62760f4e5578055f05727119ad11` passes all 21 terminal native commands against
37,307 unchanged source files and 48 retained outputs. This follows the
completed `87aa7e4a0f` checkpoint and the independently reproduced broker
availability defect. Malformed strict audit input now remains a denied client
fault; the daemon still performs a governed provision and drains and restarts
correctly. All 206 default broker tests and both separately executed regressions
pass. Real-enforcement all-target Clippy and formatting pass.

The historical PostgreSQL run passed both trajectories and supplied 23 verified
receipts, but failed its separately selected broker test on missing key-log
helpers. Keep that overall failure and require a final-head rerun. The corrected
fixture builds both services from the candidate and publishes their paths only
after every executable validates. Native workflow and executable-export controls
reproduce missing paths and pass after repair. Repository-authorized definition
`c009aced79d69f01880b5f7c53ed3c1754e3b7da` replaces the preceding pin.

The security lane still owns the absent committed Linux evidence and policy,
including coherent integration of that definition's supporting closed-shard
producer controls. No authority variable is changed. Final-hosted main CI,
research matrix, fuzz, Kani and confined native acceptance remain required.
This record establishes no merge, deployment or publication approval.


## Archived README follow-up

Source `c2d75712df3ca2bc78c4964bdcf09658baaeb1a7` passes all 21 terminal qualification commands against
37,307 unchanged inputs and 48 retained outputs. The preceding
`acf34b0746` hosted artifact job reproduced an altered archived README. Restore
its original assembly bytes and retain the later comparison correction in the
current historical-validation document. All 15 historical tests and the actual
validator pass without a changed source pin, manifest exception or hash waiver.
Production Rust, measurements, PDFs and archive inputs remain unchanged. The
archived README is restored to its original bytes.

The refreshed source package includes actual parent SIGKILL, evolving funded
work, all earned-child cases and 20 artifact-tool tests. Retained prior failed
and successful campaigns preserve their original scope. Final-head main, x86,
proof, fuzz, native and PostgreSQL acceptance remain separate, as does the
security lane's committed Linux package and supporting-source handoff.


## Final hosted-campaign source repairs

Source `91373484e6feafce458de730c10e5f2e39af5168` passes all 21 native commands against 37,311 unchanged
inputs and 48 retained outputs. The additional lifecycle, task-subject,
portable, nested-auditor, formal-anchor and workflow-identity repairs are recorded
in SECOND-REVIEW.md. Preserve all original failed and interrupted campaigns.
All 116 A2A edge tests, three live client scenarios and both strict Clippy
commands pass. Final hosted qualification and the independently owned security
evidence package remain separate acceptance requirements.


## Published advisory follow-up

Source `9be968e6869d706fa5c42aef56ce47e52e17bed0` passes all 21 terminal native commands against
37,311 unchanged inputs and 48 outputs after the three published
JavaScript fixes. SECOND-REVIEW.md records the original failures, eight repaired
installation graphs, real behavioral controls, 502 SDK/conformance tests and
unfiltered zero-finding scan. Rust sources are unchanged from the preceding
qualified checkpoint. The failed hosted campaign retains its original scope;
final-head hosted and signed security-package acceptance remain separate.


## Nonterminal v1 task custody

Source `9b40dc9128b1c62849558af387c1bf918d9c40f0` retains successful nonterminal v1 tasks after blocking
SendMessage while releasing terminal results and execution/projection failures.
Existing caller quotas, authority deadlines and output modes govern retained
custody. V1 GetTask remains observational. Two real SQLite-backed cumulative
approval regressions fail against the original removal, then pass with signed
proposal and receipt authority, stable JSON/text task projections, caller
isolation, cancellation and no dispatch or additional receipts.

The full consumer run also finds four stale threshold fixtures. Bind their exact
tool invocation using the public approval context and install their explicit
approver roster. All successful capture and restart assertions are retained;
production approval validation is unchanged. All ten consumer tests, 116 edge
tests, three live HTTP tests, both strict Clippy commands and structural checks
pass. Formal selection remains 66 rows and 182 artifacts, with its input digest
renewed. Original failures and the preceding candidate's authenticated successful
advisory archive remain historical. Final-head hosted acceptance and the
security owner's coherent source and signed Linux package remain separate.

The preceding hosted flow job passes all 26 default security-type library tests,
then fails its stale twenty-name inventory. The repaired gate includes every
compiled clock and bounded-reader case, preserves the exact default library
target, and rejects each identity substitution through its actual validator.
Positive and negative information-flow models, both portable WASM checks and
all 71 composed test inventories pass in the preceding local campaign.
Its source scope precedes the final delegated-ceiling and revocation repairs;
fresh final-head hosted flow acceptance remains mandatory. Earlier failed checks retain
their actual outcomes. The security owner must still supply the coherent
closed-shard source closure and a fresh caught-only signed Linux package.

## Delegated cost and revocation epoch boundaries

An exact one-invocation dispatch binds the smaller of its signed per-call
and total ceilings. Both ceilings and their currency remain mandatory.
Actual SQLite execution admits the 20/100 and 20/20 grants for the same
20-unit offer, signs the result, captures exactly one 20-unit hold and
replays observationally. A 100/20 grant retains the ordinary worst-case
budget refusal before payment or dispatch. The original maximum rejects
the admissible 20/100 case; all 14 repaired delegation tests pass.

The pinned-origin revocation sink retains the kernel-core strict epoch
compare-and-swap. Identical projected snapshots and older roots remain
idempotent; conflicting installed-epoch hashes, issue times or locally
materialized subjects receive typed rejection without changing the view.
Conflicting signed root bodies inside a batch are rejected before its
single install, including conflicts below a valid highest epoch. Six
authentic-signature controls cover these cases, actual handler rejection
and concurrent duplicate/conflicting writers. Five controls fail against
the original acknowledgement while the replay/stale positive control
passes. The complete typestate-enabled transport campaign records 407
passes and 0 ignored tests. Both affected strict Clippy commands and
the renewed structural controls pass. No second authority registry or
same-epoch update protocol is introduced.

Legacy in-place preparation now retains its effective connection for
signed launch attribution. All ten delivery-revalidation cases and
strict kernel Clippy pass; actual x86 confinement and runtime retirement
remain a separate final-head hosted requirement. The certification
fixtures create private authority parents and live in normal modules
below 2,000 lines. All thirteen certification cases pass with the one
existing timing-sensitive ignore preserved. Complete workspace test compilation
and strict library/binary/example Clippy pass with unchanged captured
Rust/build inputs. The local consumer gate passes six inventories and
fifteen tests, then correctly refuses its first native MCP case on ARM.
That exit-101 campaign remains failed. Complete consumer and workspace
execution require the qualified final-head Linux x86 enforcing host.

The stub scanner distinguishes lint tokens from executable unfinished
macros and comments, admits only the three reviewed exact domain lines,
and removes stale exceptions. The whole repository and every contract
control pass. All 414 SDK/recovery tests pass under system CPython with
both Linux pidfd APIs. The original failed interpreter run is retained;
subsequent workspace/native qualification uses a separately prepared
locked system-CPython environment without changing the dependency lock.

The investigative x86 run at 4b7480c686 completes all five selected native
jobs successfully, including both installed operators, the original
65-second repository command, coding sessions, installed packages,
adaptive review, AI SDK 6/7 and the swarm benchmark. The conditionally
disabled optimized comparison is skipped. Its successful archive is
authenticated in memory; private worker files are not retained. The
earlier request timeout does not reproduce, and retains its failed
source scope. This investigative source precedes the final Rust repairs;
fresh final-head native, PostgreSQL retirement, complete consumer and
workspace qualification remain mandatory.

## Checked-output rejection and replacement graph

Qualified source `199c9cd8a714359eeaf06af3a95a6c26c9df6628` passes all 21 terminal native commands against 37,318 unchanged inputs and 48 retained outputs, including all 20 artifact-tool tests. Earlier qualification packages and all original failed, interrupted and successful campaigns retain their source and result.

The ordinary funded-work suite records 96 passes and six explicit private-chain ignores. Those six Rust tests are not counted as execution; the profile's participant drivers and every separately retained private-chain campaign keep their own command, source and result.

A contractual checker that rejected or panicked once could previously be evaluated again and upgraded to acceptance. All three real kernel regressions fail against that implementation. The repair preserves ordinary validation before persistence and defers opted-in checkers to authoritative durable evaluation, where a denial is retained before payment or release. Rejection remains monotone across the raw and transformed values. Signed redacted denial, one hold release, no output or capture, projection recovery and immutable replay all pass. The captured pre-dependency campaign passes 1,538 kernel tests, strict Clippy and all 72 flow inventories covering 741 tests, with formal and omission controls. Its kernel sources agree with this checkpoint; its earlier whole-input map is retained. Final-head hosted execution remains mandatory.

The publisher yanks iroh-blobs 0.103.0 during preceding-head CI. The replacement 0.103.1 restores per-request mask selection. Authenticated complete delta reviews cover that package and cfg_aliases 0.2.1 to 0.2.2, retaining the existing base acceptance boundaries and adding no exemptions. Actual admitted loopback peers demonstrate that both default and read-only protocols accepted unsolicited writes before the patch. The replacement rejects those writes while signed-root fetches and explicit push permission remain functional. Active root and generated deployment locks, complete affected suites, strict Clippy, six locked audit graphs and enforced deny policy pass on the replacement.

The preceding PostgreSQL job passes both confined worker trajectories; offline verification accepts 23 signed receipts and the existing crash, ownership, fencing and no-redispatch controls. Its retirement fixture then fails because it expects the local diagnostic spelling rather than the authenticated IPC namespace. Only that exact fixture expectation changes. The signed protocol and all canary, substitution, quota, launch and lifecycle assertions remain. Portable broker tests and strict Clippy pass; actual unignored final-head x86 retirement remains required before PostgreSQL acceptance.

The preceding workspace job stops at two stale delivery-readiness mirror hashes before workspace execution. Both complete abstractions have been reviewed against retained connection custody and revalidation. The checked-output repair adds a third reviewed raw-return anchor. Only those three review records change. No modeled action or invariant changes; concrete connection, native launch identity, stateful checker calls and external settlement remain outside these abstractions. Matching hashes are not a Rust refinement proof. Final-head hosted workspace, consumer and native acceptance, and the security owner's coherent source and signed Linux package, remain separate.

The preceding MSRV lane reaches the multi-hop federation fixture and fails because evidence export omits its required private signing-key file. Its subsequent import likewise needs an independently trusted kernel key. The fixture now supplies its existing private file and pins import to the authority key independently derived from that file. Its selected exported receipt is signed by that same private fixture key: the first command-repaired run correctly rejected an independently random receipt signer locally before remote dispatch, and that failed campaign remains retained. Production requirements and all delegation, imported-parent, lineage and replay assertions remain unchanged. Complete federation-issue and evidence-export suites and strict affected Clippy pass; final-head hosted MSRV and workspace acceptance remain required.

The preceding active-defense job passes all sixteen materialization cases then refuses a stale fifteen-name inventory. The repaired exact gate includes that existing bounded-path case and the sealed registry's existing cross-tenant restart case. The contract verifies both source closures and rejects omission or same-count identity substitution for each case. All twelve actual inventories and eighty-five tests pass without changing filtering policy or ignoring any case. External source closure and signed Linux evidence remain separate.

## Checked-output preparation failure closure

Source `d187d763f4879b358c8911e79e0fd3e1a25fe7a4` passes all 21 terminal native commands against 37,319 unchanged inputs and 48 retained outputs, including all 20 artifact-tool tests. All 550 preceding records retain their exact raw bytes, hashes and original result/source scope.

The preceding repair still invoked a contractual checker before later ordinary output checks and frozen transforms. If that preparation failed, recovery could re-run a checker that now accepted and release previously rejected output. Four actual old-source cases fail with Allow instead of Deny: refusal or panic followed by an ordinary-guard failure or a post-invocation contract violation. All four pass after the repair, requiring a signed redacted denial, one invocation, one hold release, no output or capture, and identical retained replay. Initial supervisory and inventory-count failures remain separately recorded.

The kernel borrows its installed guard/context selection, finishes all role probes, ordinary validation, frozen output preparation and result canonicalization before aggregating contractual raw/released rejections. It reuses the existing durable resolved outcome and settlement authority. No durable schema, public API, authority bypass or mutable denial cache is introduced. The resolved-outcome commit remains the durability boundary; an observation whose durable write never commits has no new persistence guarantee.

Complete kernel verification passes 1,542 tests with no ignores and strict all-target Clippy. All 72 flow inventories pass 745 exact cases, including all ten checked-output cases; actual omissions and same-count substitutions are rejected. All 230 formal mirrors already match. No new mirror blessing or modeled invariant change is needed. Coverage is regenerated and checked; mirror correspondence remains a review record rather than a concrete Rust refinement proof.

The renewed follow-up campaign passes complete broker/federation and affected CLI suites, strict Clippy, six locked Vet graphs and default/FIPS controls, enforced deny policy, generated deployment locks, and all twelve deception inventories (85 exact tests). The funded suite retains 96 passes and six explicitly ignored private-chain cases; separately executed participant drivers keep their own evidence. The receipt verifier is built from this source and authenticates its binary hash, without claiming physical x86 confinement.

Three actual owned hosted CI failures are also repaired. Both static security-image lock pins now require the genuinely audited workspace lockfile; actual lock-content and Docker-pin mutations remain rejected. The canonical module-qualified scheduler selector executes one real case, all 31 dispatch cases pass, and the complete recovery gate passes. The federation-policy fixture reuses the existing private temporary directory helper after a diagnostic HTTP500 proved the authority correctly rejected public fixture custody. Its typed HTTP200 response binds the requested subject. A complete broad CLI campaign remains failed with its actual 80-target result: 1,372 passes, 85 failures and seven ignores. Its 69 native MCP failures and one explicitly filtered live conformance case require the existing Linux x86_64 fixture. The 16 other failures reject public authority custody across ten targets. Existing private-directory helpers repair local reputation, issuance, passport rotation and the shared receipt-query fixture. All 19 affected targets pass on the final source, including all 15 shared-helper consumers, and strict all-target Clippy passes. Unchanged passing code retains its original coverage and every failed campaign retains its result. Final hosted workspace/MSRV must execute all locally unavailable native cases without these exclusions. No production custody or reputation policy is weakened.

The preceding full kernel/flow and follow-up campaigns preserve their original complete input maps. Their subsequent Rust deltas are five integration-only CLI fixtures or their shared fixture helper, which neither campaign compiles. All captured production, graph, flow, formal and audit inputs agree with the final source. The current-source CLI fixture campaign and native21 qualification cover the repaired fixtures and CI scripts separately; no prior campaign is retagged.

Hosted results for preceding candidate 2b608eb2d1 remain historical. Its security image rejects an authorized-source lockfile checksum mismatch; its portable security contract lacks the closed-shard fixture. The security owner retains the coherent approved source, definition, signed Linux package and policy handoff. No authority variable, evidence digest or qualification rule is bypassed. Fresh final-head workspace, MSRV, consumer, Kani, fuzz, supply-chain, advisories and actual unignored x86 PostgreSQL retirement acceptance remain mandatory.

## Approval-continuation and current advisory closure

Source `372552646f101d958c53114037eaadb728249962` passes all 21 terminal native commands against 37,322 unchanged source inputs and 48 retained outputs. All 697 preceding raw records retain their complete original entries, bytes and hashes. Previous full kernel, flow, CLI, audit and hosted campaigns remain scoped to their original source; they are not retagged as current.

The actual approval-blocked A2A v1 consumer exposed a liveness loss: GetTask correctly observed retained work, but SendMessage rejected the task reference needed to attach later signed approvals. The repaired profile reports INPUT_REQUIRED and accepts an explicit owner continuation of the frozen original work. It compares the existing complete canonical kernel request and bridge/source bindings after removing only approval artifacts. The original message, task, context, deadline, output mode and all other authority remain fixed. No background executor, mutable authority cache or durable schema is introduced. Authoritative terminal denial remains terminal. Polling remains read-only.

Actual old-source continuation and inaccessible/expired-task campaigns fail before the repair. The current complete edge 118, adapter 115 plus one golden, and consumer 14-case suites pass with no ignores. The signed SQLite consumer verifies one invocation and identical durable replay, owner isolation, refusal of changed frozen authority, cancellation and observational polling with fresh approvals. Strict Clippy passes for all edge/adapter targets and the consumer test. The producer verifies all 14 exact consumer cases, and independent fixture controls reject omission and same-count substitution of each new continuation case. The remaining consumer producer native MCP fixtures require physical Linux x86 and remain final-head hosted prerequisites.

The authenticated preceding 15d5 dependency artifact identifies newly indexed Sharp and shell-quote advisories. The generated root/SDK locks now select Sharp 0.35.5 with bundled librsvg 2.63.2 and shell-quote 1.11.0. Only those package families change; registry integrity is authenticated. Actual installed vulnerable-package controls fail and the fixed three-case suite passes, including post-comment shell line terminators and native SVG decoding. Both full filtered and unfiltered OSV scans exit 0 without findings; existing authenticated private-tooling repairs and advisory-gate refusal controls pass. No exception is added.

The current physical x86 PostgreSQL lifetime trajectory, Kani, fuzz, workspace/MSRV and all other required hosted checks still need terminal final-head acceptance. The security owner retains the approved source, definition, signed Linux evidence package and policy handoff. Local passing campaigns do not close those external production boundaries or the four independent publication requirements.

## Terminal continuation error closure

Source `2f20769dbdd024ca4b65137ed3ca727778e9f974` passes all 21 terminal native commands against 37,322 unchanged source inputs and 48 retained outputs. All 784 preceding raw records retain their original entries, bytes and hashes. Earlier source and hosted results retain historical scope.

Fresh candidate199 review identified an approval rollback after dispatch. The confirmed actual SQLite regression performs one invocation, commits outcome_unknown_after_dispatch and verifies a signed kernel cancellation; the preceding edge nevertheless returns INPUT_REQUIRED. The corrected edge keeps the approved frozen request and bounded failed protocol custody, preserving its deadline. It clears obsolete approval evidence and uses a fixed status message without inventing a kernel decision or receipt. Any terminal kernel response already projected remains intact. Prevalidation refusals still preserve pending custody.

The complete current edge118 and consumer15 suites pass without ignores, alongside strict all-target edge and consumer-target Clippy. Repeated GetTask is read-only, inaccessible owners cannot observe the failed task, terminal continuation/cancellation is refused, and retrying the original stable message leaves the effect count at one under kernel authority. The actual producer verifies all15 exact cases; independently derived controls reject omission and same-count substitution of all5 continuation cases. Formal mirrors, generated coverage, hygiene, format and diff checks pass. The initial unsupported wire-error assertion is retained as a diagnostic failure, not the accepted RED.

No kernel API, schema, authority cache, new dependency or qualification exemption is introduced. Earlier dependency/source audits remain scoped to their actual inputs; current hosted audit/advisory checks must qualify the final candidate. Physical x86 PostgreSQL lifetime, Kani, fuzz, workspace/MSRV and all other required hosted checks need final-head terminal acceptance. The security agent owns the signed Linux package and policy handoff. The four independent publication gates remain open.

## Retryable pre-evaluation preparation failure

Source `76a052c5b8ae519426584764552d84a941438cb7` passes all21 terminal native commands against 37,324 unchanged source inputs and48 retained outputs. All830 preceding raw records retain their original entries, bytes and hashes. Earlier source and hosted results retain historical scope.

Fresh candidate37 review identified a transient clock failure after continuation validation but before orchestration. The actual signed SQLite RED permits that validation clock read, fails the next deadline read, verifies zero dispatches and no new receipt, and observes the incorrect terminal task. The corrected private task-completion module records NotEvaluated or Evaluated at the existing orchestration call boundary; it does not infer physical dispatch from an error. The legacy complete_task wrapper and public response remain unchanged. Before evaluation, failure preserves the original pending response/request and deadline, and cannot recreate an expired removed task. After evaluation, the preceding signed-cancellation protection remains intact without restoring obsolete approval evidence or fabricating a kernel receipt.

Current edge118 and consumer16 suites pass without ignores. Both P1 regressions pass: transient clock recovery completes the same original task with a verified signed Allow and one invocation, while an actual post-dispatch cancellation remains failed and stable-message retry does not redispatch. Strict Clippy, all16 exact consumer identities, omission/same-count substitution controls for all6 continuation cases, formal mirrors, refreshed coverage, hygiene, format and diff checks pass. The initial stale coverage failure remains distinct from the separate5-command finish. Test support reuses the existing injected clock API; no new kernel API, schema, authority cache, dependency or qualification exemption is added.

Final-head physical x86 PostgreSQL lifetime, Kani, fuzz, workspace/MSRV, supply-chain and other hosted checks remain required. The security agent owns the signed Linux evidence package and policy. All four independent publication requirements remain open.
