# Combined process and M4 qualification

## Current checkpoint (2026-09-23)

The continuation is on draft PR #1160. Both required parents remain ancestors. The primary
checkout was fast-forwarded after its frozen workspace run terminated;
`output/` retains untracked evidence. Qualification below names each source
separately and does not establish a complete current-candidate workspace pass.
Use the [completion execution plan](../superpowers/plans/2026-09-22-security-roadmap-completion.md)
for the reconciled queue and original-requirement coverage. Older checkpoints
below retain their historical source boundaries.

| Area | Current evidence | Remaining boundary |
| --- | --- | --- |
| Foundation | The locked x86 workspace run at `36ddfcf69e` stopped on three CLI sandbox tests. All three exact cases pass with the matching stock Ubuntu Bubblewrap profile and unchanged restrictions. The full retry is terminal, exit 101, on `auth_live`: Node 18.19.1 cannot import the TypeScript SDK. The temporary profile cleanup completed, with namespace restrictions restored to 1/1. | Complete workspace and workspace-Clippy passes remain open. Original failures and the cleanup record are retained in `chio-workspace-36dd-terminal-20260923.tgz`, SHA-256 `51098e8f1182b07fc84476cda9f54a4786b9d0de3dcb0b345b8299768ae0425e`, under `output/process-security-20260915/`. |
| Dependency and source policy | Reviewed AWS-LC repairs and exact audits remain selected. Exact, expiring exceptions cover 34 inspected upstream text occurrences; the scanner passes on a clean source export and rejects new incomplete code. Current generated coverage has 59 rows and 170 artifacts. The root lock digest is `e3f42ccac4fd0397f507cc3767a25eda3436fd4f43296359d740e39de7cd8d76`; the process-host dependency selections change no registry version. The image and structural contract pins match. The runner handoff repair at `900f0ff639` passes the existing behavior, structural contract and full mutation suites. | Preserve audit scope and qualify final hosted inputs. Retained source archives remain separate from clean-source qualification. Mirror matching is not a solver proof. |
| Fuzz compilation | All 30 targets compiled with ASan on x86_64 at `84c0ca4e89`; retained log hash matches. | Required fuzz campaigns and final-source requirements remain separate. |
| Cage | The `84c0ca4e89` native run reports 69 tests, 26 real probes and ten mutants with exit 0; retained log hash matches. | The retained runner's release-helper adaptation and trusted capture require their own acceptance. |
| M5 | Original nonce custody, receipt checkpoints and inclusion proofs are implemented. Runtime `317b3a9128` with qualifier `6170900d7f` passed all seven native scenarios and rejected 15 substitutions; a separately built aarch64 observer verified both inventories. | Final source, combined-foundation qualification and independently authorized trusted-runner acceptance remain open. The artifact does not claim full M5 acceptance. |
| Image | Source `6170900d7f` built and passed identity, ownership, toolchain and offline locked-dependency checks. Image ID: `sha256:f17db010c5e6e5e1d6ad8eea8ce97f8e2a530888a737e59bbb16afdfdb1a245a`; all 199 archive hashes and 225 package pins match. | The current lock and broker gate differ. Rebuild and validate those inputs before authorized publication, registry identity verification or trust-root rotation. |
| M6 | The real confined kernel/broker/MCP/TLS invocation composes governed keyring issuance, witnessed rotation, contiguous synchronization and stale signer fencing. V2 completion signs returned headers and checks original completion time; its recorded 206-test broker inventory passes. Ordinary process hosts now use the same durable authority and invocation-owned confined children. The governed single-root profile issues through the keyring, retains original authority across rotation and restart, and exports v3 keyring/capture/cage/nonce/log joins. The real x86 CLI flow and a separately built ARM artifact verifier pass. | Final-source owning gates and designated trusted capture remain separate acceptance work. Governed delegation is explicitly unsupported; the existing non-keyring profile retains static children. ARM verifies artifacts but retains the native-enforcement refusal. Full M6 acceptance is not claimed. |
| M7 | At `6170900d7f`, deception passed 82 tests; response recovery, flow and temporal gates exited 0. Temporal covered 10 inventories and 40 exact cases; retrieved hashes match. The 28 archived adversarial definitions and 35 campaign identities are restored as pending cases. Broker quota controls now target the owning SQLite composite authority; corpus consumers exclude pending cases from completed coverage. | All 35 campaigns need current-source control and caught-mutation evidence before promotion. Restored definitions and historical outcome hashes do not close M7. |
| M8 | At frozen `d5884b4d87`, the fresh million-receipt recovery campaign passes in 6,869.58 seconds with 1,000,000 actual appends and no profiling intervention. It verifies integrity, pagination, backup, reopen, half archive, retained append and restored append. The unchanged 24-case retention property also passes under declared 25 ms fsync/fdatasync delay in 265.71 seconds. | Both results are tied to their frozen source. The delayed-sync diagnostic did not reproduce #1045, so its quarantine remains. Final-source qualification and the liveness repair remain open. |
| Hosted delivery | #1160 publishes the continuation. Main prerequisite #1168 is at `2fb4a6c1c8`; definition-only #1167 retains `88b9b2a3cb`. Original hosted failures remain recorded. | New-head qualification, independent review, protected integration and the exact source/definition/image/verifier authority transition remain required. |
| M9-M11 | Packaging and handoff work remains preserved. | No milestone-level M9-M10 acceptance or M11 operational promotion is established. |

The September 23 M7 recovery continuation services previously authorized
responses before new correlation/planning work and independent declassification
outbox maintenance. Three real-store outage cases verify that admission remains
closed while expired overlays are lifted. Shutdown moves blocking SQLite probes
off the async executor and retains the same probe through cancellation. A caught
worker panic publishes its terminal failure before cleanup, including when that
cleanup also fails. All 22 host lifecycle cases and the focused panic/cleanup
regression pass; the classifier's 11 existing cases also pass after removing
repeated JSON decoding for field findings.

The M8 continuation keeps rotation counted as in flight through archive I/O and
accounts for its queue admission. A real SQLite write-lock regression verifies
wedged health while rotation is blocked and healthy state after it completes.
All 63 selected retention cases pass; the original #1045 property remains
ignored and this fix is not claimed as its root cause. Strict all-target Clippy
passes for control-plane, store and data guards. Source hygiene and 225 formal
mirrors pass. The original shutdown deadlock, captured thread stacks, crash-state
failure, compile-path mistake, and fixture correction are retained separately
from the passing retries under `output/process-security-20260915/m7-recovery-20260923/`.

The M9 continuation adds the six runtime companion binaries, their SBOMs and
digests, and provisioning assets to the Linux x86 release archive. A remote
staging-mechanism check validates all seven real x86 executables and static
confinement helpers. Its inputs are explicitly labeled historical `a24204b42b`
debug binaries, so it does not qualify a current release build. The supervisor
also implements `--credential-fd ARGUMENT=CREDENTIAL` for the broker and response
authority: it transfers private, owned files through child-only inherited
descriptors and supplies the actual descriptor numbers as daemon options.
Nine process-supervision cases and four existing reference-unit cases pass,
including exact binary bytes, distinct descriptors, unsafe-file refusal and
conflicting-option refusal. Strict all-target CLI Clippy and source hygiene
pass. Current release builds, full installation and the Rust registry package
closure remain separate M9 work.

The broker daemon now handles SIGTERM/SIGINT by stopping acceptance and joining
its fixed workers before releasing socket custody. Failures racing that drain
remain errors, and existing provider/IPC deadlines are unchanged. The real
process inventory passes all three cases, including preserved hard-kill secret
custody and a new SIGTERM/restart flow over the same durable stores; the worker
panic propagation case and strict all-target broker Clippy also pass. These
results and the initial test-only signal-constant compile correction are retained
under `output/process-security-20260915/m9-broker-shutdown-20260923/`.

The response authority publishes a request-worker panic as a fatal stop and
joins workers already created if a later worker cannot start. The authenticated
process regression requires failure exit and removal of the owned socket.
All 17 authority tests and strict all-target Clippy pass; the two ignored helper
entrypoints run inside the process tests. Evidence is retained under
`output/process-security-20260915/m7-authority-worker-20260923/`.

The governed-host qualified full-index patch on `3dd65e1fba` is
`47b5f18164ac39f4c48ec4debcaad14bd977724879d702462066c51a8a136f73`.
Its real CLI case passes in 95.45 seconds, including witnessed rotation after
parent issuance, missing-verifier startup refusal, one provider effect, private
input refusal, restart replay and independently pinned artifact verification.
The original mixed-signer checkpoint failure led to separate anchored keyring
audit and kernel call logs. Shutdown retains the host lease until signer and
writer custody is released. The provisioning fixture's original duplicate
selector-owner failure is retained separately.

The public artifact also passes all 14 reported checks on a separately built
ARM observer; physical effects, complete graph/task authority and aggregate
history remain explicit unchecked claims. The x86 CLI binary hashes to
`f70ef0c90acc4c955f62f8c3925b9d749b269d19450d087e186a693142336053`;
the ARM observer hashes to
`82d91eecdf4d0ceb6e7704caebaee4d674cf1cbe9e0f7a0cf44afc0e0a62af10`.
The observer was built from patch `98e56527da971188eb3bee39996f99f5fb6f73b9d84282bcec77ad0a0834d6fe`,
before the final host-only field drop ordering change; its verification code is
unchanged. Initial observer invocations correctly rejected a relative database
path and group-writable ancestors; the retained retry uses a private absolute
path. Archive `output/process-security-20260915/chio-governed-process-host-20260923.tgz`
has SHA-256 `cd20929f622b75207456888622ca9644d6d1e45cc0d42e029bfb18684def6e24`;
its manifest verifies locally. Strict all-target CLI/broker Clippy, formatting,
source hygiene, structural CI, formal mirrors and generated coverage pass.
Only qualification documentation and generated coverage follow the qualified
Rust patch.

The ordinary-host Rust patch qualified on `3dd65e1fba` has full-index SHA-256
`150d589e642d5c422bcd92ffdf556bcbcbd5e2ab7d61cd37b7bb2cb65ef73746`.
The shipped CLI case passes in 76.18 seconds with the original deadlines and
one independently observed TLS provider effect across restart replay. Missing
external host pins and a substituted broker key both reject the v3 artifact.
All eight prior native scenarios also pass at that Rust source in 280.14 seconds.
The retrieved original-host archive has SHA-256
`c8de5f14117e55f91e43ce0265f4afe64b43fe37c7aa66ffbf473f077a8ec354`.
Nine kernel delivery lifecycle cases, the native nonce-generation regression,
16 process cases and 33 host unit cases pass in their recorded slices. Strict
all-target Clippy passes for CLI, process, broker and control-plane at this
Rust source. Policy-denial diagnostics contain fixed reasons; the kernel still
redacts extension errors and retains its conservative recovery contract.
Original failures remain separate, including the supplementary-group fixture,
provider readiness and incomplete classifier-map failures. Seven abstraction
anchors were refreshed after reviewing unchanged authorization and cleanup
ordering; matching anchors do not establish Rust/model equivalence.

The completion repair reproduced two accepted substitutions: altered response
headers under the original signature, and a correctly signed native receipt
claiming completion one hour in the future. V2 evidence commits to the exact
canonical sanitized header vector under a separate digest domain; v2 receipts
use a new signature domain. Shared live and durable response verification checks
that commitment. Native completion also binds original parent issuance and
broker activation to the trusted receiver's observation time, while historical
verification remains valid after capability expiry. Historical v1 schemas and
positive vectors remain unchanged; they cannot authorize a v2 completion.

The qualified Rust, protocol and binding patch on `3dd65e1fba` has full-index
SHA-256 `469eea553c2a14a0b04761bfca1722f5153a34dfd9d3a54ebae1de0fc0ed611f`.
The 175 x86 unit tests and 31 integration tests pass with no ignored tests;
retrieved archive `output/process-security-20260915/chio-broker-v2-final-3dd65e1fba-20260923.tgz`
hashes to `766927873a413a16cb0279c0ec8d40216de00578d91a3a43c55ad2046421cc5f`.
The existing wire checker passes five indexes, 90 positives and 264 negatives.
All four binding generators and their check modes pass. Original failing
regressions and the obsolete-v1-fixture gate failure remain retained separately.
The `5d643420b1` checkpoint adds only this ledger after the qualified patch.

Native broker composition now obtains its local serving owner from
`DurableAdmissionRuntime`, the same runtime used by the process host. Its kernel
uses the persisted runtime identity and the original runtime attachment path.
The broker reader, authority handler and native flow share that exact owner;
remote authority profiles have no local handle. All eight native scenarios pass
on x86 in 276.45 seconds, including real cage/keyring delivery and all death and
invalid-completion cases. The original MCP completion case also passes locally,
and strict all-target Clippy passes for both affected crates. The two-file Rust
patch on `5d643420b1` hashes to
`82655f12a16be6e45aa684a2625843dcaf19d4dddb796db9d907c264371caa0d`.
Retrieved archive `output/process-security-20260915/chio-broker-runtime-authority-20260923.tgz`
hashes to `d16a4d6342fd629c51a59da2ac65ea0f2b798e37b41ccfec2d9d956bd74e7e98`.
Only documentation follows this qualified Rust patch. Ordinary process-host
broker routing and complete offline artifact joins remain open.

The broker-death patch is retained as full-index SHA-256
`c5a4a390284a7550e11b7b2ede9a9d1d8170584b9a121871c9f0be5257c68407`
on `900f0ff639`. Its test-only adapters interrupt the original production
participant after registration, the transport after composite capture, or the
broker after an independent TLS peer validates the actual request. The provider
observes zero connections before send and exactly one authenticated request after
send. Existing report-loss, substitution, credential-leak and replay assertions
remain in the owning gate. The two confined tests pass in 81.87 seconds.
Retrieved raw logs, build identities and terminal markers verify against
`output/process-security-20260915/chio-broker-cutpoints-900f0ff639-20260923.tgz`,
SHA-256 `f43cac431602a97a03b45e6c32af903c72d1daffcbd278e814d8379ba5a2eb54`.
These observations do not grant retry authority or authorize release capture.

The daemon integration exposed a clock-boundary rejection and repeated custody
reads that exhausted the provider observer's ten-second accept deadline. The
broker now validates authority responses at trusted completion time and retains
the original signed request times in independently verified audit evidence.
Original request and physical custody are read in one authenticated snapshot;
capture separately verifies its original commitments and current physical hold.
All 13 budget atomicity and ten retained-request cases pass, including an
owned-transaction corruption that previously accepted an altered quota limit.
No freshness bound, IPC
deadline, observer deadline or success assertion was increased or weakened.
Original failures and the full 161-case passing retry remain in the execution
ledger. The changed capture implementation anchor was reviewed against
`PostAdmissionDropGuard.tla`; concrete SQL integrity remains outside that model.

The subsequent MCP composition exposed a distinct lifecycle problem: a raw
preconnected descriptor expired during legitimate final kernel authorization
and capture. The host now authenticates and prepares the exact original
request before passing that descriptor to the selected tool transport. A fixed
worker services one retained connection, bounded by 30 seconds and both signed
capability and registered nonce expiry. Ordinary frame and response deadlines
are unchanged. Completion must match the original signed capture; lost replies,
altered bodies and extra MCP content retain unknown-outcome accounting and
refuse retry. See the [prepared connection contract](broker-prepared-connections.md).
The full library passed 167 cases in 290.15 seconds; the boundary gate also
passed all three native process cases and five control-plane integrations.
The existing source-policy scan passes on the staged source export, and the
updated image input contract passes its complete mutation suite. This does not
qualify a rebuilt execution image or the complete M6 topology.

Retained native evidence is under
`output/process-security-20260915/resume-20260921/oci-remote/`, including
`m5-317b3a9128-retry1/`, `image-6170900d7f-offline/`, `m7-6170900d7f/` and
`storage-20260922-84c0ca4e89/`. The M5 bundle SHA-256 is
`7832b4cb4ef28661b632e8db692fbadf6001f62eea7080de6352a1c5cdf439ce`.
Earlier cage and fuzz evidence retains its original `84c0ca4e89` identity.
The current image input digest and publication boundary are recorded in
[the image input record](execution-image-inputs-2026-09-20.md).

Continue the original roadmap through M10 while completing the foundation and
trusted-authority gates. M11 remains a separately authorized observed pilot.
The accepted steps 1-4 map to packets 1-10 in the completion plan.

## Current checkpoint (2026-09-21)

The current local finalization candidate is based on
`c4beda6ea02bc1dc988a52b904c8422608a06902`. It preserves both required
parent histories and includes the September 20 dependency continuation plus
the September 21 source-audit and native qualification repairs:

- `0b33f3b3a7`: preserve ignore filters across size and filename cases.
- `b36b1d5b69`: backport the upstream regress UTF-8 search-boundary repair.
- `9f0a8a0648`: qualify nono against the repaired local dependencies.
- `ce19d8f3f6`: close all remaining vendored Rust file-size violations.
- `c4beda6ea0`: preserve complete seccomp ioctl request values on musl.

The clean execution checkout is `/tmp/arc-security-launch` on
`integration/process-security-m4`. Draft PR #1160 remains the delivery path.
The complete review and continuation records are tracked under `docs/reviews/`.

| Area | Current state | Remaining boundary |
| --- | --- | --- |
| Ancestry and review dispositions | Both required parents and all 109 dispositions are retained. | Original review threads remain administratively unresolved. |
| Foundation implementation | Combined process/security behavior and dependency repairs are present. The 69-test cage inventory, 26 real probes and ten mutants pass at `c4beda6ea0` on native Linux/x86_64. | Run the remaining exact-candidate workspace, process, flow and fuzz inventories, then repeat affected cage evidence at final head. |
| Dependency policy | The three AWS-LC sources were reviewed against their exact registry archives and upstream trees. A reproduced `legacy-des` parity flaw in `aws-lc-rs 1.18.1` is repaired in a local source selection with a failing-before, passing-after regression. Exact audits cover `aws-lc-sys 0.45.0` and `aws-lc-fips-sys 0.14.2`; locked cargo-vet passes. | Preserve the reviewed local repair and exact audit records through final integration. Do not replace them with exemptions. |
| Execution image | Source `c4beda6ea0` has a locally built and validated Linux/amd64 image, `sha256:d76567ce471f44f70776aed86c8e6a8be4a7040b92bd878d55ba7fbfd6a10243`. It was not published or authorized for trusted capture. | The worker recovery and AWS-LC changes make that image historical. Rebuild and validate final head; publication and trusted-capture authorization remain separate. |
| M5 | Six of seven scenarios pass at `c4beda6ea0` on the designated native Linux/x86_64 runner. The budget scenario exposed a retained-checkpoint recovery race after both effects and signed quota denials were durable. The worker now recovers that checkpoint before invoking. | Rerun all seven scenarios at final head and verify the joined artifact independently. `m5_acceptance_complete` remains false. |
| M6-M10 | Individual broker, retention, recovery and packaging slices have evidence below. | No milestone-level M6-M10 acceptance is claimed. |
| Delivery | Draft PR #1160 is open, draft and mergeable at remote head `bf8b666274095acb1d103e428f21eaaa7bfdeb54`. The latest refresh has 105 successes, 16 skips, 11 failures, one cancellation and one still-running MSRV job. | Keep the local finalization unpushed until exact-head gates complete, then reconcile terminal hosted checks and the final PR head before merge. |
| M11 | Promotion remains explicitly separate. | No production promotion is claimed or authorized. |

The local finalization Cargo.lock SHA-256 is
`8e7154ee265ed4521d92130aeb145070c8da1026d02b2939761af758f447ade1`.
Local validation retained for the September 20 continuation includes the full
Rust hygiene gate and mutation fixtures, 693 nono tests, 201 ignore tests, the
supported regress matrices, strict affected Clippy, workspace formatting,
structural security checks and a proof inventory of 59 rows and 170 artifacts.
These results are source-bounded local evidence. They do not replace the
exact-candidate Linux, hosted or trusted-runner gates.

The next execution order is: commit the reviewed recovery and dependency
repairs; run the remaining exact-head foundation, cage and M5 evidence-join
gates; rebuild and validate the exact-head execution image; then reconcile
hosted results and protected integration. Do not restart from the historical
entries below unless a current gate points to a specific retained failure.

## Historical qualification ledger

Status on 2026-09-15: Task 5 of the
[integration plan](process-security-integration.md) is in progress. A draft
integration PR is a source/CI checkpoint, not completed qualification, a merge,
or M5 acceptance. The user requested execution without subagents; subsequent
review is direct primary-agent review, not independent reviewer evidence.

Retained pre-M5 qualification checkpoint: `58c632ce0f9066a777e6b2e322e661dd18f198a2` on
`integration/process-security-m4`, in [draft PR #1160](https://github.com/bb-connor/arc/pull/1160).
Both reviewed parent histories and all
[109 inherited thread dispositions](process-security-review-dispositions.md)
are retained. Main remains `f5566d9a765c21cb36652a99c79de64968a656bf` at the
remote refresh. Original PR threads have not been represented as resolved.

## Recovery and resumed qualification (2026-09-15)

### September 15-16 continuation

#### Current local evidence (2026-09-15, continued September 16 UTC)

The receipt-history campaign at `15cd4178efe80cda959e16e7c70ceacde412b265`
adds a separate million-entry inventory for full checkpoint integrity, filtered
pagination, consistent SQLite backup, reopen readiness, half-history archival,
authenticated retained receipts/commitments and post-restore sequence continuity.
It uses real appends and the unchanged checkpoint batch size of 100. The normal
1,000-entry calibration is not the million-entry acceptance case. Both scale
script regressions pass and reject empty, ignored, failed and substituted test
output. Rust compilation, calibration, strict Clippy and the million-entry
recovery campaign are pending; this commit does not establish M8 acceptance.

At 10:28-10:36 UTC the host reported load averages around 379-397 on ten CPU
cores and about 16 GiB of occupied swap. The frozen foundation workspace run
reported four failed cases during that interval; their causes remain unclassified
until the test target emits its captured failures. Its raw output remains in
`linux-810664017-retry2/workspace-tests.log`. The original append-scale campaign
also remains in progress. Pending graph/recovery work is held until the host
settles, with automatic resume and load samples retained in
`host-contention-queued-controllers.json` and `host-contention-recovery.json`.
No test deadline or acceptance bound was changed, and host contention is not
treated as proof that a failed assertion is harmless.

The fresh seven-scenario matrix completes on Linux/x86_64 at 09:28 UTC on
September 16. Runtime `2d4b28da06ae06b0040acc67fadb141a2b6c9c89`, built with
the unchanged `docker-release` profile, runs the qualifier at
`167a17110931d0cf83e6dfe48928057e99fc1827` with the retained static tools at
`e42e0ed41656e345438664a3d382727f454296f9`. Reference execution, authority,
revocation, filesystem, network, host-crash and shared-budget scenarios all
pass. The 1,789,290-byte bundle covers 17 worker outcomes and has SHA-256
`e4aa37f0d2b86d5da96bb5112e2cd32dc8555e36f853f1f0a31b86fa7e6c2658`.
Both its Linux verifier and the separately built macOS observer at `1ae9f9dda`
accept it and reject all 15 evidence substitutions. Exact commands, source and
binary identities, separately retained pins and results are in
`linux-x86-complete-matrix-167a17110/` and
`matrix-independent-macos-167a17110/`.

The first launcher attempt stopped before any scenario or process pause because
its preflight recognized `cargo build` but not a `cargo test` still compiling
dependencies. `linux-x86-complete-matrix-167a17110-preflight1/` retains that
failure. The retry verifies that a compiler is present and no test executable
is running, then pauses only that compilation group for the timed scenarios.
The group resumed after the matrix. No runtime deadline, enforcement condition
or scenario assertion changed. This is fresh local evidence; combined-foundation,
full cage and designated-runner qualification remain open. The verifier still
does not establish execution nonces or receipt-log inclusion, and its
`m5_acceptance_complete` remains false.

At `10c3995ee4aab5c0dbbed707af2b4d9be43d3176`, reference-runtime provisioning
can sign an operator-reviewed broker socket, authentication digest and peer
identity into an Enforced `brokered_native_v1` launch. Ten reference-provision
tests, ten existing demo-provision tests and strict CLI all-target Clippy pass
on macOS in `macos-broker-provision-10c3995ee/`. The new cases check exact reopen,
identity/digest substitution, malformed/non-socket input and refusal of Shadow,
discovery and file grants. The exact live-peer test also passes on Linux/x86_64:
the pinned peer is accepted, a different PID and a closed endpoint refuse.
`linux-x86-broker-peer-test-10c3995ee/` retains the one-test inventory, terminal
result and executable hash; the cross-compiled test build also passes.
This is launch-material composition, not M6 acceptance: the production broker
authority adapter, supplemental verifier installation, original composite hold
and keyring/broker/cage receipt join remain unqualified. Existing native outcome
verification still refuses brokered artifacts.

The receipt-scale gate previously selected an ignored test without `--ignored`,
so exit zero did not establish a scale run. It now executes the exact ignored
library test under the release profile and checks the listed and passing test
inventory. Its histories remain 1,000, 100,000 and 1,000,000 receipts, with the
unchanged ratio bound. The gate regression rejects empty, ignored, failed and
substituted test output; the existing inventory verifier self-test also passes.
The actual million-receipt campaign and retention issue #1045 remain open.
At `1628feb14be889bb7eba21e02eee491392ef44de`, explicitly executing the
unchanged retention property on macOS passes all 24 generated cases in
77.33 seconds with `PROPTEST_RNG_SEED=20260916`; no Rust test is ignored in
that selected invocation. `macos-retention-reproduction-1628feb14/` retains
the command, log, source and executable hashes. This local result does not
reproduce the slow-filesystem CI liveness failure described in the still-open
[#1045](https://github.com/bb-connor/arc/issues/1045), so its quarantine remains.
The corrected scale campaign is building the unchanged release profile in
`/tmp/arc-m8-retention-1628feb14`, with a separate target and source owner;
`macos-receipt-scale-1628feb14/` retains its progress. No scale result is claimed
while that campaign is running.

All seven retained runtime states now export and verify native-bound outcomes
at `1ae9f9dda`. Independent macOS verification accepts all seven and rejects
42 missing/extra/wrong policy-pin, wrong kernel-key/runtime-pin and unsigned-edit
cases. `outcomes-*-cb5a34e72-1ae9f9dda/` and
`outcomes-*-native-offline-1ae9f9dda/` retain these results. Linux at the same
source passes all six gates: native evidence unit tests, supervised outcomes,
completed runs, retained calls, uncertain-call fixtures and strict CLI all-target
Clippy. The x86 link retry passes after the competing native build finishes;
the original OOM failure remains retained.

`matrix-retained-cb5a34e72-1ae9f9dda/` contains one independently verified bundle
of those seven original runs: 17 worker outcomes, three successful completion
artifacts, eight authority denials and six original pre-crash launches, joined
to checked input hashes, accounting and pinned external observations. This is
a retrospective collection of the retained runtime, not a fresh matrix run.
`matrix-strengthened-tests-2d4b28da0/` records the portable Python verifier's
exact file hashes, a passing whole-bundle check and 15 rejected capture,
signature and semantic substitutions. External file/socket/PID observations
remain the capturing operator's assertions; their separately retained digest
is not a kernel receipt or designated-runner authorization.

The real version 1 network and version 2 budget artifacts are now regression
fixtures. At `2d4b28da0`, both pass on macOS, including native policy/receipt
substitutions, missing and extra pins, and preservation of unknown exits.
Strict CLI all-target Clippy also passes. The new
`qualify-process-matrix.py run` entry point composes all seven unchanged local
scenarios and exports the portable bundle; `verify` and `test-evidence` allow
independent checks. Its fresh end-to-end execution now passes as recorded above.
Combined-foundation, full cage inventory and designated-platform qualification
remain open, so M5 is not marked accepted.

At `1ae9f9ddac749d71f27c9c7f62c49c519a53c7b3`, worker-outcomes version 2
joins each MCP response to its original signed native launch reference. It
requires independent policy signer pins and verifies policy, manifest, host
configuration, route bytes and executable identity. A retained exit must match
the original launch; a missing exit stays explicitly unknown. Recovery
connections do not establish the earlier effect's launch or target death.
The completed-run verifier still requires an actual terminal receipt.
macOS build, three native evidence tests, two uncertain-call fixtures and
strict CLI all-target Clippy pass in `macos-outcomes-1ae9f9dda/`. All seven
version 1 artifacts also pass compatibility verification, including 21 rejected
wrong-key, wrong-runtime and unsigned-edit cases, retained in
`outcomes-v1-*-offline-1ae9f9dda/`. Linux qualification is still running. The
first x86 observer link failed with signal 9; guest OOM records identify `ld`
at 07:49:12 UTC. Its failure remains in `cross-x86-call-1ae9f9dda/`.

All seven current confined scenario states export version 1 worker-outcomes
artifacts at observer `48c7b8314`, retained in
`outcomes-*-cb5a34e72-48c7b8314/`. Independent macOS verification at `95b11b74a`
passes all seven and rejects all 21 wrong-key, wrong-runtime and unsigned-edit
cases. These records are retrospective observations of runtime `cb5a34e72`;
they do not represent a fresh runtime or full M5 acceptance. The complete
Linux regression queue at `48c7b8314` passes the supervised-outcomes,
completed-run and call-evidence integrations, both real uncertain-call fixtures
and strict CLI all-target Clippy.

The frozen foundation `810664017` retry stopped after 5,374 passes, one failure
and 18 ignores in 299 completed test targets. The failing security-vector test
could not import Python `referencing`. `foundation-python-810664017/` records a
dedicated environment matching the owning CI's exact PyYAML 6.0.2, jsonschema
4.26.0 and referencing 0.37.0 pins. With that environment, all four tests in
`security_generated_vectors` and strict workspace Clippy pass. The next
proof-coverage check reports stale generated input digests. Regeneration at the
current source preserves all 59 rows and 170 artifacts and updates only input
hashes. The original failure remains in `linux-810664017-retry2/`; that frozen
queue now runs the full workspace with `--no-fail-fast`. A complete workspace
pass is still pending.

At `48c7b83148262ed83a415fc54dbed01ac21da54d`, the new Linux supervised-outcomes
integration test passes: four actual supervised workers across two issued graphs
retain two completed calls and two compensated calls, with exactly two mailbox
writes and captured family invocations. Offline outcome verification rejects 13
re-signed substitutions across usage, graph inventory, worker identity, runner
input and observation time, plus a wrong runtime pin. `process attest-outcomes`
reads the existing stopped-host journal, fenced call state and budget authority
under one host lease. `process verify-outcomes` checks their combined public
artifact. It retains the original live graph authorities without inventing
successful joins or graph completion. Confinement and external-effect evidence
remain separate. `linux-outcomes-48c7b8314/` retains this passing test and the
continuing regression queue. The first Linux build failed at an ambiguous module
import, retained in `linux-outcomes-95b11b74a/`; the import was qualified explicitly.

The network scenario exposed a second genuine uncertain-call representation.
Its original signed receipt is `Incomplete`, has no admission projection, and
contains the original retained continuation reference. The later host-crash
recovery refusal instead has a signed unknown-state projection and no original
call reference. `411b553908e6c2b640a7aeedee7a4856fbfe72da` verifies both while
requiring an exact matching commitment whenever the original receipt supplies
one. The first network export refusal remains in
`call-observation-network-cb5a34e72-5d71ef11e/`. Actual network and revocation
readback now pass; separate macOS verification passes their four calls and
rejects 16 wrong-key, wrong-runtime, wrong-context and unsigned-edit cases.
`call-observation-{network,revocation}-offline-411b55390/` retains those results.
The verifier SHA-256 is
`16fcc074c0e694083f1a20a052bfb5f8062ce7a9aadae3ef8d32889e7a247d57`.
Both real public uncertain-call fixtures and strict CLI all-target Clippy pass
on macOS at `48c7b8314`. Linux at `411b55390` also passes the earlier uncertain
regression, live allowed/compensated call integration and strict CLI Clippy.

The current optimized reference, authority and filesystem completion artifacts
pass independent macOS verification at `5d71ef11e`; commands and externally
retained operator pins are in `offline-verification-docker-release-cb5a34e72/`.
The filesystem copy driver initially selected the wrong retained artifact path;
its failed copy is preserved and `filesystem-retry1/` contains the original
public artifact copied from the guest's evidence directory. Both original
launches from the current host-crash run also pass offline semantic verification
at `411b55390`, retained in `original-launches-host-crash-cb5a34e72/`. These are
readbacks of the recorded runtime, not new runtime execution or a designated
platform qualification.

The unchanged optimized CLI at
`cb5a34e722b52c794f2aaf84fbcb02a40bac3f03` now passes all seven local x86_64
scenarios: reference fan-out, authority, revocation, filesystem, network, host
crash, and actual shared-budget contention. The CLI SHA-256 is
`f8500b76f7a9f513f2818206b5f8746df2dedab80845f7f76380c229a433fe7a`;
`x86-executables-docker-release-cb5a34e72/manifest.json` records the separately
retained static tool identities. This closes the earlier observed executor
starvation failure for the tested runtime. It is not designated-runner or
complete M5 acceptance.

`linux-x86-release-budget-cb5a34e72-retry1/` retains four workers across two
graphs contending for one family budget of two. Carol and Dave append while
both admitted calls remain outstanding; Alice and Bob checkpoint signed quota
denials. After host death, all four pinned targets terminate within five
seconds. The admitted workers recover their original requests as uncertain;
the denied workers retain their original responses. A second reopen produces
no extra effects. Aggregate usage is max two, reserved zero, captured two.
The run retains 82 public diagnostic files and all four original native launch
receipts. `budget-original-launch-verification-cb5a34e72-retry1/` records four
successful offline semantic verifications using the independently built macOS
verifier at `5d71ef11e26aaaca21363d4bcb85cdb182dc44ec`.

The preceding `linux-x86-release-budget-cb5a34e72/` run passed those runtime
checks but failed its final no-WAL assertion. The Python observer kept a
read-only SQLite connection open: its connection context manager handled the
transaction without closing the connection. `budget-sqlite-reader-reproduction.json`
records the retained WAL with that reader and its removal after explicit close.
Qualifier `8e7b53347e4e8050d8f96de1babc2740e8efe76b` closes all three observer
connections with `contextlib.closing`. The retry passes the unchanged assertion;
no WAL, retained state, timeout or admission condition was removed.

The other current runtime results are retained in
`linux-x86-release-reference-cb5a34e72/`,
`linux-x86-release-authority-cb5a34e72-retry1/`, and the corresponding
`linux-x86-release-{revocation,filesystem,network,host-crash}-cb5a34e72/`
directories. The reference passes all nine checks. The first authority attempt
stopped before execution because its old Docker image ID was unavailable.
The retained replacement image has exactly matching filesystem layers, runtime
configuration, architecture and OS for all five continued scenario images;
`worker-image-runtime-equivalence-cb5a34e72.json` records that comparison.
The fresh plans pin its actual immutable digest
`sha256:261460d71f4e8546b563fdb73968382366def31f4884937464dc3c827154cbaa`.
The unavailable old image identity is not claimed as present or reused. Cage
compilation was paused only during timed qualification and resumed afterward.

At `5d71ef11e26aaaca21363d4bcb85cdb182dc44ec`, the allowed/compensated call
integration test and strict CLI all-target Clippy pass again on Linux/aarch64.
Both the x86 observer build and separate macOS offline-verifier build pass.
The implementation distinguishes an uncertain original operation from the
signed kernel refusal returned during recovery. Such a refusal has no original
completed-call custody reference. Its custody claim is explicitly a signed
readback of the fenced store. The passing budget and host-crash states now
export six verified call observations: three uncertain original calls, two
compensated calls and one completed canary. Independent macOS verification
passes all six and rejects 24 wrong-key, wrong-runtime, wrong-context and
unsigned-edit cases. Results are retained in
`call-observation-{budget,host-crash}-cb5a34e72-5d71ef11e/` and
`call-observation-{budget,host-crash}-offline-5d71ef11e/`. No private retained
request or private key is exported. A public uncertain-call fixture at
`b98659aea` passes its original signatures and 19 semantic rejection cases;
strict CLI all-target Clippy also passes on macOS, retained in
`macos-call-unknown-b98659aea/`. The complete scenario artifact remains open.

The frozen foundation at `810664017dffa38235e3914a0a4477c8345cf359` passes
consumer boundaries, the complete flow-security gate and workspace build.
`linux-810664017/` retains the exact commands and terminal results. Its workspace
test run fails at the native standards fixture because the external Cargo target
cannot discover the checkout. The tracked draft and alignment matrix are present.
With the existing explicit `CHIO_CHECKOUT_ROOT` set to that same frozen checkout,
both native-suite tests pass. `linux-810664017-retry1/` retains that result and the
resumed workspace test, workspace Clippy and proof-coverage queue. No source,
assertion or fixture was changed to fix this runner configuration; the original
failed workspace run remains retained. No full-workspace acceptance is claimed.

The shared-family plan extension accepts multiple independently valid graphs
under the original issued family and single durable quota owner. Focused parser
tests and both live mailbox swarm tests pass on macOS: four distinct requests
across two graphs yield exactly two allowed responses, two signed budget denials,
and two actual writes. Independently verified responses and the two captured
family invocations survive host death and restart without extra effects. The
single-graph compatibility case and strict CLI all-target Clippy pass. The first
new integration attempt failed because its recovery fixture reused an existing
credential output filename; the corrected run is retained separately in
`swarm-shared-family-plan/`. Both live swarm tests and strict CLI all-target
Clippy also pass on Linux/aarch64 at `f612cb257874bb9df83015f6f987a82faff983ff`,
retained in `linux-m5-f612cb257/`. Its unmodified optimized x86 CLI build passes,
with SHA-256 `efc9c7dd94afb310ce62a9021aba6e3c3740268e37182505e2d424cc111fb01a`.
The first actual Enforced contention run fails before proving overlap: the two
writes occur about 67 seconds apart, transport waits reach their unchanged
60-second limit, and worker attempts time out. The ledger retains exactly two
captured invocations, two unknown-after-dispatch operations and two compensated
before-dispatch operations. This is not a contention or recovery acceptance pass.
`linux-x86-release-budget-f612cb257/` retains the failure, 26 diagnostic files,
effect hashes and read-only store observations. Cage compilation was paused
during this runtime scenario and resumed afterward; no cage test was paused.

The MCP adapter's async interface performs synchronous transport waits on the
executor thread. Two new single-worker regressions reproduce starvation of an
independent server through both plain and context-bound calls. Marking those
waits as blocking on Tokio multithread runtimes makes both regressions pass;
all 116 adapter unit tests and strict adapter all-target Clippy pass on macOS.
The original call stack and borrowed nested-flow bridge remain owned, and no
transport deadline changes. `mcp-blocking-dispatch/` retains the failing and
passing tests. A fresh confined run must establish whether this repair resolves
the observed scenario failure before contention can be qualified.

At `cb5a34e722b52c794f2aaf84fbcb02a40bac3f03`, all 116 adapter tests, both live
shared-family host tests and strict adapter/CLI all-target Clippy also pass on
Linux/aarch64, retained in `linux-m5-cb5a34e72/`. An attempted faster diagnostic
link with final CLI LTO disabled fails because the cached release dependencies
cannot be linked in that configuration. `cross-x86-diagnostic-cb5a34e72/` retains
that build failure; no diagnostic executable or runtime pass is claimed. The
unmodified `docker-release` build is recorded separately.

The new `process attest-call` and offline `process verify-call` commands retain
one call's observed outcome and operation-owned continuation custody without
requiring a successful graph completion. Export checks the original private
request through the fenced, anchored store API; those private request bytes are
not exported. The artifact carries the public binding, original signed response
and existing claim commitment preimages. Completed calls require their actual
terminal receipt; uncertain calls retain an incident rather than inventing a
tool result. Compensated calls cannot claim committed dispatch or live custody.

The Linux integration gate at `bf263bf6a5811553fbc330a0ffa1cdd1a9d87909` exports
and verifies two real allowed calls and two compensated calls from the shared
family fixture. It rejects 38 re-signed semantic substitutions, 12 wrong runtime,
key or caller-context selections, and four unsigned changes. Strict CLI
all-target Clippy passes. `linux-call-bf263bf6a/` retains both gates. Earlier
compile errors and a fixture directory-permission failure remain in
`linux-call-f2e72bc05/` and `linux-call-08c4300ed/`; the fixture now explicitly uses
0700 without relaxing the host's credential boundary. The macOS offline verifier
build passes at `08c4300ed`, with identical command implementation and SHA-256
`2761a616b55d4438c280e41e508167527e39c001da3026355eae40c5d32a70ff`.
Real uncertain-call readback and the composed scenario artifact remain open.

The retained host-crash result exposes an artifact distinction: the signed
unknown-outcome receipt observes the replacement connection opened during
recovery. Its `native_launch` reference is not the original target's launch.
At qualifier source `0927874c0c142d40caa26eeceb2d3294d26c3a60`, crash and contention
fixtures retain the original enforcement receipts by matching their signed
process IDs to the actual targets pinned before host death. They independently
verify receipt signatures after the crash. A retrospective readback of the
existing passing host-crash run verifies both original launch signatures and
confirms that the writer's original and recovery launch identities differ.
`original-launch-readback-e42e0ed41/` retains that result. It is not a new live
capture. PID linkage and death remain external observations, and no missing
terminal receipt is fabricated. The complete scenario verifier must preserve
these distinct claims instead of treating recovery launch evidence as proof of
the earlier effect's execution.

`d9a070c57f65a98fec77a46203570bcd50ed3629` adds offline
`receipt verify-native-start` for that original launch. It reuses the same
policy, manifest, typed cage receipt, executable and execution-identity checks
as the completed-run verifier. The caller must supply the policy signer,
selected receipt ID and expected target digest. It makes no claim about target
death or terminal outcome. The two owning verifier tests, strict all-target CLI
Clippy and CLI build pass on macOS. Against retained actual x86 evidence, both
original host-crash launches pass; eight wrong-server, wrong-receipt,
wrong-target and wrong-signer cases fail as required; all three existing
completed artifacts still pass. These 13 offline results, command logs and
verifier SHA-256 `a6b34b0388457718f023f0b1076d4ff5c4729194660feb15a8796c57f3bd5d04`
are retained in `native-start-verifier/offline/`. The original runtime source
remains `e42e0ed41`, and this is retrospective verification, not a new live run.
The affected Linux verification queue also passes: both native-evidence tests,
the live completed-artifact test with semantic substitutions, and strict CLI
all-target Clippy. Exact commands and unchanged-source checks are retained in
`linux-m5-d9a070c57/`. The full scenario artifact remains open.

The unmodified `docker-release` CLI build passes at Rust source
`e42e0ed41656e345438664a3d382727f454296f9`, with executable SHA-256
`cb7f42f5fdf54d8dea33d129228455e1efca67bd14ebf0689192d280d365ab82`.
Its manifest is `x86-executables-docker-release-e42e0ed41/manifest.json`.
Using qualifier source `445c3d313`, unchanged deadlines and the same optimized
CLI, the following actual Linux x86_64 scenarios now have terminal passes:

| Scenario | Observed result | Retained directory |
| --- | --- | --- |
| Reference fan-out | Nine stages including completed-run verification, byte-identical recovery and refusal of missing/wrong native pins and output/runtime substitutions | `linux-x86-release-reference-445c3d313-retry1/` |
| Authority and worker restart | Scope widening, peer authority, changed intent and continuation reuse denied; allowed reads and logical replay succeed; Alice restarts only after the deliberate checkpoint crash; aggregate capture remains two | `linux-x86-release-authority-445c3d313/` |
| Revocation | Issued unspent capability remains revoked after reopen; signed denial returns no secret; the allowed canary works and protected files remain unchanged | `linux-x86-release-revocation-445c3d313/` |
| Filesystem | Raw unconfined controls succeed; confined forbidden read/write return `EACCES`; allowed read succeeds, protected file is unchanged and secret is withheld | `linux-x86-release-filesystem-445c3d313/` |
| Network | Unconfined connection reaches the external listener; confined connection is absent, with signed caller denial and matching native `SIGSYS` terminal receipt; canary succeeds | `linux-x86-release-network-445c3d313/` |
| Host death and uncertain recovery | One append, both pinned targets terminate within five seconds, original request remains `outcome_unknown_after_dispatch`, writer completes on attempt two, repeated reopen does not repeat the effect, capture remains two and continuation custody remains retained | `linux-x86-release-host-crash-445c3d313-retry1/` |

The earlier optimized host-crash run fails when reopening its host at
`PreparedRecordInvalid at fully_enforced_evidence`. Its one append and both
target deaths were observed, but recovery did not complete. Source analysis
narrows this stage to a likely reversed observation timestamp: the prepared
record has already passed all identity/digest checks against the same retained
objects used to construct the exec observation. The actual failed timestamps
were not retained. The VM reports an unstable tracing clock at boot, while a
later 6,000-sample cross-process clock measurement records no backward step.
These observations do not prove the clock's cause or resolve the earlier
intermittent refusal. The failed run remains in
`linux-x86-release-host-crash-445c3d313/`; the fresh passing run does not erase it.

The first reference rerun fails because its previously recorded worker image ID
is no longer available after subsequent builds moved the shared local tag. A
dedicated tag now retains the exact worker image before the fresh run's immutable
plan is initialized. The original failed state and logs remain retained. No
existing runner plan was rewritten to replace its image identity.

The reference, filesystem and authority completed artifacts also pass offline
verification using a separately built macOS verifier at `dcb7fab72`. Operator
public keys, runtime IDs and native signer pins were copied separately from
submitted artifacts. No live database is used. Commands, verifier hash and
results are in `offline-verification-docker-release-e42e0ed41/`.

`e0187de56` distinguishes reversed launch timestamps as
`exec_time_precedes_prepared` while preserving the existing fail-closed check.
The eight evidence tests, strict all-target cage Clippy, formatting and unchanged
69-case source inventory pass on macOS. The evidence regression checks that equal
millisecond timestamps remain valid and backwards timestamps cannot mint an
enforced record. Linux x86_64 all-target cross-checking with real-kernel and
mutant features passes in `cross-x86-cage-e0187de56/`. The six runtime results
above still name their actual preceding source and executable.

`eea8733b1` passes the full actual Enforced reference workflow with exported
continuation custody, then passes the filesystem qualifier. The same raw OS
probe first reads and modifies private fixture files unconfined. Under Enforced
launch, both forbidden read and write return `EACCES`, the allowed read succeeds,
the protected file is unchanged, and no secret reaches a worker. All ten stages
pass in `linux-x86-reference-eea8733b1/`. The filesystem completed artifact has
SHA-256 `df3f72d7d530875d9c07f05460304607e5c004852b1a228d51b65b8891697eeb`.
Both completed artifacts also pass offline verification on macOS with public
keys, runtime IDs and native policy pins copied separately from operator state;
see `offline-verification-eea8733b1/`. This is independent artifact verification,
not an independent source review or designated release capture.

The Linux custody queue at `8f1da077c` passes both store regressions,
`process_run_evidence` with 13 re-signed semantic substitutions, and strict
all-target CLI/store Clippy (`linux-m5-8f1da077c/`). The prior `9dd317b6f` host and
response suite passes all 15 cases, then Linux Clippy fails a Linux-only tuple
complexity lint. The named return structure repairs it without suppression.
The failed log remains retained.

`c11aaf538` adds stopped-host `process revoke-capability` through the existing
persistent kernel revocation store. Its mailbox regression and strict CLI
Clippy pass on macOS and Linux (`linux-m5-c11aaf538/`). This proves busy-host
refusal, durable revocation across reopen, retained worker authentication and
no new protected mailbox effect. The later optimized Enforced scenario passes
as recorded above.

The actual network scenario passes at `c11aaf538`, retained in
`linux-x86-adversarial-c11aaf538/network-qualification.json`: the unconfined probe
connects and transmits a marker; the confined call returns a verified denial
without output, the external listener receives no connection, and the matching
native terminal receipt reports `SIGSYS` (31). The allowed canary still works.
These are verified raw signed receipts, not receipt-log inclusion proofs.

The initial authority scenario at `c11aaf538` fails its 60-second worker
lifetime after the multi-request prelude; the allowed operations nevertheless
complete in the durable ledger. `248ba9c0f` adds request progress markers and
`1938ec33e` gives this six-request fixture a 180-second total lifetime while
retaining each SDK request's 60-second deadline. That fresh run also fails:
Alice's first scope probe receives a generic runtime error and Bob restarts
after reaching continuation reuse. Both eventually complete, but their attempt
counts fail the qualifier. These runs are not authority qualification passes.
`e42e0ed41` installs trusted host-side error observation while preserving redacted
worker error frames, and requires an explicit deliberate-crash marker after
Alice's retained checkpoint. All 12 worker-protocol cases, strict all-target
CLI/process Clippy, format and source hygiene pass on macOS at that source
(`macos-m5-e42e0ed41/`). Its x86 CLI and static tools cross-build successfully.
The diagnostic authority run at that source fails before the deliberate crash:
the trusted host records `receipt persistence failed: sqlite receipt commit
write timed out after 5000ms`. Bob's first worker reaches the allowed call before
its lifetime expires; subsequent worker authentication/transport errors follow
restart, and the runner exhausts its attempt budget. The terminal exit is one.
Host and worker logs are retained in
`linux-x86-adversarial-e42e0ed41/runtime-diagnostics/`. This establishes the
receipt writer deadline failure, not its performance cause. The existing
`docker-release` profile subsequently builds and passes the authority scenario
at the same Rust source, with no request, receipt or scenario deadline changes.

`445c3d313` streams qualification command output to retained files and records
partial diagnostics when a command times out. Actual subprocess checks cover
success, nonzero exit and timeout; the production command deadline remains
600 seconds (`qualification-streaming-regression-retry1.log`).

The host-crash qualifier at `97bdb43c2` observes one actual Enforced append,
kills the host before any outcome is returned, and recovers the original request
as `outcome_unknown_after_dispatch`. Reopening again does not repeat the effect;
aggregate capture remains two, and the writer's continuation claim is retained.
The report is in `linux-x86-adversarial-97bdb43c2/`. This run also exposes a
separate lifecycle defect: the original confined target survives the host as a
PID-1 orphan. Its process identity and explicit cleanup after qualification are
retained in `orphaned-target-observation.json` in the same folder.

`4e7c0055d` arms a kernel parent-death `SIGKILL` after the helper's final
credential change and verifies that the authenticated parent still exists.
The strengthened host-crash qualifier pins both actual targets with pidfds and
requires them to terminate after host death. Cross-build passes. Both targets
terminate within the existing five-second assertion in the fresh runtime run,
and the effect remains exactly one append. The full scenario nevertheless fails:
the writer completes on attempt three instead of the required attempt two after
a generic runtime error on the first recovery attempt. Revocation does not run
behind that failed gate. `linux-x86-adversarial-4e7c0055d/` retains this failure;
its `host-death.json` remains in the VM scenario directory. No complete
host-crash pass is claimed for this source.

`221c3c19d` adds a bounded launch-thread lifetime regression to the existing
real-kernel lifecycle case. A target handle moved to another thread must still
observe `SIGKILL` after the original launching thread exits. Formatting and the
69-case source inventory pass. The full real-Linux cage gate at that source
passes the library, receipt and compilation cases, then fails several real
launch cases. It was interrupted after those failures to retain fixtures and
diagnose the first failure; this is an incomplete failed inventory, not a pass
(`linux-x86-221c3c19d/`). An isolated rerun fails at the initial trace-handshake
deadline (`trace_timeout`), before the new parent-death setup. With the existing
optimized helper and unchanged test deadlines, both the same network case and
the full existing lifecycle case, including the new launch-thread regression,
pass. `cage-diagnostic-221c3c19d/` retains both failures and isolated passes with
binary identities. Startup cost under emulation is a hypothesis; the complete
69-case/ten-mutant pass remains bounded to `bcf81182a`. A full rerun with optimized
debug code, explicit debug assertions and overflow checks is active at the same
`221c3c19d` source (`linux-x86-221c3c19d-optimized-debug/`). Its compilation was
paused and resumed around the runtime scenarios to isolate the emulated CPU;
all tests, mutation controls and deadlines remain unchanged.

The source review found a reproducible custom-default invariant failure in
`enumflags2`/`enumflags2_derive` 0.7.12. Exact hashes, safe reproduction and the
current native Landlock reachability analysis are recorded in
[the audit finding](../../supply-chain/reviews/enumflags2-0.7.12.md).
No certification has been added for either crate.
The separately applied typed-default repair rejects the original invalid
declaration, passes valid defaults across all five unsigned widths, and passes
the published library's two unit tests and 29 documentation tests (two existing
documentation examples remain ignored). The patch is retained for review and
is not installed in the workspace dependency graph.

Two idle build caches were relocated to the VM's existing writable host mount
after checking Cargo ownership and verifying complete file hashes, modes and
symlinks before and after copying. Their original guest paths remain symlinks
to the verified copies. `native-m5-cache-relocation.json` and
`cross-x86-debug-cache-relocation.json` retain the inventories. Active targets,
VMs, source and qualification artifacts were preserved; these cache directories
are regenerable build storage, not qualification results.

The current runtime diagnostic source is `e0187de56`, the lifecycle test source
is `221c3c19d`, and the streaming qualifier source is `445c3d313`, retained in
`/tmp/arc-m5-evidence`. The full
scenario artifact, genuine over-budget contention case, intermittent launch
evidence refusal and the remaining foundation gates are open. Existing fixed fan-out
preallocates one unit per task and rejects a graph larger than its family quota;
two successful simultaneous calls do not prove a contended over-capacity denial.
All 109 inherited dispositions remain unchanged. No protected publication,
designated release capture or administrative thread resolution has occurred.

##### Preceding checkpoints

The first actual Enforced repository-reader fan-out passes at `bcf81182a`.
A fresh run at `9dd317b6f` also passes all nine stages: initialization, two
supervised Docker workers, collection, completed-run export/verification,
byte-identical worker-response recovery, and refusal of missing/wrong native
policy keys, output substitution and runtime substitution. The exported v2
artifact verifies one actual cage launch and its signed terminal receipt.
Evidence is retained in `linux-x86-reference-9dd317b6f/`, including the completed
artifact and verifier report. These local x86 VM results are not designated
release-capture evidence or complete M5 scenario acceptance.

`bcf81182a` repairs the minimal profile's missing read-only Rust startup queries,
`sched_getaffinity` and x86 `readlink`, exposed by an actual `SIGSYS`. Its complete
owning cage gate passes all 69 cases and all ten mutation controls with unchanged
assertions and deadlines (`linux-x86-bcf81182a/`). The failed `6374eb394` mutation
run and diagnostic retries remain retained separately. The matching mutant
helper has SHA256 `094a473d9d153e1a1ff30f6b686afd1209f8f0394662af2cd5c912ee7c1afe05`.

`5c8cb8e7f` binds each tool receipt to the persisted cage launch ID and canonical
digest. `9dd317b6f` exports the existing launch policy and original enforcement
and terminal receipts. Verification requires an externally pinned policy key,
the admitted host record, manifest, route, executable identity and actual call
lifetime. All four host-route cases pass, including malicious context and
recovery under a different later launch without repeating an effect. The Linux
native-evidence unit, host-route and completed-run artifact gates pass at this
source; host/response and strict Clippy remain running. Strict macOS Clippy passes.
CLI and static helper/tool cross-builds pass with hashes retained in
`x86-executables-9dd317b6f/manifest.json`.

The subsequent continuation-custody export passes strict macOS CLI/store Clippy
and the existing store recovery regression. The export reads the same fenced,
anchored operation-owned ledger; it does not acquire or release claims. The
artifact carries the original claim preimages so verification can recompute the
commitment already named in the tool receipt. Stale-owner readback and modified
claim/operation preimages are rejected. Linux integration validation is pending.
`7ceab1818` repairs an existing store-test `expect_err` lint while preserving its
stale-time refusal assertion.

The `97705575b` foundation flow gate failed on an outdated exact inventory after
all 31 selected return-context tests passed. It omitted
`caller_custody_rejects_each_selected_family_without_its_physical_ledger`.
`810664017` adds that existing case and corrects the contract count; all 69
inventory contracts pass. The frozen foundation queue has passed consumer
boundaries and is running flow-security before workspace build/test/Clippy.
No complete flow or workspace pass is claimed.

The implementation checkout is `/tmp/arc-m5-evidence`, branch
`integration/process-security-m5-evidence`, at `7ceab1818` plus the custody export.
The same single agent owns it and the frozen qualification queues. The execution
checkout remains `/tmp/arc-security-launch` at `a4c3a77ee`. Both parent histories
and all 109 inherited dispositions remain preserved; no protected publication
or administrative thread resolution has occurred.

#### Earlier source-bounded checkpoints

The entries below are historical records. Their pending statements describe
those specific checkpoints; the current status above supersedes them.

Current implementation checkpoint: `4ddf40ada850d77d205d694908d3e2516ff1d375`,
with the execution checkout qualifying `a4c3a77eee190c9feac589d035f25c9474346e9f`.
The implementation checkout is `/tmp/arc-m5-evidence`, maintained by the same
single agent while frozen qualification checkouts run. No subagents or protected
publication actions have been used.

| New gate / behavior | Frozen source | Terminal evidence |
| --- | --- | --- |
| Signed receipt-anchor provisioning and runtime units on macOS | `6b2552d0e` | 7 provisioning and 4 unit cases pass; strict Clippy, format and hygiene pass. `macos-provision-6b2552d0e/` |
| Independent receipt-anchor ownership on Linux | `6374eb394` | Exact anchor case, 7 provisioning and 4 unit cases, strict all-target CLI Clippy pass. `linux-m5-6374eb394-retry1/`. Initial filter selected zero tests and the runner rejected that attempt. |
| Actual completed fan-out export and semantic verification | `db7f7049b` | `process_run_evidence` passes with real supervised effects, seven re-signed semantic substitutions, runtime substitution and unsigned tampering. `linux-m5-db7f7049b/run-evidence.log`; host/response and Clippy gates continue. |
| x86 cage gate with matching helper features | `6374eb394` | 69 cases pass; mutation lane has 8 passes and two timeouts where exact prepared-record refusal was required. Gate remains failed. `linux-x86-6374eb394/` |
| Enforced initialization with anchored receipts | `6374eb394` | Refuses receipt persistence because the adapter retained pre-stdio plan bindings. `linux-x86-reference-6374eb394/`; no useful workflow accepted. |
| Prepared launch receipt binding repair | `54cc0c052` | All 8 receipt-evidence cases pass, including immutable identity substitutions; source inventory remains 69. `cage-prepared-receipts.log`. Actual Enforced rerun pending. |
| x86 CLI plus static helper/tool cross-build | `a4c3a77ee` | Both gates pass. `cross-x86-m5-a4c3a77ee/` and `x86-executables-a4c3a77ee/manifest.json`. |

`db7f7049b` adds `process attest-run` and `process verify-run`. The signed
observation joins actual worker request/response receipts, issued capabilities,
strict complete task authority, original allocation authority and a separately
read aggregate quota snapshot. It does not claim exported continuation custody,
confinement receipt linkage, execution nonce verification or complete M5 scenario
coverage. `4ddf40ada` makes the supervised script export and independently verify
that observation. `a4c3a77ee` corrects collection of native MCP content from the
verified value envelope.

`54cc0c052` consumes receipt bindings from the owned sealed launch preparation.
The signing context follows the stdio-dependent profile digest only while the
admitted manifest, helper, target and executable identity remain unchanged.
The mismatch check itself remains mandatory. The next actual Enforced run uses
scripts `4ddf40ada`, binary `a4c3a77ee`, and a private anchor on `/dev/shm`; this
local anchor profile covers process restart and database rollback, not VM reboot
or power loss. It is not designated release-capture evidence.


Latest source repairs include `97705575b` (explicit signed artifact ceilings) and
`6b2552d0e` (independent receipt rollback anchor in the signed runtime policy).
The real Enforced reader initialization exposed both requirements before any
workflow effect. Their failed runs remain in `linux-x86-reference-a34e7e20b/`
and `linux-x86-reference-97705575b/`. Anchor-backed runtime qualification is
pending. The macOS fixture now canonicalizes its temporary parent and checks the
unsupported operating system before architecture; both failures are retained.

At `6f99a5465`, all 69 real-Linux cage cases passed. Seven of ten subsequent
mutation controls failed because the harness launched a normal helper while
only the parent test binary had the mutation feature. The repaired harness
builds and checks matching normal/mutant static helpers, preserves both as
separate files during the run, and logs their hashes. Every original mutation
assertion and required inventory remains in force. Source stack checks and the
missing-mutant-helper checker regression pass; a complete real-kernel rerun is
required. The failed lane is retained in `linux-x86-6f99a5465/`.

The Linux consumer-boundary gate passes at `97705575b`; flow and the remaining
workspace gates continue on that frozen source. All eight Linux container unit
cases and strict all-target Clippy pass at `3ec843a866`.

The execution branch retains the preceding repair and M5 commits through
`3ec843a866` (Linux container test fixture initialization). The primary checkout
remains unchanged. New reference commands at `a34e7e20b` prepare a signed
Enforced repository-reader fan-out and independently verify the returned file
contents against operator-pinned runtime/capability/request identities and input
hashes. They do not declare complete M5 acceptance.

Fresh terminal results, under the evidence root below:

| Gate | Frozen source | Result / evidence |
| --- | --- | --- |
| macOS host and response tests; strict all-target Clippy; formatting; hygiene | `9833a537f` | All four gates pass, nine host/response cases. `macos-m5-9833a537f/` |
| Linux host and response tests | `9833a537f` | 15 pass, no failures or ignores. `linux-m5-9833a537f-retry1/process-host-response.log` |
| Fresh supervised native and container workers | `9833a537f` | Both pass, actual two-worker effects and byte-identical completed-run recovery. Same directory, `native-fresh-workers.log` and `container-fresh-workers.log` |
| Linux strict all-target Clippy | `9833a537f`, then `3ec843a866` | First fails on a Linux-only fixture's old initializer call; repaired invocation passes. `linux-m5-3ec843a86/strict-clippy.log`. Container unit tests continue separately. |
| Native restart and authenticated caller inventories | `1e747084d` | Both pass; consumer, flow and workspace gates remain queued. `linux-1e747084d/` |
| x86 real-kernel cage all-target execution | `f3497e23e` | All 26 enforcement probes, 14 compilation cases, eight evidence cases and 20 library cases pass. The gate fails its required 21-library-case inventory before later lanes. `linux-x86-f3497e23e/cage.log` |
| x86 cross-build, CLI plus static helper/tools | `f3497e23e` | Both build gates pass. `cross-x86-m5-f3497e23e/`; explicit executable hashes in `x86-executables-f3497e23e/manifest.json`. |
| First Enforced reader run | scripts `a34e7e20b`, binaries `f3497e23e` | Initialization refuses the unoptimized 4.2 MiB helper under the signed 1 MiB retention limit. No tool-workflow pass. `linux-x86-reference-a34e7e20b/`; optimized helper/tool builds continue without relaxing the limit. |

The missing x86 library case was the unsupported-architecture admission test,
previously excluded by its `not(target_arch = "x86_64")` condition. The repaired
test submits unsupported architecture results through the same private admission
path on every Linux host. The public boundary still selects the compiled host
architecture. The actual public-admission refusal remains tested on non-x86
Linux. All required names, the 69-case commitment and ten mutation controls stay
unchanged; complete qualification requires a new terminal gate result.

The first Linux M5 build attempt was killed by the guest's global OOM during
linking while separate target owners compiled concurrently. Its failed output
and kernel diagnosis are retained in `linux-m5-9833a537f/` and
`linux-m5-oom-kernel.log`. A 4 GiB temporary build swap file was then enabled;
`linux-build-memory-adjustment.json` records the affected active queues. No
application, test or enforcement limit was changed. These runs make no
performance claim. The successful retry has its own immutable evidence directory.

Full M5 scenario coverage, signed joined accounting/confinement/terminal evidence,
dependency audits, reviewed execution-image inputs and designated trusted capture
remain open. These local x86 VM results are not release-capture authority.

Execution checkout restored at `/tmp/arc-security-launch`, branch
`integration/process-security-m4`, from live PR head
`b7211ce2d063ea36ea0f512b6f3c0253b65ecd71`. Both parents remain ancestors:
security `5d1a9ec0d900bd03ce55de903919d972be852d79` and process
`2e84f121273df7f205cc218739b86e93c91bdc37`. Their live PR heads are unchanged.
The primary main checkout, its local commit and all pre-existing modifications
remain intact. Execution uses one agent and no subagents.

Two current hosted failures are source gates before runtime execution:
`35006606125/104507817752` stopped on Ruff formatting in the new worker tests;
`35006605899/104507815578` stopped on file-size caps for the swarm verifier and
proof CLI fixture helpers. The resumed source formats the Python tests and
extracts unchanged graph validators and disposable bundle helpers into focused
modules. No hygiene cap, authority check or required test is relaxed. A direct
comparison confirmed the extracted bodies are unchanged. Review is direct owner
review, not independent reviewer approval.

Fresh local artifacts are retained outside temporary checkouts at
`/Users/connor/Medica/backbay/standalone/arc/output/process-security-20260915/`.
Commands below use Rust 1.94.1, locked dependencies, `umask 022`,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, two build jobs, debug info disabled
and no custom `RUST_MIN_STACK`. External target directories preserve the explicit
owned-checkout fixture boundary. Subprocess fixture executions are not counted
again as distinct tests.

| Gate | Source / platform | Terminal result | Evidence file |
| --- | --- | --- | --- |
| `cargo test --locked -p chio-process --features worker-server,mailboxes` | `b7211ce2` process closure; macOS/aarch64 | Exit 0: 72 tests, no failures or ignores, including all 12 worker protocol cases | `process-initial.log`, `process-counts.json`, `process-initial.exit` |
| `cargo test --locked -p chio-swarm-authority -p chio-runtime-core` | `b7211ce2` plus graph-module extraction; macOS/aarch64 | Exit 0: 348 tests, no failures or ignores; includes 91 runtime admission and 61 swarm stage-0 cases | `m5-runtime-authority.log`, `m5-runtime-authority-counts.json`, `m5-runtime-authority.exit` |
| Python process `unittest discover` | `b7211ce2` plus test formatting; Linux/aarch64 | Exit 0: all 34 tests, no skips | `python-process-linux.log` |
| Node process `node --test test/*.test.mjs` | `b7211ce2`; macOS/aarch64 | Exit 0: all seven tests | `node-process.log` |
| Strict Clippy, all targets of process (worker/mailbox features), runtime core and swarm authority | Current recovery patch; macOS/aarch64 | Exit 0, warnings denied | `m5-clippy.log`, `m5-clippy.exit` |
| Rust formatting / source hygiene | Current recovery patch; macOS/aarch64 | Exit 0 for both; existing size warnings retained | `fmt-fixed.log`, `hygiene-fixed.log` |
| Security CI source contract | Unchanged execution inputs | Exit 1: Cargo.lock digest ratchet mismatch | `security-ci-contract.log` |
| Hosted dependency audits | PR head `b7211ce2` | Terminal failure: 26 missing safe-to-deploy audits | `hosted-cargo-vet.log` |
| Hosted trusted capture | PR head `b7211ce2`, authorized source `f5566d9a` | Terminal failure before isolated capture | `hosted-capture.log` |

The initial macOS Python run is retained as a failed platform invocation
(`python-process.log`: 16 Linux-only errors and five skips). It is superseded for
this SDK gate by the complete Linux result, not counted as a pass. The runtime
suite emitted one unused-import warning from extraction; that import is removed
before strict Clippy and final-source qualification.

The existing default Colima guest refused both Docker and SSH connections. A
separate `chio-m5-qualification` profile now provides Linux/aarch64 kernel
6.8.0-64, Rust 1.94.1, the WASM target, Node 22 and pinned Apalache 0.50.1 for
ordinary local gates. The existing VM was not restarted or reconfigured.
This profile does not provide the required Linux/x86_64 cage qualification or
trusted-controller authority. Full foundation qualification remains open.

All 109 disposition identities remain unique, every cited file and named
regression still exists, and every cited checkpoint remains an ancestor. This
source integrity check does not rerun all disposition tests or resolve threads.
No review record was rewritten or original thread administratively resolved.

### Active frozen-source Linux queue

Local repair commit: `7b57f2ef6ef7a7ec9be9ec55db5653db94979276`.
The complete source is frozen in a separate local qualification checkout at
`/home/connor.guest/chio-foundation-7b57f2ef6` inside
`colima --profile chio-m5-qualification`. Both parent ancestry checks pass there.
The execution checkout remains `/tmp/arc-security-launch`; the Linux snapshot
must not be edited while qualification runs.

The serial runner is the retained `run-linux-gates.py` in the artifact directory
above. It started at 20:55 UTC. Formatting, process (72 tests), runtime/swarm
(348 tests) and the proof CLI contract (147 tests) have terminal exit 0, with
no failures or ignores. Subprocess fixtures are excluded from these counts.
The process-host/response-verifier gate (14 tests) and signed lineage (eight)
also passed. The queue stopped at the native restart gate: 46 passed, one failed
with `trusted operation time regressed` during the concurrent late-caller report.
The rest of that queue has not executed. Its raw failure is retained in
`linux-7b57f2ef6/native-restart.log`; do not overwrite or resume that frozen source
in place. A new `/home/connor.guest/chio-foundation-current` checkout is used to
calibrate and repair the caller lookup's coordination/time race.

`linux-7b57f2ef6/identity.json` pins compiler, source, environment and lock hash;
`active.json` names the current command and PID; each terminal gate writes its
exit, retained log hash and test/CLI binary hashes. `results.json` contains only
completed gates. The queue stops at the first failure and retains that output.
After process and M5 suites it runs the full proof CLI contract, process-host
and response verification, signed lineage, exact native restart and caller
inventories, consumer and flow gates, workspace build/test/Clippy, and generated
proof coverage. Fuzz compilation, remaining SDK/generated-wire gates, dependency
audits and trusted x86_64 qualification are still separately outstanding.

### M5 boundary after recovery

The authenticated transport and live verifier changes now have complete fresh
owning test results. Live fan-out needs no future join or terminal receipt;
fan-in still requires its real join. The operation-owned test exercises the
sealed SQLite source, persisted continuation custody, signed capability binding
and identical completed-outcome replay with a single effect. These are local
component/composition results, not the final swarm artifact.

Two host composition primitives are implemented in the next local slice:

- `ProcessRuntime::with_routes` supplies host-selected `ProcessRoute` metadata.
  Each route is included in the existing immutable operation binding. Changing
  or removing it on reopen refuses recovery before another effect or journal
  charge. The worker protocol cannot select a route, and worker context cannot
  replace signed top-level route or process attribution. Unrouted legacy
  operations preserve their previous bindings and wire representations.
- `ChioKernel::issue_aggregate_family_root` requests a signed shared invocation
  limit through the configured authority. It requires qualified durable
  admission in `All` mode and refuses context-free issuance when tenant/lineage
  admission is installed. Local and governed signing authorities support the
  explicit request; other authorities default to refusal. The policy wrapper
  retains reputation and runtime-assurance checks and persists the exact root
  snapshot. Ordinary issuance still rejects unexpected aggregate authority.

Implementation commit: `a4d8c2c7dd9befe14a9adf1501922d56a3ee0cfb`.
The exact clean commit passed six process tests (routes and shared aggregate),
two aggregate issuance tests, the tenant-context refusal test, all 18 policy
issuance tests, and strict all-target Clippy for process/kernel/control-plane.
The retained `m5-host-a4d8c2c7d/` records command, compiler, unchanged source,
terminal exit, log hash and test binary hashes. Every test passed without
failures or ignores; filtered counts remain explicit in the owning logs.
The full 78-test process suite and a 41-test kernel authority selection also
passed during development, but those earlier logs record an evolving working
tree and are not an exact-commit certificate. A Linux-only import found during
macOS compilation is correctly gated; no warning suppression was added.

The reference host now implements a bounded, fixed fan-out profile using these
primitives. `process init --aggregate-invocations N --swarm-plan tasks.json`
binds actual issued root/child capability bodies to the signed graph, routes,
witnesses and single-use continuations. It activates the existing local runtime
participant once. Restart requires the signed profile and the original active
source generation, installs its hook before recovery, and does not import a
fresh source or fabricate future result receipts. Native servers require
verified Enforced cage launch and a manifest with no network destinations.

The four macOS process-host tests and five response-verification tests passed
with `TMPDIR=/tmp`, including the new authenticated-worker, borrowed-context,
SIGKILL recovery, two-effect and sealed-continuation test. Strict all-target
Clippy for CLI/process/control-plane passes after correcting platform guards in
`dea823c4b` and simplifying one new condition. No lint suppression was added.
Development logs are `m5-swarm-host-owning-short-tmp.log` and
`m5-swarm-host-clippy-4.log`; earlier failures are retained. These logs record an
evolving working tree and are not an exact-source acceptance certificate.

The new `examples/reference-swarm/process-run.py` uses the existing Linux
supervisor, exports worker checkpoints and independently verifies responses
with the operator-pinned kernel key. Its optional immutable Docker image uses
the existing fixed confinement profile; native workers remain cooperative
same-user processes. The image stores code outside the runner's `/work` tmpfs.
Host implementation: `84f8e77740c521829999071c9861d335b97be1de`.
Fresh-supervisor fixture: `9833a537ffa8bff878355409e1d93b13608c24d9`.
Frozen `9833a537f` passed all nine macOS host/response tests, strict all-target
Clippy, formatting and source hygiene with clean source and lock unchanged.
Exact commands, compiler, terminal results, log and binary hashes are retained
in `macos-m5-9833a537f/`.

The separate Linux checkout `/home/connor.guest/chio-m5-9833a537f` and target
`/home/connor.guest/chio-m5-target` run the full host/response tests, fresh native
workers, fresh isolated container workers, completed-run reopening and strict
Clippy. `run-linux-m5-9833a537f.py` records these gates in `linux-m5-9833a537f/`.
The worker image is built from that same source and pinned to local ID
`sha256:6bcdff881f83af9262b475c226c0e5e5fb5be82faa011fbe639d9b9d948099d8`;
the build log and full image metadata are retained. Linux supervisor and actual
Enforced reference-tool runs remain unqualified until their terminal gates pass.
The Disabled smoke is unchanged. Full fan-in, all scenario/effect oracles,
independent complete-artifact verification and M6-M10 remain required.

### Local x86_64 enforcement qualification

A separate `chio-m5-x86` Colima QEMU guest now runs Linux 6.8.0-64/x86_64.
Initial probes observed Landlock ABI 4, sealed memfds and pidfd support. Rust
1.94.1 and GCC 13.3 are installed. The default VM and Docker context are unchanged.
A clean frozen clone of `a4d8c2c7d` is at
`/home/connor.guest/chio-foundation-a4d8c2c7d`; its Git LFS objects were verified
against their tracked hashes and the checkout is clean.

The original `a4d8c2c7d` local real-kernel gate passed the source stack and
all-target inventory checks, then exited 101 before tests: static helper
`RUSTFLAGS` reached host procedural macros. Commit `81e41bf824a886be44ae1a1356cba8aeb1c7c584`
adds an explicit `x86_64-unknown-linux-gnu` Cargo target and uses its matching
helper path. Static PIE ELF checks, probe/test inventories and mutation checks
are unchanged. The gate's shell contract and source stack checks pass.

The frozen `73f3d7fa528c76e6953d5b2a4ddab38757cc328d` retry runs via
`run-linux-x86-cage-73f3d7fa5.py`, retaining source, compiler, platform,
environment, log and binary identities in `linux-x86-73f3d7fa5/`.
It stopped at 22:46:51 UTC with exit 101. The static helper built and passed its
ELF checks, but every real-kernel probe refused before launch: this guest's
`getgroups` includes its primary gid, and the observer passed that duplicate to
the strict configured-identity constructor. All 26 probe failures are retained.

The repair adds an observed-credentials constructor that removes only the
redundant primary gid and sorts the remaining groups. Root, sentinel and
duplicate additional groups still refuse; configured identities remain strict.
The helper and its real-kernel fixture use the same normalization. A focused
red/green regression preserves the additional group set. Strict macOS cage
Clippy and the unchanged 69-test source inventory pass. Real-kernel qualification
must rerun with a rebuilt helper; the pure regression is not confinement proof.
Logs and calibration patch are `cage-observed-groups-*`.

Earlier failed gates and VM setup failures remain retained. No run changes
trusted capture pins or provides designated-runner release authority.

### Native late-caller recovery repair

The frozen `7b57f2ef6` native-restart gate stopped with 46 passes and one failure:
`late_caller_report_cannot_replace_native_unknown_outcome` observed
`trusted operation time regressed`. A caller lookup read trusted time before
waiting behind recovery's mutation. The store correctly rejected that stale time.

Commit `73f3d7fa528c76e6953d5b2a4ddab38757cc328d` makes that retained lookup acquire
the existing mutation sequencer before selecting time. Store time validation is
unchanged. A calibrated regression holds the original coordinator and proves
that the lookup waits, then confirms the late unsigned report is still refused.
The test-only calibration failed on `a4d8c2c7d`; the implementation plus test
passed the owning case. Both source diffs and binary/log hashes are preserved in
`native-restart-calibration/` and `native-restart-fixed/`.

The full unchanged native-restart script passed on frozen `73f3d7fa5`:
47 exact process-recovery cases and five exact live ownership cases, zero
failures or ignores. The gate exited zero at 22:01:50 UTC with both source and
Cargo.lock unchanged. The log SHA256 is
`a6e45ea83c9c6e8f6ae013b38d395e6f6c7b8abac934e0f6ec192d8b579a91d7`.
Its owning binary hashes are in `linux-73f3d7fa5/native-restart.json`.
The authenticated-caller script also passed: 33 exact lifecycle cases, nine
durable-executor cases and 19 native-custody cases, zero failures or ignores.
It exited zero at 22:13:35 UTC with source and lock unchanged; log SHA256 is
`2009897228feccca7648e664787f8ec5a45151a4845bc9b10f7d163dcae2591e`.
The consumer gate subsequently stopped at the adapter no-bypass source check.
It requires an exact inventory entry for the new late-caller regression helper.
The next checker run also exposed its stale requirement for the complete swarm
verifier at the live admission boundary. The source contract now names the live
verifier and additionally requires exact request/capability binding, with both
calls included in removal-sensitive tests. No runtime authority is bypassed.
The failed consumer log and unchanged-source manifest remain retained in
`linux-73f3d7fa5/`. Flow and workspace gates have not run in this queue.
The original runner is
`run-linux-gates-73f3d7fa5.py`, Codex session `62677`. Neither frozen
qualification checkout is edited during these runs.

## Retained pre-M5 evidence

These are distinct local runs, not one exact-head acceptance certificate.

The serial qualification queue at `58c632ce0f` completed workspace build,
process features, process host and signed lineage before it was deliberately
interrupted to begin the user-approved local M5 work. The native-restart gate
was interrupted, not passed; later queued gates did not execute. The queue
exited 130 with the candidate still clean and unchanged. Logs remain under
`/tmp/chio-task5-final-gates.niZqyr`. M5 source changes require fresh affected
qualification and do not inherit an exact-head pass from that checkpoint.

| Scope | Result and boundary |
| --- | --- |
| Patched full workspace Clippy | Passed with Rust 1.94.1, locked/offline dependencies and warnings denied. |
| Patched full workspace tests | Exited 101 in the proof-contract target: 138 passed, nine fixture-discovery failures. The repaired target now passes all 147 cases. The workspace invocation stopped at that failure; later targets and full workspace acceptance remain open. |
| Rust dependency policy | cargo-deny advisories, bans, licenses and sources pass after the rustls 0.23.45 repair. |
| Rust dependency audits | Locked cargo-vet fails with 26 missing safe-to-deploy audits. No new exemptions, certificates or trust authorities were added. |
| Python SDK and LangGraph | 206 SDK cases and 58 LangGraph cases pass, including installed wheels and two supported LangGraph profiles. Installed typing passes. All 22 Python lockfiles pass offline consistency checks. |
| TypeScript packages | Full publishable workspace build/test and six owning standalone package gates pass. Dashboard passes 103 tests; web3 example builds and passes six real Chromium tests. |
| JavaScript/Python advisory scan | The final expanded OSV scan passes with three pre-existing policy filters unchanged. This is not a zero-known-vulnerability claim for excluded findings. |
| Native Docker process recovery | Complete patched-snapshot qualification passes, including live owned-container host SIGKILL, restart, credential rotation, one-effect receipts, unresolved custody, shutdown and resource bounds. Container CPU/memory accounting remains explicitly unavailable. |
| Installed process starter | Complete patched-snapshot qualification passes with real external Python/Node consumers, mailbox exchange, independent receipt verification and installed package/sdist tests. |
| Installed AI SDK 6/7 | Complete patched-snapshot qualification passes, including recovery, journals, state pressure, cooperative swarms and supervision. No live model calls. The earlier mixed-binary run remains diagnostic only. |
| M4 SDK parity | Owning Python/Go/TypeScript parity gate passes. Native Rust consumer, M3 and composed gates remain distinct. |
| Fuzz and Docker locks | Full 30-target selector fixture passes. Fuzz locked metadata and generated Docker workspace lock consistency pass after regeneration. This is not a fuzz campaign or full fuzz compilation pass. |
| Security CI contract | Both the full checker and its full fixture suite remain blocked by the execution-image Cargo.lock digest ratchet. Isolated fixture results do not waive it. |

The TLS update addresses
[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
Required AWS-LC and webpki updates preserve existing feature selections. The
source Cargo.lock digest is
`47bf5b6fc16784c18104912b1d90ee1160c2e8e330baff34fde35478e66fdbce`.
The security execution-image ratchet still requires
`a4e631319b00c54f2cbc6457ad0149198a4a367db8dec060fcce376c98728b49`.
No image, controller, trusted-source or enterprise-workflow pin was changed.

## Patched executable and fixture-discovery closeout

All three installed qualifiers completed at clean source `f0ff43b819`, using
the same privately retained CLI, SHA256
`82ba58ec8a8d742b9d22504ff4f0fd604ee6e0361b7f33df7d591163870b92a5`.
This was a Rust 1.94.1 workspace-test build on Linux/aarch64, not an optimized
release or x86_64 confinement certificate. Report SHA256 identities:

- AI SDK: `4d47b452f93fb0616bc1411766a14f3087122ff2f3f8ba42f58e96570dea5352`.
- Docker: `a74d4c975237dc3ed8ba680483158b3f2f87ea54916c3692ffaaaee17c204b73`.
- Starter: `81496d691735292ddc111c4758c6839b38e585d12fc926a7f8aed2a161a32138`.

The workspace failure exposed missing test setup for an external Cargo target
directory. The hardened runtime resolver correctly refuses to infer checkout
authority from the current directory or embedded build paths. The proof-test
command helper now supplies its owned `CHIO_CHECKOUT_ROOT`. The original
recursive-swarm fixture case failed without that anchor and passed with it;
the complete repaired proof target passes 147 cases with no ignores. Production
resolution, installed fixture overrides, verifiers and trust policy are unchanged.

Hosted run `34977549611` passed the authenticated-worker job, but its larger
process-host job exceeded its 90-minute job limit during the research swarm
benchmark. It is not a passing complete workflow. The ordinary process job
also does not run the feature-gated real x86_64 cage-enforcement inventory.

## Remaining gates

Finish the patched workspace and explicit process-feature suites, complete
M1-M4 exact inventories and rollback/caller crash matrix, and check generated
proof coverage and all fuzz binaries. Preserve the completed installed results;
rerun affected profiles after executable or package changes. Keep commands, source,
compiler, features, executable hashes and terminal results together.

The five already-trusted audit feeds have no exact target records for the five
new TLS dependency versions at this refresh. An unlocked cargo-vet refresh also
requires an explicit ownership policy for the locally patched sigstore-verify
0.6.3. That policy was not guessed or changed to bypass source review. Existing
source-review preparation is not a completed package security audit.

Exact-head hosted qualification, protected merge, and required trusted-runner
authorization remain open. Linux/aarch64 process/container evidence is not
Linux x86_64 tool-confinement evidence. The user authorized local Task 7/M5
implementation before protected integration on 2026-09-15. Acceptance still
requires the governed, confined reference swarm and the remaining foundation
gates; existing process demos do not replace it.
