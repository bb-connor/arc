# Foundation qualification input repairs

Execute inline on the existing #1160 branch. Preserve unique work, existing
review history, failed evidence and all native isolation requirements.

The landing ledger and foundation acceptance scope remain authoritative. This
plan repairs failures on `b587a81cd3932aeb9580dbe55cad30fa199a3b99`; it adds no
features or landing PRs.

1. Retain the exact pinned Alpine CA package as a bounded, hash-checked build
   input. Hosted job `111617963793` received HTTP 404, while a local fetch still
   returned the original hash. Use a read-only build mount, keep APK signature
   verification and the complete installed inventory, and test tampered,
   missing, linked and oversized inputs before changing the implementation.
2. Reconcile the trust-boundary and wire-schema inventories against the actual
   new PostgreSQL resource and caller projection. Review each new decoder and
   constructor before recording it. Strengthen the nine new negative assertions
   to check the rejection variant; do not expand the weak-assertion baseline.
3. Diagnose PostgreSQL process initialization after the successful enforcing
   host and TLS component checks. Reproduce the actual failure and repair the
   owning boundary, then rerun the native handoff and uncertain recovery lanes.
4. Run the affected suites and structural checks, retain their results, update
   the ledger, commit and push. Obtain GitHub Codex review of the exact source
   before rotating trusted source authorization and launching a fresh campaign.

Review focus: build input provenance and bounded reads, unchanged package
closure, authenticated caller projection, configuration rejection reasons,
secret-free hosted diagnostics, native isolation and failed-result retention.

Completion requires native/trusted qualification and protected landing. Local
checks and a positive independent review do not satisfy that boundary alone.

## Local execution

- The six image-input regressions failed before repair and pass afterward.
  The full CI contract mutation suite passes. The original APK signature verifies
  using the official x86_64 Alpine signing key. This is portable package
  verification, not a native image or enforcement pass.
- Both new bounded document readers and the renamed caller projection were
  reviewed. All 37 boundary calibration tests pass. Wire inventory, 180 broker
  tests, strict owning Clippy, the negative-assertion gate and proof coverage pass.
- Native PostgreSQL run `37262578320` passed the enforcing-host fixture, public
  worker API and TLS resource component, then failed process initialization.
  The initializer omitted the mandatory aggregate invocation budget. The
  qualification now supplies its existing 100-call family limit explicitly;
  full native execution of this repair remains required.
- Native worker job `111613584111` failed direct CLI-module formatting. Those
  module checks now pass locally, as do workspace formatting, all 20 trusted
  definition tests and the container/committed-evidence/source-inventory checks.

Fresh independent review, supported native campaigns, authenticated publication,
strict merge-context activation and protected merge remain incomplete.

## Hosted follow-up on `68cff8cd6a8654815ff0c4478faa1012aadd71d7`

Continue inline with `superpowers:executing-plans`; do not spawn subagents.
This source passed independent GitHub Codex review. Qualification remains open.

- [x] Reconcile `scripts/check-flow-security.sh` with the existing overflow
  regression in `crates/security/chio-flow/src/engine.rs`. Hosted job
  `111634854713` executed all 47 tests successfully, then correctly refused the
  stale 46-test inventory. Update the corresponding expected count in
  `scripts/tests/check-flow-security.test.sh`, observe its failure before adding
  the missing name, and rerun the exact gate. Keep every existing test required.
- [x] Reconcile the remaining exact inventories against executed Rust test
  lists, including keyring state. Keep every new security regression required.
  The three former v1 migration tests were removed with their API in
  `da4086017fc04e0d69dbe942a8ba42f6f4404b71`; document that source transition
  instead of advertising an unavailable compatibility path. Repair review PR7
  in the manifest README, architecture and normative protocol, using the
  current v2 types, verifier and generated schema as the authority.
- [x] Reproduce PostgreSQL native job `111629368055` on the existing isolated
  x86_64 qualification worker. Initialization, enforcing-host qualification and
  the TLS component pass; the first assignment receives a kernel denial. Inspect
  the original operator response, signed receipt and private host/broker logs
  before changing the responsible boundary. Keep credentials out of retained
  public evidence. Add an owning regression before any behavior repair.
- [x] Export the per-call denial evidence already retained by the SDK before
  qualification assertions can abort. The regression failed when the workflow
  omitted the original receipt and verification status; all four consumer-job
  tests pass after the allowlist repair, with no success report synthesized.
  Export only the signed receipt and bounded nonsecret status;
  never upload host configuration, credentials, runtime state or private logs.
- [ ] Preserve terminal hosted outcomes, skipped cases, controller queue expiry
  and the separate read-only #1029 reconciliation. Update the landing ledger,
  verify affected boundaries and commit one reviewed repair checkpoint. Obtain
  exact-source GitHub Codex review before rotating source authorization.

Do not count the old authorized-tooling image results as qualification of the
retained CA input. Native diagnostics on the isolated worker are component
evidence; the required final trusted campaign must still run on its prescribed
hosted runner. Stop the diagnostic worker after its owned work completes.

### Follow-up findings and bounded results

- All 69 flow target lists are reconciled. Ten inventories changed and now
  require 706 exact test names. The two renamed regressions retain their owning
  tests; the removed v1 migration API is explicitly documented as unsupported.
  All 706 tests have successful execution evidence across the original run,
  continuation and focused repair reruns. The original campaigns remain failed;
  the final candidate still requires its fresh hosted gate. The separate
  keyring gate passes all 93 required tests across 12 targets.
- PR7's manifest documentation repair compiles and runs as a README doctest.
  The normative protocol, README and architecture now describe the current v2
  contract and explicit operator review, re-signing and admission requirements.
- The MSRV job's four certification failures came from authority databases
  placed directly beneath the shared temporary directory. Their fixtures now
  use the existing private temporary-directory helper. All 13 active tests pass;
  the pre-existing ignored multi-operator timing test remains unverified.
- Native PostgreSQL diagnosis reproduced an upstream TLS refusal: the generated
  certificate incorrectly had CA:TRUE. Explicit CA:FALSE and serverAuth fix
  that boundary. A second regression corrects the harness to decode the broker
  value already projected by the kernel. Both tests failed before their repairs;
  all four mediation tests pass afterward.
- The repaired debug CLI completes assignment, exact replay and release, then
  correctly refuses inspection when preparation takes 10,707 ms against the
  unchanged 10,000 ms policy window. A curve-arithmetic-only optimization did
  not repair that expiry and is not adopted. The existing production profile
  passes that boundary, then exposes a separate child-lifetime failure after
  restart. No deadline or security check is relaxed.
- The broker launched a caged child on a Tokio blocking worker, which retired
  after ten seconds. Linux correctly delivered the armed parent-death SIGKILL.
  The native terminal receipt records a 10,009 ms lifetime. A process regression
  reproduces this failure when the caller's runtime shuts down. A bounded,
  invocation-owned dedicated launch thread now remains until delivery shutdown
  and terminal-receipt persistence finish. Cancellation, preparation failure,
  exhausted capacity and runtime retirement pass four focused regressions.
  All 206 native-MCP broker library tests and strict all-target Clippy pass.
  The complete PostgreSQL handoff/restart and committed-claim-loss scenarios
  both pass on the isolated x86_64 enforcing host. The existing production CLI
  profile is now selected by the workflow. This component check uses the prior
  debug broker helper and static tool, with the repaired CLI and Python harness;
  final exact-candidate hosted and trusted qualification remain required.
- The release-recovery expiry fixture restored an earlier wall clock before
  replay and hit the independent rollback refusal. Retaining its advanced
  fixture clock through replay restores the intended lease-expiry test. All
  25 release-recovery tests pass without changing production clock enforcement.
- Sixteen bounded source comparisons across nine #1029 commits are recorded.
  Unique interval compaction and provenance timestamp work remain preserved;
  reworked owners still need their listed execution and compatibility evidence.
  No whole-commit equivalence or PR retirement follows from these comparisons.
- Native-worker recovery and SDK parity workflows complete successfully on
  `68cff8cd6a`. Foundation CI, the original PostgreSQL workflow and both expired
  controller attempts remain unsuccessful. Component results do not establish
  the final native/trusted publication or protected merge.

## Evidence binding and refresh discovery follow-up

Repair `850ee8ab38725f90384be265ffe72072250524a8` fixes the reproduced signed-output input cycle using binding
schema v7 and a closed, no-follow three-file output namespace. Nine controls
cover output addition and refresh, unexpected entries, aliases, replacement and
compile references. Seven real-engine tests cover selected discovery, full
ordinary discovery and retained path/function refusal. The original failures
and the stable-source contract rerun are retained in the landing ledger bundle.

The superseded 254fbd native attempt is cancelled after its successful initial
baseline, without a caught mutation or complete campaign. Its image and installed
boundaries remain component evidence. All 35 current-source campaigns and the
final hosted/trusted chain remain mandatory. Publish all source and ledger work
before freezing inputs; mutation refresh and signed publication may then change
only their exact derived paths. Do not append status prose after regeneration.

The #1029 reconciliation now covers 29 source comparisons across 22 commits and
all 219 unique commits in the path inventory. Preserve that PR and its remaining
semantic, compatibility and execution obligations.

### Independent review: computed publication-input paths

GitHub Codex review `5993144649` identifies a P1 on `aa76f23b11`: literal source
inspection cannot exclude a path assembled dynamically by a build script.
A real Rust build regression reproduces the changed result after publication.

Ruling: keep the three signed outputs outside candidate execution through the
existing immutable Git source projection. Reject unknown entries, non-regular
output modes and non-directory ancestors before materialization. Direct controls
refuse the namespace before candidate code executes. The original signed files
remain available to the separate committed-evidence verifier. This fixes the
qualification boundary without expanding compiler privileges or parsing arbitrary
Rust expressions as an authorization mechanism.

All 16 focused tests pass, including actual cold Rust builds before and after
publication. The complete checker fixture block, container controls, all 12
committed-verifier tests, current CI contract and complete CI mutation suite pass.
The host runner now has a reviewed full-source commitment, with two regression
mutations covering projection bypass and unexpected output acceptance.

The superseded native run retains one caught approval mutation and a successful
baseline, then is cancelled after 1,723.704 seconds with a clean source checkout.
It is partial component evidence only. The worker is stopped. Review the new
composition before authorization; all 35 campaigns, terminal hosted checks,
trusted publication and protected foundation landing remain required.
