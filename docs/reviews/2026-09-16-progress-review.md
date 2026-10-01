# Progress and change review, September 16, 2026

Snapshot: 11:36 UTC. Follow-up to the September 15 portfolio audit and execution
handoff. Confidence is high in the recorded branch identities, completed gates
and reproduced finding. Foundation failure causes remain unknown.

## Assessment

The implementation has advanced substantially: a fresh Linux/x86_64 matrix now
exercises all seven reference scenarios, portable evidence verifies on macOS,
broker provisioning has live peer checks, and the corrected million-receipt
append campaign has completed. The combined foundation and M5 acceptance remain
open. The latest implementation is still ahead of the published integration PR.

Finish and qualify this candidate before expanding the implementation surface.

## Confirmed review finding

### P2: Bind the complete launch policy to the observed cage receipt

Location: `/tmp/arc-m5-evidence/crates/products/chio-cli/src/cli/mcp/cage_policy/evidence.rs:158-164`.
Introduced within the reviewed changes. Confidence: high, reproduced.

`verify_policy_bound_enforcement` verifies the policy signature and cage receipt,
then compares the manifest digest, helper digest, target digest and execution
identity. It does not establish that the signed launch plan/profile corresponds
to the supplied policy's command arguments, working directory or resource limits.
The standalone `receipt verify-native-start` command nevertheless reports
`enforced_policy` among its successful checks.

If an operator has issued multiple policies for the same server, binary and
identity, a receipt from one configuration can be paired with another signed
configuration. This gives an auditor a successful policy/launch association
without proving that the selected configuration was the one executed.

Reproduction against the retained macOS verifier at `1ae9f9dda`:

1. Keep the real `v2-budget.json` fixture's cage receipt unchanged.
2. Use a public deterministic test operator key to sign a baseline policy that
   still trusts the original cage receipt signer.
3. Sign separate policy variants changing only argv, working directory or
   descriptor limits. Keep the selected receipt ID and expected binary fixed.
4. All four combinations return exit zero and the same successful checks.
5. Changing the target binary digest is rejected, confirming that the existing
   partial binding is active.

The relevant verifier files are unchanged between `1ae9f9dda` and reviewed HEAD
`ee81b3ace`. No original private key or receipt modification is needed for this
test. The substitution requires another valid operator-signed policy; it is a
policy-to-launch evidence defect. The combined matrix adds route and bundle
digest pins, which constrain substitution separately.

Recommended repair: include the exact admitted policy digest in signed launch
evidence and verify it, or carry authenticated launch-plan material that lets
the verifier compare every claimed policy field with the signed plan/profile.
Add regressions for two valid policies signed by the same operator. Each wrong
configuration must be rejected while the original combination remains valid.

Reproduction script and results:

- `output/process-security-20260915/progress-review-20260916/native-policy-repro.py`
- `output/process-security-20260915/progress-review-20260916/native-policy-results.json`

## Branch and PR progress

| Location | Current identity | Relationship |
| --- | --- | --- |
| Published [ARC #1160](https://github.com/bb-connor/arc/pull/1160) | `b7211ce2d063ea36ea0f512b6f3c0253b65ecd71` | Open draft, unchanged from the handoff |
| `/tmp/arc-security-launch`, `integration/process-security-m4` | `178667e505bc1daee9da53a95322baecdb5bd59c` | 33 commits ahead of published #1160 |
| `/tmp/arc-m5-evidence`, `integration/process-security-m5-evidence` | `ee81b3ace998346253604567c1507fb73d0fcaa8` | Another 45 commits; 78 total ahead of published #1160 |

The complete local delta is 144 files, 14,457 additions and 661 deletions. Both
execution checkouts were clean. The original main checkout retains its unrelated
dirty files and untracked review/evidence work.

Live metadata also confirms #1117 at `5d1a9ec0`, #1156 at `7059c71c` and #1161
at `7755d376`; all remain open. This review did not repeat the entire 86-PR audit.

The 135 check runs returned for the published #1160 head contain 110 successes,
16 skips and nine failures. They cover the old published head, not the new local
candidate. Failures include security contract/controller binding, MSRV,
build/lint/test, two cargo-vet runs, process-host recovery, PostgreSQL isolation
and isolated Linux capture dispatch. Do not use these totals as qualification
of `ee81b3ace`.

## Evidence-backed progress

Evidence paths below are relative to `output/process-security-20260915/`.

| Workstream | Verified progress | Remaining boundary |
| --- | --- | --- |
| M5 governed confined swarm | Fresh seven-scenario Linux/x86_64 run: reference, authority, revocation, filesystem, network, host crash and shared budget. 17 worker outcomes. | `m5_acceptance_complete=false`; combined foundation, full cage inventory and designated runner remain open. |
| Portable evidence | Separate macOS observer accepts the matrix. This review reran `test-evidence`, including baseline verification and all 15 negative cases, successfully. | The new policy-substitution finding is outside those cases. Execution nonces and receipt-log inclusion remain explicitly unchecked. |
| M6 preparation | Broker provisioning, existing demo provisioning and strict CLI Clippy pass. A Linux live-peer test passes and refuses wrong-PID/closed endpoints. | Production broker authority, supplemental verifier and original keyring/broker/cage receipt composition remain unqualified. |
| M8 append scale | Corrected exact ignored-test gate finishes with exit zero at 11:30:29 UTC. Histories: 1,000, 100,000 and 1,000,000 real appends. | Append-cost evidence does not close the separate history recovery campaign or retention issue #1045. |
| M8 retention | Retained macOS property run passes 24 generated cases with seed `20260916`. | The slow-filesystem CI liveness failure has not been reproduced and closed. |
| Combined foundation | Generated security vectors and strict workspace Clippy pass on frozen source `810664017`. | Workspace test output contains six failures and no terminal result at this snapshot. This source also precedes the latest M5 work. |

### Exact retained evidence

- Matrix: `linux-x86-complete-matrix-167a17110/{result,verification,negative-verification}.json`.
  Runtime source `2d4b28da06ae06b0040acc67fadb141a2b6c9c89`; qualifier
  `167a17110931d0cf83e6dfe48928057e99fc1827`; static tools `e42e0ed41`.
  Bundle SHA-256 `e4aa37f0d2b86d5da96bb5112e2cd32dc8555e36f853f1f0a31b86fa7e6c2658`.
- Separate observer: `matrix-independent-macos-167a17110/result.json`, source
  `1ae9f9ddac749d71f27c9c7f62c49c519a53c7b3`.
- Broker: `macos-broker-provision-10c3995ee/results.json` and
  `linux-x86-broker-peer-test-10c3995ee/result.json`.
- Scale: `macos-receipt-scale-1628feb14/million-receipt-scale.{json,log}`.
  Source `1628feb14be889bb7eba21e02eee491392ef44de`; one passed, zero failed,
  zero ignored. Reported append means were 2.641 ms, 2.466 ms and 2.394 ms for
  the three history sizes. Whole command: 7,219 seconds, including build/setup;
  test runtime: 6,218 seconds. These are local campaign measurements.
- Retention: `macos-retention-reproduction-1628feb14/results.json`.
- Foundation: `linux-810664017-retry2/{results,active}.json` and
  `linux-810664017-retry2/workspace-tests.log`.

### Foundation failures visible in the current raw log

All six are in `security::adapters::tests::native_flow::support::capture`:

- `combined_credentials::nested::native_declassification_supports_public_nested_sync_and_async_with_all_credentials`
- `combined_credentials::nested::native_nonce_supports_public_nested_sync_and_async_dispatch`
- `corruption::native_capture_physical_corruption_denies_readback_and_reopen`
- `native_atomic_capture_faults_roll_back_budget_and_operation_together`
- `native_atomic_capture_preserves_dpop_required_by_another_matching_grant`
- `native_atomic_capture_retains_quota_and_ledger_without_tool_effect`

The test target had not printed the corresponding assertion details. The
qualification notes record severe host contention, but that does not establish
the cause of any failure. Preserve the original failures and reproduce them on
a controlled runner with the same deadlines and assertions.

The old frozen-source proof-coverage check also failed. A later local commit
refreshes generated coverage; it does not turn that older check into a pass.
Current qualification still needs source-consistent terminal gate results.

## Next execution order

1. Repair and regression-test the launch-policy binding finding.
2. Triage the six foundation failures from terminal output. Allocate a controlled
   test runner, retain the original evidence and qualify the repaired candidate.
3. Freeze one integration candidate including the M5 evidence branch. Publish a
   reviewable checkpoint under the existing execution authorization so GitHub,
   reviewers and retained evidence identify the same candidate. Publishing a
   draft checkpoint is distinct from merging or release acceptance.
4. Close combined-foundation and full cage inventories, then the outstanding M5
   evidence/runner requirements. Preserve the successful matrix and rerun the
   affected acceptance tests after the verifier change.
5. Finish the separate M8 recovery campaign and retention reproduction, then
   complete M6/M7 composition. Supply-chain audits, image-lock/source pins,
   designated capture and package/release qualification remain explicit work.
6. Reconcile #1156 and the other product branches once the common foundation is
   qualified. Keep the existing portfolio dependency map as the integration
   reference; do not replay superseded stacks.

## Review scope

Directly reviewed the new swarm authority/provisioning path, call and run
evidence verifiers, native launch verification, host-death changes, MCP blocking
transport adaptation, matrix qualification scripts and receipt-scale campaign.
The confirmed finding was reproduced with the retained verifier binary; the
portable matrix baseline and 15 negative cases were rerun during this review.
Broad Rust tests were read from retained results rather than launched alongside
the active qualification campaigns. This is a targeted review of the new delta,
not exhaustive review of all 144 files or a completed security acceptance gate.

Only this review document and its isolated reproduction artifacts were added.
Execution branches, original evidence, remote PRs and unrelated dirty files were
preserved.
