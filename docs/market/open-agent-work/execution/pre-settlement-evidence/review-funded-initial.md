# Funded execution integration review

Reviewed checkout: `/home/connor/backbay/arc-funded-integration`.
Base: `df2e7ef0ed1e1ba3ba5ef244e2247347b2c0f3e0`.
HEAD: `ad3dedbf37dfe732771d4458721156fc543fd524`, including the working changes available during review.

Read-only source review against `docs/superpowers/specs/2026-09-15-pre-settlement-execution-design.md` and its implementation plan. No Cargo, tests, commits, or implementation edits were performed by this reviewer. The findings below refer to the initial reviewed working snapshot, before the root agent's announced fixes.

## P2: Failed execution standing can mint a financial rejection

Location: `examples/federated-work/src/funded_work/verification.rs:187-197`; replay acceptance at `verification.rs:243-247`.

The new execution assessment can be `Rejected` because a production or checkpoint signer status has an invalid signature, a foreign signer, or revocation. `decide` only rejects `Unavailable` and `Unsupported`, then signs and retains an `accepted=false` financial decision for `Rejected`. `verify_decision` similarly accepts that negative decision after deriving the same failed assessment.

Reproduction at the verifier boundary:

1. Create a valid v2 execution, submission, and observed original claim.
2. Replace a retained execution bundle's production or checkpoint status signature with a signature from a foreign key, preserving the status body and role fields. Reload `original.execution` from the resulting canonical custody bytes.
3. Call `decide` using the original policy, claim, request binding, output custody, verifier key, and checker.
4. `execution_evidence::validate` authenticates the receipt and checkpoint without signer-status verification. `finding_acceptance::validate_execution_bundle` checks status shape and role but not signatures. The actual Finding verifier reports failed authenticity/membership facets, which classify as `Rejected`.
5. `decide` signs a negative financial decision, and `verify_decision` accepts that decision by reproducing the failed assessment.

This violates the agreed rule that changed or unpinned evidence cannot create either financial decision. The legitimate signed wrong-output case already has an accepted four-facet assessment and `matches_native=false`, so refusing failed execution assessments does not remove that refund path. The normal lifecycle's preliminary check masks this at its current call site, but it does not secure the decision API or replay boundary.

Requested fix: require an accepted execution assessment before creating or accepting either positive or negative v2 financial decisions. Retain the independent output comparison for authenticated negative results. Add a signed/foreign-status mutation test at `decide` and `verify_decision`, plus the valid wrong-output refund regression.

## P2: Current-time evidence checks block replay of earned payment

Location: `examples/federated-work/src/funded_work/lifecycle.rs:113-127`.

The lifecycle now unconditionally validates the submission and evaluates the execution bundle at `common::now()` before it reaches retained-decision replay at line 180. `evidence::verify` rejects when current time reaches `Finding.expires_at` (`evidence.rs:203-204`), and the new assessment also requires a currently live context. Those rules are appropriate for first claim/decision creation, but they prevent historical replay of an already accepted decision.

Reproduction:

1. Execute valid work, submit its claim, create a valid accepted decision, and record that decision on-chain.
2. Kill the lifecycle worker at `after-recorded-decision`, before payment withdrawal.
3. Resume after the Finding expiry (or context expiry), with the chain still showing accepted/payable work.
4. The timeout/refund shortcut does not handle the accepted/payable state. The new unconditional current-time check rejects before `verify_decision` can replay the retained assessment at `evaluated_at` and before the payout is driven.

The accepted work remains payable under its recorded contract decision, but regular lifecycle recovery cannot collect it. The separate `child::collect` route avoids these current-time checks, so this affects the general lifecycle rather than that specialized collection path.

Requested fix: replay an existing decision at its original assessment time before applying fresh claim checks. Put first-claim validation at the shared settlement request boundary and skip first-issuance expiry checks when a valid retained decision authorizes historical continuation. Cover an accepted decision resumed after Finding expiry and retain the original claim, receipt, checkpoint, and one-execution assertions.

## Additional review notes

- Original `Native::evidence` compares exported receipt bytes to custody on replay and checks the resolved output hash. Bundle custody is canonical and insert-once through the journal API.
- The v2 context floor contains the four agreed facets; cost authority remains unavailable. Legacy contexts keep their prior empty-evidence path and retention capacity.
- Provisioning pins separate checkpoint and status keys before agreement. Production/checkpoint standing is signed after the artifacts exist.
- The one-allocation journal cap and one-leaf checkpoint bounds are explicit. Existing checkpoint creation adopts a persisted checkpoint on retry, preserving checkpoint identity after a crash.
- The low-level `settlement::request(Action::Submit)` initially lacked the lifecycle's execution gate. The root agent is moving that gate to the shared boundary as part of the replay fix.
- While reconstructing original evidence at that boundary, compare `Binding.expires_at` to the original agreement's `refund_after`, and compare the receipt policy hash to `digest(policy)`. The initial validator did not explicitly compare those fields, although the original native evidence path constructs them correctly.

## Post-fix source review

The root agent confirmed both P2 findings and implemented fixes. I re-read the resulting funded source changes without running Cargo:

- `verification.rs:188-191` now requires `Accepted` for any execution-backed decision. `verification.rs:245-249` enforces the same rule when replaying positive or negative decisions.
- The unconditional current-time checks were removed from `lifecycle.rs`.
- `settlement.rs:150-159` validates first claims at the shared `Action::Submit` boundary only when no retained decision exists. Existing decisions are authenticated above this branch and replay their assessments at the original evaluation time.
- `execution_evidence.rs:157-192` reconstructs original input from the request and original output from custody addressed by the signed receipt's content hash, then validates the original signed Finding and four-facet assessment. `retain` stores the original output even when the submitted output differs, preserving the negative-result path.
- `execution_evidence.rs:82` compares the receipt policy hash to the original policy, and `execution_evidence.rs:145` compares binding expiry to the original agreement's refund deadline.

Both reported findings are addressed by the reviewed source changes. No further concrete blocker was found in these edits. Executable regression verification remains with the root agent: foreign-status signature/revocation must refuse both financial decision signs; valid signed wrong-output must retain its negative decision/refund; an already accepted decision must replay and pay after Finding expiry. This review does not claim those tests passed.
