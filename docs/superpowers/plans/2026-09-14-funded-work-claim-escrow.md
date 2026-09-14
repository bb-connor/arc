# Funded Work Claim Escrow Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` task-by-task in an isolated workspace. This plan selects inline execution, not subagent dispatch. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Demonstrate one finalized allocation, one admitted W0 job, one verifier-established claim and one reconciled payment, including rejection/refund and an earned child claim surviving parent failure.

**Execution status (2026-09-14):** Tasks 1-2 are implemented and locally tested.
See [claim-escrow results](../../market/open-agent-work/execution/05-claim-escrow-results.md).
The complete model suite passes 18 tests; the combined Node suite passes 143
checks, including all 118 model trace representatives. The independent private
chain reproduction retains an unpaid child claim through parent refund and
then pays the child. Task 3 remains gated on a qualified Security M4 checkpoint;
Task 4 native integration is not started. The independent [artifact/custody sub-slice](2026-09-14-funded-work-artifacts.md) now joins actual Rust W0 output, Python verification and retained local custody to private-chain payment, rejection/refund and child withdrawal. Its example-local profiles do not qualify native Finding facets or public-chain finality. This is not vertical-slice completion.

**Architecture:** Prototype an experimental claim escrow separately from existing `ChioEscrow`. Fund immutable work terms, commit a timely result, arbitrate through a pinned F1 verifier, and preserve accepted withdrawals. Connect the rail to native admission only after an isolated paper/Security M4 integration is reviewed and qualified for the selected surface.

**Tech Stack:** Python standard-library transition model, Solidity with the locked Node/solc/Ganache test environment, existing Rust market/kernel/store/settlement code, and the standalone federated example. Local development chain and mock ERC20 only.

**Spec:** [F1 draft 0.1](../../market/open-agent-work/execution/02-contract-draft.md), [escrow fit](../../market/open-agent-work/execution/01-escrow-fit.md), [Q1-Q10](../../market/open-agent-work/05-qualification.md).

## Global Constraints

- Fail closed; preserve required-facet failures, unknown execution and occupied nonces.
- RFC 8785 for signed JSON; explicit domain separation for EVM authorizations.
- No em dashes. Conventional commits. No `unwrap`/`expect` in Rust production paths.
- Preserve the paper and security working directories. Use `using-git-worktrees`.
- Local mock funds only. No live RPC, private external keys, deployments or partner messages.
- Do not alter existing escrow semantics or claim contract-only tests qualify native execution.
- Price 100 mock minor units, verifier/dispute fees zero; record actual checker/gas costs separately.
- One output commitment per obligation. Exact replay only. Separate funding for child liability.
- Accepted claims have no withdrawal expiry. Pending claims protect the resolution window.
- New-profile monetary strings and checked sums cap at `2^53 - 1`; conversion rejects loss.
- Root workspace tests do not select the standalone examples; name those commands explicitly.

## File and interface map

| File | Responsibility |
| --- | --- |
| Create `examples/funded-work-model/claim_model.py`, `test_claim_model.py` | Executable monetary transitions and short counterexample traces |
| Create `contracts/src/experimental/ChioWorkClaimEscrow.sol` | Funded agreement, timely claim, final decision, mutually exclusive withdrawal |
| Create `contracts/scripts/work-claim-escrow.test.mjs` | Real bytecode tests including negative controls and deadline ordering |
| Create `docs/market/open-agent-work/execution/05-claim-escrow-results.md` | Versioned source, commands, balances, assumptions and failed controls |
| Create `docs/market/open-agent-work/execution/06-native-integration.md` | Chosen M4 commit, predecessor map, conflict dispositions and selected checks |
| Create `examples/federated-work/src/funded_work.rs` and child modules as needed | Experimental agreement profile, funding-admission observer, verifier and recovery journal |
| Modify `examples/federated-work/src/main.rs` | Explicit experimental CLI dispatch, no legacy mode fallback |
| Create `examples/federated-work/funded_smoke.py` | Allocation-to-terminal process scenario, fault injection and independent balance reconstruction |
| Create `examples/federated-work/FUNDED.md` | Reproduction, trust limits and public evidence selection |

The proposed contract exposes `fund(terms) -> agreementId`,
`submitClaim(agreementId, commitment)`,
`recordDecision(agreementId, decisionDigest, accepted, verifierSignature)`,
`withdrawPayment(agreementId)` and `withdrawRefund(agreementId)`.
Terms bind the entire agreement digest, payer/provider/verifier, token, amount
and ordered deadlines. Domain-bound signatures include the submitted commitment
and complete decision digest. Implementation must define explicit typed structs
and canonical conversion vectors before making these methods public.

The example's funding observer returns only a verified allocation tied to a
pinned deployment/code hash, finalized block and exact agreement. It cannot
return a generic boolean copied from the payer. A durable journal correlates
agreement, allocation, native operation, claim, decision and transaction IDs.
Unknown broadcast state triggers reconciliation of the same IDs.

## Task 1: exhaust the small monetary state machine

**Files:** New claim-model pair; retain existing allocation model unchanged.

- [x] Read the F1 terminal matrix and freeze enum states: Funded, Submitted, Payable, Paid, Rejected, TimedOut and Refunded. Keep execution-unknown as independent metadata.
- [x] Write failing tests for exact submission replay, changed commitment, early/late decisions, payment/refund exclusion, verifier outage, failed transfer and accepted withdrawal after all deadlines.
- [x] Add two sources and a parent/child relationship. Test that parent refund cannot erase a child's Payable state and that unfunded parent revenue cannot reserve a child.
- [x] Implement only the model transitions needed by those tests, with explicit chain-time input and bounded integer amounts.
- [x] Exhaust bounded action sequences and adversarial orderings, including duplicate decisions and competing withdrawals. Emit minimal traces and verify conservation per funding source after every step.
- [x] Retain a broken legacy-expiry transition as an expected negative calibration. Run both model suites with `python3 -B -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v`.
- [x] Review and commit `test: model funded claim and refund exclusivity`. Report a bounded model result, not an unbounded proof.

## Task 2: enforce claim eligibility on the development chain

**Files:** New experimental Solidity contract and `work-claim-escrow.test.mjs`.

- [x] Start with contract tests that fail because the experimental artifact is absent. Reuse locked compilation/deployment patterns from `funded-work-fit.test.mjs`, with private in-process chain construction only.
- [x] Test exact received backing; derived ID and all agreement bindings; wrong payer, beneficiary, verifier, chain and contract; signature replay; duplicate/mutated commitment; safe-integer bounds and deadline ordering.
- [x] Implement full-price funding, timely submission and resolution with no existing-contract edit. Record final decision before token withdrawal; use checks/effects/interactions and reentrancy protection.
- [x] Test `submit_by` inclusively, challenge window closure, `resolve_by` inclusively and timeout refund strictly after `refund_after`. Reject refund while claim resolution is pending.
- [x] Test accepted withdrawal after expiry and after new-job pause/key rotation, with no buyer action. Test rejected refund, absent submission, unavailable verifier timeout and failed-token-transfer retry without double accounting.
- [x] Test actual transaction ordering for competing payment/refund attempts and decision conflicts. Run model-generated traces against contract state and balance deltas.
- [x] Fund child separately, establish child Payable, expire/refund parent, then withdraw child successfully. This specifically improves on the already-paid-child characterization.
- [x] Run `node --test contracts/scripts/work-claim-escrow.test.mjs contracts/scripts/funded-work-fit.test.mjs`. Retain legacy counterexample and mutation controls that fail for the intended missing guard.
- [x] Review code, source/bytecode hashes, limits and all test skips. Commit `feat: prototype funded work claim escrow`. Do not deploy or expand legacy public claims.

## Task 3: qualify the paper/security integration before native funding

**Files:** Integration report and explicitly mapped existing native files.

- [ ] Refresh #1117 and select an actually closed Security M4 commit with its exact qualification evidence. The latest [gate record](../../market/open-agent-work/execution/06-native-integration.md) has differing local/PR heads and incomplete qualification; neither is presumed closed. Keep local contract research executable while this gate is pending.
- [ ] Create a separate integration worktree from that checkpoint. Apply reviewed paper behavior from the source ledger in bounded slices; inspect each conflict rather than merging the legacy #1029 integration.
- [ ] Record old/new schema layouts, fingerprinted predecessors and unsupported migrations. Never reinterpret research version 10 as security version 10 or fabricate caller custody for old rows.
- [ ] Port A2A through verified manifest construction, preserve session/profile negotiation and adapt start/report handling to the security contract. Preserve immutable unknown execution and original payment-release authority.
- [ ] Select optional process hosting only if necessary for the actual test. Pin its compatible source and host/cage profile; do not require that optional stack for contract-only work.
- [ ] Run affected named inventories in `check-authenticated-caller-delivery.sh`, `check-native-restart-safety.sh`, `check-consumer-boundaries.sh`, `check-consumer-sdk-parity.sh` and `check-flow-security.sh`, then required formatting/build/test/Clippy/generated/security checks for that candidate.
- [ ] Run standalone federated Rust/Python/smoke regressions and the relevant composed/outcome examples explicitly. Record every actual command and prerequisite.
- [ ] Review/commit the integration report and candidate. Do not begin Task 4 native changes until this gate passes. No rewrite of the active security worktree.

## Task 4: connect finalized funding to one native W0 obligation

**Files:** Experimental federated modules and smoke harness; only necessary adapters in the reviewed candidate.

- [ ] Write an admission test showing unfinalized, wrong-domain, reused or mismatched allocations deny before kernel dispatch and before a new reservation.
- [ ] Define the registered experimental agreement/submission/decision encoding and shared malformed vectors. Map existing bid/ask/acceptance and Finding facets without overriding buyer reimbursement semantics.
- [ ] Implement the funding observer and durable operation correlation using existing settlement proof requirements. Fail closed on observer unavailability or changed deployment/chain state.
- [ ] Execute existing W0 checker on the exact agreed input and establish custodian retrieval before a positive verifier decision. Required unavailable/failed facets reject; synthetic contract-only signatures are not accepted here.
- [ ] Drive finalized deposit, native admission, committed start, execution, timely on-chain claim, verifier decision and one payout. Reconstruct all balances independently from contract events/state and token transfers.
- [ ] Drive invalid-result rejection/refund, no submission and unavailable verifier timeout. Keep execution uncertainty separate from financial closure.
- [ ] Inject process loss before broadcast, after broadcast before local journal update, after claim commit, after decision and before payout observation. Reconcile original IDs without second admission or payment; never edit databases to pass.
- [ ] Drive a Payable child, stop the parent before final delivery, reconcile parent refund and withdraw the child using only its retained authority. Publish payer/provider/custodian dependencies and exact losses.
- [ ] Add native disclosure, key/manifest substitution, capacity exhaustion and unknown-payment successor regressions. Reject new work before the 64-operation retention ceiling is exceeded; sustained trial capacity stays a later P53 gate.
- [ ] Run selected Rust, Python, Node and native security checks with no required skips. Add required schema/error/SDK/fuzz selection when shared manifests or public artifacts change; preserve existing unsupported-profile denials.
- [ ] Commit only after review and record source hashes, commands, public artifacts and residual assumptions. Do not claim independent companies, real settlement finality or H1-H5 from this one-host mock-token run.

## Independent recovery subset completed

The [2026-09-14 recovery slice](../../market/open-agent-work/execution/10-recovery-review-results.md)
adds durable exact signed transactions and four actual rail-worker SIGKILL
boundaries around real W0 payment. It also fixes custody capacity reservation
and loads the pinned Python checker bytes directly. This is preparation for
Task 4: it has no native operation/hold, finalized funding admission, Finding
facets or killed parent tool process. Tasks 3 and 4 remain unchecked until those
integrated behaviors are qualified on the selected security checkpoint.

The [complete lifecycle extension](../../market/open-agent-work/execution/12-lifecycle-recovery-results.md)
adds actual crash recovery for submission, decision and refunds, with 16 W0
cases and 48 killed workers. Earlier operations remain observable after later
Paid/Refunded transitions. A read-only integration rehearsal records ten
conflicts on pinned committed inputs. Security now reports local M4 gates
passing; uncommitted closeout/hosted qualification still prevent selecting the
native integration checkpoint. Funding and the native parent process remain
outside the independent recovery slice.

## Completion and next gate

The vertical slice completes when the same reviewable candidate demonstrates
success, rejection/refund, uncertainty reconciliation and a still-unpaid earned
child claim surviving parent failure, with direct authoritative evidence.
Task 2 alone is a useful contract milestone but does not complete this slice.
Tasks 3-4 depend on the qualified Security M4 source. Thereafter qualify W1,
independent implementation and sustained retention before the external trial.
