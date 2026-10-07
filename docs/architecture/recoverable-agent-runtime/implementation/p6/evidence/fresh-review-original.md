# Original fresh-context P6 review

Reviewer: `/root/p6_final_review`, `gpt-6-astra`, high reasoning, fresh context,
read-only, no delegated reviewers. This retained report precedes the author's
single primary fix pass. Its original verdict is not rewritten after fixes.

**P6 is not ready to seal: two Important/P1 findings remain. No Critical/P0
finding identified. Confidence: high.** No Minor findings were proposed.

The implementation has strong native ownership boundaries and explicit
evidence custody. The remaining failures affect supported operator recovery
and qualification reproduction.

## Findings

**P1-1: Protected setup bootstrap permanently pins a stale resume revision.**

`crates/platform/chio-store-sqlite/src/admission_operation_store/setup/service.rs`
lines 69 and 85 construct the retained benign Resume with revision one;
`make_selection` saves it at lines 395-397. Normal creation/materialization in
`crates/platform/chio-control-plane/src/recovery/setup.rs:103`, selection and
approval advance the workflow revision. `setup_preparation` returns the
unchanged command and `probe_inner` executes it at line 222. The normal owning
`recovery/commands.rs:143` correctly rejects its stale revision.

The ordinary `configure_protected_setup` entry point also freezes an early
revision when the unfinished workflow is subsequently selected or approved.
The supported operator path after profile change or probe expiration cannot
finish qualification; protected work remains locked despite valid approval.
This is an availability failure, not an authority bypass. The replacement
test only checks `action.is_some()` at `tests/knowledge/setup.rs:173-179`.

Required regression: complete real native selection, approval, probe, actual
writer reopen and qualification; assert one additional benign effect/charge,
stable operation/receipt on replay, and new protected work only after current
qualification. Cover initial bootstrap too. Bind the stable benign command
to the eligible workflow revision before its first execution in the native
owner, then preserve its exact bytes. Do not relax ordinary revision checks
or generate a different replay command.

**P1-2: Shipped model-free preflight does not satisfy the CrewAI model interface.**

`fixtures/recovery-product/campaign_runner.py:130-131` writes framework frames
to `model.attempts[-1]`; `preflight.ExplicitAction` at lines 15-21 has only
`model`, `calls` and `call`. Passing it to `crew_trial` at `preflight.py:61`
raises `AttributeError: ExplicitAction has no attribute attempts` after one
scripted call and zero tools. The public eight-case reproduction preflight
fails on its first CrewAI case. This does not invalidate the separately
retained corrected controller/preflights or live cohort D.

Required regression: actual pinned CrewAI with shipped ExplicitAction, one
native tool invocation and actual returned category; then all eight real
native helper combinations. Record compatible scripted attempts without
pretending that a provider request occurred.

## Reviewed scope and evidence

All 733 qualification source hashes were verified at binding
`0ae9c64641df39623275e33f3dc0ff48a917eb036605c17b1a06007b9492317f`.
The archived-source comparison has 366 changed paths. All 55 handwritten Rust
deltas and all 64 identified authored SDK/schema/harness/auditor/operations
entries were reviewed. Generated output was assessed through authoritative
inputs and current codegen gates, not a manual reading of every generated
line or every unchanged source body. Runtime: 712 sources at
`167c0487c96e7391f25436bb8eab898c22a3037bb141c2902c727ba80b2e1c19`.
HEAD independently read as `de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`.

The reviewer read the plan, binding specifications, eight P6 requirements,
both ledgers, all 40 packaged rulings/costs and the subsequent shared-VM
cleanup ruling. Read-only recomputation passed the source archive, immutable
P5 package, 33 local gates, four complete Linux suites, all ten P5 Linux case
identities, performance provenance, assurance, adoption, requirements and
all four live cohorts. Fourteen package tests passed. Complete Rust/Linux
suites were audited from retained actual executions, not rerun by the reviewer.

The earlier Linux/quiet performance subjects are reusable at this reviewed
snapshot: 710 unchanged subjects, with only two standalone campaign Python
files changed and not executed by those Cargo/benchmark subjects. That
argument does not grandfather the importing Python preflight.

Live conclusions remain finite: 384 planned, 339 measured, 45 unknown;
corrected cohort 47 complete, 45 refused and four skipped tools. All sixteen
positive strata meet the threshold. Three noisy performance failures and
older request-provenance gaps remain limitations. No source, evidence, index,
HEAD or branch mutation, and no subagent dispatch, occurred during review.

## Declined to judge

- All 108 crates, optional workspace features and unrelated historical/dirty changes: outside the archived P6 delta and finite gates.
- Complete re-audit of unchanged P0-P5: predecessor custody and relevant regressions assessed, not every earlier body.
- Hosted CI, merging, publication and deployed production behavior: absent from this phase evidence/action.
- Production migration effort or supervisory-code savings: fixture-specific measurements, zero removed supervisory lines.
- Other framework/provider versions or deployment platforms: exact supported pins; local CrewAI 0.203.2 excluded.
- Security advantage over an independent runtime or OpenAPPA: both arms share competent native owners.
- General utility superiority or account-independent availability: three repetitions and differently situated attempts cannot establish these.
- Safety, effects or utility for 45 unmeasured slots: unknown.
- Complete request content for 25 old prompt gaps: original immutable bytes unavailable.
- Independent provider-side response attestation: recorded custody/native evidence does not attest provider internals.
- Shared-workstation latency SLA: quiet profile only, later noisy failures retained.
- Unconditional settlement progress against indefinitely hung providers or arbitrary scheduling failures: reserved capacity and job ownership only.
- P6 protection for legacy unmarked profiles: protected service must be mounted and configured.
- General production artifact HTTP: private trusted native bridge only.
- Arbitrary-recipient exactly-once delivery: native identity and authorized redelivery do not prove arbitrary external semantics.
- Expanded confinement, nested launches, non-Boolean/additional channels and covert-channel elimination: outside selected profile.
- Complete SQL, two-store, provider or whole-system formal proof: eight abstractions/Loom explicitly leave seams uncovered.
- Live cloud cleanup, concurrent ownership and final billing: rulings read, OCI not independently operated/inventoried by reviewer.
- Final verification seal/review manifest: intentionally absent until review and fix pass complete, not a defect.

## Assessment

Fix both P1 findings in the single primary TDD pass, preserve the original
verdict, run complete affected owning suites and regenerate source-bound
qualification. Ready to seal or merge: **No** at this original snapshot.
After verified fixes the evidence supports the stated local/Linux/finite-live
boundaries, not a general production release.
