# Chio M1 - Phase-0 Launch Spec (tokenless marketplace + Pass M0)

Status: execution spec, derived from the multi-agent M1 design synthesis (5 readers + 3 planners + judge).
Drives the M1 build the way `CHIO-PASS-M0-SPEC.md` drove M0. Branch: `chio/m1-launch` off `chio/m0-pass-build`.

## 0. What M1 is

M1 IS the launch: the tokenless posted-price capability marketplace (custodial offer-safety escrow)
plus Chio Pass M0. The M0 build already landed every Pass primitive (T1-T10), the `freetier:global`
pool ceiling, the A2 single-ledger escrow, the committed digest baseline, and the DO-NOT-WEAKEN /
schema / recompute hygiene locks. The remaining work is almost entirely:

- (a) WIRING the already-built control-plane orchestrator into an operable entrypoint and into the
  commerce-order state machine,
- (b) producing the Section 8.3 gate EVIDENCE that the coded mechanisms fire fail-closed,
- (c) one genuine CODE gap: the `freetier:global` namespace-isolation exclusion from the comptroller
  reserve view and aggregate budget projections,
- (d) the own-data DisclosureLineageBundle upgrade over the spec 3-key strip,
- (e) the cleanup swarm under the digest guardrail,
- (f) the contract-surface config + regulatory prose gated by two legal sign-offs.

Two seams held throughout:
1. pool-vs-escrow never merge (one build, two ledgers, hard isolation both ways).
2. the digest baseline is the keystone before any signed-body edit or the swarm (acceptance bar is
   per-crate digest-diff vs the RED baseline RR3-T07-01, NOT cargo-test-green).

The Pass software gate reaches launch-readiness while legal closes in parallel, because the on-chain
leg is prepare-only and anchoring is read-only.

## 1. Already done in M0 (do not rebuild)

- WS-PASS-T1..T10: full Pass spine (window-scoped capability id, kernel mint, tier_0 gating, single-mint
  admission incl B7 UUIDv7-id XCC rejection, anti-farm, refresh-on-genuine-use, control-plane
  orchestrator, read-only prepare-only anchoring job at commit `677ea3311`).
- WS-PASS-T3 / WS-MKT-POOL: `freetier:global` aggregate pool ceiling + CONTROL-1 per-Pass+pool co-debit
  with in-closure reversal (`chio-kernel/src/kernel/validation.rs:775-1012`).
- WS-MKT-ESCROW-LEDGER: A2 single-ledger custodial escrow over chio-settle + ChioEscrow.sol (conservation
  proptest green); wiring into `accept()` is M1.
- WS-CL-DIGEST-BASELINE committed (RED baseline RR3-T07-01); WS-CL-SCHEMA-GATE / WS-CL-RECOMPUTE-GATE green;
  anchor schemas registered (Pass adds no new signed-artifact schema).
- WS-TC-M0-HYGIENE DO-NOT-WEAKEN invariants present and passing (no-CHIO pin, premium.rs 3-letter
  uppercase validator, chio-credit netting/capital flags false, ABI lock byte-identical).
- Gate 3 (soulbinding) and Gate 2 determinism + B7 admission already code+test complete.
- Immutable four value contracts (ChioRootRegistry, ChioEscrow, ChioBondVault, ChioPriceResolver)
  deployed unchanged; ChioIdentityRegistry admin = multisig+timelock.

## 2. Task ledger (M1-1 .. M1-26)

Kinds: code | config | docs | legal | evidence | infra | decision.

| id | kind | title | depends_on |
|----|------|-------|------------|
| M1-1 | decision | Pin board-approved ChioPassConfig + accepted_kernel_keys (RR2-TM-01) + tenant-id + HA posture | - |
| M1-2 | decision | Pin swarm model for the cleanup fleet | - |
| M1-3 | decision | Ship read-only Gate-6 anchoring round-trip at M1; defer proof panel + cadence to M2 | - |
| M1-4 | decision | M1 marketplace = primary posted-price + escrow offer-safety + live selection | - |
| M1-5 | legal | RG-MTMEMO: 50-state MTL/MSB + FinCEN CVC + GENIUS counsel memo | - |
| M1-6 | legal | RG-NONCUSTODY: non-custody key-surface demonstration | - |
| M1-7 | code | Freeze DO-NOT-WEAKEN regression suite as fail-closed pre-swarm/pre-acceptance gate | - |
| M1-8 | evidence | Confirm digest-baseline keystone committed; freeze per-crate digest-diff harness | - |
| M1-9 | code | CODE GAP (Gate 7): exclude freetier:global from comptroller reserve view + aggregate budget, both directions | M1-8 |
| M1-10 | evidence | Kernel free-tier pool suite + Gate 1 exhaustion evidence run | M1-1 |
| M1-11 | code | Wire Pass orchestrator into operable CLI entrypoint (chio pass issue\|refresh\|anchor) | M1-1 |
| M1-12 | evidence | E2e issue->mint->charge->read->rollover + dormant (Gates 2 and 5) | M1-10, M1-11 |
| M1-13 | code | Own-data gift as verified DisclosureLineageBundle (replace 3-key strip) | M1-11 |
| M1-14 | evidence | Five tier_0 gifted streams + Gate 4 cross-tenant / byte-identity hardening | M1-1, M1-13 |
| M1-15 | code | WS-MKT-ESCROW-WIRE: wire A2 escrow into accept() + commerce-order state machine (prepare-only) | M1-8, M1-4 |
| M1-16 | code | WS-PASS-ELIG + selection: bind eligibility/selection to provider-admission substrate | M1-11, M1-15 |
| M1-17 | config | Bind commerce proofs + accepted_kernel_keys to trust-market context (RR2-TM-01) | M1-1 |
| M1-18 | evidence | Order-passport replay green with escrow digest pinned (Gate 9) | M1-15 |
| M1-19 | docs | PASS-NAMING copy-lint + free-tier release-truth copy with no-future-value recital | - |
| M1-20 | evidence | Gate 6 in-cut: mock ChioRootRegistry publishRoot + verifyInclusionDetailed round-trip | M1-3, M1-8, M1-11 |
| M1-21 | infra | WS-CL-SWARM-EXEC: cleanup swarm across economy crates + contracts under digest guardrail | M1-2, M1-7, M1-8, M1-15, M1-20 |
| M1-22 | config | WS-TC-M0-CONTRACTS: advisory allowlist + stablecoin-feeds-only (zero immutable edits) | M1-5, M1-6 |
| M1-23 | docs | WS-TC-M0-DOCS: strike flat-vs-bps prose; re-ground MT defense | M1-5 |
| M1-24 | evidence | Re-verify DO-NOT-WEAKEN invariants post-swarm | M1-21 |
| M1-25 | evidence | Final launch-acceptance digest-diff-clean gate vs M0 baseline + one-liner green | M1-7,9,12,13,14,15,18,19,20,21,24 |
| M1-26 | decision | Launch-readiness SIGN-OFF assembly (gate evidence bundle) | M1-10,12,14,18,22,25,1 |

Per-task scope, verification, and exit-gate detail are carried in the workflow synthesis record
(`tasks/wbhmtwiwv.output`) and restated in each delegated build prompt.

## 3. Launch-readiness gate checklist (spec Section 8.3 gates 1-7 + program gates)

- Gate 1 aggregate-pool-denies-fail-closed: TODO via M1-10 (mechanism coded in M0).
- Gate 2 re-mint-reset-closed: TODO via M1-12 (determinism + B7 done in M0).
- Gate 3 soulbinding-holds: DONE in M0.
- Gate 4 five-stream parity + own-data-never-tier-gated + cross-tenant denied: TODO via M1-13/M1-14 (core done in M0).
- Gate 5 dormant-stops-drawing: TODO via M1-12 (decision tested in M0).
- Gate 6 anchoring round-trip read-only: TODO via M1-20 (prepare half done in M0; in-cut per M1-3).
- Gate 7 namespace-isolation + copy: TODO via M1-9 (code gap) + M1-19 (copy). Sealed proof-room panel deferred to M2.
- Program G9 escrow-wire replay: TODO via M1-15/M1-18.
- Program G8/G10 launch-acceptance digest-diff clean: TODO via M1-25.
- Program RG-NONCUSTODY: BLOCKED-EXTERNAL via M1-6.
- Program RG-MTMEMO + stablecoin-feeds-only: BLOCKED-EXTERNAL via M1-5/M1-22.
- Build green one-liner: DONE (re-run each slice, finally M1-25).

## 4. Critical path

M1-1 -> M1-11 -> M1-12 -> M1-13 -> M1-14 -> M1-15 -> M1-18 -> M1-21 -> M1-25 -> M1-26.

## 5. External blockers (cannot be code-executed)

- RG-MTMEMO (M1-5): outside fintech counsel; longest lead; gates contract-surface config (M1-22) and
  docs (M1-23) and the Phase0->1 escalation. Does NOT block the Pass software gate.
- RG-NONCUSTODY (M1-6): internal protocol-security key-surface demonstration; gates the contract-surface config.
- WS-PASS-GOV board sign-off (M1-1): board pins the ChioPassConfig numbers + accepted_kernel_keys. Blocks SIGN-OFF, not the build.
- Named licensed partner: NOT an M1 blocker (gates M2+ credit, M4 slashing, M5/M6 governance).

## 6. Founder decisions (defaults adopted for the build, board to confirm)

- M1-2 swarm model: keep glm-5.2 / Hermes per standing constraint; reliability comes from the
  digest-diff acceptance bar + commerce-aware review, not the model.
- M1-3: SHIP the read-only Gate-6 round-trip at M1; DEFER proof panel + anchoring cadence to M2 (recommended).
- M1-4: primary posted-price + custodial escrow offer-safety + live selection at M1; resale -> M3; revenue rail -> M5 (recommended).
- M1-1 HA: single-node `budget_store_lock` (pool ceiling HARD). tenant_id = raw did:chio verbatim.
  tier->units default 1000/1000/2500/5000. accepted_kernel_keys pinned to RR2-TM-01 with rotation epochs.
  POOL, caps, MIN_GENUINE_USE_RECEIPTS floor, and board_approval_ref carried as board-pending placeholders
  clearly marked in code; numbers do not change code structure.

## 7. Biggest risks (mitigations are in-plan)

- Cleanup-swarm fleet reliability (TOP): a flaky model silently re-canonicalizes a signed body while
  cargo test stays green. Mitigation: digest baseline + per-crate digest-diff acceptance (M1-8),
  commerce-aware review on the six signed-body crates (M1-21), final diff-clean gate (M1-25).
- Signed-body digest keystone (seam B): baseline must precede the swarm AND every signed-body change.
- Gate-7 namespace isolation is an unmet CODE gap, not just missing evidence (M1-9). Ship-block.
- Pool-vs-escrow non-merge (seam A): hard isolation tests both ways (M1-9, M1-15).
- Tenant-id derivation mismatch silently denies ALL own-stream reads (resolve in M1-1).
- Spec/alignment divergence on own-data redaction: DisclosureLineageBundle posture wins (M1-13).
- Securities seam on the soulbound Pass: any secondary/OTC pricing or future-CHIO wink is a stop-event (M1-19).

## 8. Execution discipline

House rules apply (no em dashes; fail-closed; additive within the immutable-contract boundary; no
weakening of DO-NOT-WEAKEN invariants; no `unwrap`/`expect` in non-test code; clippy `-D warnings`).
Every code/evidence task is delegate-then-independently-verify (clippy + tests + `cargo check --workspace`
+ em-dash/unwrap scan + diff sanity), committed as one conventional commit. Signed-body edits (M1-9,
M1-13, M1-15, M1-20) land after the baseline (M1-8) and must be per-crate digest-diff clean. Legal tasks
(M1-5, M1-6) and their gated config/docs (M1-22, M1-23) are surfaced as blocked-external, never faked.
