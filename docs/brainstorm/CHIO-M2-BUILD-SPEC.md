# Chio M2 - Phase-1 Build Spec (off-chain netting + verifiability pricing + interop)

Status: execution spec, from the multi-agent M2 design synthesis. Branch: `chio/m2-build` off `chio/m1-launch`.
Drives the M2 build the way CHIO-M1-LAUNCH-SPEC.md drove M1. Roadmap: CHIO-EXECUTION-ROADMAP.md Section M2.

## 0. What M2 is

M2 (Phase 1) proves Chio delivers credit netting, verifiability-graded pricing, and standards interop
(x402 / EAS / Verax) ENTIRELY INSIDE the existing immutable-contract boundary: NO new immutable contract
(no ChioCreditVault), NO off-TCB ledger, and every support-boundary flag held default-false
(`cross_currency_netting_supported`, `capital_allocation_supported`, `mixed_currency_netting_supported`).

Two lanes:
- UNBLOCKED software (ships now, no external dependency): off-chain netting collapse, the recompute keystone,
  the conformance harnesses, verifiability grade, EAS/Verax projections, the code-only x402 legs, the prepaid VIEW code.
- BLOCKED track (entry-gated): the live CDP x402 leg and the prepaid SHIP declaration, gated by RG-MICA,
  RG-CLOSEDLOOP, a named licensed issuer-of-record partner, and a named high-frequency customer with a MEASURED bottleneck.

Keystone code blocker: WS-CL-RECOMPUTE-GATE (M2-2) gates x402-verify, EAS/Verax, and both conformance harnesses.
Acceptance bar: digest-diff-against-baseline for signed-body crates (not cargo-test-green alone); re-green the
RED launch-acceptance (RR3-T07-01) before fixture-touching work lands.

## 1. Task ledger (M2-1 .. M2-24)

| Task | Workstream | Kind | Blocked | Title |
|------|-----------|------|---------|-------|
| M2-1 | NETTING | code | no | Off-chain ExposureLedger single-denomination netting collapse (kill-evidence) |
| M2-2 | RECOMPUTE-GATE | code | no | Verifier recompute-not-trust keystone: close fail-closed negatives |
| M2-3 | DIGEST-BASELINE | infra | no | Re-green launch-acceptance + stamp M2 digest baseline (RR3-T07-01) |
| M2-4 | NETTING | code | no | Currency-code hygiene for non-USD private-use credit codes |
| M2-5 | NETTING | code | no | Extend DO-NOT-WEAKEN regression locks for netting flags |
| M2-6 | NETTING | docs | no | Record netting kill-evidence + gated flag-flip + NO-BUILD commitment |
| M2-7 | SLASH-LANE-GATE | code | no | Single-slash-lane conformance harness |
| M2-8 | CAPITAL-SOURCE-GATE | code | no | Single-source capital-book conformance harness |
| M2-9 | EAS-VERAX-PROJ | code | no | EAS/Verax carried ONLY as proof-envelope projections, recompute sole lane |
| M2-10 | VGRADE | code | no | Verifiability-graded price: deterministic + monotone, quote-option/last-look expiry |
| M2-11 | VGRADE | evidence | no | VGRADE determinism + strict-lower-monotonicity proptests |
| M2-12 | X402-VERIFY | code | no | Invert approval to fail-closed-by-construction (Risk-2 prerequisite) |
| M2-13 | X402-VERIFY | code | no | x402 Test B: payment-success-does-not-authorize (negative) |
| M2-14 | X402-VERIFY | code | no | x402 custody-neutral prepare-only signing path |
| M2-15 | X402-VERIFY | docs | no | x402/ACP/AP2 projection fixtures + mandate-allowlist + interop-profile docs |
| M2-16 | X402-VERIFY | infra | YES | x402 Test A: live CDP money-movement on Base Sepolia (positive) |
| M2-17 | PREPAID | code | no | Escrow-socketed closed-loop prepaid credit VIEW + refund-after-deadline non-transferability tests |
| M2-18 | PASS-PROOFPANEL | code | no | Sealed proof panel (deferred from M1, optional within M2) |
| M2-19 | PREPAID | legal | YES | RG-MICA: MiCA e-money classification opinion |
| M2-20 | PREPAID | legal | YES | RG-CLOSEDLOOP: 31 CFR 1010.100(ff)(4) closed-loop sign-off |
| M2-21 | PREPAID | evidence | YES | Name a high-frequency customer with a MEASURED permit/gas bottleneck |
| M2-22 | PREPAID | legal | YES | Name a licensed partner as issuer/custodian of record |
| M2-23 | PREPAID | decision | YES | Declare WS-TC-M2-PREPAID READY/SHIP (entry-gate close + kill-check) |
| M2-24 | RECOMPUTE-GATE | evidence | no | Assemble and seal the M2 fail-closed gate package |

## 2. Critical path

M2-1 (netting, lead) and M2-2 (recompute keystone) run in the SAME first wave (independent).
M2-2 -> M2-3 (re-green baseline) before any fixture-touching change.
M2-2 -> M2-7 / M2-8 (conformance harnesses); M2-2 + M2-3 -> M2-9 (EAS/Verax).
M2-2 -> M2-12 -> M2-13 / M2-14 -> M2-16 (blocked on partner + creds).
M2-10 -> M2-11 (vgrade, parallel from day 0).
All code-side gates -> M2-24 (gate package). Blocked legal track (M2-19/20/21/22/23) runs parallel, longest lead.

## 3. Execution model: Claude leads, Hermes assists

- CLAUDE (substantive logic, signed-body, security): M2-1 netting collapse, M2-2 recompute invariant,
  M2-7/M2-8 conformance assertions, M2-10 verifiability grade + quote-option, M2-12 approval inversion,
  M2-13 x402 Test B deny logic, M2-14 custody-neutral signing, M2-9 display-only semantic, M2-17 decrement
  logic, M2-18 sealed panel, M2-24 gate assembly.
- HERMES (glm-5.2 swarm; mechanical scaffolding, fixtures, docs, repetitive projection wiring): M2-4 currency
  mapping, M2-5 regression-lock extension, M2-6 kill-evidence doc, M2-9 projection manifests/envelopes/negative
  fixtures, M2-11 proptests, M2-13/M2-15 x402 fixtures + interop docs, M2-7/M2-8 harness boilerplate, M2-17
  VIEW fixtures + non-transferability scaffolding. Dispatched off chio/m2-build via the FIXED fleet
  (fleetctl: CR-submit + --base-branch). Acceptance bar: digest-diff clean.

## 4. Invariants (DO-NOT-WEAKEN, carried from M0/M1)

NO new immutable contract. All support-boundary flags default-false; books stay mixed_currency_book
(per-currency fail-closed exposure accounting is the prudential safeguard). IOUs only from non-zero
cost, currency pinned USD/USDC. Recompute is the SOLE proof lane (anchoring-readback and
payment-as-authorization both fail closed). House rules: no em dashes; fail-closed; clippy -D warnings;
no unwrap/expect in non-test code; signed bodies keep canonical-JSON digest stability.

## 5. Open blockers (cannot be code-executed)

RG-MICA (M2-19), RG-CLOSEDLOOP (M2-20), named high-frequency customer (M2-21), named licensed partner
(M2-22) - all gate the prepaid SHIP (M2-23) and the live CDP x402 leg (M2-16). Kill-criterion: if no
licensed partner will serve as BSA-obligated issuer of record, kill the credit program. The prepaid VIEW
CODE (M2-17) is buildable now; only the SHIP declaration is gated.
