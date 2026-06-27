# Chio M2 - Phase-1 Fail-Closed Gate Package (M2-24)

Branch: `chio/m2-build` (off `chio/m1-launch`). This is the M2-24 assembly: the fail-closed
gate evidence for the UNBLOCKED M2 surface. Companion to `docs/brainstorm/CHIO-M2-BUILD-SPEC.md`.

## 0. Verdict

The unblocked M2 software is complete, merged, and green on every engineering gate. M2 introduced
NO new immutable contract and NO off-TCB ledger; every credit support-boundary flag stays default-false.
The remaining open items are NOT software: the live CDP testnet leg and the credit-program partner +
legal gates.

## 1. Fail-closed gate evidence (with commit hashes)

| Gate | Evidence | Commit |
|------|----------|--------|
| GATE-NETTING (single-denomination netting realized OFF-CHAIN, all 3 flags default-false) | M2-1 off-chain ExposureLedger collapse + M2-5 flag locks | `d89d6b75b`, `0b02eb4b7` |
| GATE-RECOMPUTE (recompute is the SOLE proof lane; EAS-as-anchoring + payment-as-authorization fail closed) | M2-2 recompute keystone | `025a7e50d` |
| GATE-DIGEST (launch-acceptance green, DIFF-clean vs baseline `3931b972f`) | M2-3 re-green + M2 baseline | `320afed64` |
| Currency hygiene (XCC private-use 3-letter code; non-3-letter fails closed) | M2-4 | `be32fcc6a` |
| Single-slash-lane (slash routes ONLY through the comptroller; no second slash authority) | M2-7 conformance harness | `c4c1cdde0` |
| Single-source capital book (denies >1 facility/bond or mixed currency) | M2-8 conformance harness | `0b8dee58b` |
| EAS/Verax recompute-only (carried as display-only projections, denied in a proof position) | M2-9 | `ee87c7b05` |
| Verifiability grade deterministic + strict-lower-monotone; quote-option expiry | M2-10 + M2-11 exhaustive property tests | `f968d9243`, `ff4f98965` |
| x402 approval inverted to fail-closed-BY-CONSTRUCTION (settlement verdict cannot mint authorization) | M2-12 | `86f0903f8` |
| x402 Test B: a verified payment receipt does NOT authorize a tool call (structural, not runtime) | M2-13 | `64051fdad` |
| x402 custody-neutral prepare-only signing (no value moves, testnet-gated, mainnet rejected) | M2-14 | `175cb5c2c` |
| x402 / ACP-Commerce / AP2 interop profile (recompute-bound, not authorization) | M2-15 docs | `363528860` |
| Prepaid closed-loop VIEW: non-transferable by construction, refund-to-original-funder-only, SHIP gated | M2-17 | `3e5f72bc6` |
| Sealed Pass proof panel: recompute-bound read-only verdict, tamper-evident | M2-18 | `fa0163a93` |

Recompute primitives (`verify_anchor_inclusion_proof`, `verify_public_settlement_proof`) and the kernel-
signed checkpoint remain the sole proof substrate throughout. No producer/witnessed on-chain state is trusted.

## 2. Invariants held (DO-NOT-WEAKEN)

- NO new immutable contract; NO restricted-ERC20 ChioCreditVault; NO off-TCB ledger.
- `cross_currency_netting_supported`, `capital_allocation_supported`, `mixed_currency_netting_supported`
  all default-false; books stay `mixed_currency_book` (per-currency fail-closed exposure accounting).
- IOUs/credit only from non-zero cost, pinned USD/USDC.
- Immutable four value contracts byte-unchanged; ABI lock intact.
- Digest gate green DIFF-clean vs the M0/M1 baseline at every signed-body merge (M2-1, M2-12, M2-14).

## 3. Open blockers (the ONLY items between here and the M2 credit program)

All BLOCKED-EXTERNAL (cannot be code-executed):
- M2-16 - x402 live CDP money-movement on Base Sepolia (needs a CDP account + a named licensed partner as principal of record).
- M2-19 - RG-MICA: MiCA e-money classification opinion (EU counsel; longest lead).
- M2-20 - RG-CLOSEDLOOP: 31 CFR 1010.100(ff)(4) closed-loop prepaid-access sign-off.
- M2-21 - a named high-frequency customer with a MEASURED permit/gas bottleneck.
- M2-22 - a named licensed partner as BSA-obligated issuer/custodian of record (kill-criterion if none will serve).
- M2-23 - the prepaid READY/SHIP declaration (gated by all of the above).

The prepaid VIEW code (M2-17) and the x402 code legs are built and tested; only the SHIP declaration
and the live money-movement leg are gated.

## 4. Known issue (pre-existing, not an M2 regression)

`e2e_pass_issue_charge_rollover_dormant_gates_2_and_5` (M1-12, chio-control-plane) is a wall-clock
time-dependent test that fails once the clock advances past its hardcoded validity window (it began
failing on 2026-06-27). Confirmed pre-existing on the clean `chio/m2-build` base. It should be made
time-deterministic (inject a fixed clock) as a follow-up; it is unrelated to M2 code.

`chio/m2-build` is ready to merge / open a PR. The unblocked M2 surface ships once the six items in
Section 3 close.
