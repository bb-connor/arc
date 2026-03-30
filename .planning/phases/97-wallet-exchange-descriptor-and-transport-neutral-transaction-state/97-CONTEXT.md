# Phase 97: Wallet Exchange Descriptor and Transport-Neutral Transaction State - Context

## Goal

Define ARC's wallet exchange descriptor and canonical transaction state so
holder, verifier, and relay flows can share one replay-safe transport-neutral
contract.

## Why This Phase Exists

ARC already has bounded portable credential and verifier bridges, but the full
endgame needs one neutral wallet exchange model before optional identity
assertions or sender-constrained authorization can widen further.

## Scope

- wallet exchange descriptor and transaction identifiers
- same-device, cross-device, and relay-capable transaction state
- replay-safe request and response correlation
- fail-closed handling for ambiguous or duplicated transaction state

## Out of Scope

- identity assertions or login continuity
- sender-constrained runtime proofs
- end-to-end interop qualification beyond the neutral transaction substrate
