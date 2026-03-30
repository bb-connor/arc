# Phase 110: Escrow and Reserve Instruction Contract - Context

## Goal

Define custody-neutral escrow and reserve instruction artifacts over the live
capital book so ARC can express intended movements without assuming a single
custodian or rail.

## Why This Phase Exists

Once capital posture is explicit, ARC needs a portable instruction contract for
locks, releases, and transfers before governed actions can allocate funds live.

## Scope

- escrow and reserve instruction artifacts
- role chains, counterparties, and execution windows
- custody-neutral intended versus executed state
- fail-closed handling for stale authority or reconciliation mismatch

## Out of Scope

- governed-action allocation decisions
- automatic provider pricing or claims payout flows
- open registry or marketplace economics
