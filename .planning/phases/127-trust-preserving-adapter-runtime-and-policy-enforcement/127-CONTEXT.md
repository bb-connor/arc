# Phase 127: Trust-Preserving Adapter Runtime and Policy Enforcement - Context

## Goal

Define how custom adapters execute and how ARC prevents them from silently widening trust, mutating signed truth, or bypassing policy.

## Why This Phase Exists

ARC needs runtime enforcement semantics before it can trust any custom execution, evidence, or transport plugin.

## Scope

- adapter runtime envelopes
- policy enforcement over custom execution
- evidence import constraints
- privilege and isolation rules

## Out of Scope

- official-versus-custom qualification closure
- web3 execution adapters
- ecosystem identity expansion
