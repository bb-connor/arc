# Phase 74: Sender-Constrained and Discovery Contracts - Context

## Goal

Make ARC's authorization profile legible for sender-constrained and metadata
driven enterprise deployment without widening trust through discovery alone.

## Why This Phase Exists

Enterprise IAM teams expect explicit semantics for who is allowed to present a
token or request, how that binding is advertised, and what discovery material
exists. ARC needs one concrete answer instead of leaving those questions
implicit.

## Scope

- sender-constrained semantics profile
- metadata and discovery contract for the ARC authorization profile
- assurance-bound and delegation-bound sender semantics
- fail-closed behavior for missing proof or mismatched discovery data

## Out of Scope

- enterprise adapter implementations
- reviewer packs and partner proofs
- broader public marketplace discovery
