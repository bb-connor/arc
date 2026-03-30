# Phase 93: Portable Claim Catalog and Governed Auth Binding - Context

## Goal

Define ARC's first broader portable claim catalog and align subject or issuer
binding with governed request-time authorization semantics.

## Why This Phase Exists

ARC already ships one narrow portable credential profile and one bounded
authorization-details projection, but the full endgame needs those surfaces to
share a standards-native identity and provenance model instead of remaining two
separate derived views.

## Scope

- portable claim catalog over ARC passport truth
- explicit ARC provenance, portable issuer, and portable subject binding rules
- governed intent and request-time authorization binding semantics
- fail-closed rules for unsupported or ambiguous identifier mappings

## Out of Scope

- multi-format credential projection
- wallet transport adapters
- token exchange or transaction-token propagation
