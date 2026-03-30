# Phase 94: Multi-Format Credential Profiles and Verification - Context

## Goal

Broaden ARC from one narrow projected credential lane into a small,
standards-legible multi-format credential family over one canonical passport
truth.

## Why This Phase Exists

The research endgame requires broader portable identity than ARC's current
single SD-JWT VC projection. ARC needs explicit format negotiation and
verification rules before it can claim wider wallet or verifier compatibility.

## Scope

- multi-format credential projection engine
- explicit format negotiation and issuer metadata
- verification rules for each supported portable profile
- fail-closed handling for unsupported or mixed-format requests

## Out of Scope

- wallet launch adapters
- public discovery network
- cross-issuer trust packs
