# Phase 107: Public Issuer/Verifier Discovery, Transparency, and Local Policy Import Guardrails - Context

## Goal

Publish issuer and verifier discovery surfaces plus transparency metadata while
keeping local policy import and runtime admission explicit and fail closed.

## Why This Phase Exists

ARC needs public discovery for the endgame, but discovery must remain separate
from trust activation or runtime policy import.

## Scope

- public issuer and verifier discovery metadata
- transparency, freshness, and provenance reporting
- local policy import guardrails and review requirements
- fail-closed behavior for unsigned, stale, or incomplete discovery data

## Out of Scope

- additional verifier families or provider adapters
- automatic policy activation from discovery visibility
- live capital or marketplace execution semantics
