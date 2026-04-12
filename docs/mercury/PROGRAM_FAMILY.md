# MERCURY Program Family

**Date:** 2026-04-04  
**Milestone:** `v2.64`  
**Audience:** product, shared review, portfolio claim discipline, and operators

---

## Purpose

This document freezes the bounded Mercury program-family lane selected for
`v2.64`.

The lane is intentionally narrow:

- one program motion only: `program_family`
- one review surface only: `shared_review_package`
- one Mercury-owned shared-review path only
- one Mercury-owned portfolio-claim-discipline and family-handoff path only

It reuses the validated third-program chain and does not authorize generic
portfolio management, revenue-platform tooling, channel programs, merged
shells, or ARC commercial consoles.

## Frozen Program Motion

- `program_family`

## Selected Review Surface

- `shared_review_package`

## Owners

- family owner: `mercury-program-family`
- review owner: `mercury-shared-review`
- claim-discipline owner: `mercury-portfolio-claim-discipline`

## Supported Scope

Supported in `v2.64`:

- one program-family profile contract
- one program-family package contract
- one program-family boundary-freeze artifact
- one program-family manifest
- one shared-review summary
- one shared-review approval artifact
- one portfolio-claim-discipline artifact
- one family handoff

Not supported in `v2.64`:

- universal multi-program portfolio claims
- generic portfolio-management tooling
- revenue-platform or channel-program breadth
- ARC-side commercial control surfaces

## Canonical Commands

```bash
cargo run -p arc-mercury -- program-family export --output target/mercury-program-family-export
```

```bash
cargo run -p arc-mercury -- program-family validate --output target/mercury-program-family-validation
```
