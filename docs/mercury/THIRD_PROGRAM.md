# MERCURY Third Program

**Date:** 2026-04-04  
**Milestone:** `v2.63`  
**Audience:** product, multi-program review, repeatability governance, and operators

---

## Purpose

This document freezes the bounded Mercury third-program lane selected for
`v2.63`.

The lane is intentionally narrow:

- one program motion only: `third_program`
- one review surface only: `multi_program_reuse_bundle`
- one Mercury-owned third-program path only
- one Mercury-owned approval-refresh and multi-program-guardrails path only

The lane reuses already validated Mercury artifacts:

- one second-portfolio-program package
- one second-portfolio-program boundary freeze artifact
- one second-portfolio-program manifest
- one portfolio-reuse summary
- one portfolio-reuse approval artifact
- one revenue-boundary-guardrails artifact
- one second-program handoff artifact
- one portfolio-program package
- one proof package
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic portfolio-management suite, revenue
operations system, forecasting stack, billing platform, channel program,
merged shell, Chio commercial console, or broader Mercury multi-program claim.

## Frozen Program Motion

The program motion is fixed for this lane:

- `third_program`

If Mercury needs generalized multi-program tooling later, that is a new
milestone, not an implicit widening of `v2.63`.

## Selected Review Surface

The selected review surface is:

- `multi_program_reuse_bundle`

That surface packages the existing Mercury truth chain for one repeated
adjacent-program reuse decision only. The workflow sentence remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

## Owners

- program owner: `mercury-third-program`
- review owner: `mercury-multi-program-review`
- guardrails owner: `mercury-multi-program-guardrails`

Third-program ownership stays inside Mercury. Chio remains the generic
substrate that Mercury consumes.

## Supported Scope

Supported in `v2.63`:

- one third-program profile contract
- one third-program package contract
- one third-program boundary-freeze artifact
- one third-program manifest
- one multi-program-reuse summary
- one approval-refresh artifact
- one multi-program-guardrails artifact
- one third-program handoff over the validated second-portfolio-program chain

Not supported in `v2.63`:

- multiple program motions or review surfaces
- generic portfolio-management tooling
- revenue operations systems, forecasting stacks, billing platforms, or channel programs
- Chio-side commercial control surfaces

## Canonical Commands

Export the bounded third-program package and repeated portfolio-reuse bundle:

```bash
cargo run -p chio-mercury -- third-program export --output target/mercury-third-program-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p chio-mercury -- third-program validate --output target/mercury-third-program-validation
```
