# Enforced native and protocol boundary implementation plan

> Execute inline in the existing isolated worktree. User approved this complete batch.

**Goal:** Native MCP launches require enforced cage authority; original protocol input and policy time observations fail closed with preserved causes.

**Architecture:** Use `CageRequiredLaunch` directly. Transport test doubles live at test-owned boundaries. Parse bounded original bytes before converting to protocol values. Shared fallible clocks supply time at evaluation boundaries, before boolean condition composition.

**Base:** `150f7bea8e`, `/tmp/arc-security-launch`, `packet/3-retention-accounting`.

## Tasks

1. Remove legacy native launch authorization and enum. Migrate CLI, doctor, remote, hosted and test consumers to enforced launch or explicit mocks. Remove A2A edge compatibility passthrough.
2. Harden MCP remote and A2A edge ingress with original-byte bounds, duplicate rejection, typed local sources and redacted external errors. Record hosted facade delegation.
3. Replace policy ambient UTC reads with an explicit shared fallible clock. Reject clock faults before condition inversion and audited receipt emission. Add boundary regressions.
4. Extract the two over-cap test owners without increasing file caps or changing scenarios.
5. Reconcile source inventories and docs; run focused owning/consumer verification; perform one independent review and repair pass; create local conventional commits and propose the next owner batch.

## Verification

Use focused regression failures where they distinguish a security property, followed by owning suites and affected consumers. Preserve terminal outputs. No full-workspace build, lint or test campaign in this batch. Check changed Rust formatting, applicable source gates and strict owning-package lints. Do not claim hosted, release or M5 completion.
