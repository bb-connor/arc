# ARC-Wall

**Companion Product Brief**  
**Date:** 2026-04-02

---

## 1. Product Definition

ARC-Wall is a companion product built on the same ARC substrate as MERCURY. It
focuses on evidence and enforcement at the tool-access boundary for
information-domain separation workflows.

ARC-Wall is aimed at environments where firms need stronger evidence that an
agent, workflow, or service stayed within the allowed information domain and
that blocked cross-domain attempts were recorded credibly.

---

## 2. Problem

AI agents complicate traditional information-barrier controls because:

- context and tooling can span systems quickly
- workflow automation is harder to monitor than human communication alone
- existing barrier tooling is not built around agent-to-tool invocation traces

ARC-Wall addresses the tool-boundary evidence problem. It does not claim to
solve every model-memory or prompt-injection risk by itself.

---

## 3. What ARC-Wall Does

ARC-Wall uses ARC capability and guard mechanics to:

- scope access by information domain
- deny cross-domain tool access where policy requires it
- record signed allow or deny evidence
- publish those records into the same checkpoint and verification framework

Core evidence objects:

- domain-scoped authorization context
- guard outcome
- denied-access record
- retained policy and configuration references

---

## 4. Proof Boundary

ARC-Wall can support:

- proof that the configured tool-boundary rule was evaluated
- proof that an action was allowed or denied under a specific policy reference
- durable records for barrier review and investigation

ARC-Wall does not prove:

- absence of model memorization
- absence of prompt-injection risk
- completeness of broader barrier operations
- overall MNPI compliance by itself

---

## 5. Target Buyers

- control-room or barrier-management teams
- compliance leadership
- security teams responsible for agent access patterns

The buyer motion is different from MERCURY's trading-workflow motion, which is
why ARC-Wall is treated as a companion program rather than part of the initial
product release.

---

## 6. Relationship to MERCURY

Shared foundations:

- signing
- checkpoints
- verification
- trust-distribution and publication logic

Different application focus:

- MERCURY records workflow decision provenance in trading contexts
- ARC-Wall records tool-boundary control evidence for information-domain
  separation

This makes ARC-Wall a natural expansion path once the core evidence platform is
stable.

---

## 7. Canonical Companion-Product Surface

The bounded `v2.50` ARC-Wall lane now ships as its own app on ARC:

- docs: [`../arc-wall/README.md`](../arc-wall/README.md)
- export: `cargo run -p arc-wall -- control-path export --output target/arc-wall-control-path-export`
- validate: `cargo run -p arc-wall -- control-path validate --output target/arc-wall-control-path-validation`
- next hardening step: [`PRODUCT_SURFACE_BOUNDARIES.md`](PRODUCT_SURFACE_BOUNDARIES.md)
  and [`CROSS_PRODUCT_GOVERNANCE.md`](CROSS_PRODUCT_GOVERNANCE.md)

That keeps ARC generic, MERCURY opinionated for trading workflows, and ARC-Wall
explicitly separate as a companion product on the same substrate.
