# MERCURY Trust Network Operations

**Date:** 2026-04-03  
**Milestone:** `v2.49`

---

## Purpose

The trust-network lane shares one bounded counterparty-review proof bundle
across one sponsor boundary. This runbook defines how that bundle is witnessed,
resolved, and recovered without widening into a generic trust service.

---

## Required Bundle Components

Every `trust-network export` bundle must include:

- one trust-network profile
- one trust-network package
- one interoperability manifest
- one shared proof package
- one shared counterparty-review review package
- one shared inquiry package
- one shared inquiry verification report
- one reviewer package
- one qualification report
- one witness record
- one trust-anchor record

The trust-network surface is incomplete if any of those files are missing,
inconsistent, or unresolved.

---

## Operating Boundary

- sponsor owner: `counterparty-review-network-sponsor`
- Mercury support owner: `mercury-trust-network-ops`

The sponsor owner owns the bounded exchange lane and witness continuity.
Mercury support owns fail-closed recovery and re-export when artifact
integrity, checkpoint continuity, or trust-anchor references are lost.

---

## Fail-Closed Rules

The trust-network path must fail closed when:

- the trust-network profile and interoperability manifest disagree
- the shared proof package omits the witness or trust-anchor reference
- the embedded OEM package or partner manifest is missing
- the shared inquiry package or its verification report is missing
- the reviewer package or qualification report cannot be matched back to the
  same workflow

Recovery posture:

1. stop trust-network sharing immediately
2. regenerate the export from the canonical embedded-OEM lane
3. require a fresh witness record and trust-anchor record before the bundle is
   considered active again

---

## Deferred Operations

This runbook does not authorize:

- multiple sponsor-specific exchange lanes
- multi-network witness or trust-broker services
- generic ecosystem interoperability operations
- ARC-Wall companion-product operations
- multi-product platform hardening

Those remain separate milestones, not hidden responsibilities inside `v2.49`.
