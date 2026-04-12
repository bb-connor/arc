# ARC-Wall Operations

**Date:** 2026-04-03  
**Milestone:** `v2.50`

---

## Purpose

The ARC-Wall lane records one bounded denied cross-domain tool-access path.
This runbook defines the fail-closed operating model and recovery posture
without widening into a generic barrier platform.

---

## Required Package Components

Every `control-path export` bundle must include:

- one control profile
- one policy snapshot
- one authorization context
- one guard outcome
- one denied-access record
- one buyer-review package
- one control package
- one ARC evidence export directory

The ARC-Wall surface is incomplete if any of those files are missing,
inconsistent, or unresolved.

---

## Operating Boundary

- control owner: `barrier-control-room`
- ARC-Wall support owner: `arc-wall-ops`

The control owner owns the selected buyer motion, domain boundary, and
escalation path. ARC-Wall support owns fail-closed recovery and re-export when
package integrity or ARC evidence continuity is lost.

---

## Fail-Closed Rules

The ARC-Wall lane must fail closed when:

- the policy snapshot and guard outcome disagree about the allowed tool set
- the authorization context and denied-access record disagree about the
  requested domain or tool
- the buyer-review package cannot be matched back to the same control package
- the ARC evidence export is missing or cannot be reconciled to the denied
  control-path record

Recovery posture:

1. stop using the ARC-Wall bundle immediately
2. regenerate the export from the canonical control-path command
3. require the control owner to re-review the denied-access artifact before the
   bundle is treated as current

---

## Deferred Operations

This runbook does not authorize:

- multiple buyer motions
- multiple domain-boundary policies in one package family
- generic barrier-platform operations
- MERCURY workflow evidence operations
- multi-product platform hardening
