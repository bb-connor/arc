# ARC-Wall Control Path

**Date:** 2026-04-03  
**Audience:** product, engineering, compliance, and barrier-control teams

---

## Purpose

This document freezes the bounded ARC-Wall lane selected for `v2.50`.

The lane is intentionally narrow:

- one buyer motion only: `control_room_barrier_review`
- one control surface only: `tool_access_domain_boundary`
- one source domain only: `research`
- one protected domain only: `execution`
- one fail-closed owner boundary only: `barrier-control-room` plus
  `arc-wall-ops`
- one bounded ARC-Wall package family over ARC evidence export truth

It does not approve a generic barrier platform, multiple buyer motions,
multiple domain-separation programs, folding ARC-Wall into MERCURY, or
multi-product hardening.

---

## Selected Buyer Motion

The selected ARC-Wall path is:

- buyer motion: `control_room_barrier_review`
- control surface: `tool_access_domain_boundary`
- source domain: `research`
- protected domain: `execution`
- policy reference: `arc.wall.research_execution_barrier.v1`

The first shipped scenario is one denied cross-domain request:

- actor: `research-agent-alpha`
- requested tool: `execution_oms.submit_order`
- evaluation mode: ARC tool-guard allowlist, fail-closed

This is deliberate. ARC-Wall is not claiming complete information-barrier
coverage. It is claiming one bounded control-path evidence surface on top of
ARC.

---

## Operational Owners

- control owner: `barrier-control-room`
- support owner: `arc-wall-ops`

The control owner owns the buyer-facing barrier review motion and the policy
boundary for the selected source and protected domains. The support owner owns
re-export, fail-closed recovery, and artifact integrity when profile,
authorization-context, guard-outcome, denied-access, buyer-review, or ARC
evidence files are missing or inconsistent.

---

## Scope Boundary

Supported in `v2.50`:

- one control profile contract
- one policy snapshot contract
- one domain-scoped authorization-context contract
- one guard-outcome contract and one denied-access record
- one buyer-review package over the same ARC evidence export
- one repo-native `arc-wall control-path export` / `validate` path

Not supported in `v2.50`:

- additional buyer motions
- multiple source or protected-domain combinations
- generic barrier-platform breadth
- MERCURY workflow evidence expansion
- multi-product platform hardening

---

## Canonical Commands

Export the bounded control-path package:

```bash
cargo run -p arc-wall -- control-path export --output target/arc-wall-control-path-export
```

Generate the validation package and explicit next-step decision:

```bash
cargo run -p arc-wall -- control-path validate --output target/arc-wall-control-path-validation
```

ARC stays generic, MERCURY stays opinionated for trading workflows, and
ARC-Wall stays a separate companion product on the same ARC substrate.
