# 0001: The swarm protocol supersedes single-owner plan rules

- Date: 2026-10-06
- Decided by: Connor (approved design `docs/superpowers/specs/2026-10-06-agent-swarm-design.md`)

## Context

The #1173 and #1174 plans say "use one implementation owner" and "the user
prohibits subagents". Those rules prevented uncoordinated parallel edits
before a coordination mechanism existed.

## Decision

For work dispatched through the swarm, the swarm protocol replaces those
instructions:

- one owner per item, enforced by `claims/<ID>.json`;
- path claims keep owners off each other's files, and hotspot items are
  serialized through `depends_on`;
- every change gets a cross-vendor review before the integrator merges it;
- the evidence bar is unchanged: test first, no weakened checks, hosted CI on
  the integration branch, Connor approves every merge to `main`.

Agents working outside the swarm (the security pair until #1160 lands) keep
following their existing plans.
