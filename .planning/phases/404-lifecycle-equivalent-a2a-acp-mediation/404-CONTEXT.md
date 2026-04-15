---
phase: 404
milestone: v3.15
title: Lifecycle-Equivalent A2A/ACP Mediation
status: complete locally 2026-04-14
created: 2026-04-14
---

# Context

The strongest remaining runtime blocker after protocol-aware binding is
lifecycle symmetry. The authoritative A2A edge still exposes only blocking
`message/send`, and the authoritative ACP edge still exposes blocking
`tool/invoke` while rejecting `tool/stream`, `tool/cancel`, and `tool/resume`.

This phase owns the decision and execution work required to make that surface
honest at the claim-gate level:

- either implement receipt-bearing lifecycle-equivalent mediation where ARC
  wants to claim it
- or narrow the official claim gate again so the repo stops implying stronger
  lifecycle symmetry than the runtime actually ships

# Requirements

- `LIFE2-01`
- `LIFE2-02`
- `LIFE2-03`
