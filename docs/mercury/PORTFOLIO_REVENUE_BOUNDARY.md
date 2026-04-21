# MERCURY Portfolio Revenue Boundary

**Date:** 2026-04-04  
**Milestone:** `v2.65`  
**Audience:** product, commercial review, channel-boundary governance, and operators

---

## Purpose

This document freezes the bounded Mercury portfolio-revenue-boundary lane
selected for `v2.65`.

The lane is intentionally narrow:

- one program motion only: `portfolio_revenue_boundary`
- one review surface only: `commercial_review_bundle`
- one Mercury-owned commercial-review path only
- one Mercury-owned channel-boundary and commercial-handoff path only

It reuses the validated program-family chain and does not authorize generic
revenue platforms, billing systems, channel-program automation, merged
shells, or Chio commercial consoles.

## Frozen Program Motion

- `portfolio_revenue_boundary`

## Selected Review Surface

- `commercial_review_bundle`

## Owners

- revenue-boundary owner: `mercury-portfolio-revenue-boundary`
- commercial-review owner: `mercury-commercial-review`
- channel-boundary owner: `mercury-channel-boundary`

## Supported Scope

Supported in `v2.65`:

- one portfolio-revenue-boundary profile contract
- one portfolio-revenue-boundary package contract
- one revenue-boundary-freeze artifact
- one revenue-boundary manifest
- one commercial-review summary
- one commercial-approval artifact
- one channel-boundary-rules artifact
- one commercial handoff

Not supported in `v2.65`:

- generic revenue-platform, billing, or forecasting tooling
- channel-program automation or marketplaces
- Chio-side commercial control surfaces

## Canonical Commands

```bash
cargo run -p chio-mercury -- portfolio-revenue-boundary export --output target/mercury-portfolio-revenue-boundary-export
```

```bash
cargo run -p chio-mercury -- portfolio-revenue-boundary validate --output target/mercury-portfolio-revenue-boundary-validation
```
