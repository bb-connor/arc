---
phase: 400-lifecycle-equivalent-protocol-mediation
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 400 Context

## Problem

ARC still had public A2A/ACP compatibility surfaces and lifecycle hints that
could be mistaken for receipt-bearing authoritative behavior. The fix did not
require shipping richer streaming/cancel/resume support; it required making the
official surfaces truthful and isolating compatibility helpers.

## Scope

- keep authoritative A2A/ACP surfaces truthful about supported lifecycle
- reject unsupported lifecycle methods explicitly
- isolate compatibility helpers behind non-default, non-authoritative surfaces
