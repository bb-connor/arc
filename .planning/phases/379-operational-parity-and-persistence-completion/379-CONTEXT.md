---
phase: 379-operational-parity-and-persistence-completion
milestone: v3.12
created: 2026-04-14
status: completed
---

# Phase 379 Context

## Goal

Bring the last weaker runtime surfaces up to the production bar already reached
by the core HTTP substrate: durable sidecar receipt persistence,
request-body-bound tower evaluation, and kernel-backed Kubernetes admission
validation.

## Current Reality

- `arc-api-protect` advertised `receipt_db` but only kept receipts in an
  in-memory log.
- `arc-tower` still evaluates with `body_hash: None` and `body_length: 0`
  regardless of the actual request body.
- The Kubernetes admission controller only checked for annotation presence and
  non-empty required scope strings rather than validating a real capability
  token and scope match.
- The three gaps are independent enough to land in narrow slices without
  redesigning the milestone.

## Boundaries

- Keep the first slice focused on `arc-api-protect` receipt persistence.
- Preserve the current in-memory log as the live inspection surface, but back it
  with configured durable storage when `receipt_db` is set.
- Fail closed when configured receipt persistence is unavailable.
- Defer `arc-tower` body replay and Kubernetes capability parsing to later phase
  `379` slices.

## Decision

Phase `379` landed in two slices:

1. Wire `arc-api-protect`'s `receipt_db` setting to a real SQLite-backed
   `HttpReceipt` store, persist receipts from both proxy and `/arc/evaluate`,
   and reload persisted history on startup.
2. Bind raw request bodies into `arc-tower` evaluation on the supported
   replayable body path, and replace Kubernetes annotation-presence checks with
   signed token plus required-scope validation.
