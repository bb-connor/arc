---
phase: 308-sdk-publication
milestone: v2.81
created: 2026-04-13
status: complete
---

# Phase 308 Context

## Goal

Turn the in-repo TypeScript and Python SDKs into stable public-facing packages
with installable release artifacts, receipt-query support, and official
examples that exercise the real ARC hosted-edge plus trust-service flow.

## Current Reality

- The TypeScript SDK already shipped as `@arc-protocol/sdk` at `1.0.0`, but
  its README still read like a production candidate and its default
  `clientInfo.version` lagged at `0.1.0`.
- The Python SDK still published itself as `arc-py` at `0.1.0`, documented a
  beta posture, and lacked a `ReceiptQueryClient`.
- The repo already had a credible hosted runtime lane through `arc trust serve`
  plus `arc mcp serve-http --control-url ...`, and the remote admin endpoint
  could expose the capability issued for a session.

## Boundaries

- Keep phase `308` scoped to SDK publication, docs, release checks, and
  package-local examples. Do not consume the separate framework-example work
  already queued for phase `310`.
- Preserve the user's unrelated dirty worktree, especially the existing local
  edits in `README.md`, planning pointers, and federation/formal files.
- Reuse the existing Docker/mock-server fixture path instead of introducing a
  new demo topology that phase `309` would have to replace immediately.

## Key Risks

- Renaming the Python distribution without updating release qualification,
  metadata checks, and docs together would leave a half-stable package.
- Adding examples that bypassed the real trust-service and hosted-edge flow
  would satisfy the letter of the milestone but not the actual onboarding goal.
- The package examples needed a truthful way to identify the active capability
  used by the governed call so receipt queries could be tied back to the same
  execution.

## Decision

Stabilize the Python package as `arc-sdk` `1.0.0`, add a Python
`ReceiptQueryClient` plus package-local governed examples for both SDKs, and
verify those examples against a locally launched `arc trust serve` +
`arc mcp serve-http` stack that exposes the session's issued capability through
`/admin/sessions/{session_id}/trust`.
