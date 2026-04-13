---
phase: 309-deployable-experience
milestone: v2.81
created: 2026-04-13
status: complete
---

# Phase 309 Context

## Goal

Give a new developer a Docker-based local deployment path that starts ARC's
hosted edge, wrapped demo tool, and receipt viewer with one `docker compose up`
from the example directory.

## Current Reality

- `examples/docker` already had a minimal hosted-edge demo, but it only started
  one container and exposed no trust service or receipt viewer.
- The receipt dashboard already existed and `arc trust serve` could serve it,
  but the Docker packaging did not include the dashboard build output or a
  deployable trust-service container.
- The existing host-side smoke script proved tool invocation only; it did not
  confirm that the governed call became a visible receipt in the viewer path.

## Boundaries

- Keep phase `309` focused on the deployable quickstart path. The framework
  examples in `examples/anthropic-sdk` and `examples/langchain` remain phase
  `310` work.
- Reuse the existing dashboard SPA and trust-control server instead of
  inventing a second viewer implementation.
- Preserve unrelated dirty planning/docs/runtime work already present in the
  repository.

## Key Risks

- The trust-service viewer only works when `dashboard/dist` is present at the
  correct runtime path, so Docker packaging could easily produce an API-only
  container by accident.
- `arc mcp serve-http` depends on the trust service for receipts and capability
  issuance in this topology, so the compose startup order and runtime wiring
  must be explicit.
- A pure API smoke check would not be enough for the roadmap contract; the
  final verification needed a real browser pass over the Dockerized viewer.

## Decision

Package two demo images from the repo Dockerfile: one trust-service image that
 serves the dashboard viewer and owns the local SQLite stores, and one hosted
 edge image that wraps the demo MCP subprocess and points at the trust service
 through `--control-url`. Then wire the example directory around that topology
 with an end-to-end smoke script and browser verification.
