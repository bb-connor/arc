---
phase: 309-deployable-experience
created: 2026-04-13
---

# Phase 309 Validation

## Required Evidence

- `docker compose up` from `examples/docker` starts the trust-service viewer
  and hosted edge successfully.
- A governed tool call made against the hosted edge produces a receipt that is
  visible through the trust-service query API.
- The browser-served viewer shows the receipt table and the selected receipt's
  detail panel with timestamp, decision badge, and delegation-chain content.

## Verification Commands

- `./scripts/check-dashboard-release.sh`
- `./scripts/check-docker-deployable-experience.sh`
- Playwright browser pass against `http://127.0.0.1:8940/?token=demo-token`

## Regression Focus

- Docker build inputs for the ARC CLI binary and dashboard assets
- runtime wiring between `arc trust serve` and `arc mcp serve-http --control-url`
- host-side smoke client receipt lookup and viewer URL guidance
- viewer rendering over the Dockerized trust-service deployment rather than the
  local developer build path
