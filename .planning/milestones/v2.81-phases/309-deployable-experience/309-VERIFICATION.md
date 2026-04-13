---
phase: 309
status: passed
completed: 2026-04-13
---

# Phase 309 Verification

## Outcome

Phase `309` passed. ARC now has a Docker-based local deployable path that
starts the trust-service receipt viewer and hosted edge from `examples/docker`,
produces a governed receipt through the wrapped demo tool, and renders that
receipt in the browser with the correct decision badge, timestamp, and
delegation chain.

## Automated Verification

- `./scripts/check-dashboard-release.sh`
- `/usr/bin/time -p ./scripts/check-docker-deployable-experience.sh`
- Timed result: `real 170.04`

## Live Flow Verification

- `python3 examples/docker/smoke_client.py`
- Result:
  - `receiptId`: `rcpt-019d88d7-8acd-7ff3-80d3-2734e9746ab7`
  - `capabilityId`: `cap-019d88d7-8986-7711-b945-8e843b004f69`
  - `viewerUrl`: `http://127.0.0.1:8940/?token=demo-token`
- Playwright browser pass against `http://127.0.0.1:8940/?token=demo-token`
- Screenshot artifact:
  [page-2026-04-13T21-57-21-685Z.png](/Users/connor/Medica/backbay/standalone/arc/output/playwright/phase309/.playwright-cli/page-2026-04-13T21-57-21-685Z.png)

## Requirement Closure

- `DEPLOY-01`: `examples/docker/compose.yaml` now starts a trust-service viewer
  and hosted edge together from the cloned repo with one `docker compose up`.
- `DEPLOY-02`: the dashboard renders live receipt rows plus the selected
  receipt's `Allow` decision badge, timestamp, capability id, and delegation
  chain.
- `DEPLOY-03`: the smoke client triggers a governed tool call, resolves the
  resulting receipt from the trust service, and the receipt appears in the
  viewer path within the verified quickstart window.

## Next Step

Proceed to phase `310` to add the progressive tutorial and framework examples
on top of the now-stable SDK plus Docker onboarding path.
