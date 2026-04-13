---
phase: 309-deployable-experience
created: 2026-04-13
status: complete
---

# Phase 309 Research

## Findings

- `arc trust serve` already serves the receipt dashboard from `dashboard/dist`
  when that directory exists relative to the runtime working directory.
- The dashboard detail panel already renders timestamps, outcome badges, and a
  lazy `DelegationChain` view for the selected receipt, so the viewer itself
  did not need a new feature slice.
- The existing Docker example already had the right wrapped tool payload through
  `examples/docker/mock_mcp_server.py` and `examples/docker/policy.yaml`; the
  missing piece was the trust-service and viewer packaging around it.
- The environment has both `docker compose` and `npx`, so the phase can be
  verified with a real compose launch and a Playwright-driven browser check.

## Consequences

- The Dockerfile should build the dashboard during image construction rather
  than depending on checked-in `dist/` artifacts.
- The compose example should default to local builds from the cloned repo so it
  truly satisfies the "from git clone" milestone contract.
- The smoke client should fetch the issued capability and resulting receipt so
  the viewer/browser verification can target the exact governed call that was
  just made.
