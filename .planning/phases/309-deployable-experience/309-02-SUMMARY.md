---
phase: 309
plan: 02
created: 2026-04-13
status: complete
---

# Summary 309-02

The end-to-end viewer flow is now live from the Docker example. The upgraded
`examples/docker/smoke_client.py` initializes an MCP session against the hosted
edge, invokes `echo_text`, resolves the issued capability through the admin
session endpoint, queries the trust service for the resulting receipt, and
prints the exact viewer URL plus receipt id.

Phase 309 also added `scripts/check-docker-deployable-experience.sh` as the
automated lane for the deployable experience. It builds the compose stack,
waits for both services to become ready, runs the governed smoke flow, and
asserts that the receipt viewer is reachable.

During browser verification, the dashboard exposed two real packaging/viewer
issues: a stale favicon request and an outdated `decisionKind()` parser that
misread tagged allow receipts as `Incomplete`. Both are fixed. The live viewer
now loads cleanly and renders the selected receipt with the correct `Allow`
decision badge, timestamp, delegation chain, and full receipt payload.
