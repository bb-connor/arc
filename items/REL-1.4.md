---
id: "REL-1.4"
title: "Release container image with the trust-control dashboard embedded"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-REL.1"]
paths: ["deploy/docker/Dockerfile.sidecar", ".github/workflows/sidecar-image.yml", "scripts/tests/check-sidecar-image-workflow.test.sh"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1 ("a container image with the dashboard embedded. Today the dashboard is in no release artifact"). The dashboard source is `crates/products/chio-cli/dashboard` (React/Vite, checked by `scripts/check-dashboard-release.sh`); trust-control serves it only from the relative `dashboard/dist` (`crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs:250`). The published image `ghcr.io/<owner>/chio-sidecar` (`deploy/docker/Dockerfile.sidecar`) has no dashboard; only the demo stages in `deploy/docker/Dockerfile` copy it, and `chio-trust-demo` defaults to `--service-token demo-control-token`, so it must not become the release image. Add a pinned node `dashboard-builder` stage, copy `dist` to `/opt/chio/dashboard/dist` with `WORKDIR /opt/chio`, and require explicit tokens for `trust serve` (fail closed). A configurable dashboard path is REL-4's concern.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/check-dashboard-release.sh`; `bash scripts/tests/check-sidecar-image-workflow.test.sh` with a new dashboard-stage case.
- Container smoke: `trust serve` with tokens returns `index.html` at `/`; without tokens it refuses to start.

## Log
- 2026-10-09T04:51:58Z connor: created
