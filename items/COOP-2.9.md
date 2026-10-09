---
id: "COOP-2.9"
title: "TLS reverse-proxy recipe and rotation runbook"
severity: "P1"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.9", "COOP-2.7"]
paths: ["docs/runbooks/cooperate/TLS-REVERSE-PROXY.md", "docs/runbooks/cooperate/ROTATION-RUNBOOK.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Native rustls (`chio-http-serve/src/transport.rs:83`, `.with_no_client_auth()`; non-loopback plaintext refused unless explicitly allowed) versus a reverse proxy; rotation of the authority key, door signer, TLS certificate and partner card.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Every command in both runbooks is checked against `--help` output (script in the PR); no em dashes.

## Log
- 2026-10-09T04:51:58Z connor: created
