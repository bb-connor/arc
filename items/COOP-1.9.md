---
id: "COOP-1.9"
title: "Service packaging: systemd units, user units and LaunchAgents"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.8a", "COOP-1.8b"]
paths: ["deploy/reference-runtime/systemd/chio-api-protect.service", "deploy/reference-runtime/systemd-user/**", "deploy/reference-runtime/launchd/**", "crates/products/chio-cli/tests/reference_runtime_units.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Roadmap COOP-1 ("service packaging: systemd units, a LaunchAgent, and a container image"; the image is REL-1.4). #1160 already has `deploy/reference-runtime/systemd/chio-trust-control.service` (system unit, `LoadCredential`, `chio security supervise`), `chio-mcp-edge.service`, sysusers.d, tmpfiles.d, and `tests/reference_runtime_units.rs` checking unit argv against the CLI; there is no api protect unit, no user unit, no LaunchAgent. Seeds via `LoadCredentialEncrypted=` with `credential:` refs, or `keychain:` refs on macOS. TLS flags are required for non-loopback listeners.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test reference_runtime_units` passes and covers every new unit and plist.

## Log
- 2026-10-09T04:51:58Z connor: created
