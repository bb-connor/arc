---
id: "COOP-1.12"
title: "Optional desktop review moments (notifier, bar and menu-bar snippets)"
severity: "P3"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.4b"]
paths: ["crates/products/chio-cli/src/issuance_watch.rs", "integrations/omarchy/desktop/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Roadmap COOP-1 ("the desktop review moments (Waybar or QML, menu bar, notifier) are optional follow-ons, not gates"). The dashboard issuance panel is REL-4.3. Announce each request once and never show prompt content.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --lib issuance_watch` passes (`announces_each_request_once_and_omits_prompt_content`).

## Log
- 2026-10-09T04:51:58Z connor: created
