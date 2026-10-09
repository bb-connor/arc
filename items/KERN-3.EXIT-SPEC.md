---
id: "KERN-3.EXIT-SPEC"
title: "Spec: process exit as an authority transition"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1174.1"]
paths: ["docs/superpowers/specs/*-process-exit-authority-transition-design.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 ("a new spec for process exit as an authority transition. `ProcessState` has no exit state today"); KERN unowned primitive "process exit" (this item owns the design). Today `ProcessState { Running, Cancelled }` (`crates/kernel/chio-process/src/types.rs:126-129`, CHECK at `store.sql:15`, admission check `store.rs:403`); `JOURNAL_VERSION = 2`; #1173 and #1179 carry the same enum. Specify `Exited { outcome_digest }` set by an authenticated runner report under cancel serialization; admission refuses calls for an exited process; an explicit orphan policy (an owner decision inside the spec: present options and a recommendation); exit code 75 stays `Running`; exit is a closure trigger and a hint subject; the state goes into ABI v4 (CT-ABI must reserve it); `JOURNAL_VERSION` bumps through the ledger lock. Name it as a proposed KSPEC-12 with the `KSPEC-` prefix.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Spec reviewed by Lane KERNEL with a disposition table; the orphan-policy choice is listed for the owner; no em dashes.

## Log
- 2026-10-09T04:51:58Z connor: created
