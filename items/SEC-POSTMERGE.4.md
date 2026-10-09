---
id: "SEC-POSTMERGE.4"
title: "Native mini-swe and cold-platform acceptance (MINISW-PDEATH, MINISW-NATIVE-DENY)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/products/chio-cli/src/cli/process_host/runner/child/**", "sdks/python/chio-mini-swe/tests/**", "docs/security/audits/native-acceptance-*.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.1 (`MINISW-NATIVE-DENY` coordination item; obligation `native-mini-swe-and-cold-platform-acceptance`). Defined in `docs/security/audits/native-attachment-diagnostic-20261008.json:50` (P1, "Identify and repair the native dispatch capture or lifecycle-handoff denial reached on the third sandbox execution", cause unidentified) and its sibling `MINISW-PDEATH` (P1, root cause known: a Tokio worker thread that set `PR_SET_PDEATHSIG` retires and kills the child). Fix PDEATH by keeping the spawning thread alive for the supervised child; root-cause NATIVE-DENY with an original-first repair that keeps custody, trusted time and the 10-second fence; then run the enforcing native trajectory and cold-start timing on the designated native profile (Linux x86_64, kernel 6.7 or newer, cage prerequisites; `docs/security/launch-execution-plan.md:30-32`). Needs an authorized native host (serialization point).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- New lifetime test `runner_death::pdeathsig_thread_outlives_child` passes (`cargo test -p chio-cli --features real-linux-enforcement pdeathsig`).
- An enforcing native mini-swe run with zero unexpected denials and cold-start measurements recorded in the audit JSON.

## Log
- 2026-10-09T04:51:58Z connor: created
