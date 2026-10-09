---
id: "KDEF-N4"
title: "Mechanism D escape-hatch gate: `cargo xtask check escape-hatches`"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-03.P1.4"]
paths: ["xtask/src/escape_hatches.rs", "xtask/src/escape_hatches/**", "xtask/src/cli.rs", "xtask/src/dispatch.rs", "formal/escape-hatches.toml", "scripts/ci-pr-tier.sh"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-6 (KDEF-N4: the Mechanism D gate). `xtask/src/cli.rs` `CheckCommand` has only `AdapterNoBypass`, `CratePaths`, `FormalMirrors` and `Fixtures`. Design: `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md:440-518`. Build the gate that rejects new escape hatches (discarded results in post-effect regions, `let _ =` on fallible kernel evidence, and so on) with an allowlist carrying expiry dates. A `.github/CODEOWNERS` entry for `formal/escape-hatches.toml` is an owner change: propose it in the PR description, do not apply it.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- One violating fixture per rule (including an `.inc` file and a closure-nested discard) fails; a stale allowlist entry fails; `cargo xtask check escape-hatches` is green on main.

## Log
- 2026-10-09T04:51:58Z connor: created
