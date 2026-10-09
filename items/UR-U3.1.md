---
id: "UR-U3.1"
title: "README hero, subhead SVGs and unscoped claims: positioning cleanup"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1177.1"]
paths: ["README.md", "docs/assets/subhead.svg", "docs/assets/subhead-mobile.svg", "docs/assets/kernel-boundary.svg", "docs/assets/kernel-boundary-mobile.svg", "docs/assets/hop.svg", "docs/assets/hop-mobile.svg"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U3, OUT-2, section 9 ("Stale surfaces on main to fix"); supersedes Task 8 of `docs/superpowers/plans/2026-10-08-north-star-restructure.md`. North-star sentence, verbatim: "Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries." Supporting line, verbatim: "Authority that only narrows. Work that survives. Evidence that travels." Retired phrases: "The kernel your agents answer to", "Agents that pay each other", "only protocol", "kernel for building agentic operating systems".

The roadmap cites README line numbers against main `002b4d14e`; after #1160 merges they shift (verified with a simulated merge): "The kernel your agents answer to" stays at line 16, the subhead `<img>` alt at 22, "pay each other" moves to about 77 and 165, unscoped "every call" to about 72, 137, 181, 186 and 273. Edit by string, not line number. The installer links the roadmap cites (lines 44 and 251) were already replaced by #1160 with links to `docs/install/README.md` and `docs/install/PROCESS_PREVIEW.md`; verify and leave them for UR-U10.

Changes: lead with the north star and the cross-org clause; remove "Agents that pay each other" from the hero, the subhead SVGs (both `<text>` and `alt`/`aria-label`) and body copy, and describe payments as optional rail modules (holds and caps are `prevent` for kernel-mediated calls; rail settlement is `detect_only`; no on-chain or escrow claims); scope every "every call" to kernel-mediated calls. Absorb #1177's README and SVG copy edits (diff them from the PR head) so #1177 does not need to touch these files.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-native-host-docs.py --rule retired-phrases` reports nothing for README.md and the listed SVGs.
- `grep -n "every call" README.md` shows only occurrences scoped to kernel-mediated calls (list them in the commit body).
- SVGs still render (open each in a browser or `rsvg-convert` them in the test log) and keep their dimensions.

## Log
- 2026-10-09T04:51:58Z connor: created
