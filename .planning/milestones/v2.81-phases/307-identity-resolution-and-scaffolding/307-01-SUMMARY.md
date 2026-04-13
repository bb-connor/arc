---
phase: 307
plan: 01
created: 2026-04-13
status: complete
---

# Summary 307-01

Phase 307 closed the remaining user-facing identity drift in the files covered
by the roadmap gate. `README.md` now speaks about ARC consistently, the old
standard/document links point at the `ARC_*` paths, and the review-remediation
package no longer mixes ARC with the legacy name.

The cleanup stayed intentionally narrow: only the files matched by
`rg -n -i '\\bchio\\b' README.md docs/ crates/*/src/*.rs` were edited, so the
existing unrelated dirty work in other docs and CLI modules was left intact.
