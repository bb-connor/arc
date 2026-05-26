# Background and Motivation
Hourly high-severity bug sweep for recent Chio commits. The goal is to identify only concrete correctness failures with severe impact: data loss, crashes, security bypasses, resource leaks, or major user-facing breakage.

# Key Challenges and Analysis
Active mode: Reviewer, with Executor handoff only if a critical bug is confirmed.

Success criteria:
- Recent commits are scoped against `main` history.
- Suspicious behavioral paths are traced beyond the diff.
- If a critical bug is confirmed, a minimal failing test is added before the fix.
- If confidence is insufficient, no PR is opened and Slack receives a short summary.

# High-Level Task Breakdown
- [x] Task #1 - Scope recent commits and changed subsystems
  **Success:** Identify candidate changes with meaningful blast radius.
- [x] Task #2 - Trace suspicious paths
  **Success:** Either produce a concrete trigger scenario for a critical bug or rule out candidates as non-critical.
- [x] Task #3 - Fix confirmed critical issue if present
  **Success:** A failing regression test is observed, minimal fix passes it, and the branch is committed and pushed.
- [ ] Task #4 - Report outcome
  **Success:** Slack summary states bug/impact/root cause/fix/validation if fixed, or "no critical bugs found" if not.

# Project Status Board
- **In Progress:** Task #4
- **Blocked On:** None
- **Done:** Task #1, Task #2, Task #3 - 2026-05-26

# Current Status / Progress Tracking
2026-05-26T17:03Z - Reviewer started. Branch `cursor/critical-correctness-bugs-df2b` currently points at `origin/main` with no local changes before creating this scratchpad.
2026-05-26T17:20Z - Confirmed adapter-base fixed-signature arity overflow leaked raw trailing positional values into receipt payloads for chio-default tools. Added a red regression by changing `test_typeerror_fallback_arity_mismatch_keeps_alias_map` to require overflow redaction, observed the expected failure, then fixed `bind_and_redact`.
2026-05-26T17:36Z - Confirmed hybrid-canonical receipt signing drifted from legacy sync signing because the helper skipped signing-nonce metadata. `cargo test -p chio-kernel --features pq --test canonical_bytes_hybrid shared_canonical_bytes_match_legacy_classical_path -- --exact` failed before the fix and passed after binding the nonce in replicated signing paths.
2026-05-26T17:45Z - Verification passing: adapter-base ruff + pytest, Rust focused tests, `cargo fmt --all -- --check`, `cargo clippy -p chio-kernel --lib --features 'pq legacy-sync' -- -D warnings`. Full `cargo clippy -p chio-kernel --all-targets --features 'pq legacy-sync' -- -D warnings` is blocked by an existing unrelated `clippy::too_many_arguments` in `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs`.

# Executor's Feedback or Assistance Requests
None.

# Lessons
2026-05-26 - When a helper reimplements receipt signing instead of delegating to `ChioReceipt::sign_with_backend`, it must share the nonce-binding preparation step or identical invocations can collide.
