# Background and Motivation
High-severity cron review for recent commits on `cursor/critical-correctness-bugs-8ece`.

# Key Challenges and Analysis
Reviewer mode selected because the request is to inspect recent commits and only fix confirmed critical correctness bugs.
2026-05-26 18:02 UTC - Recent first-parent merges reviewed include #684 research papers, #682/#678 v1 receipt/capability collapse, #676 archive package extraction, #679 Python redaction helper, and #685 treaty/rename work.
2026-05-26 18:02 UTC - Confirmed critical bug: `restore-drill` and `external-review` accepted standalone archive package report JSON as verified evidence. A forged report could set trusted-packager/exporter and extractability booleans without a signed tarball or manifest verification.
2026-05-26 18:02 UTC - Additional blocking compile regressions were found while validating: `chio-runtime-harness` had a stale `ChioReceiptBody` initializer and `chio-cli` command enums were missing fields/variants used by dispatch and parser tests.

# High-Level Task Breakdown
- [ ] Task #1 - Define recent commit range and changed subsystems
  **Success:** Identify the reviewed SHAs and high-risk files.
- [ ] Task #2 - Trace high-risk behavioral changes through callers
  **Success:** Any surfaced issue has a concrete trigger scenario with severe impact.
- [ ] Task #3 - Fix confirmed critical bug, if found
  **Success:** Minimal patch and targeted regression test pass.
- [ ] Task #4 - Report outcome
  **Success:** Slack summary states bug status, fix status, and validation.

# Project Status Board
- **In Progress:** Task #4
- **Blocked On:** None
- **Done:** Task #1 - 2026-05-26; Task #2 - 2026-05-26; Task #3 - 2026-05-26

# Current Status / Progress Tracking
2026-05-26 18:02 UTC - Started high-severity review. Branch matches `origin/main`, so scope is recent first-parent merges on main.
2026-05-26 18:02 UTC - Regression test first failed because JSON-only package reports were accepted. Fix now keeps only signed archive tarballs for restore/external aggregation and allows sidecar JSON only when it matches a freshly verified tarball report.
2026-05-26 18:02 UTC - Focused verification passed: `cargo fmt --all -- --check`, `cargo test -p chio-cli archive_restore_input_tests`, `cargo test -p chio-cli receipt_flush`, `cargo test -p chio-cli receipt_checkpoint`, and `cargo test -p chio-runtime-harness treaty::tests`.
2026-05-26 18:02 UTC - Known broader validation gaps not fixed in this narrow PR: `cargo test -p chio-cli receipt_` reaches an unrelated `evidence_export` mixed-signer checkpoint failure; `cargo test -p chio-runtime-harness` still has generated fixture JSON missing v1 receipt semantic fields outside the touched treaty tests.

# Executor's Feedback or Assistance Requests
None.

# Lessons
2026-05-26 - Assurance aggregation must not trust unsigned report JSON for fields that claim packager/exporter verification; recompute from signed packages or fail closed.
