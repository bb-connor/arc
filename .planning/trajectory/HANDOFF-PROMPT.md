# Handoff: Sweep all P0/P1/P2 issues across trajectory-2 milestones (M01 → M10)

You are taking over a long-running trajectory-2 push on the Chio repo at `/Users/connor/Medica/backbay/standalone/arc`. All 10 milestones (M01-M10) have shipped their P0-P5 phase tickets across ~59 PRs in the previous session. **Phase work is COMPLETE.** Your job is the next layer: sweep every P0, P1, and P2 severity issue across all 10 milestones until each milestone is clean.

## Working mode

- You are a SINGLE agent. NO subagent dispatch. NO orchestrator/dispatcher pattern. Do the work yourself.
- Do not halt for operator-discretion checkpoints, "session-budget" reviews, or "is this getting too long" pauses. Only halt for the eleven canonical halt triggers (Lean fail, threat-model gap, mutation regress, verdict-matrix divergence, WASM escape panic, hardware-custody key compromise, anchor-chain break, fail-open detected on a trust boundary, supply-chain compromise, scoped revocation bypass, capability lineage break).
- Use TodoWrite to track milestone-by-milestone progress. One top-level todo per milestone, sub-todos per fix item if useful.
- CI is broken (account billing). `gh pr merge --admin` is authorized. Skip CI gates; verify locally with `cargo build`, `cargo clippy -- -D warnings`, and per-ticket `gate_check.cmd` where it exists.
- Worktree-per-PR. Conventional commits. House rules: no em-dashes (U+2014), `clippy::unwrap_used`/`expect_used` denied, fail-closed.

## Definition of "P0/P1/P2 issue"

Any of the following that is not resolved:

1. **Open bot review threads on merged PRs** (PRs #342 onwards from this session). Use `gh api repos/bb-connor/arc/pulls/<N>/reviews` and `gh api repos/bb-connor/arc/pulls/<N>/comments` (and `/threads` if available). Filter for severity tags `P0`/`Critical`, `P1`/`High`, `P2`/`Medium`. Skip `P3`/`Low`/`Nit`/style. Codex bot uses these tags explicitly; treat anything tagged "Bug", "Security", or "Correctness" as at least P2.
2. **Items in `.planning/trajectory-2/deferred/*.md`** — every file in that directory is a worker-flagged punt. Resolve or explicitly carry-forward with rationale.
3. **Audit doc residual risks** in `.planning/audits/M01-*.md` through `M10-*.md` flagged as load-bearing (read each audit's "Residual risk" / "Outstanding gaps" / "Deferred" section).
4. **Pre-existing baseline regressions** documented in audit docs or commit messages.

Skip nits, docs-only style preferences, and `P3`/Low.

## Walkthrough order

Process strictly **M01 → M10**, one milestone at a time. For each:

### Step 1: Compile the milestone fix list

```bash
# All merged PRs in this milestone's branches
gh pr list --search "is:merged base:main head:wave/W*/m<NN>/" --limit 50 --json number,title,mergedAt

# Per PR, pull review threads
for pr in <list>; do
  gh api repos/bb-connor/arc/pulls/$pr/reviews --paginate
  gh api repos/bb-connor/arc/pulls/$pr/comments --paginate
done
```

- Tag each finding with severity (P0/P1/P2/skip).
- Cross-reference `.planning/trajectory-2/deferred/m<NN>-*.md`.
- Cross-reference `.planning/audits/M<NN>-*.md` residual risk.
- Write the fix list to `.planning/trajectory/sweep/M<NN>-FIX-LIST.md` (create the dir if needed). One row per finding: source link, severity, scope, file path, intended fix, gate command.

### Step 2: Fix

```bash
git worktree add .worktrees/sweep/m<NN> sweep/m<NN>
cd .worktrees/sweep/m<NN>
```

- One commit per logical fix using conventional commits (`fix(crate): ...`, `test(crate): ...`, `docs(audit): ...`).
- After each fix, run that finding's gate command (or the touched crate's `cargo test -p <crate> && cargo clippy -p <crate> -- -D warnings`).
- Reply to each addressed thread on GitHub via `gh api repos/bb-connor/arc/pulls/<PR>/comments/<id>/replies -f body="Fixed in <commit-sha>: <one-line summary>"`. Mark as resolved if the API supports it.

### Step 3: Open ONE PR for the milestone

Title: `fix(M<NN>): sweep P0/P1/P2 review and audit findings`. Body: a table mapping each finding to its commit SHA. Trust-boundary milestones (M03/M04/M05/M10) need security review noted in the description.

### Step 4: Verify and merge

```bash
cargo build --workspace 2>&1 | tail -5
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
gh pr create ...
gh pr merge <N> --admin --merge --delete-branch
git checkout main
git pull --rebase origin main
git worktree remove --force .worktrees/sweep/m<NN>
git branch -D sweep/m<NN>
```

If `gh pr merge --admin` fails with merge conflicts: re-fetch the branch, `git merge origin/main`, resolve, push, retry. For Cargo.lock conflicts use `git checkout --theirs Cargo.lock && cargo build --workspace --offline`.

### Step 5: Move to the next milestone. No interim status report. Just execute.

## Stop condition

You stop ONLY when:

1. Every merged trajectory-2 PR (search `head:wave/W*/m*`, `head:audit/W*/m*`, `head:deslop/*`, plus the early bundle PRs from #342-#384) has **zero** unresolved P0/P1/P2 review threads.
2. Every file in `.planning/trajectory-2/deferred/` is either deleted (resolved) or has an explicit "carried forward to <doc>" line with rationale.
3. Every audit doc's P0/P1/P2 residual-risk entry has either a fix commit SHA or a tracking note.
4. All ten milestones M01-M10 can be declared shipped.

When all four conditions hold, write a final report to `.planning/trajectory/SWEEP-FINAL.md` with: per-milestone tally (PR URL, fixes count, severity breakdown), residual deferred items with rationale, and a one-line ship verdict. Then stop.

## Hard "do NOT" list

- Do NOT touch `.planning/trajectory-2/EXECUTION-STATE.json` or `.planning/trajectory-2/tickets/manifest.yml` — those belong to the LEDGER-R chore (separate work).
- Do NOT skip hooks except where authorized (`--no-verify` for merge commits resolving conflicts and `gh pr merge --admin`).
- Do NOT spawn subagents. You are one agent.
- Do NOT halt to "check in" with the user. Execute through.
- Do NOT delete or rewrite previously-merged commits.
- Do NOT widen scope beyond P0/P1/P2 findings — leave nits, P3/Low, and stylistic preferences alone.

## Known starting points (verify, don't take on faith)

- Pre-existing `chio-core-types --no-default-features` baseline build break — see `.planning/trajectory-2/deferred/m04-p2-deferred.md`. Likely a missing feature gate on `Box`/alloc imports.
- Mutation aggregate kill-score is 30.7% vs >=80% target — gate is still advisory. Either bring scores up or document the carry-forward; the lane flip lives in `releases.toml: cycle_end_tag` which currently is empty.
- Pre-existing flaky tests:
  - `chio-cli::trust_control_cluster_snapshot_replays_holds_and_mutation_events`
  - `chio-kernel::delegated_tool_call_records_observed_capability_lineage`
  - `chio-a2a-adapter` mTLS localhost
  Both pass in isolation; investigate root cause and stabilize or quarantine.
- `crates/chio-kernel-core/tests/mutation_boundaries.rs:148,158` — `clippy::assertions_on_constants` errors.
- `crates/chio-attest-verify/tests/integration.rs:98` — `assert!(false, ...)` trips `clippy::assertions_on_constants` under `--tests -D warnings`.
- Bot review threads on PRs #404-414 (most recent merges) have NOT been swept yet. Start with these; they will likely dominate the M03/M04/M05/M10 sweeps.
- A pre-existing `Vite` import-resolution failure in `docs/demo/main.ts` (cannot resolve `@chio-protocol/browser/pkg/chio_kernel_browser.js`) — needs the wasm bundle built or import path fixed.
- `crates/chio-conformance/verdict_matrix` sub-workspace has a never-type-fallback warning and an unresolved `chio_kernel_browser` test import — out of main workspace, but blocks `cargo test --workspace` if cycled in.

## First action

```bash
cd /Users/connor/Medica/backbay/standalone/arc
git pull --rebase origin main
mkdir -p .planning/trajectory/sweep
gh pr list --state merged --limit 60 --search "head:wave/W" --json number,title,headRefName,mergedAt > /tmp/sweep-prs.json
# Filter to wave/W*/m01/* entries; build the M01 fix list per Step 1; then proceed through Steps 2-5.
```

Build the M01 fix list. Open `.worktrees/sweep/m01`. Start fixing. Don't write a status report. Execute.

Reach the four-part stop condition. Then and only then write `SWEEP-FINAL.md` and stop.
