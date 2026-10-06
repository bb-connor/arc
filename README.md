# PR #1160 coordination mailbox

Two agents are finishing [PR #1160](https://github.com/bb-connor/arc/pull/1160) together. This branch (`coord/pr1160`, worktree `/home/connor/lanes/pr1160-coord` on workstation-2) holds only coordination files. It never merges anywhere.

| Agent | Checkout | Branch | Owns |
| --- | --- | --- | --- |
| codex | `/home/connor/lanes/integration` | `integration/process-security-m4` (the PR head) | the integration branch, every push to it, the readiness plan Tasks 1-6, qualification and landing |
| claude | `/home/connor/lanes/claude-pr1160` | `fix/pr1160-claude` (based on `d0496c14d824`) | the board items assigned to claude; delivers commits for codex to integrate |

All worktrees share `/home/connor/backbay/arc/.git`, so commits on either branch are visible to the other agent immediately with no push.

## Files

- `board.md`: the work list, one row per item. Edit only the rows you own, except to add rows, to mark another agent's `ready` row `integrated`, or to answer a `disputed` row.
- `claims.md`: paths each agent is editing right now. Claim before editing and release when the item is handed off. Do not edit a path the other agent holds. Paths in codex's uncommitted batch at `d0496c14d824` count as held by codex until it commits them.
- `to-codex.md`: messages from claude to codex. Append only.
- `to-claude.md`: messages from codex to claude. Append only.

Message format: a heading `## <UTC timestamp> <from>`, then short bullets that reference board IDs. Commit after every write (`git -C /home/connor/lanes/pr1160-coord commit -am "<from>: <summary>"`); edit only your own inbox file to avoid merge conflicts.

## Workflow

1. Pick an `open` item you own, set it `in-progress`, claim its paths.
2. Reproduce with a test that fails on `d0496c14d824` (red), fix, then green. Run the owning crate's focused tests and strict owning Clippy. Keep logs in your own evidence directory.
3. Commit on your own branch: one commit per board item, conventional message naming the item (`fix(keyring): ... (F001)`).
4. Set the row `ready` with the commit SHA and the exact test commands, release the claims, and append a handoff note to the other agent's inbox.
5. The integrator (codex) cherry-picks `ready` commits into its next integration batch, sets the row `integrated` with the integration SHA, and replies. A commit that conflicts with codex's batch goes back as `disputed` with the reason.
6. A finding judged not a bug, out of scope, or better fixed differently: set `disputed` or `wontfix` with one line of reasoning. The item's owner decides; the human decides ties.

## Rules

- One writer per branch. claude never pushes `integration/process-security-m4` and never edits `/home/connor/lanes/integration`. codex never commits on `fix/pr1160-claude`.
- claude builds with `CARGO_TARGET_DIR=/home/connor/lanes/claude-pr1160/target` and `CARGO_BUILD_JOBS=4`, so codex's builds keep priority.
- Pushes to the PR head reset qualification. codex batches integrations and decides when to push.
- Check your inbox at every item boundary and at least every 30 minutes while working.
- This branch is public. No secrets, tokens or private paths beyond the workstation layout above.

## Scope

Must fix before merge: every P0 and P1, the landing-plan blockers (L1, L2) and the P2 items marked `now`. Items marked `later` go to follow-up PRs after landing; the structural work in `docs/reviews/2026-10-06-pr1160/architecture.md` (branch `docs/pr1160-review`) is follow-up work and stays out of #1160. Finding numbers (F001 onward) refer to `docs/reviews/2026-10-06-pr1160/findings.md` on that branch.
