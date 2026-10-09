# Chio swarm protocol

Every agent reads this at startup. It is short on purpose. The design is
`docs/superpowers/specs/2026-10-06-agent-swarm-design.md` on `bb-connor/arc`.

## Identity

- You are `$SWARM_AGENT`, role `$SWARM_ROLE`, vendor `$SWARM_VENDOR`.
- All coordination goes through the `swarm` CLI. Never edit files under
  `~/swarm` by hand and never push the `swarm` branch with git.
- Decision 0001 applies: the swarm protocol replaces any plan text that says
  "one implementation owner" or forbids subagents.

## Work

1. Work only on an item you own (`swarm next` claims one for you).
2. Edit only paths your claim covers. Need another path? Block the item with a
   note; the conductor decides.
3. Test first: a regression test that fails, then the fix, then focused tests
   and strict Clippy for the owning crate, through `swarm build -- ...`.
   Linux x86_64-only tests run through `swarm ci <ID> --packages <crate>`.
4. One commit per fix, containing the code and its regression test, on the
   item's `lane/<ID>-<slug>` branch, with a conventional message naming the
   item ID. `swarm submit <ID>` pushes the lane and marks it `submitted`. It
   refuses to overwrite commits someone else pushed to your lane (the integrator
   fixing it in place); pull them with `git pull --rebase` and submit again.
5. Check trains, not per-item reviews: the integrator's `swarm check-train`
   builds every submitted `lane/` branch in one pass, one train at a time per
   host, in a reused worktree whose `target/` stays warm. A failing or
   conflicting lane comes back `in-progress` with the exact error; a green one
   becomes `ready`, and is `integrated` when the train lands. A failure no
   single lane clearly owns (for example a break downstream of two lanes) is
   reported as unattributed with its suspects and moves nobody. Reviews are
   batched: one cross-vendor whole-PR review per pushed head (`swarm review-pr`).
6. Only the integrator lands on `integration/beta-next`, through
   `swarm check-train --land`, which will not push while CI is running or while
   its latest run is red (`--allow-red` when the train carries the fix). The
   integrator fixes small integration breaks in place rather than bouncing them,
   and the owner is told when it does.
7. Only the integrator or the conductor merges to `main`, and only with `swarm merge`. Its gate
   requires, on the PR's head commit: the four required checks green, a completed Codex review,
   no open P0-P2 review-bot finding (fixed, or `wontfix` with a recorded reason), and an accepted
   cross-vendor whole-PR review (`swarm review-pr`). Never `gh pr merge` by hand, never `--admin`.

## Never

- Weaken a check to make it pass: no new `#[ignore]`, no Clippy `allow`, no
  skipped or filtered tests, no advisory or audit suppression, no fixture
  edited to match wrong output.
- `git reset --hard`, `git clean`, `rm -rf`, `cargo clean` outside your own
  lane, deleting worktrees, force-pushing anything but your own lane branch.
- Paste credentials anywhere. The CLI refuses credential-shaped content.
- Push `main`, `swarm`, `integration/beta-next` (unless integrator) or the
  #1160 branch (unless security pair).

## House rules (from CLAUDE.md)

Fail closed. No `unwrap`/`expect`. No em dashes. Conventional commits.

## Budgets

Two review rounds, three failed CI runs, twice the estimated hours. Past any
of them the item is blocked and the conductor re-slices it.

## When stuck

`swarm status <ID> blocked --note "<one line>"` and stop. Questions only
Connor can answer go to `swarm send human`.
