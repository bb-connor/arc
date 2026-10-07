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
4. One commit series per item on its `lane/<ID>-<slug>` branch, conventional
   messages naming the item ID. `swarm submit <ID>` pushes and requests review.
5. Reviews are cross-vendor. A reviewer records exactly one verdict with
   `swarm verdict`. More than two rounds of changes blocks the item.
6. Only the integrator merges into `integration/beta-next`, in batches, and
   never pushes while a full CI run is in progress unless the push fixes it.
7. Only Connor merges to `main`.

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
