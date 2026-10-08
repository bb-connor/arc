# Agent Swarm Design: blitz to beta across three machines

- Date: 2026-10-06
- Status: APPROVED in conversation (sections 1-6); written spec awaiting owner review
- Owner: Connor (human merge authority for `main`)
- Scope: development process and tooling only. No product code, schema or wire changes.
- Branch: `docs/agent-swarm-design` off `main`

## 1. Goal

Get Chio to beta as fast as possible by running a coordinated swarm of
coding agents across the three tailnet machines, without slowing the
security critical path and without lowering the evidence bar the project
already holds itself to.

Order of work:

1. Land the security foundation: PR #1176 (prerequisite), then PR #1160.
2. In parallel, burn down independent bug-fix and docs lanes into a stacked
   integration branch.
3. After #1160, #1173 and the recovery implementation land, execute the
   verifiable-work program (W1-W4) and the FTL lessons specs (PR #1174).

### What "beta" means

From the agentic work kernel design and the W4 beta-convergence plan on
`work/verifiable-work-session-20261003` (#1173):

- An installable developer kernel plus reference host, first qualified on
  Linux x86_64 Enforced mode, with Rust, Python and TypeScript workers on one
  work model, and MCP, A2A, ACP-Client and HTTP qualified separately.
- Readiness requires all five: security acceptance for every enabled surface;
  recovery acceptance for advertised phases; W1-W3 acceptance (AW01-AW31);
  one integrated candidate with install, migration, replay, cross-owner,
  protocol and docs evidence; blocking reviews closed plus a remaining-scope
  record.
- Not beta gates: Security M11 observed pilot, public-money operation, paper
  step P.5, publication.

## 2. Decisions

| # | Decision | Choice |
| --- | --- | --- |
| D1 | Human role | Agents merge into integration branches. Amended 2026-10-08: agents also merge to `main`, but only through `swarm merge`, whose gate is section 8.3. Codex review bots (and Greptile, while it has credits) review PRs into `main`. |
| D2 | Spend posture | Tiered. Premium models for kernel/security authoring, design calls and final review. Mid-tier subscription models (Claude Sonnet 5.5, Codex 6.1-sol) for routine implementation and review fixes. Hermes on OpenRouter (DeepSeek, Kimi, GLM) for mechanical work. |
| D3 | Compute | Free first: clean up workstation-2, enable sccache, GitHub Actions as the x86 test farm (the repo is public, so standard hosted runners are free), cloud agent sessions for lanes that need no full Rust build. Add a preemptible Oracle E5 build box only on measured need. No E2B, no Cursor cloud agents. |
| D4 | Coordination substrate | Approach A: a git-native coordination store on an orphan `swarm` branch of `bb-connor/arc`, driven by a `swarm` CLI. GitHub PRs on the public repo carry code and review bots only. |
| D5 | Conductor | Claude (premium) on workstation-2. |
| D6 | GitHub identity | Amended 2026-10-08: agents act as Connor's account (`bb-connor`), reading the existing `gh` login at runtime; no machine user. Accepted costs: agents could bypass admin-bypassable rules, GitHub attributes their actions to Connor, and they share his API rate limit. |
| D7 | Hermes spend cap | OpenRouter key credit limit of $25/day. |
| D8 | Existing security pair | Runs unchanged on its own `coord/pr1160` mailbox until #1160 lands, then migrates onto the swarm. |

Rejected alternatives: Linear (setup cost, every agent needs an API
integration, one human user of its UI); GitHub Issues as the store (all agents
share one user's API rate limit, label claims race, chatter buries the human
view); a central dispatcher service (a day to build, single point of failure,
unreachable from cloud sessions).

## 3. Current state (observed 2026-10-06)

| Machine | Hardware | Agents installed | Notes |
| --- | --- | --- | --- |
| workstation-2 (tailnet `tag:workstation`) | Linux aarch64, 12 cores, 46 GB RAM, 145 GB disk with 31 GB free | codex, claude, hermes | Always on. Load average about 14 with about 16% CPU pressure. Hosts the Codex root threads and the `coord/pr1160` mailbox. `~/lanes` holds 89 GB, `~/backbay` 41 GB; the integration lane target is 53 GB. sccache installed but not enabled. Git over SSH to GitHub is not authenticated. |
| MacBook Air | 8 cores, 8 GB RAM | codex, claude, cursor-agent | Too small for workspace Rust builds. |
| MacBook Pro | Not yet inventoried | Not yet inventoried | Remote Login enabled; this design's key is not yet authorized there. Probable location of the uncommitted recovery implementation. |

Other facts that shape the design:

- `main` is 912 commits behind #1160. Parallel work must stack on #1160.
- Every commit on #1160 invalidates its exact-SHA hosted evidence, so its
  scope is frozen to the security pair.
- #1160's last hosted run shows 130 cancelled checks: frequent pushes cancel
  in-progress CI.
- The #1173 plans state "one implementation owner" and "user prohibits
  subagents". The swarm must explicitly supersede this.
- About 117K lines of recovery implementation (`feat/recoverable-agent-runtime-20261002`)
  exist only as uncommitted changes on one disk. W1.6, W2.4 and W4 depend on it.
- Only two of 87 workflows trigger on push to any branch, and both are
  path-filtered to unrelated directories. An orphan branch containing only
  `swarm/` files triggers no CI.

## 4. Architecture

### 4.1 Topology

- **workstation-2 is the hub.** Runs the conductor, the integrator, the
  janitors, the existing security pair and about three build slots. Swarm
  builds run in a low-priority cgroup scope so the security pair keeps CPU
  priority.
- **MacBook Air** runs edit-only lanes: docs, paper, Python/TS SDK work and
  Cursor agent lanes. It never builds the Rust workspace.
- **MacBook Pro** takes one or two Rust lanes for cross-platform crates if it
  has an M-series chip with 32 GB RAM or more. Linux-only crates (cage,
  seccomp) are never tested on macOS.
- **Claude and Codex cloud sessions** run fire-and-forget lanes. The
  conductor writes a self-contained brief; the session returns a branch; the
  conductor registers the result on the item. Cloud sessions never write to the
  `swarm` branch.
- **GitHub Actions** is the x86 test farm via a dispatchable `lane-test.yml`.

### 4.2 Roles and starting roster (about 12 concurrent agents)

| Role | Count | Placement | Model tier | Responsibilities |
| --- | --- | --- | --- | --- |
| Conductor | 1 | workstation-2 | Premium Claude | Plans, writes items and briefs, orders hotspot work, assigns, unblocks, records decisions, writes digests. Never writes product code. |
| Security pair | 2 | workstation-2 | Existing Codex root + Claude | Unchanged until #1160 lands. |
| Integrator | 1 | workstation-2 | Premium Codex | Sole pusher to `integration/beta-next`. Batches merges, runs integration checks, owns train PRs. |
| Fix-lane worker | 3-4 | workstation-2, Pro | Mid tier; premium for kernel items | Implements one claimed item at a time, test first. |
| Reviewer | 1-2 | any | Premium, opposite vendor from the author | Reviews lane diffs against brief and acceptance; records verdicts. |
| Docs/paper/SDK lane | 2 | Air, cloud | Mid tier, Cursor, cloud sessions | Docs, paper P.1-4, Python/TS SDK items. |
| Janitor | 2-3 | workstation-2 | Hermes (DeepSeek, Kimi, GLM) | CI log triage, flake detection, batch bisects, evidence bookkeeping, board regeneration, registering cloud results, importing bot reviews, watchdog. |

Agent IDs follow `<vendor>-<machine>-<role><n>`, for example
`claude-ws2-conductor`, `codex-ws2-integrator`, `hermes-ws2-janitor1`,
`cursor-air-docs1`.

Every local agent runs under a `swarm-agent` runner in a named `tmux` session
`swarm-<agent-id>`. Workers, reviewers and docs lanes start a fresh headless
session per item (fresh context per item). The conductor and integrator keep
one persistent headless session each, resumed with every event, so their
context survives restarts. Connor can open the conductor's session
interactively (and attach Remote Control) after halting its runner.

## 5. Coordination store and `swarm` CLI

### 5.1 Layout (orphan branch `swarm`)

```
swarm/
  PROTOCOL.md               rules every agent reads at startup
  bin/swarm                 the CLI (one Python 3 file, standard library only)
  agents/<agent-id>.md      roster entry: machine, vendor, model, tier, status, last heartbeat
  items/<ID>.md             one per work item: front matter + brief + acceptance + log
  claims/<ID>.json          existence means the item is claimed: {agent, paths[], acquired, expires}
  msgs/<agent|role|all|human>/<ts>-<from>-<slug>.md   append-only inboxes
  decisions/NNNN-<slug>.md  conductor rulings
  digests/<date>-<am|pm>.md conductor digests
  BOARD.md                  generated view, never hand-edited
  HALT                      present only while the swarm is halted
```

Each machine keeps a single-branch clone at `~/swarm`. Agents never edit
these files by hand; all writes go through the CLI. Commit messages are
`[swarm] <agent>: <op> <item>`.

### 5.2 Item model

Front matter fields: `id`, `title`, `severity` (P0-P3), `wave`, `depends_on`,
`paths` (globs), `crates`, `tier`, `status`, `owner`, `branch`, `commits`,
`review` (verdict, reviewer, round), `evidence` (links), `attempts`
(review rounds, CI failures, started).

Statuses: `open`, `claimed`, `in-progress`, `review`, `ready`, `integrated`,
`done`, plus `blocked`, `disputed`, `deferred`, `wontfix`.

Transition authority: the owner advances its own item; the reviewer records
verdicts; the integrator sets `integrated` and bounces reverted items; the
conductor may set any field. An item cannot be claimed until every
`depends_on` item is `integrated`.

### 5.3 Concurrency

Every CLI write is an idempotent mutation (set field, append log line, create
file). The CLI fetches `origin/swarm`, applies the mutation, commits and
pushes. On a rejected push it resets to the fresh `origin/swarm`, reapplies
the mutation and retries with jitter, up to a bounded number of attempts.
The non-fast-forward rejection is the compare-and-swap, so concurrent agents
never produce merge conflicts.

### 5.4 Commands

| Command | Behavior |
| --- | --- |
| `swarm register` | Creates or updates the caller's `agents/` entry. |
| `swarm claim <ID> --paths <globs> [--share] [--steal]` | Creates `claims/<ID>.json`. Refuses when the item is claimed, its dependencies are not integrated, or the paths overlap an active claim (unless `--share`). `--steal` takes an expired claim and messages the previous owner. |
| `swarm heartbeat` | Renews the caller's claims and agent entry. Every other command also renews. |
| `swarm release <ID>` | Removes the claim. |
| `swarm status <ID> <status> [--note]` | Applies a permitted transition. |
| `swarm submit <ID> --branch <b>` | Pushes the lane branch, records commits, sets `review`, messages the reviewer role. |
| `swarm verdict <ID> accept\|changes --findings <file>` | Reviewer verdict; `changes` returns the item to the owner. |
| `swarm send <to> --item <ID> --kind request\|handoff\|verdict\|blocker\|fyi` | Posts a message. |
| `swarm inbox` | Shows unread messages; read state is local only. |
| `swarm wait --timeout <s>` | Blocks until a new message or a change to the caller's items, fetching every 30 seconds. |
| `swarm brief <ID>` | Prints the item as a self-contained prompt for cloud sessions and Hermes. |
| `swarm board --write` | Regenerates `BOARD.md` grouped by wave and status, with owner, age and blockers; `human` items first. |
| `swarm build -- <cmd>` | Runs a build under a build slot (section 7.2). |
| `swarm ci <ID> --packages <p> [--filter <f>]` | Dispatches `lane-test.yml`, waits, records the run URL as evidence. |
| `swarm import-reviews <PR#>` | Converts review bot findings on a train PR into items. |
| `swarm halt [--all\|--role R\|--agent A]` / `swarm resume` | Kill switch (section 8.5). |

Claims expire 45 minutes after the last heartbeat, with a two-minute grace for
clock skew between machines. Every write command renews the caller's claims,
and `swarm wait` renews them every ten minutes while it blocks. The
implementation plan adds small helper commands (`next`, `list`, `reassign`,
`sweep`, `config`, `worktree`, `metrics`, `ci-busy`, `scan`) around this core.

### 5.5 Secret guard

The `swarm` branch is on a public repository. Before every push the CLI scans
the staged content for credential-shaped strings (API key prefixes, private
key blocks, high-entropy tokens) and refuses to push on a match. Keys live
only in each machine's local environment files.

## 6. Work lifecycle and integration

### 6.1 Branches

```
main  <-- Connor approves -----------------------------+
  ^                                                    |
  |  #1160 integration/process-security-m4             |  train PRs (review bots here)
  |   (frozen scope; security pair only; lands first)  |
  |                                                    |
  +-- integration/beta-next  (integrator only) --------+
          ^  batched merges, one push per batch
          |
   lane/<ID>-<slug>   one branch per item, cut from beta-next
```

- `integration/beta-next` is stacked on #1160's head and rebased onto `main`
  by the integrator once #1160 merges.
- #1173 keeps its current owner and joins `beta-next` after #1160 lands.
- Work reaches `main` in trains: a `beta-next` to `main` PR whenever a
  coherent green set has landed, roughly every two to three days.
- Lane branches are not opened as PRs. Per-lane PRs would trigger CI and bot
  reviews per lane. Lanes are reviewed by reviewer agents; bots review trains.

### 6.2 Item lifecycle

1. The conductor writes the item with brief, acceptance criteria, paths,
   dependencies and tier.
2. A worker claims it and creates a worktree from the current `beta-next`
   head.
3. Test first: a failing regression, then the fix, then the owning crate's
   focused tests and strict owning Clippy. Linux x86 tests run through
   `swarm ci`. Full-workspace builds are the integrator's job.
4. `swarm submit`. A reviewer from the other vendor checks the diff against
   the brief and acceptance criteria and the anti-weakening checklist
   (section 8.4). Any P0-P2 finding returns the item. After two rounds the
   conductor intervenes.
5. The integrator merges `ready` items in batches (every two to three hours or
   five items), runs affected-crate tests plus a workspace build and Clippy,
   and pushes once.
6. If hosted CI goes red, a janitor triages the log and bisects the batch's
   merge commits with `swarm ci`. The integrator reverts the culprit and
   returns it with evidence, keeping `beta-next` green.
7. Review bot findings on a train PR become items through
   `swarm import-reviews` and follow the same loop.

### 6.3 Hotspots

Items touching these paths (as they exist on the #1160 and #1173 branches)
are serialized by the claim overlap check and ordered by the conductor:

- `crates/kernel/chio-kernel/src/kernel/evaluation/*`, `kernel/validation.rs`,
  `kernel/construction.rs`, `kernel/mod.rs`
- `crates/platform/chio-store-sqlite` (serving owner, global commit chain,
  schema migration, admission operation store)
- `crates/platform/chio-control-plane/src/work/*`, `lib.rs`, `Cargo.toml`
- `crates/kernel/chio-process/src/{worker,lib,store}.rs`
- `crates/kernel/chio-runtime-core/src/work/*`
- release and CI files: `.github/workflows`, `scripts/tests`, `supply-chain`,
  `docs/release/*`

### 6.4 Superseding the single-owner rule

Decision record `decisions/0001-swarm-supersedes-single-owner.md` states that
the swarm protocol (one owner per item, claims enforcing exclusive paths,
cross-vendor review) replaces the "one implementation owner" and "no
subagents" instructions in the #1173 and #1174 plans for work dispatched
through the swarm. Every brief cites it.

### 6.5 Waves

- **Wave 1 (start now, into `beta-next`):** #1174 bug-fix lane B1-B7 (spec 3
  phase 1; spec 5 Part A; spec 8 phase 0 then phase 1; D6; spec 6 phase 1;
  spec 7 step 1; D5, D7, N6), open review findings, #1173 readiness items,
  paper P.1-4, gates G2 (spec 1 phase 0) and G3 (spec 3 phase 2).
- **Wave 2 (after #1160, #1173 and the recovery commit land):** W1.0, then
  W1.1 alone (it freezes shared types), then W1.2 and W1.3 in parallel, then
  W1.4-W1.7, W2, W3, W4 per the W plans' dependencies.
- **Wave 3:** FTL keystone specs 9, 10 and 11 in the umbrella's order, after
  the beta gates.

## 7. Build and CI capacity

### 7.1 workstation-2 cleanup

An inventory script lists every worktree with last commit age, uncommitted
file count, whether its branch exists on `origin`, and target directory size.
Only clean, pushed, stale worktrees are removed, and only after Connor
approves the list. Worktrees with uncommitted changes are never touched.
Expected recovery: 50-100 GB. Connor then grows the Oracle boot volume to
about 500 GB and the filesystem is grown online.

### 7.2 Build slots

`swarm build -- <cmd>`:

- acquires one of N file-lock slots (N=2 initially);
- runs the command in `systemd-run --user --scope -p CPUWeight=20 -p MemoryMax=14G`
  so the security pair (default weight) keeps priority and a large link
  cannot invoke the OOM killer against it;
- sets `RUSTC_WRAPPER=sccache` (60 GB local cache) and `CARGO_INCREMENTAL=0`;
- uses one target directory per lane (shared target directories serialize on
  cargo's lock);
- records queue wait time for the metrics in section 9.

Workers build only the crates their item touches.

### 7.3 `lane-test.yml`

A `workflow_dispatch` workflow with inputs `target_ref`, `item`, `packages`,
`filter`, `features` and `nonce`. It is always dispatched on `main` (GitHub runs
the workflow file from the dispatched ref, and lane branches do not carry it)
and checks out `target_ref` itself. It runs on `ubuntu-24.04` with a Rust cache keyed by packages,
executes `cargo nextest run -p ...`, and uploads logs and JUnit results. Its
concurrency group is per item, so a new run cancels only that item's previous
run. The CLI keeps at most about ten lane-test runs in flight to leave the
account's concurrent-job capacity for main CI. The workflow file must be on
the default branch to be dispatchable, so it lands through a small PR that
Connor approves.

### 7.4 Hosted CI for `beta-next`

Full CI on `beta-next` runs through a standing draft train PR targeting
`main`; `ci.yml`, which carries the required checks, only runs for pull
requests into `main`. The
integrator does not push to `beta-next` while a full CI run is in progress,
except to fix that run's failure.

### 7.5 Cloud and Mac lanes

Cloud session environments use a setup script under five minutes (Rust
toolchain and sccache) so the environment is cached, and run only
`cargo check -p <crate>`. A janitor dispatches their lane tests. The Air never
builds Rust. The Pro builds cross-platform crates only.

### 7.6 Scaling trigger for the Oracle box

If for two consecutive days either the median build-slot wait exceeds 20
minutes or workstation-2 CPU pressure stays above 30%, provision a preemptible
Oracle E5.Flex box (24 OCPU, 128 GB RAM, 500 GB block volume, about $85 per
week preemptible or $170 on demand) joined to the tailnet as `tag:builder`.
`swarm build` then also dispatches slots to it over SSH.

## 8. Failure handling, safety and spend

### 8.1 Agent failure

- **Crash or hang:** a janitor watchdog checks heartbeats. After 30 minutes of
  silence it restarts a dead process in its `tmux` session with a resume
  prompt ("check the current state before repeating any action"); for a live
  but silent process it messages the agent and the conductor decides. Claims
  expire at 45 minutes regardless.
- **Thrash:** per-item budget of two review rounds, three failed CI runs and
  twice the estimated time. Exceeding any limit sets `blocked` and escalates
  to the conductor, which re-slices, raises the tier or escalates to Connor.
- **Usage caps:** agent wrappers detect rate-limit and usage-cap errors, set
  the agent `throttled` with its reset time, and the conductor reassigns. The
  fallback order is premium subscription, then mid-tier subscription, then
  Hermes. Hermes never authors P0 or P1 security fixes.

### 8.2 Spend caps (provider-enforced)

- OpenRouter key credit limit: $25 per day.
- Cursor usage spend limit set in its dashboard.
- Oracle budget alert if the build box is provisioned.
- Claude and Codex subscriptions cap themselves; throttling routes around them.

### 8.3 Branch protection and the merge gate

Amended 2026-10-08 (D1, D6). Agents act as Connor's account. The
`main-required-checks` ruleset (required checks, no deletion, no force push,
no bypass actors) binds every merge to `main`, admin or not; the earlier
`main-human-merge` update restriction was deleted because it could not bind
agents acting as an admin.

Agents land PRs on `main` only through `swarm merge <PR>`, run by the
integrator (train PRs) or the conductor (PRs it owns). On the PR's current
head commit it requires all of:

- the four required checks completed with success;
- a completed Codex review (its summary row names the head commit);
- every P0-P2 finding from the review bots imported as an item and either
  `integrated`/`done` or `wontfix` with a recorded reason;
- an accepted whole-PR review (`swarm review-pr`) of that head by a reviewer
  whose vendor differs from the author's.

It then runs `gh pr merge --merge --match-head-commit <head>`, never
`--admin`, and notifies Connor. A pre-push hook in every swarm worktree still
enforces roles: nobody pushes `main` directly, only the integrator pushes
`beta-next`, only the security pair pushes the #1160 branch, and workers
force-push only their own `lane/*` branches.

### 8.4 Agent rules (`PROTOCOL.md`, backed by agent permission deny rules)

- No `git reset --hard`, `git clean`, `rm -rf` or `cargo clean` outside the
  agent's own lane directory. No deleting worktrees. No force-pushing shared
  branches.
- Never make a check pass by weakening it: no new `#[ignore]`, no new Clippy
  `allow`, no skipped or filtered tests, no advisory or audit suppressions, no
  edited fixtures to match wrong output. Reviewers check every diff for these.
- Follow `CLAUDE.md` house rules: fail closed, no `unwrap`/`expect`, no em
  dashes, conventional commits naming the item ID.
- Check the item's claim before editing any path; never edit a path another
  agent holds.

### 8.5 Kill switch

`swarm halt [--all|--role R|--agent A]` commits `HALT`. Every `swarm` command
then exits non-zero and agents stop at their next checkpoint. `swarm resume`
removes it. Killing the `tmux` sessions is the hard stop.

### 8.6 Human interface

- `msgs/human/` holds items needing Connor's decision; they head `BOARD.md`.
- The conductor writes a digest twice daily: what landed, what is blocked,
  spend, CI health and the section 9 metrics.
- Connor can drive the conductor through Claude Remote Control.

## 9. Rollout

### Day 0 (setup, about half a day)

1. Locate the uncommitted recovery implementation, commit it and push it to a
   WIP branch.
2. Run the workstation-2 cleanup inventory, get approval, remove, then grow
   the Oracle boot volume.
3. Create the machine user and token, configure GitHub auth on
   workstation-2, add the `main` ruleset.
4. Build the `swarm` CLI with its tests, `PROTOCOL.md` and decision 0001 on
   the orphan `swarm` branch.
5. Land `lane-test.yml` on `main` through a small approved PR.
6. Install the build-slot wrapper, sccache configuration and cgroup scope on
   workstation-2.
7. Inventory the MacBook Pro (authorize this design's SSH key there first).

### Day 1 (pilot, six agents)

Conductor, integrator, two fix workers, one cross-vendor reviewer and one
janitor, on small independent items: B6 (N3), B4 (D6), B5 (D8 adapters) and
P.1 docs.

Pilot exit criteria: at least three items through the full lifecycle to
`integrated`; `beta-next` green on hosted CI; no claim collisions; no lost
work; security pair turnaround unchanged. If the pilot fails, fix the process
before scaling.

### Days 2-3 (scale to about 12 agents)

Add kernel items B1, B2 and B3 on premium models, docs/paper/SDK lanes on the
Air and cloud sessions, and more janitors. Decide on the Oracle box using the
section 7.6 trigger.

### After #1160 lands

The security pair migrates onto the swarm (a script imports the remaining
`coord/pr1160` board rows as items). The first train PR goes to Connor. Wave 2
starts with W1.1 under a single owner, then fans out.

## 10. Success metrics

| Metric | Target |
| --- | --- |
| Items integrated per day | 8 or more by day 3 |
| Hosted CI green rate on integrator pushes | 80% or more; red to green within 4 hours |
| Median build-slot wait | Under 20 minutes |
| Review bounce rate | Under 30% |
| Security pair turnaround | Not slowed |
| Lost work, protected-branch violations | Zero |
| Spend | Within section 8.2 caps |

## 11. Testing the tooling

- CLI: two clones racing to claim one item (exactly one wins); claim expiry
  and steal; overlapping-path refusal and `--share`; retry after a rejected
  push reapplies the mutation once; secret guard refuses a planted key;
  `HALT` makes every command fail.
- Build wrapper: slot exhaustion queues rather than oversubscribes; the scope
  applies the CPU weight and memory limit.
- `lane-test.yml`: one dispatch against a known-green crate and one against a
  deliberately failing test, confirming results and evidence links.
- Pilot (section 9) is the end-to-end test.

## 12. Planning-time checks

These do not change the design. Resolved while writing the plan (2026-10-06):

- `ci.yml` (required checks) runs `pull_request` only for base `main`; 45 other
  workflows accept any base. The train PR therefore targets `main`.
- The `main` ruleset has no approval rule; section 8.3 adds one.
- The repository uses Git LFS (Swift xcframework only), so the swarm pre-push
  hook chains to `git lfs pre-push`.
- workstation-2 supports `systemd-run --user` scopes with cpu and memory
  controllers, already has `extensions.worktreeConfig`, and needs node on PATH
  for Codex in non-interactive shells.

Still open, resolved during execution:

- Whether Claude and Codex cloud sessions can push arbitrary branch names, or
  only tool-prefixed ones; the janitor's registration step adapts either way.
- MacBook Pro hardware and whether it holds the recovery implementation.
- The account's concurrent-job limit for hosted runners, which sets the
  lane-test cap in section 7.3.

## 13. Out of scope

Linear; a central dispatcher service; E2B; Cursor cloud agents; automatic
merges to `main`; changes to how the security pair works before #1160 lands;
any product code, schema or protocol change.
