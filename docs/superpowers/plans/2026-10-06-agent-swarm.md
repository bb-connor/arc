# Agent Swarm Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a coordinated swarm of Codex, Claude, Cursor and Hermes agents across workstation-2 and both Macs, then run a six-agent pilot that lands four real fixes into `integration/beta-next`.

**Architecture:** A git-native coordination store lives on an orphan `swarm` branch of `bb-connor/arc`. A standard-library Python CLI (`swarm`) is the only writer: every write fetches the branch, applies an idempotent mutation, commits and pushes, and a rejected push means "someone else won, reapply". A runner (`swarm-agent`) drives each registered agent headlessly in `tmux`. Builds go through bounded, low-priority build slots on workstation-2, Linux x86_64 tests go through a dispatchable `lane-test.yml` on free GitHub-hosted runners, and only Connor merges to `main`.

**Tech Stack:** Python 3.11+ standard library, git, `gh`, `tmux`, `systemd-run --user`, `sccache`, GitHub Actions, Codex CLI, Claude Code CLI, Cursor agent CLI, Hermes (OpenRouter).

**Spec:** `docs/superpowers/specs/2026-10-06-agent-swarm-design.md` (branch `docs/agent-swarm-design`). Read it before starting; this plan argues from it.

## Global Constraints

- No em dashes (U+2014) in any file, message, commit or PR text. Use hyphens or parentheses.
- Fail closed: every refusal exits non-zero with a message; nothing half-applies.
- The `swarm` branch is an orphan branch. It never shares history with `main` and must not contain a `.github/` directory.
- The `swarm` CLI and runner use only the Python 3.11 standard library. No third-party packages.
- Claims expire 45 minutes after the last heartbeat, with a 2 minute grace for clock skew.
- Budgets: 2 review rounds, 3 failed CI runs, 2x the estimated hours. Past any one, the item is `blocked`.
- Build slots: `CPUWeight=20`, `MemoryMax=14G`, `CARGO_INCREMENTAL=0`, `RUSTC_WRAPPER=sccache`, 60 GB sccache, 2 slots to start.
- `lane-test.yml` is always dispatched on `main` and checks out `target_ref`; at most 10 lane-test runs in flight.
- Agents push as the machine user `bb-chio-swarm` (write, not admin). Only Connor (repository admin) and GitHub Actions bypass the `main` update restriction.
- OpenRouter key credit limit: $25 per day.
- Hermes never authors P0 or P1 security fixes.
- Never commit, print or message a credential. The E2B key Connor pasted is not used by this plan; rotate it.
- Commits follow conventional commits (`feat(swarm): ...`, `ci: ...`, `chore(swarm): ...`).

## Review Focus

These failure modes are implied by the spec but easy to miss. Each one has a pinned test in the task named.

1. **Clock skew between machines**: a claim that expired a minute ago on a machine whose clock runs fast must not be stealable. Pinned by `test_expiry_respects_grace_then_allows_steal` (Task 5).
2. **Agent killed between commit and push**: the local clone holds an unpushed commit; the next command must discard it and the remote must be untouched. Pinned by `test_interrupted_push_is_discarded_by_next_sync` (Task 4).
3. **Hand-edited, malformed item file**: one bad `items/*.md` must not break `list`, `board` or `next`; it is reported by name. Pinned by `test_malformed_item_is_reported_not_fatal` (Task 6) and the "Unparseable items" board section (Task 7).
4. **GitHub unreachable**: every write fails closed with a clear error and leaves no state. Pinned by `test_unreachable_origin_raises_git_error` (Task 4).
5. **Resuming a lane on another machine**: when the lane branch already exists on the remote, the new worktree starts from it, not from the base, so no pushed work is lost. Pinned by `test_resumes_from_remote_lane_branch` (Task 6).

## Scope

One plan in four phases, because the pilot needs every piece. Phase 0 is urgent operations, Phase 1 builds and publishes the tooling (Tasks 3-14 can run before Phase 0 finishes), Phase 2 prepares machines, Phase 3 runs the pilot and scale-up. Remote build slots on an Oracle box (spec section 7.6) are not built here: Task 20 measures the trigger, and a follow-up plan covers the box only if the trigger fires.

## File Structure

Orphan branch `swarm` (worked on in the worktree `/Users/connor/backbay/arc-swarm` on this Mac, cloned to `~/swarm` on every machine):

| Path | Responsibility |
| --- | --- |
| `swarmlib/clock.py` | UTC time, `SWARM_FAKE_NOW` for tests |
| `swarmlib/frontmatter.py` | `key: <json>` front matter parse and dump |
| `swarmlib/secrets.py` | credential-shape scanner |
| `swarmlib/paths.py` | conservative glob overlap |
| `swarmlib/gitio.py` | git subprocess wrapper, `$GH_TOKEN` credential helper |
| `swarmlib/store.py` | `Store`, the fetch-mutate-commit-push transaction, halt/resume, `config.json` |
| `swarmlib/agents.py` | roster in `agents/<id>.md`, heartbeats |
| `swarmlib/items.py` | items in `items/<ID>.md`, status table, dependencies |
| `swarmlib/msgs.py` | inboxes in `msgs/<to>/`, local read state |
| `swarmlib/claims.py` | leases in `claims/<ID>.json`, steal, reassign, renew |
| `swarmlib/lifecycle.py` | status moves, submit, verdict, `next`, sweep, wait, brief, evidence |
| `swarmlib/worktree.py` | lane and review worktrees with swarm hooks |
| `swarmlib/board.py` | `BOARD.md` rendering |
| `swarmlib/metrics.py` | spec section 10 metrics |
| `swarmlib/build.py` | build slots, cgroup scope, sccache env |
| `swarmlib/ci.py` | `gh` wrappers for lane tests and CI state |
| `swarmlib/reviews.py` | review-bot comments to items |
| `swarmlib/cli.py`, `bin/swarm` | the `swarm` command |
| `swarmlib/agent.py`, `bin/swarm-agent` | the runner, watchdog and `tmux` launcher |
| `hooks/pre-push`, `hooks/post-*` | role guard for lane worktrees, Git LFS passthrough |
| `prompts/*.md` | role prompts for the runner |
| `agent-config/claude-settings.json` | Claude deny rules |
| `ops/worktree_inventory.py`, `ops/install.sh` | workstation cleanup and per-machine install |
| `PROTOCOL.md`, `README.md`, `decisions/0001-*.md`, `config.json` | rules, orientation, first decision, defaults |
| `tests/*.py` | `unittest` suites; `tests/support.py` holds fixtures |

On `main` of `bb-connor/arc`: `.github/workflows/lane-test.yml` (Task 14).

Run any suite from the worktree root with `PYTHONPATH=. python3 -m unittest discover -s tests -p '<file>' -v`. Run everything with `PYTHONPATH=. python3 -m unittest discover -s tests`.

---

# Phase 0: urgent operations

### Task 1: Preserve the uncommitted recovery implementation

About 117K lines of recovery work (`feat/recoverable-agent-runtime-20261002`, phases P0-P5) exist only as uncommitted changes on one disk. W1.6, W2.4 and W4 depend on them. This task needs Connor for the machine it lives on.

**Files:** none in this repo. Creates the remote branch `wip/recoverable-agent-runtime-20261002`.

- [ ] **Step 1: Find it.** On each machine (workstation-2 and this Mac were checked on 2026-10-06 and do not have it; start with the MacBook Pro) run:

```bash
for repo in ~/backbay/arc ~/backbay/chio; do
  [ -d "$repo/.git" ] || continue
  git -C "$repo" worktree list | grep -iE 'recover' || true
  git -C "$repo" branch --list '*recoverable*'
done
```

Expected: one worktree on `feat/recoverable-agent-runtime-20261002`. If no machine shows it, stop and ask Connor where the recovery work lives.

- [ ] **Step 2: Measure and scan it.** In that worktree (`cd <path>`):

```bash
git status --short | wc -l
git diff --shortstat HEAD
git ls-files --others --exclude-standard | wc -l
git diff HEAD | grep -nE 'BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|e2b_[A-Za-z0-9]{24,}' || echo "no credential shapes in tracked changes"
git ls-files --others --exclude-standard -z | xargs -0 grep -lE 'BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}' 2>/dev/null || echo "no credential shapes in untracked files"
```

Expected: a large change count and both "no credential shapes" lines. If anything matches, show Connor the file names (not the contents) and wait.

- [ ] **Step 3: Commit it on a WIP branch without running hooks or tests.**

```bash
git switch -c wip/recoverable-agent-runtime-20261002
git add -A
git commit --no-verify -m "wip(recovery): preserve uncommitted P0-P5 recovery implementation"
```

- [ ] **Step 4: Push it.** Use whatever credential that machine already pushes with (`gh auth status` shows it):

```bash
git push origin wip/recoverable-agent-runtime-20261002
git ls-remote origin refs/heads/wip/recoverable-agent-runtime-20261002
```

Expected: `ls-remote` prints the new commit's SHA. Tell Connor the branch name and SHA. Do not open a PR.

### Task 2: Machine user and the `main` merge restriction

Today the `main` ruleset (`main-required-checks`) has only deletion, non-fast-forward and required-status-check rules, with no bypass actors. This task adds a second ruleset that restricts updates to `main` and creates the agents' GitHub identity. Steps 1-3 are Connor's.

**Files:** none. Creates the ruleset `main-human-merge` and the account `bb-chio-swarm`.

- [ ] **Step 1 (Connor): Create the machine user.** Sign up a new GitHub account `bb-chio-swarm` with its own email. Then invite it from your account:

```bash
gh api -X PUT repos/bb-connor/arc/collaborators/bb-chio-swarm -f permission=push
```

Accept the invitation while signed in as `bb-chio-swarm`.

- [ ] **Step 2 (Connor): Create its token.** Signed in as `bb-chio-swarm`, create a classic personal access token (fine-grained tokens cannot reach a repository owned by another personal account) with scopes `repo` and `workflow`, expiry 90 days. Keep it for Task 15; never paste it into chat or a file in a repository.

- [ ] **Step 3 (Connor): Set the provider spend caps.** In the OpenRouter dashboard, set the credit limit of the key in `~/.hermes/.env` on workstation-2 to $25 with a daily reset. In the Cursor dashboard, set a usage-based spend limit for the account the Cursor agent CLI uses.

- [ ] **Step 4: Write the ruleset definition.** `release-cpp.yml` pushes `HEAD:main` from a workflow, so GitHub Actions (integration 15368) bypasses alongside the admin role (5). Save as `/tmp/main-human-merge.json`:

```json
{
  "name": "main-human-merge",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [{ "type": "update" }],
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" },
    { "actor_id": 15368, "actor_type": "Integration", "bypass_mode": "always" }
  ]
}
```

- [ ] **Step 5: Create it (as Connor's admin `gh` login) and verify.**

```bash
gh api -X POST repos/bb-connor/arc/rulesets --input /tmp/main-human-merge.json --jq '.id'
gh api repos/bb-connor/arc/rules/branches/main --jq '[.[].type] | sort | join(",")'
```

Expected: an id, then `deletion,non_fast_forward,required_status_checks,update`.

- [ ] **Step 6: Prove the machine user cannot update `main`.** With the token from Step 2 in your shell only:

```bash
read -rs SWARM_TOKEN
GH_TOKEN="$SWARM_TOKEN" gh api repos/bb-connor/arc/rules/branches/main --jq '[.[] | select(.type == "update")] | length'
unset SWARM_TOKEN
```

Expected: `1` (the update restriction applies to this identity). The live proof comes in Task 18, when the first train PR shows that only Connor can merge it.

---

# Phase 1: the swarm tooling

All of Phase 1 runs on this Mac in the worktree created in Task 3. Tasks 3-14 do not depend on Phase 0.

### Task 3: Orphan branch and pure helpers

**Files:**
- Create: `swarmlib/__init__.py`, `swarmlib/clock.py`, `swarmlib/frontmatter.py`, `swarmlib/secrets.py`, `swarmlib/paths.py`
- Test: `tests/test_basics.py`

**Interfaces:**
- Produces: `clock.now() -> datetime`, `clock.fmt(dt) -> str`, `clock.parse(str) -> datetime`, `clock.stamp(dt=None) -> str`, `clock.minutes(n) -> timedelta`; `frontmatter.parse(text) -> (dict, str)`, `frontmatter.dump(meta, body) -> str`, `frontmatter.FrontMatterError`; `secrets.scan(text) -> list[(kind, line)]`; `paths.literal_prefix(glob)`, `paths.globs_overlap(a, b) -> bool`, `paths.find_overlaps(wanted, held) -> list[(w, h)]`.

- [ ] **Step 1: Create the orphan worktree.**

```bash
cd /Users/connor/backbay/arc
git fetch origin
git worktree add --detach ../arc-swarm origin/main
cd ../arc-swarm
git switch --orphan swarm
mkdir -p bin swarmlib tests hooks prompts agent-config ops decisions agents items claims msgs digests
ls -a
```

Expected: only the new empty directories (and `.git`).

- [ ] **Step 2: Write the failing test** at `tests/test_basics.py`:

```python
import unittest

from swarmlib import clock, frontmatter, paths, secrets


class FrontMatterTest(unittest.TestCase):
    def test_round_trip_preserves_order_and_types(self):
        meta = {"id": "F1", "wave": 2, "paths": ["a/**"], "review": {"round": 1}, "title": "x: y"}
        text = frontmatter.dump(meta, "## Brief\n\nbody\n")
        parsed, body = frontmatter.parse(text)
        self.assertEqual(parsed, meta)
        self.assertEqual(list(parsed), list(meta))
        self.assertEqual(body, "## Brief\n\nbody\n")

    def test_rejects_missing_fences_and_bad_values(self):
        for text in ("id: \"x\"\n---\n", "---\nid: \"x\"\n", "---\nid: x\n---\n", "---\nnocolon\n---\n"):
            with self.assertRaises(frontmatter.FrontMatterError):
                frontmatter.parse(text)


class ClockTest(unittest.TestCase):
    def test_format_parse_round_trip(self):
        moment = clock.parse("2026-10-06T12:34:56Z")
        self.assertEqual(clock.fmt(moment), "2026-10-06T12:34:56Z")
        self.assertEqual(clock.stamp(moment), "20261006T123456Z")


class SecretsTest(unittest.TestCase):
    def test_detects_credential_shapes(self):
        # Built at runtime so this file never contains a real-looking key.
        samples = [
            "token " + "gh" + "p_" + "A1b2" * 9,
            "OPENROUTER=" + "sk-" + "or-v1-" + "x" * 30,
            "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
            "key " + "e2b" + "_" + "f" * 40,
            "aws " + "AKIA" + "Z" * 16,
            "api_key = " + "Q" * 30,
        ]
        for sample in samples:
            self.assertTrue(secrets.scan(sample), sample[:12])

    def test_ignores_hashes_and_prose(self):
        clean = [
            "commit 15d5b373a8e3d7f7f76404261ce6be7234806954",
            "pdf sha256 39d292f325c5f9e427f58fff39089ac7894538366c6b92e29c8c185c87fa4598",
            "the token budget is 4096 and the rate limit is 59 calls per second",
        ]
        for text in clean:
            self.assertEqual(secrets.scan(text), [], text)


class PathsTest(unittest.TestCase):
    def test_overlap_rules(self):
        self.assertTrue(paths.globs_overlap("crates/a/src/**", "crates/a/src/lib.rs"))
        self.assertTrue(paths.globs_overlap("crates/*/src/lib.rs", "crates/a/src/lib.rs"))
        self.assertTrue(paths.globs_overlap("crates/a", "crates/a/src/lib.rs"))
        self.assertTrue(paths.globs_overlap("**", "anything/at/all"))
        self.assertFalse(paths.globs_overlap("crates/a/**", "crates/b/**"))
        self.assertFalse(paths.globs_overlap("crates/a/x.rs", "crates/a/x.rs.bak"))

    def test_find_overlaps_pairs(self):
        self.assertEqual(
            paths.find_overlaps(["crates/a/**", "docs/x.md"], ["crates/a/src/lib.rs", "docs/y.md"]),
            [("crates/a/**", "crates/a/src/lib.rs")],
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_basics.py' -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'swarmlib'`.

- [ ] **Step 4: Implement.** `swarmlib/__init__.py`:

```python
"""Chio swarm coordination library."""
```

`swarmlib/clock.py`:

```python
"""Clock helpers. SWARM_FAKE_NOW (ISO-8601 UTC) pins the clock for tests."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now() -> datetime:
    fake = os.environ.get("SWARM_FAKE_NOW")
    if fake:
        return parse(fake)
    return datetime.now(timezone.utc).replace(microsecond=0)


def fmt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(FORMAT)


def parse(text: str) -> datetime:
    return datetime.strptime(text, FORMAT).replace(tzinfo=timezone.utc)


def stamp(moment: datetime | None = None) -> str:
    """Compact, sortable timestamp for file names."""
    return (moment or now()).strftime("%Y%m%dT%H%M%SZ")


def minutes(count: float) -> timedelta:
    return timedelta(minutes=count)
```

`swarmlib/frontmatter.py`:

```python
"""Front matter: `key: <json value>` lines between `---` fences, then a body."""

from __future__ import annotations

import json

FENCE = "---"


class FrontMatterError(ValueError):
    pass


def parse(text: str) -> tuple[dict, str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\n") != FENCE:
        raise FrontMatterError("missing opening ---")
    meta: dict = {}
    for index, raw in enumerate(lines[1:], start=1):
        line = raw.rstrip("\n")
        if line == FENCE:
            return meta, "".join(lines[index + 1 :])
        key, sep, value = line.partition(": ")
        if not sep or not key:
            raise FrontMatterError(f"line {index + 1}: expected 'key: value', got {line!r}")
        try:
            meta[key] = json.loads(value)
        except json.JSONDecodeError as err:
            raise FrontMatterError(f"line {index + 1}: value for {key!r} is not JSON: {err}") from err
    raise FrontMatterError("missing closing ---")


def dump(meta: dict, body: str) -> str:
    head = "".join(f"{key}: {json.dumps(value, ensure_ascii=False)}\n" for key, value in meta.items())
    return f"{FENCE}\n{head}{FENCE}\n{body}"
```

`swarmlib/secrets.py`:

```python
"""Detect credential-shaped strings before anything is pushed."""

from __future__ import annotations

import re

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("sk- api key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("e2b api key", re.compile(r"\be2b_[A-Za-z0-9]{24,}")),
    ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    (
        "assigned secret",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_=.-]{24,}"),
    ),
)


def scan(text: str) -> list[tuple[str, int]]:
    """Return (kind, line number) for every credential-shaped match."""
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS:
            if pattern.search(line):
                hits.append((kind, number))
    return hits
```

`swarmlib/paths.py`:

```python
"""Conservative overlap test for path globs (false positives are fine, misses are not)."""

from __future__ import annotations

from pathlib import PurePosixPath

WILDCARDS = frozenset("*?[")


def literal_prefix(glob: str) -> tuple[str, ...]:
    """Path components before the first component that contains a wildcard."""
    prefix = []
    for part in PurePosixPath(glob.strip("/")).parts:
        if any(char in WILDCARDS for char in part):
            break
        prefix.append(part)
    return tuple(prefix)


def globs_overlap(left: str, right: str) -> bool:
    a, b = literal_prefix(left), literal_prefix(right)
    shared = min(len(a), len(b))
    return a[:shared] == b[:shared]


def find_overlaps(wanted: list[str], held: list[str]) -> list[tuple[str, str]]:
    return [(w, h) for w in wanted for h in held if globs_overlap(w, h)]
```

- [ ] **Step 5: Run it to verify it passes.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_basics.py' -v`
Expected: `Ran 7 tests` and `OK`.

- [ ] **Step 6: Commit.**

```bash
printf '__pycache__/\n' > .gitignore
git add .gitignore swarmlib tests/test_basics.py
git commit -m "feat(swarm): pure helpers for time, front matter, secrets and path overlap"
```

### Task 4: Git transport and the store transaction

**Files:**
- Create: `swarmlib/gitio.py`, `swarmlib/store.py`, `tests/support.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: Task 3 modules.
- Produces: `gitio.run(repo, *args, check=True) -> CompletedProcess`, `gitio.out(repo, *args) -> str`, `gitio.auth_args() -> list[str]`, `gitio.GitError`; `Store(root, agent, role="", vendor="", remote="origin", hooks=[])` with `.from_env()`, `.path(*parts)`, `.git(*args, check=True)`, `.sync()`, `.config() -> dict`, `.halt_reason() -> str | None`, `.transact(message, mutate: Callable[[], bool], *, ignore_halt=False) -> bool`; `store.SwarmError`, `store.Halted`, `store.halt(store, scope, reason)`, `store.resume(store, scope | None)`, `store.set_config(store, key, raw_json)`, `store.record(store, kind, name, text) -> str` (kind `decision`, auto-numbered `decisions/NNNN-<name>.md`, or `digest`, `digests/<name>.md`; conductor only), `store.CONFIG_DEFAULTS`. Test fixture `support.SwarmCase` with `clone(agent, role, vendor) -> Store`, `at(iso)`, `add_item(conductor, item_id, **overrides)`, `make_arc() -> (arc_bare, local_clone)`; helpers `git(cwd, *args)`, `commit_all(repo, msg)`, `BRIEF`.

- [ ] **Step 1: Write the fixture** at `tests/support.py`:

```python
"""Shared fixtures: a bare origin with a seeded swarm branch, agent clones, and a fake arc repo."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from swarmlib.store import Store

SEED_DIRS = ("agents", "items", "claims", "msgs", "decisions", "digests")
BRIEF = "## Brief\n\nDo the thing.\n\n## Acceptance\n\n- It is done.\n"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class SwarmCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="swarm-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.dict(os.environ, {
            "SWARM_STATE_DIR": str(self.tmp / "state"),
            "SWARM_BUILD_DIR": str(self.tmp / "build"),
            "SWARM_LOG_DIR": str(self.tmp / "logs"),
            "SWARM_FAKE_NOW": "2026-10-06T12:00:00Z",
            "GH_TOKEN": "",
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        self.origin = self.tmp / "origin.git"
        git(self.tmp, "init", "--quiet", "--bare", "--initial-branch=swarm", str(self.origin))
        seed = self.tmp / "seed"
        git(self.tmp, "init", "--quiet", "--initial-branch=swarm", str(seed))
        for name in SEED_DIRS:
            (seed / name).mkdir()
            (seed / name / ".keep").write_text("")
        commit_all(seed, "seed")
        git(seed, "push", "--quiet", str(self.origin), "swarm")

    def clone(self, agent: str, role: str = "worker", vendor: str = "codex") -> Store:
        path = self.tmp / "clones" / agent
        git(self.tmp, "clone", "--quiet", "--single-branch", "--branch", "swarm", str(self.origin), str(path))
        return Store(root=path, agent=agent, role=role, vendor=vendor)

    def at(self, when: str) -> None:
        os.environ["SWARM_FAKE_NOW"] = when

    def add_item(self, conductor: Store, item_id: str, **overrides) -> None:
        from swarmlib import items  # imported late: items arrives after the store task

        fields = dict(
            item_id=item_id, title=f"Fix {item_id}", severity="P2", wave=1, tier="mid",
            paths=[f"crates/{item_id.lower()}/**"], depends_on=[], estimate_hours=4, assignee="", brief=BRIEF,
        )
        fields.update(overrides)
        items.new(conductor, **fields)

    def make_arc(self) -> tuple[Path, Path]:
        """A bare 'arc' remote with main and integration/beta-next, plus a local clone."""
        arc = self.tmp / "arc.git"
        git(self.tmp, "init", "--quiet", "--bare", "--initial-branch=main", str(arc))
        work = self.tmp / "arc-seed"
        git(self.tmp, "init", "--quiet", "--initial-branch=main", str(work))
        (work / "README.md").write_text("arc\n")
        commit_all(work, "init")
        git(work, "push", "--quiet", str(arc), "main", "main:integration/beta-next")
        repo = self.tmp / "repo"
        git(self.tmp, "clone", "--quiet", str(arc), str(repo))
        os.environ["SWARM_GIT_URL"] = str(arc)
        return arc, repo
```

- [ ] **Step 2: Write the failing test** at `tests/test_store.py`:

```python
import shutil
import unittest

from support import SwarmCase, git

from swarmlib import gitio
from swarmlib.store import Halted, SwarmError, halt, record, resume, set_config


class StoreTest(SwarmCase):
    def test_transact_pushes_and_other_clones_see_it(self):
        a, b = self.clone("codex-ws2-worker1"), self.clone("claude-air-worker2")

        def write() -> bool:
            a.path("items", "note.md").write_text("hello\n")
            return True

        self.assertTrue(a.transact("note", write))
        b.sync()
        self.assertEqual(b.path("items", "note.md").read_text(), "hello\n")
        self.assertIn("[swarm] codex-ws2-worker1: note", git(self.origin, "log", "-1", "--format=%s", "swarm"))

    def test_rejected_push_reapplies_mutation_on_fresh_head(self):
        a, b = self.clone("codex-ws2-worker1"), self.clone("claude-air-worker2")
        calls = []

        def b_write() -> bool:
            calls.append(1)
            if len(calls) == 1:  # someone else lands a commit mid-transaction
                a.transact("a", lambda: bool(a.path("items", "a.md").write_text("a\n")))
            b.path("items", "b.md").write_text("b\n")
            return True

        self.assertTrue(b.transact("b", b_write))
        self.assertEqual(len(calls), 2)
        a.sync()
        self.assertTrue(a.path("items", "a.md").exists() and a.path("items", "b.md").exists())

    def test_noop_mutation_does_not_commit(self):
        a = self.clone("codex-ws2-worker1")
        before = git(self.origin, "rev-parse", "swarm")
        self.assertFalse(a.transact("noop", lambda: False))
        self.assertEqual(git(self.origin, "rev-parse", "swarm"), before)

    def test_secret_guard_blocks_push(self):
        a = self.clone("codex-ws2-worker1")
        before = git(self.origin, "rev-parse", "swarm")
        planted = "key " + "sk-" + "ant-" + "z" * 40

        with self.assertRaises(SwarmError):
            a.transact("leak", lambda: bool(a.path("msgs", "leak.md").write_text(planted)))
        self.assertEqual(git(self.origin, "rev-parse", "swarm"), before)

    def test_halt_blocks_writes_until_resumed(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        halt(conductor, "role:worker", "pilot paused")
        with self.assertRaises(Halted):
            worker.transact("x", lambda: bool(worker.path("items", "x.md").write_text("x\n")))
        resume(conductor, None)
        self.assertTrue(worker.transact("x", lambda: bool(worker.path("items", "x.md").write_text("x\n"))))

    def test_only_conductor_halts_and_sets_config(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(SwarmError):
            halt(worker, "all", "nope")
        with self.assertRaises(SwarmError):
            set_config(worker, "active_waves", "[1, 2]")

    def test_config_defaults_and_override(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.assertEqual(conductor.config()["base_branch"], "integration/beta-next")
        set_config(conductor, "active_waves", "[1, 2]")
        conductor.sync()
        self.assertEqual(conductor.config()["active_waves"], [1, 2])

    # Review focus: an agent killed between commit and push leaves nothing behind.
    def test_interrupted_push_is_discarded_by_next_sync(self):
        a = self.clone("codex-ws2-worker1")
        before = git(self.origin, "rev-parse", "swarm")
        a.path("items", "half.md").write_text("half\n")
        git(a.root, "add", "-A")
        git(a.root, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "--quiet", "-m", "unpushed")
        a.sync()
        self.assertFalse(a.path("items", "half.md").exists())
        self.assertEqual(git(self.origin, "rev-parse", "swarm"), before)

    # Review focus: GitHub unreachable fails closed with a clear error.
    def test_unreachable_origin_raises_git_error(self):
        a = self.clone("codex-ws2-worker1")
        shutil.rmtree(self.origin)
        with self.assertRaises(gitio.GitError):
            a.transact("x", lambda: bool(a.path("items", "x.md").write_text("x\n")))

    def test_record_numbers_decisions_and_names_digests(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.assertEqual(record(conductor, "decision", "first", "one"), "decisions/0001-first.md")
        self.assertEqual(record(conductor, "decision", "second", "two"), "decisions/0002-second.md")
        self.assertEqual(record(conductor, "digest", "2026-10-07-am", "landed: F1"), "digests/2026-10-07-am.md")
        with self.assertRaises(SwarmError):
            record(conductor, "digest", "2026-10-07-am", "again")
        conductor.sync()
        self.assertEqual(conductor.path("decisions", "0002-second.md").read_text(), "two\n")

    def test_record_requires_conductor_and_safe_names(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(SwarmError):
            record(worker, "decision", "x", "y")
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        with self.assertRaises(SwarmError):
            record(conductor, "digest", "../escape", "y")

    def test_missing_agent_identity_refused(self):
        a = self.clone("codex-ws2-worker1")
        a.agent = ""
        with self.assertRaises(SwarmError):
            a.transact("x", lambda: True)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_store.py' -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'swarmlib.store'`.

- [ ] **Step 4: Implement.** `swarmlib/gitio.py`:

```python
"""Thin subprocess wrapper around git."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

AUTH_HELPER = '!f() { test "$1" = get || exit 0; echo username=x-access-token; echo "password=$GH_TOKEN"; }; f'


class GitError(RuntimeError):
    pass


def auth_args() -> list[str]:
    """Credential helper that answers HTTPS prompts from $GH_TOKEN, if set."""
    if not os.environ.get("GH_TOKEN"):
        return []
    return ["-c", "credential.helper=", "-c", f"credential.helper={AUTH_HELPER}"]


def run(repo: Path | None, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if check and proc.returncode != 0:
        shown = [a for a in args if not a.startswith("credential.helper")]
        raise GitError(f"git {' '.join(shown)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def out(repo: Path | None, *args: str) -> str:
    return run(repo, *args).stdout.strip()
```

`swarmlib/store.py`:

```python
"""Git-backed coordination store with optimistic concurrency.

Every write fetches the remote `swarm` branch, applies an idempotent
mutation, commits and pushes. A rejected (non-fast-forward) push means
someone else won the race: reset to the new head and apply again.
"""

from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import clock, frontmatter, gitio, secrets

BRANCH = "swarm"
MAX_ATTEMPTS = 8
CONFIG_DEFAULTS = {
    "active_waves": [1],
    "base_branch": "integration/beta-next",
    "ci_max_in_flight": 10,
    "train_pr": 0,
}


class SwarmError(RuntimeError):
    """A refusal the CLI reports to the caller (exit status 2)."""


class Halted(SwarmError):
    """The swarm, this role, or this agent is halted."""


@dataclass
class Store:
    root: Path
    agent: str
    role: str = ""
    vendor: str = ""
    remote: str = "origin"
    hooks: list[Callable[[], None]] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Store":
        root = Path(os.environ.get("SWARM_HOME", str(Path.home() / "swarm"))).expanduser()
        return cls(
            root=root,
            agent=os.environ.get("SWARM_AGENT", ""),
            role=os.environ.get("SWARM_ROLE", ""),
            vendor=os.environ.get("SWARM_VENDOR", ""),
        )

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def git(self, *args: str, check: bool = True):
        return gitio.run(self.root, *gitio.auth_args(), *args, check=check)

    def sync(self) -> None:
        """Discard local state and move to the remote head."""
        self.git("fetch", "--quiet", self.remote, BRANCH)
        self.git("reset", "--quiet", "--hard", "FETCH_HEAD")
        self.git("clean", "-fdq")

    def config(self) -> dict:
        path = self.path("config.json")
        data = json.loads(path.read_text()) if path.exists() else {}
        return {**CONFIG_DEFAULTS, **data}

    def halt_reason(self) -> str | None:
        path = self.path("HALT")
        if not path.exists():
            return None
        meta, _ = frontmatter.parse(path.read_text())
        mine = {"all", f"agent:{self.agent}"} | ({f"role:{self.role}"} if self.role else set())
        if mine & set(meta.get("scopes", [])):
            return str(meta.get("reason", "halted"))
        return None

    def transact(self, message: str, mutate: Callable[[], bool], *, ignore_halt: bool = False) -> bool:
        """Apply `mutate` to a fresh copy of the remote head and push it."""
        if not self.agent:
            raise SwarmError("SWARM_AGENT is not set")
        for attempt in range(MAX_ATTEMPTS):
            self.sync()
            if not ignore_halt:
                reason = self.halt_reason()
                if reason is not None:
                    raise Halted(f"swarm is halted: {reason}")
            if not mutate():
                return False
            for hook in self.hooks:
                hook()
            self.git("add", "-A")
            staged = self.git("diff", "--cached", "--name-only").stdout.split()
            if not staged:
                return False
            self._refuse_secrets(staged)
            email = os.environ.get("SWARM_EMAIL", f"{self.agent}@swarm.invalid")
            self.git(
                "-c", f"user.name={self.agent}", "-c", f"user.email={email}",
                "commit", "--quiet", "--no-verify", "-m", f"[swarm] {self.agent}: {message}",
            )
            pushed = self.git("push", "--quiet", self.remote, f"HEAD:refs/heads/{BRANCH}", check=False)
            if pushed.returncode == 0:
                return True
            time.sleep(random.uniform(0.05, 0.3) * (attempt + 1))
        raise SwarmError(f"gave up after {MAX_ATTEMPTS} contended pushes: {message}")

    def _refuse_secrets(self, staged: list[str]) -> None:
        findings = []
        for name in staged:
            path = self.path(name)
            if path.is_file():
                text = path.read_text(errors="replace")
                findings += [f"{name}:{line}: {kind}" for kind, line in secrets.scan(text)]
        if findings:
            raise SwarmError("refusing to push credential-shaped content:\n  " + "\n  ".join(findings))


def halt(store: Store, scope: str, reason: str) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor (or Connor, with SWARM_ROLE=conductor) can halt")
    if scope != "all" and not scope.startswith(("role:", "agent:")):
        raise SwarmError("scope must be 'all', 'role:<role>' or 'agent:<id>'")

    def mutate() -> bool:
        path = store.path("HALT")
        meta = frontmatter.parse(path.read_text())[0] if path.exists() else {"scopes": []}
        if scope in meta["scopes"]:
            return False
        meta.update(scopes=meta["scopes"] + [scope], reason=reason, by=store.agent, at=clock.fmt(clock.now()))
        path.write_text(frontmatter.dump(meta, ""))
        return True

    store.transact(f"halt {scope}", mutate, ignore_halt=True)


def resume(store: Store, scope: str | None) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor (or Connor, with SWARM_ROLE=conductor) can resume")

    def mutate() -> bool:
        path = store.path("HALT")
        if not path.exists():
            return False
        meta, _ = frontmatter.parse(path.read_text())
        remaining = [] if scope is None else [s for s in meta["scopes"] if s != scope]
        if remaining:
            meta["scopes"] = remaining
            path.write_text(frontmatter.dump(meta, ""))
        else:
            path.unlink()
        return True

    store.transact(f"resume {scope or 'all'}", mutate, ignore_halt=True)


def set_config(store: Store, key: str, raw_value: str) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor changes config.json")
    if key not in CONFIG_DEFAULTS:
        raise SwarmError(f"unknown config key {key!r}; known: {', '.join(CONFIG_DEFAULTS)}")
    value = json.loads(raw_value)

    def mutate() -> bool:
        path = store.path("config.json")
        data = json.loads(path.read_text()) if path.exists() else {}
        data[key] = value
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        return True

    store.transact(f"config {key}", mutate)


RECORD_KINDS = {"decision": "decisions", "digest": "digests"}


def record(store: Store, kind: str, name: str, text: str) -> str:
    """Write a conductor decision (auto-numbered) or digest. Returns its path in the store."""
    if store.role != "conductor":
        raise SwarmError("only the conductor records decisions and digests")
    if kind not in RECORD_KINDS:
        raise SwarmError(f"kind must be one of {', '.join(RECORD_KINDS)}")
    if not name or not all(c.isalnum() or c in "-." for c in name):
        raise SwarmError("name may contain only letters, digits, '-' and '.'")
    written: list[str] = []

    def mutate() -> bool:
        folder = store.path(RECORD_KINDS[kind])
        folder.mkdir(parents=True, exist_ok=True)
        if kind == "decision":
            numbers = [int(p.name[:4]) for p in folder.glob("[0-9][0-9][0-9][0-9]-*.md")]
            filename = f"{max(numbers, default=0) + 1:04d}-{name}.md"
        else:
            filename = f"{name}.md"
        target = folder / filename
        if target.exists():
            raise SwarmError(f"{RECORD_KINDS[kind]}/{filename} already exists")
        target.write_text(text.rstrip("\n") + "\n")
        written[:] = [f"{RECORD_KINDS[kind]}/{filename}"]
        return True

    store.transact(f"record {kind} {name}", mutate)
    return written[0]
```

- [ ] **Step 5: Run it to verify it passes.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_store.py' -v`
Expected: `Ran 12 tests` and `OK`.

- [ ] **Step 6: Commit.**

```bash
git add swarmlib/gitio.py swarmlib/store.py tests/support.py tests/test_store.py
git commit -m "feat(swarm): git-backed store with optimistic push transactions"
```

### Task 5: Roster, items, messages and claims

**Files:**
- Create: `swarmlib/agents.py`, `swarmlib/items.py`, `swarmlib/msgs.py`, `swarmlib/claims.py`
- Test: `tests/test_msgs.py`, `tests/test_claims.py`

**Interfaces:**
- Consumes: `Store`, `SwarmError`, `clock`, `frontmatter`, `paths`.
- Produces: `agents.ROLES`, `agents.VENDORS`, `agents.TIERS`, `agents.register(store, *, agent_id, machine, vendor, role, model, effort, tiers)`, `agents.load(store, id) -> dict | None`, `agents.all_agents(store) -> list[dict]`, `agents.touch(store, *, status=None, throttled_until=None) -> bool`, `agents.is_stale(meta) -> bool`; `items.Item(meta, body)` with `.id`, `.status`, `.log(agent, text)`, `.add_section(heading, text)`, plus `items.STATUSES`, `SEVERITIES`, `FINISHED`, `CLOSED`, `TRANSITIONS`, `exists`, `load`, `save`, `all_items(store) -> (list[Item], list[str])`, `create(...)`, `new(store, **fields)`, `deps_unmet(store, item) -> list[str]`, `check_transition(store, item, new_status)`; `msgs.KINDS`, `msgs.write(store, to, kind, item_id, subject, body) -> Path` (inside a transaction), `msgs.send(...)`, `msgs.inbox(store, *, include_seen=False, mark=True, sync=True) -> list[dict]`, `msgs.mark_seen(store, keys)`; `claims.DEFAULT_TTL_MINUTES`, `claims.GRACE_MINUTES`, `claims.read`, `write`, `remove`, `all_claims`, `is_expired(claim, now)`, `active(store, now)`, `claim(store, item_id, globs, *, share=False, steal=False, ttl=45, owner=None)`, `renew_mine(store)`, `heartbeat(store, *, status=None, throttled_until=None)`, `release(store, item_id)`, `reassign(store, item_id, new_owner, *, ttl=45)`.

- [ ] **Step 1: Write the failing tests.** `tests/test_msgs.py`:

```python
import unittest

from support import SwarmCase

from swarmlib import agents, msgs
from swarmlib.store import SwarmError


class MessagesTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="m", effort="", tiers=["mid"])

    def test_direct_role_and_broadcast_delivery(self):
        msgs.send(self.conductor, "codex-ws2-worker1", "request", "F1", "direct", "a")
        msgs.send(self.conductor, "worker", "fyi", "", "to role", "b")
        msgs.send(self.conductor, "all", "fyi", "", "everyone", "c")
        msgs.send(self.conductor, "reviewer", "fyi", "", "not mine", "d")
        subjects = [m["subject"] for m in msgs.inbox(self.worker)]
        self.assertEqual(sorted(subjects), ["direct", "everyone", "to role"])
        self.assertEqual(msgs.inbox(self.worker), [])
        self.assertEqual(len(msgs.inbox(self.worker, include_seen=True)), 3)

    def test_own_broadcasts_are_not_echoed(self):
        msgs.send(self.worker, "all", "fyi", "", "mine", "x")
        self.assertEqual(msgs.inbox(self.worker), [])

    def test_unknown_recipient_and_kind_refused(self):
        with self.assertRaises(SwarmError):
            msgs.send(self.worker, "nobody-here", "fyi", "", "s", "b")
        with self.assertRaises(SwarmError):
            msgs.send(self.worker, "conductor", "shout", "", "s", "b")


if __name__ == "__main__":
    unittest.main()
```

`tests/test_claims.py`:

```python
import unittest

from support import SwarmCase

from swarmlib import agents, claims, items, msgs
from swarmlib.store import SwarmError


class ClaimsTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.a = self.clone("codex-ws2-worker1")
        self.b = self.clone("claude-air-worker2", vendor="claude")
        for store, vendor in ((self.a, "codex"), (self.b, "claude")):
            agents.register(store, agent_id=store.agent, machine="m", vendor=vendor, role="worker",
                            model="m", effort="", tiers=["mid"])

    def test_claim_marks_item_and_writes_lease(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        self.a.sync()
        item = items.load(self.a, "F1")
        self.assertEqual((item.status, item.meta["owner"]), ("claimed", "codex-ws2-worker1"))
        lease = claims.read(self.a, "F1")
        self.assertEqual(lease["paths"], ["crates/f1/**"])
        self.assertEqual(lease["expires"], "2026-10-06T12:45:00Z")

    def test_racing_claims_exactly_one_wins(self):
        self.add_item(self.conductor, "F1")
        calls = []
        original = self.b.transact

        def racing_transact(message, mutate, **kw):
            def wrapped():
                calls.append(1)
                if len(calls) == 1:
                    claims.claim(self.a, "F1", [])  # A lands first, mid-transaction
                return mutate()
            return original(message, wrapped, **kw)

        self.b.transact = racing_transact
        with self.assertRaisesRegex(SwarmError, "claimed by codex-ws2-worker1"):
            claims.claim(self.b, "F1", [])
        self.b.sync()
        self.assertEqual(claims.read(self.b, "F1")["agent"], "codex-ws2-worker1")

    def test_overlapping_paths_refused_unless_shared(self):
        self.add_item(self.conductor, "F1", paths=["crates/kernel/src/**"])
        self.add_item(self.conductor, "F2", paths=["crates/kernel/src/eval.rs"])
        claims.claim(self.a, "F1", [])
        with self.assertRaisesRegex(SwarmError, "overlap"):
            claims.claim(self.b, "F2", [])
        claims.claim(self.b, "F2", [], share=True)
        self.b.sync()
        self.assertTrue(claims.read(self.b, "F2")["shared"])

    def test_unmet_dependencies_refused(self):
        self.add_item(self.conductor, "W1")
        self.add_item(self.conductor, "W2", depends_on=["W1"])
        with self.assertRaisesRegex(SwarmError, "W1 \\(open\\)"):
            claims.claim(self.a, "W2", [])

    # Review focus: a little clock skew must not let someone steal a live claim.
    def test_expiry_respects_grace_then_allows_steal(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        self.at("2026-10-06T12:46:00Z")  # 1 minute past expiry, inside the 2 minute grace
        with self.assertRaisesRegex(SwarmError, "claimed by"):
            claims.claim(self.b, "F1", [], steal=True)
        self.at("2026-10-06T12:48:00Z")
        with self.assertRaisesRegex(SwarmError, "--steal"):
            claims.claim(self.b, "F1", [])
        claims.claim(self.b, "F1", [], steal=True)
        self.a.sync()
        self.assertEqual(claims.read(self.a, "F1")["agent"], "claude-air-worker2")
        notes = msgs.inbox(self.a)
        self.assertEqual([m["subject"] for m in notes], ["claim on F1 taken over"])

    def test_heartbeat_extends_only_my_leases(self):
        self.add_item(self.conductor, "F1")
        self.add_item(self.conductor, "F2")
        claims.claim(self.a, "F1", [])
        claims.claim(self.b, "F2", [])
        self.at("2026-10-06T12:30:00Z")
        claims.heartbeat(self.a)
        self.a.sync()
        self.assertEqual(claims.read(self.a, "F1")["expires"], "2026-10-06T13:15:00Z")
        self.assertEqual(claims.read(self.a, "F2")["expires"], "2026-10-06T12:45:00Z")
        self.assertEqual(agents.load(self.a, "codex-ws2-worker1")["last_heartbeat"], "2026-10-06T12:30:00Z")

    def test_release_requires_owner(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        with self.assertRaises(SwarmError):
            claims.release(self.b, "F1")
        claims.release(self.a, "F1")
        self.a.sync()
        self.assertIsNone(claims.read(self.a, "F1"))

    def test_reassign_is_conductor_only_and_messages_both(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        with self.assertRaises(SwarmError):
            claims.reassign(self.b, "F1", "claude-air-worker2")
        claims.reassign(self.conductor, "F1", "claude-air-worker2", ttl=480)
        self.b.sync()
        self.assertEqual(items.load(self.b, "F1").meta["owner"], "claude-air-worker2")
        self.assertEqual(claims.read(self.b, "F1")["ttl_minutes"], 480)
        self.assertEqual(len(msgs.inbox(self.a)), 1)
        self.assertEqual(len(msgs.inbox(self.b)), 1)

    def test_conductor_only_claims_for_others(self):
        self.add_item(self.conductor, "F1")
        with self.assertRaises(SwarmError):
            claims.claim(self.a, "F1", [], owner="claude-air-worker2")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run them to verify they fail.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_[mc]*.py' -v`
Expected: FAIL with `ImportError: cannot import name 'agents' from 'swarmlib'`.

- [ ] **Step 3: Implement.** `swarmlib/agents.py`:

```python
"""Agent roster: agents/<id>.md front matter."""

from __future__ import annotations

import re
from pathlib import Path

from . import clock, frontmatter
from .store import Store, SwarmError

ROLES = ("conductor", "integrator", "worker", "reviewer", "docs", "janitor", "security")
VENDORS = ("claude", "codex", "cursor", "hermes")
TIERS = ("premium", "mid", "cheap")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
STALE_MINUTES = 30


def _path(store: Store, agent_id: str) -> Path:
    return store.path("agents", f"{agent_id}.md")


def load(store: Store, agent_id: str) -> dict | None:
    path = _path(store, agent_id)
    if not path.exists():
        return None
    return frontmatter.parse(path.read_text())[0]


def all_agents(store: Store) -> list[dict]:
    return [frontmatter.parse(p.read_text())[0] for p in sorted(store.path("agents").glob("*.md"))]


def register(
    store: Store, *, agent_id: str, machine: str, vendor: str, role: str, model: str, effort: str, tiers: list[str]
) -> None:
    if not ID_RE.match(agent_id):
        raise SwarmError(f"bad agent id {agent_id!r}; use <vendor>-<machine>-<role><n>")
    if vendor not in VENDORS:
        raise SwarmError(f"vendor must be one of {', '.join(VENDORS)}")
    if role not in ROLES:
        raise SwarmError(f"role must be one of {', '.join(ROLES)}")
    if not set(tiers) <= set(TIERS):
        raise SwarmError(f"tiers must be drawn from {', '.join(TIERS)}")
    if agent_id != store.agent and store.role != "conductor":
        raise SwarmError("agents register themselves; only the conductor registers others")

    def mutate() -> bool:
        _path(store, agent_id).parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "id": agent_id, "machine": machine, "vendor": vendor, "role": role, "model": model,
            "effort": effort, "tiers": tiers, "status": "active",
            "last_heartbeat": clock.fmt(clock.now()), "throttled_until": "",
        }
        _path(store, agent_id).write_text(frontmatter.dump(meta, ""))
        return True

    store.transact(f"register {agent_id}", mutate)


def touch(store: Store, *, status: str | None = None, throttled_until: str | None = None) -> bool:
    """Refresh the caller's heartbeat. Call inside a transaction."""
    meta = load(store, store.agent)
    if meta is None:
        return False
    meta["last_heartbeat"] = clock.fmt(clock.now())
    if status is not None:
        meta["status"] = status
    if throttled_until is not None:
        meta["throttled_until"] = throttled_until
    _path(store, store.agent).write_text(frontmatter.dump(meta, ""))
    return True


def is_stale(meta: dict) -> bool:
    beat = meta.get("last_heartbeat")
    return not beat or clock.now() - clock.parse(beat) > clock.minutes(STALE_MINUTES)
```

`swarmlib/items.py`:

```python
"""Work items: items/<ID>.md with front matter and Brief/Acceptance/Log sections."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path

from . import clock, frontmatter
from .agents import TIERS
from .store import Store, SwarmError

STATUSES = (
    "open", "claimed", "in-progress", "review", "ready", "integrated", "done",
    "blocked", "disputed", "deferred", "wontfix",
)
SEVERITIES = ("P0", "P1", "P2", "P3")
FINISHED = ("integrated", "done")
CLOSED = ("integrated", "done", "wontfix", "deferred")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

DEFAULTS: dict = {
    "id": "", "title": "", "severity": "P2", "wave": 1, "tier": "mid",
    "status": "open", "owner": "", "assignee": "", "depends_on": [], "paths": [],
    "branch": "", "commits": [], "author_vendor": "", "estimate_hours": 4,
    "review": {"verdict": "", "reviewer": "", "round": 0},
    "attempts": {"started": "", "ci_failures": 0},
    "evidence": [],
}

# (from, to) -> roles that may make the move; "owner" is the item's current owner.
# The conductor may make any move.
TRANSITIONS: dict[tuple[str, str], frozenset[str]] = {
    ("claimed", "in-progress"): frozenset({"owner"}),
    ("in-progress", "review"): frozenset({"owner"}),
    ("review", "ready"): frozenset({"reviewer"}),
    ("review", "in-progress"): frozenset({"reviewer"}),
    ("review", "blocked"): frozenset({"reviewer"}),
    ("review", "disputed"): frozenset({"owner", "reviewer"}),
    ("ready", "integrated"): frozenset({"integrator"}),
    ("ready", "in-progress"): frozenset({"integrator"}),
    ("integrated", "in-progress"): frozenset({"integrator"}),
    ("integrated", "done"): frozenset({"integrator"}),
    ("claimed", "blocked"): frozenset({"owner", "janitor"}),
    ("in-progress", "blocked"): frozenset({"owner", "janitor"}),
}


@dataclass
class Item:
    meta: dict
    body: str

    @property
    def id(self) -> str:
        return self.meta["id"]

    @property
    def status(self) -> str:
        return self.meta["status"]

    def log(self, agent: str, text: str) -> None:
        if not self.body.endswith("\n"):
            self.body += "\n"
        if "## Log\n" not in self.body:
            self.body += "\n## Log\n"
        self.body += f"- {clock.fmt(clock.now())} {agent}: {text}\n"

    def add_section(self, heading: str, text: str) -> None:
        """Insert a section directly above the Log."""
        section = f"## {heading}\n\n{text.strip()}\n\n"
        marker = "## Log\n"
        if marker in self.body:
            head, tail = self.body.split(marker, 1)
            self.body = f"{head}{section}{marker}{tail}"
        else:
            self.body += f"\n{section}"


def _path(store: Store, item_id: str) -> Path:
    return store.path("items", f"{item_id}.md")


def exists(store: Store, item_id: str) -> bool:
    return _path(store, item_id).exists()


def load(store: Store, item_id: str) -> Item:
    path = _path(store, item_id)
    if not path.exists():
        raise SwarmError(f"no such item: {item_id}")
    try:
        meta, body = frontmatter.parse(path.read_text())
    except frontmatter.FrontMatterError as err:
        raise SwarmError(f"items/{item_id}.md is malformed: {err}") from err
    merged = copy.deepcopy(DEFAULTS)
    merged.update(meta)
    return Item(merged, body)


def save(store: Store, item: Item) -> None:
    path = _path(store, item.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(frontmatter.dump(item.meta, item.body))


def all_items(store: Store) -> tuple[list[Item], list[str]]:
    """Every parseable item, plus the file names that failed to parse."""
    good, bad = [], []
    for path in sorted(store.path("items").glob("*.md")):
        try:
            good.append(load(store, path.stem))
        except SwarmError:
            bad.append(path.name)
    return good, bad


def create(
    store: Store, *, item_id: str, title: str, severity: str, wave: int, tier: str,
    paths: list[str], depends_on: list[str], estimate_hours: float, assignee: str, brief: str,
) -> Item:
    if not ID_RE.match(item_id):
        raise SwarmError(f"bad item id {item_id!r}")
    if severity not in SEVERITIES:
        raise SwarmError(f"severity must be one of {', '.join(SEVERITIES)}")
    if tier not in TIERS:
        raise SwarmError(f"tier must be one of {', '.join(TIERS)}")
    if "## Brief" not in brief or "## Acceptance" not in brief:
        raise SwarmError("brief must contain '## Brief' and '## Acceptance' sections")
    meta = copy.deepcopy(DEFAULTS)
    meta.update(
        id=item_id, title=title, severity=severity, wave=wave, tier=tier, paths=paths,
        depends_on=depends_on, estimate_hours=estimate_hours, assignee=assignee,
    )
    item = Item(meta, brief.rstrip("\n") + "\n")
    item.log(store.agent, "created")
    return item


def new(store: Store, **fields) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor creates items")

    def mutate() -> bool:
        if exists(store, fields["item_id"]):
            raise SwarmError(f"item {fields['item_id']} already exists")
        save(store, create(store, **fields))
        return True

    store.transact(f"new {fields['item_id']}", mutate)


def deps_unmet(store: Store, item: Item) -> list[str]:
    unmet = []
    for dep in item.meta["depends_on"]:
        if not exists(store, dep):
            unmet.append(f"{dep} (missing)")
            continue
        status = load(store, dep).status
        if status not in FINISHED:
            unmet.append(f"{dep} ({status})")
    return unmet


def check_transition(store: Store, item: Item, new_status: str) -> None:
    if new_status not in STATUSES:
        raise SwarmError(f"unknown status {new_status!r}")
    if store.role == "conductor":
        return
    allowed = TRANSITIONS.get((item.status, new_status))
    if allowed is None:
        raise SwarmError(f"{item.id}: {item.status} -> {new_status} is not a permitted move")
    actor = {store.role} | ({"owner"} if item.meta["owner"] == store.agent else set())
    if not allowed & actor:
        raise SwarmError(f"{item.id}: {store.agent} ({store.role or 'no role'}) may not move {item.status} -> {new_status}")
```

`swarmlib/msgs.py`:

```python
"""Append-only inboxes under msgs/<recipient>/. Read state stays local."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from . import agents, clock, frontmatter
from .store import Store, SwarmError

KINDS = ("request", "handoff", "verdict", "blocker", "fyi")
BROADCAST = ("all", "human")


def _valid_recipient(store: Store, to: str) -> bool:
    return to in BROADCAST or to in agents.ROLES or store.path("agents", f"{to}.md").exists()


def write(store: Store, to: str, kind: str, item_id: str, subject: str, body: str) -> Path:
    """Create one message file. Call inside a transaction."""
    if kind not in KINDS:
        raise SwarmError(f"unknown message kind {kind!r}; use one of {', '.join(KINDS)}")
    if not _valid_recipient(store, to):
        raise SwarmError(f"unknown recipient {to!r}")
    folder = store.path("msgs", to)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{clock.stamp()}-{store.agent}-{uuid.uuid4().hex[:6]}.md"
    meta = {
        "from": store.agent, "to": to, "kind": kind, "item": item_id,
        "subject": subject, "sent": clock.fmt(clock.now()),
    }
    path.write_text(frontmatter.dump(meta, body.rstrip("\n") + "\n"))
    return path


def send(store: Store, to: str, kind: str, item_id: str, subject: str, body: str) -> None:
    store.transact(f"msg {to}: {subject[:40]}", lambda: bool(write(store, to, kind, item_id, subject, body)))


def _state_file(store: Store) -> Path:
    base = Path(os.environ.get("SWARM_STATE_DIR", str(Path.home() / ".swarm-state"))).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{store.agent}.seen.json"


def _seen(store: Store) -> set[str]:
    path = _state_file(store)
    return set(json.loads(path.read_text())) if path.exists() else set()


def mark_seen(store: Store, keys: list[str]) -> None:
    path = _state_file(store)
    path.write_text(json.dumps(sorted(_seen(store) | set(keys))))


def inbox(store: Store, *, include_seen: bool = False, mark: bool = True, sync: bool = True) -> list[dict]:
    if sync:
        store.sync()
    folders = [store.agent, "all"] + ([store.role] if store.role else [])
    seen = _seen(store)
    found = []
    for folder in folders:
        for path in sorted(store.path("msgs", folder).glob("*.md")):
            key = f"{folder}/{path.name}"
            if key in seen and not include_seen:
                continue
            meta, body = frontmatter.parse(path.read_text())
            if meta["from"] == store.agent:
                continue
            found.append({**meta, "key": key, "body": body})
    found.sort(key=lambda message: message["sent"])
    if mark:
        mark_seen(store, [message["key"] for message in found])
    return found
```

`swarmlib/claims.py`:

```python
"""Path claims with leases. A claims/<ID>.json file existing is the lock."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import agents, clock, items, msgs, paths
from .store import Store, SwarmError

DEFAULT_TTL_MINUTES = 45
GRACE_MINUTES = 2  # tolerated clock skew between machines


def _path(store: Store, item_id: str) -> Path:
    return store.path("claims", f"{item_id}.json")


def read(store: Store, item_id: str) -> dict | None:
    path = _path(store, item_id)
    return json.loads(path.read_text()) if path.exists() else None


def write(store: Store, claim: dict) -> None:
    path = _path(store, claim["item"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n")


def remove(store: Store, item_id: str) -> None:
    _path(store, item_id).unlink(missing_ok=True)


def all_claims(store: Store) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(store.path("claims").glob("*.json"))]


def is_expired(claim: dict, now: datetime) -> bool:
    return now > clock.parse(claim["expires"]) + clock.minutes(GRACE_MINUTES)


def active(store: Store, now: datetime) -> list[dict]:
    return [c for c in all_claims(store) if not is_expired(c, now)]


def _lease(item_id: str, owner: str, wanted: list[str], share: bool, ttl: int, now: datetime) -> dict:
    return {
        "item": item_id, "agent": owner, "paths": wanted, "shared": share, "ttl_minutes": ttl,
        "acquired": clock.fmt(now), "expires": clock.fmt(now + clock.minutes(ttl)),
    }


def claim(
    store: Store, item_id: str, globs: list[str], *, share: bool = False, steal: bool = False,
    ttl: int = DEFAULT_TTL_MINUTES, owner: str | None = None,
) -> None:
    owner = owner or store.agent
    if owner != store.agent and store.role != "conductor":
        raise SwarmError("only the conductor claims on behalf of another agent")

    def mutate() -> bool:
        now = clock.now()
        item = items.load(store, item_id)
        existing = read(store, item_id)
        previous = None
        if existing is not None:
            if not is_expired(existing, now):
                raise SwarmError(f"{item_id} is claimed by {existing['agent']} until {existing['expires']}")
            if not steal:
                raise SwarmError(f"{item_id} has an expired claim by {existing['agent']}; use --steal")
            previous = existing["agent"]
        elif item.status != "open":
            raise SwarmError(f"{item_id} is {item.status}, not open")
        unmet = items.deps_unmet(store, item)
        if unmet:
            raise SwarmError(f"{item_id} waits on: {', '.join(unmet)}")
        wanted = list(globs) or list(item.meta["paths"])
        if not wanted:
            raise SwarmError(f"{item_id} lists no paths; pass --paths")
        if not share:
            clashes = [
                f"{w} vs {h} ({other['item']} by {other['agent']})"
                for other in active(store, now) if other["item"] != item_id
                for w, h in paths.find_overlaps(wanted, other["paths"])
            ]
            if clashes:
                raise SwarmError("paths overlap active claims: " + "; ".join(clashes))
        write(store, _lease(item_id, owner, wanted, share, ttl, now))
        item.meta["owner"] = owner
        if item.status == "open":
            item.meta["status"] = "claimed"
        if not item.meta["attempts"]["started"]:
            item.meta["attempts"]["started"] = clock.fmt(now)
        item.log(store.agent, f"claimed for {owner}" + (f", taking over from {previous}" if previous else ""))
        items.save(store, item)
        if previous and store.path("agents", f"{previous}.md").exists():
            msgs.write(store, previous, "fyi", item_id, f"claim on {item_id} taken over",
                       f"Your expired claim on {item_id} now belongs to {owner}.")
        return True

    store.transact(f"claim {item_id}", mutate)


def renew_mine(store: Store) -> None:
    """Extend the caller's leases and heartbeat. Runs inside every write."""
    now = clock.now()
    agents.touch(store)
    for lease in all_claims(store):
        if lease["agent"] == store.agent:
            lease["expires"] = clock.fmt(now + clock.minutes(lease.get("ttl_minutes", DEFAULT_TTL_MINUTES)))
            write(store, lease)


def heartbeat(store: Store, *, status: str | None = None, throttled_until: str | None = None) -> None:
    def mutate() -> bool:
        renew_mine(store)
        agents.touch(store, status=status, throttled_until=throttled_until)
        return True

    store.transact("heartbeat", mutate)


def release(store: Store, item_id: str) -> None:
    def mutate() -> bool:
        lease = read(store, item_id)
        if lease is None:
            return False
        if lease["agent"] != store.agent and store.role != "conductor":
            raise SwarmError(f"{item_id} is claimed by {lease['agent']}, not you")
        remove(store, item_id)
        item = items.load(store, item_id)
        item.log(store.agent, "released claim")
        items.save(store, item)
        return True

    store.transact(f"release {item_id}", mutate)


def reassign(store: Store, item_id: str, new_owner: str, *, ttl: int = DEFAULT_TTL_MINUTES) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor reassigns")

    def mutate() -> bool:
        now = clock.now()
        item = items.load(store, item_id)
        previous = item.meta["owner"]
        lease = read(store, item_id)
        wanted = lease["paths"] if lease else list(item.meta["paths"])
        write(store, _lease(item_id, new_owner, wanted, bool(lease and lease["shared"]), ttl, now))
        item.meta["owner"] = new_owner
        if item.status == "open":
            item.meta["status"] = "claimed"
        if not item.meta["attempts"]["started"]:
            item.meta["attempts"]["started"] = clock.fmt(now)
        item.log(store.agent, f"reassigned {previous or 'nobody'} -> {new_owner}")
        items.save(store, item)
        for who in (previous, new_owner):
            if who and store.path("agents", f"{who}.md").exists():
                msgs.write(store, who, "handoff", item_id, f"{item_id} reassigned to {new_owner}",
                           f"The conductor moved {item_id} from {previous or 'nobody'} to {new_owner}.")
        return True

    store.transact(f"reassign {item_id}", mutate)
```

- [ ] **Step 4: Run them to verify they pass.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_[mc]*.py' -v`
Expected: `Ran 12 tests` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add swarmlib/agents.py swarmlib/items.py swarmlib/msgs.py swarmlib/claims.py tests/test_msgs.py tests/test_claims.py
git commit -m "feat(swarm): roster, items, inboxes and leased path claims"
```

### Task 6: Lifecycle and lane worktrees

**Files:**
- Create: `swarmlib/lifecycle.py`, `swarmlib/worktree.py`
- Test: `tests/test_lifecycle.py`, `tests/test_worktree.py`

**Interfaces:**
- Consumes: Task 5 modules, `gitio`.
- Produces: `lifecycle.status(store, item_id, new_status, note="")`, `record_evidence(store, item_id, entry, *, ci_failed=False)`, `submit(store, item_id, worktree, *, repo_url, base_branch) -> list[str]`, `verdict(store, item_id, decision, findings)`, `next_item(store, tiers) -> str | None`, `next_review(store) -> str | None`, `sweep(store) -> list[str]`, `wait(store, *, timeout=600, interval=30, heartbeat_every=600, sleep=time.sleep) -> list[str]`, `brief(store, item_id) -> str`, constants `REVIEW_ROUND_LIMIT = 2`, `CI_FAILURE_LIMIT = 3`; `worktree.repo_url()`, `slug(title)`, `lane_branch(item)`, `create(store, item_id, *, repo, lanes, base_branch, review=False) -> Path`.

- [ ] **Step 1: Write the failing tests.** `tests/test_lifecycle.py`:

```python
import unittest

from support import SwarmCase, commit_all, git

from swarmlib import agents, claims, items, lifecycle, msgs, worktree
from swarmlib.store import SwarmError, set_config


class LifecycleTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        self.reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        self.same_vendor_reviewer = self.clone("codex-ws2-reviewer2", role="reviewer", vendor="codex")
        self.integrator = self.clone("codex-ws2-integrator", role="integrator", vendor="codex")
        for store in (self.worker, self.reviewer, self.same_vendor_reviewer, self.integrator):
            agents.register(store, agent_id=store.agent, machine="ws2", vendor=store.vendor, role=store.role,
                            model="m", effort="", tiers=["mid", "premium"])

    def _to_review(self, item_id: str) -> None:
        claims.claim(self.worker, item_id, [])
        lifecycle.status(self.worker, item_id, "in-progress")
        lifecycle.status(self.worker, item_id, "review", "submitted")
        self.conductor.sync()

        def stamp_vendor() -> bool:
            item = items.load(self.conductor, item_id)
            item.meta["author_vendor"] = "codex"
            items.save(self.conductor, item)
            return True

        self.conductor.transact("vendor", stamp_vendor)

    def test_transition_table_enforced(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        with self.assertRaisesRegex(SwarmError, "not a permitted move"):
            lifecycle.status(self.worker, "F1", "ready")
        with self.assertRaisesRegex(SwarmError, "may not move"):
            lifecycle.status(self.integrator, "F1", "in-progress")
        lifecycle.status(self.worker, "F1", "in-progress")
        lifecycle.status(self.conductor, "F1", "deferred", "conductor may do anything")
        self.worker.sync()
        self.assertIsNone(claims.read(self.worker, "F1"))

    def test_review_accept_cross_vendor_only(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        self.assertEqual(lifecycle.next_review(self.same_vendor_reviewer), None)
        self.assertEqual(lifecycle.next_review(self.reviewer), "F1")
        lifecycle.verdict(self.reviewer, "F1", "accept", "")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "ready")
        self.assertEqual([m["kind"] for m in msgs.inbox(self.worker)], ["verdict"])

    def test_changes_return_item_then_block_after_round_limit(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        for expected in ("in-progress", "in-progress", "blocked"):
            lifecycle.next_review(self.reviewer)
            lifecycle.verdict(self.reviewer, "F1", "changes", "fix the edge case")
            self.worker.sync()
            item = items.load(self.worker, "F1")
            self.assertEqual(item.status, expected)
            if expected == "in-progress":
                lifecycle.status(self.worker, "F1", "review", "resubmitted")
        self.assertIn("## Review round 3", item.body)
        self.conductor.sync()
        self.assertTrue(any("review rounds" in m["subject"] for m in msgs.inbox(self.conductor)))

    def test_changes_need_findings(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        lifecycle.next_review(self.reviewer)
        with self.assertRaises(SwarmError):
            lifecycle.verdict(self.reviewer, "F1", "changes", "  ")

    def test_next_item_prefers_resume_assignee_then_severity(self):
        self.add_item(self.conductor, "A", severity="P2")
        self.add_item(self.conductor, "B", severity="P0")
        self.add_item(self.conductor, "C", severity="P3", assignee="codex-ws2-worker1")
        self.add_item(self.conductor, "D", severity="P0", tier="cheap")
        self.add_item(self.conductor, "E", severity="P0", wave=2)
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "C")
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "C")  # resumes, does not take more
        lifecycle.status(self.conductor, "C", "done")
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "B")
        set_config(self.conductor, "active_waves", "[1, 2]")
        lifecycle.status(self.conductor, "B", "done")
        self.assertEqual(lifecycle.next_item(self.worker, ["mid"]), "E")

    def test_integrator_bounce_messages_owner(self):
        self.add_item(self.conductor, "F1")
        self._to_review("F1")
        lifecycle.next_review(self.reviewer)
        lifecycle.verdict(self.reviewer, "F1", "accept", "")
        lifecycle.status(self.integrator, "F1", "integrated")
        lifecycle.status(self.integrator, "F1", "in-progress", "broke CI run 123")
        self.worker.sync()
        self.assertIn("returned by the integrator", [m["subject"] for m in msgs.inbox(self.worker)][-1])

    def test_ci_failure_budget_blocks(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        for _ in range(3):
            lifecycle.record_evidence(self.worker, "F1", {"kind": "lane-test", "conclusion": "failure", "url": "u"}, ci_failed=True)
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "blocked")

    def test_sweep_blocks_items_over_twice_estimate(self):
        self.add_item(self.conductor, "F1", estimate_hours=1)
        claims.claim(self.worker, "F1", [])
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        self.at("2026-10-06T13:59:00Z")
        self.assertEqual(lifecycle.sweep(janitor), [])
        self.at("2026-10-06T14:01:00Z")
        self.assertEqual(lifecycle.sweep(janitor), ["F1"])

    def test_wait_returns_on_message_and_on_timeout(self):
        def deliver(_seconds):
            msgs.send(self.conductor, "codex-ws2-worker1", "request", "", "hello", "body")

        events = lifecycle.wait(self.worker, timeout=60, interval=30, sleep=deliver)
        self.assertEqual(len(events), 1)
        self.assertIn("hello", events[0])
        msgs.inbox(self.worker)  # mark read
        self.assertEqual(lifecycle.wait(self.worker, timeout=60, interval=30, sleep=lambda _s: None), [])

    # Review focus: a hand-edited, malformed item must not take down every command.
    def test_malformed_item_is_reported_not_fatal(self):
        self.add_item(self.conductor, "F1")
        self.conductor.transact("break", lambda: bool(self.conductor.path("items", "BAD.md").write_text("no front matter\n")))
        self.worker.sync()
        good, bad = items.all_items(self.worker)
        self.assertEqual([i.id for i in good], ["F1"])
        self.assertEqual(bad, ["BAD.md"])
        with self.assertRaisesRegex(SwarmError, "malformed"):
            items.load(self.worker, "BAD")

    def test_brief_excludes_log(self):
        self.add_item(self.conductor, "F1")
        text = lifecycle.brief(self.worker, "F1")
        self.assertIn("## Acceptance", text)
        self.assertNotIn("## Log", text)
        self.assertIn("Decision 0001", text)


class SubmitTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.arc, self.repo = self.make_arc()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="m", effort="", tiers=["mid"])

    def test_submit_pushes_lane_and_requests_review(self):
        self.add_item(self.conductor, "F1", title="Stop the bleed")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.tmp / "lanes", base_branch="integration/beta-next")
        (lane / "fix.txt").write_text("fixed\n")
        commit_all(lane, "fix: stop the bleed (F1)")
        commits = lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")
        self.assertEqual(len(commits), 1)
        self.assertEqual(git(self.arc, "rev-parse", "lane/F1-stop-the-bleed"), commits[0])
        self.worker.sync()
        item = items.load(self.worker, "F1")
        self.assertEqual((item.status, item.meta["author_vendor"]), ("review", "codex"))
        self.assertTrue(list(self.worker.path("msgs", "reviewer").glob("*.md")))

    def test_submit_without_commits_refused(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.tmp / "lanes", base_branch="integration/beta-next")
        with self.assertRaisesRegex(SwarmError, "no commits"):
            lifecycle.submit(self.worker, "F1", lane, repo_url=str(self.arc), base_branch="integration/beta-next")


if __name__ == "__main__":
    unittest.main()
```

`tests/test_worktree.py`:

```python
import unittest

from support import SwarmCase, commit_all, git

from swarmlib import agents, claims, items, worktree
from swarmlib.store import SwarmError


class WorktreeTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.arc, self.repo = self.make_arc()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="m", effort="", tiers=["mid"])
        self.lanes = self.tmp / "lanes"

    def test_creates_lane_from_base_with_hooks_and_identity(self):
        self.add_item(self.conductor, "F1", title="Fix the Thing!")
        claims.claim(self.worker, "F1", [])
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")
        self.assertEqual(git(lane, "rev-parse", "--abbrev-ref", "HEAD"), "lane/F1-fix-the-thing")
        self.assertEqual(git(lane, "config", "--worktree", "core.hooksPath"), str(self.worker.path("hooks")))
        self.assertEqual(git(lane, "config", "--get", "swarm.item"), "F1")
        self.assertEqual(git(lane, "config", "--get", "user.name"), "codex-ws2-worker1")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").meta["branch"], "lane/F1-fix-the-thing")
        self.assertEqual(worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes,
                                         base_branch="integration/beta-next"), lane)

    def test_refuses_items_owned_by_someone_else(self):
        self.add_item(self.conductor, "F1")
        with self.assertRaises(SwarmError):
            worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")

    # Review focus: resuming on another machine starts from the pushed lane, not the base.
    def test_resumes_from_remote_lane_branch(self):
        self.add_item(self.conductor, "F1", title="Resume me")
        claims.claim(self.worker, "F1", [])
        other = self.tmp / "other"
        git(self.tmp, "clone", "--quiet", "--branch", "integration/beta-next", str(self.arc), str(other))
        git(other, "checkout", "--quiet", "-b", "lane/F1-resume-me")
        (other / "progress.txt").write_text("half done\n")
        pushed = commit_all(other, "wip (F1)")
        git(other, "push", "--quiet", "origin", "lane/F1-resume-me")
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")
        self.assertEqual(git(lane, "rev-parse", "HEAD"), pushed)

    def test_review_worktree_is_detached_at_lane_tip(self):
        self.add_item(self.conductor, "F1", title="Review me")
        claims.claim(self.worker, "F1", [])
        lane = worktree.create(self.worker, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next")
        (lane / "x.txt").write_text("x\n")
        tip = commit_all(lane, "x (F1)")
        git(lane, "push", "--quiet", str(self.arc), "HEAD:refs/heads/lane/F1-review-me")
        reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        view = worktree.create(reviewer, "F1", repo=self.repo, lanes=self.lanes, base_branch="integration/beta-next", review=True)
        self.assertEqual(git(view, "rev-parse", "HEAD"), tip)
        self.assertEqual(git(view, "rev-parse", "--abbrev-ref", "HEAD"), "HEAD")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run them to verify they fail.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_[lw]*.py' -v`
Expected: FAIL with `ImportError: cannot import name 'lifecycle' from 'swarmlib'`.

- [ ] **Step 3: Implement.** `swarmlib/lifecycle.py`:

```python
"""Item lifecycle: status moves, submit, verdict, work selection, sweep, wait, brief."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from . import agents, claims, clock, gitio, items, msgs
from .store import Store, SwarmError

REVIEW_ROUND_LIMIT = 2
CI_FAILURE_LIMIT = 3
SEVERITY_ORDER = {s: i for i, s in enumerate(items.SEVERITIES)}


def status(store: Store, item_id: str, new_status: str, note: str = "") -> None:
    def mutate() -> bool:
        item = items.load(store, item_id)
        items.check_transition(store, item, new_status)
        old = item.status
        item.meta["status"] = new_status
        item.log(store.agent, f"status {old} -> {new_status}" + (f": {note}" if note else ""))
        if new_status in items.CLOSED:
            claims.remove(store, item_id)
        owner = item.meta["owner"]
        if store.role == "integrator" and new_status == "in-progress" and owner and not owner.startswith("cloud:"):
            msgs.write(store, owner, "blocker", item_id, f"{item_id} returned by the integrator", note or "see item log")
        if new_status == "blocked":
            msgs.write(store, "conductor", "blocker", item_id, f"{item_id} blocked", note or "no note")
        items.save(store, item)
        return True

    store.transact(f"status {item_id} {new_status}", mutate)


def record_evidence(store: Store, item_id: str, entry: dict, *, ci_failed: bool = False) -> None:
    def mutate() -> bool:
        item = items.load(store, item_id)
        item.meta["evidence"].append(entry)
        item.log(store.agent, f"evidence {entry.get('kind', '?')}: {entry.get('conclusion', '')} {entry.get('url', '')}".rstrip())
        if ci_failed:
            item.meta["attempts"]["ci_failures"] += 1
            if item.meta["attempts"]["ci_failures"] >= CI_FAILURE_LIMIT and item.status in ("claimed", "in-progress"):
                item.meta["status"] = "blocked"
                item.log(store.agent, f"status -> blocked: {CI_FAILURE_LIMIT} failed CI runs")
                msgs.write(store, "conductor", "blocker", item_id, f"{item_id} hit the CI failure budget",
                           f"{CI_FAILURE_LIMIT} failed lane-test runs. Latest: {entry.get('url', '')}")
        items.save(store, item)
        return True

    store.transact(f"evidence {item_id}", mutate)


def submit(store: Store, item_id: str, worktree: Path, *, repo_url: str, base_branch: str) -> list[str]:
    """Push the lane branch and hand the item to review."""
    store.sync()
    item = items.load(store, item_id)
    owner = item.meta["owner"]
    on_behalf = store.role in ("janitor", "conductor") and owner.startswith("cloud:")
    if owner != store.agent and not on_behalf:
        raise SwarmError(f"{item_id} belongs to {owner or 'nobody'}")
    if item.status != "in-progress":
        raise SwarmError(f"{item_id} is {item.status}; submit needs in-progress")
    branch = gitio.out(worktree, "rev-parse", "--abbrev-ref", "HEAD")
    if not branch.startswith("lane/"):
        raise SwarmError(f"worktree is on {branch!r}, not a lane/ branch")
    gitio.run(worktree, *gitio.auth_args(), "fetch", "--quiet", repo_url,
              f"+refs/heads/{base_branch}:refs/remotes/swarm/{base_branch}")
    commits = gitio.out(worktree, "rev-list", "--reverse", f"refs/remotes/swarm/{base_branch}..HEAD").split()
    if not commits:
        raise SwarmError(f"{branch} has no commits beyond {base_branch}")
    gitio.run(worktree, *gitio.auth_args(), "push", "--quiet", "--force", repo_url, f"HEAD:refs/heads/{branch}")
    vendor = owner.split(":", 1)[1].split("-", 1)[0] if on_behalf else store.vendor

    def mutate() -> bool:
        fresh = items.load(store, item_id)
        if fresh.status != "in-progress":
            raise SwarmError(f"{item_id} moved to {fresh.status} while submitting")
        fresh.meta.update(branch=branch, commits=[c[:12] for c in commits], author_vendor=vendor, status="review")
        fresh.meta["review"].update(verdict="", reviewer="")
        fresh.log(store.agent, f"status in-progress -> review: {len(commits)} commits on {branch}")
        items.save(store, fresh)
        msgs.write(store, "reviewer", "request", item_id, f"review {item_id}", f"Branch {branch}, {len(commits)} commits.")
        return True

    store.transact(f"submit {item_id}", mutate)
    return commits


def verdict(store: Store, item_id: str, decision: str, findings: str) -> None:
    if decision not in ("accept", "changes"):
        raise SwarmError("decision must be 'accept' or 'changes'")
    if decision == "changes" and not findings.strip():
        raise SwarmError("'changes' needs findings")

    def mutate() -> bool:
        item = items.load(store, item_id)
        review = item.meta["review"]
        if item.status != "review":
            raise SwarmError(f"{item_id} is {item.status}, not in review")
        if store.role != "conductor":
            if review["reviewer"] != store.agent:
                raise SwarmError(f"{item_id} is assigned to reviewer {review['reviewer'] or 'nobody'}")
            if store.vendor and store.vendor == item.meta["author_vendor"]:
                raise SwarmError("cross-vendor review required: you share the author's vendor")
        owner = item.meta["owner"]
        if decision == "accept":
            review["verdict"] = "accept"
            item.meta["status"] = "ready"
        else:
            review["verdict"] = "changes"
            review["round"] += 1
            item.add_section(f"Review round {review['round']} ({store.agent})", findings)
            item.meta["status"] = "blocked" if review["round"] > REVIEW_ROUND_LIMIT else "in-progress"
            if item.meta["status"] == "blocked":
                msgs.write(store, "conductor", "blocker", item_id, f"{item_id} exceeded {REVIEW_ROUND_LIMIT} review rounds",
                           findings)
        item.log(store.agent, f"verdict {decision} round {review['round']}")
        items.save(store, item)
        if owner and not owner.startswith("cloud:") and store.path("agents", f"{owner}.md").exists():
            msgs.write(store, owner, "verdict", item_id, f"{decision}: {item_id}", findings or "accepted")
        return True

    store.transact(f"verdict {item_id} {decision}", mutate)


def _priority(item: items.Item, me: str) -> tuple:
    return (item.meta["assignee"] != me, SEVERITY_ORDER.get(item.meta["severity"], 9), item.meta["wave"], item.id)


def next_item(store: Store, tiers: list[str]) -> str | None:
    """Resume the caller's unfinished item, else claim the best open one."""
    store.sync()
    everything, _ = items.all_items(store)
    mine = sorted(
        (i for i in everything if i.meta["owner"] == store.agent and i.status in ("claimed", "in-progress")),
        key=lambda i: _priority(i, store.agent),
    )
    if mine:
        return mine[0].id
    waves = store.config()["active_waves"]
    candidates = sorted(
        (
            i for i in everything
            if i.status == "open" and i.meta["wave"] in waves and i.meta["tier"] in tiers
            and i.meta["assignee"] in ("", store.agent) and not items.deps_unmet(store, i)
        ),
        key=lambda i: _priority(i, store.agent),
    )
    for candidate in candidates:
        try:
            claims.claim(store, candidate.id, [])
            return candidate.id
        except SwarmError:
            continue
    return None


def next_review(store: Store) -> str | None:
    """Resume an assigned review, else take an unassigned cross-vendor one."""
    store.sync()
    everything, _ = items.all_items(store)
    for item in everything:
        if item.status == "review" and item.meta["review"]["reviewer"] == store.agent:
            return item.id
    for item in sorted(everything, key=lambda i: _priority(i, store.agent)):
        if item.status != "review" or item.meta["review"]["reviewer"] or item.meta["author_vendor"] == store.vendor:
            continue

        def mutate(item_id: str = item.id) -> bool:
            fresh = items.load(store, item_id)
            if fresh.status != "review" or fresh.meta["review"]["reviewer"]:
                raise SwarmError("taken")
            fresh.meta["review"]["reviewer"] = store.agent
            fresh.log(store.agent, "picked up review")
            items.save(store, fresh)
            return True

        try:
            store.transact(f"review {item.id}", mutate)
            return item.id
        except SwarmError:
            continue
    return None


def sweep(store: Store) -> list[str]:
    """Block items past twice their estimate. Returns the IDs it blocked."""
    blocked: list[str] = []

    def mutate() -> bool:
        blocked.clear()
        now = clock.now()
        everything, _ = items.all_items(store)
        for item in everything:
            started = item.meta["attempts"]["started"]
            if item.status not in ("claimed", "in-progress") or not started:
                continue
            budget = clock.minutes(60 * 2 * float(item.meta["estimate_hours"]))
            if now - clock.parse(started) > budget:
                item.meta["status"] = "blocked"
                item.log(store.agent, f"status -> blocked: over twice the {item.meta['estimate_hours']}h estimate")
                items.save(store, item)
                msgs.write(store, "conductor", "blocker", item.id, f"{item.id} over time budget",
                           f"Started {started}, estimate {item.meta['estimate_hours']}h.")
                blocked.append(item.id)
        return bool(blocked)

    store.transact("sweep", mutate)
    return list(blocked)


def _snapshot(store: Store) -> dict[str, tuple]:
    everything, _ = items.all_items(store)
    return {
        i.id: (i.status, i.meta["review"]["verdict"], i.meta["review"]["round"], i.meta["owner"])
        for i in everything
        if store.agent in (i.meta["owner"], i.meta["review"]["reviewer"])
    }


def wait(
    store: Store, *, timeout: float = 600, interval: float = 30, heartbeat_every: float = 600,
    sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    """Block until a new message or a change to the caller's items. [] on timeout."""
    store.sync()
    before = _snapshot(store)
    waited = since_beat = 0.0
    while True:
        events = [f"message from {m['from']} [{m['kind']}] {m['item']}: {m['subject']}"
                  for m in msgs.inbox(store, mark=False, sync=False)]
        after = _snapshot(store)
        events += [f"item {key}: {before.get(key)} -> {value}" for key, value in after.items() if before.get(key) != value]
        if events or waited >= timeout:
            return events
        sleep(interval)
        waited += interval
        since_beat += interval
        if since_beat >= heartbeat_every and agents.load(store, store.agent):
            claims.heartbeat(store)
            since_beat = 0.0
        store.sync()


def brief(store: Store, item_id: str) -> str:
    store.sync()
    item = items.load(store, item_id)
    meta = item.meta
    body = item.body.split("## Log\n", 1)[0].rstrip()
    lines = [
        f"# Swarm item {item.id}: {meta['title']}",
        "",
        f"- Severity {meta['severity']}, wave {meta['wave']}, tier {meta['tier']}, status {meta['status']}",
        f"- Paths: {', '.join(meta['paths']) or 'none listed'}",
        f"- Depends on: {', '.join(meta['depends_on']) or 'nothing'}",
        f"- Branch: {meta['branch'] or 'assigned by `swarm worktree`'}",
        "- Protocol: ~/swarm/PROTOCOL.md. Decision 0001 supersedes any plan text that says",
        "  'one implementation owner' or forbids subagents.",
        "",
        body,
        "",
    ]
    return "\n".join(lines)
```

`swarmlib/worktree.py`:

```python
"""Lane worktrees: one per item, cut from the integration branch, with swarm hooks."""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import gitio, items
from .store import Store, SwarmError

SLUG_RE = re.compile(r"[^a-z0-9]+")


def repo_url() -> str:
    return os.environ.get("SWARM_GIT_URL", "https://github.com/bb-connor/arc.git")


def slug(title: str) -> str:
    return SLUG_RE.sub("-", title.lower()).strip("-")[:40].rstrip("-") or "item"


def lane_branch(item: items.Item) -> str:
    return item.meta["branch"] or f"lane/{item.id}-{slug(item.meta['title'])}"


def _fetch(repo: Path, branch: str) -> bool:
    proc = gitio.run(repo, *gitio.auth_args(), "fetch", "--quiet", repo_url(),
                     f"+refs/heads/{branch}:refs/remotes/swarm/{branch}", check=False)
    return proc.returncode == 0


def _configure(store: Store, repo: Path, target: Path, item_id: str) -> None:
    gitio.run(repo, "config", "extensions.worktreeConfig", "true")
    gitio.run(target, "config", "--worktree", "core.hooksPath", str(store.path("hooks")))
    gitio.run(target, "config", "--worktree", "swarm.item", item_id)
    gitio.run(target, "config", "--worktree", "user.name", store.agent)
    gitio.run(target, "config", "--worktree", "user.email", os.environ.get("SWARM_EMAIL", f"{store.agent}@swarm.invalid"))


def create(store: Store, item_id: str, *, repo: Path, lanes: Path, base_branch: str, review: bool = False) -> Path:
    store.sync()
    item = items.load(store, item_id)
    if not review and item.meta["owner"] != store.agent and store.role != "conductor":
        raise SwarmError(f"{item_id} belongs to {item.meta['owner'] or 'nobody'}")
    branch = lane_branch(item)
    target = (lanes / "review" / item_id) if review else (lanes / item_id)
    if target.exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    if not _fetch(repo, base_branch):
        raise SwarmError(f"cannot fetch {base_branch} from {repo_url()}")
    remote_lane = _fetch(repo, branch)
    if review:
        if not remote_lane:
            raise SwarmError(f"{branch} is not on the remote yet")
        gitio.run(repo, "worktree", "add", "--detach", str(target), f"refs/remotes/swarm/{branch}")
    elif gitio.run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0:
        gitio.run(repo, "worktree", "add", str(target), branch)
    elif remote_lane:
        gitio.run(repo, "worktree", "add", "-b", branch, str(target), f"refs/remotes/swarm/{branch}")
    else:
        gitio.run(repo, "worktree", "add", "-b", branch, str(target), f"refs/remotes/swarm/{base_branch}")
    _configure(store, repo, target, item_id)
    if not review and not item.meta["branch"]:
        def mutate() -> bool:
            fresh = items.load(store, item_id)
            fresh.meta["branch"] = branch
            fresh.log(store.agent, f"worktree on {branch}")
            items.save(store, fresh)
            return True

        store.transact(f"branch {item_id}", mutate)
    return target
```

- [ ] **Step 4: Run them to verify they pass.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_[lw]*.py' -v`
Expected: `Ran 17 tests` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add swarmlib/lifecycle.py swarmlib/worktree.py tests/test_lifecycle.py tests/test_worktree.py
git commit -m "feat(swarm): item lifecycle, cross-vendor review and lane worktrees"
```

### Task 7: Board and metrics

**Files:**
- Create: `swarmlib/board.py`, `swarmlib/metrics.py`
- Test: `tests/test_board.py`

**Interfaces:**
- Consumes: `items`, `claims`, `agents`, `frontmatter`, `clock`.
- Produces: `board.render(store) -> str`, `board.write(store) -> bool`; `metrics.events(item)`, `integrated_since(store, since) -> list[str]`, `bounce_rate(store, since) -> float | None`, `slot_wait_median(log_path, since) -> float | None`, `report(store, *, hours, slot_log, ci_green) -> str`.

- [ ] **Step 1: Write the failing test** at `tests/test_board.py`:

```python
import json
import unittest

from support import SwarmCase

from swarmlib import agents, board, claims, items, metrics, msgs


class BoardTest(SwarmCase):
    def test_board_sections_order_and_flags(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        agents.register(worker, agent_id=worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="gpt-6.1-sol", effort="medium", tiers=["mid"])
        self.add_item(conductor, "F1", title="Open | piped title")
        self.add_item(conductor, "F2", title="Claimed one")
        self.add_item(conductor, "W1", wave=2, depends_on=["F1"])
        claims.claim(worker, "F2", [])
        msgs.send(conductor, "human", "request", "F2", "approve train PR", "please")
        self.at("2026-10-06T14:00:00Z")
        conductor.sync()
        text = board.render(conductor)
        self.assertLess(text.index("## Needs Connor"), text.index("## Wave 1"))
        self.assertIn("approve train PR", text)
        self.assertLess(text.index("| F2 |"), text.index("| F1 |"))  # claimed sorts before open
        self.assertIn("Open \\| piped title", text)
        self.assertIn("F1 (open)", text)
        self.assertIn("claim expired", text)
        self.assertIn("STALE", text)
        self.assertTrue(board.write(conductor))
        self.assertFalse(board.write(conductor))  # unchanged board does not commit


class MetricsTest(SwarmCase):
    def test_integrated_bounce_and_slot_wait(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.add_item(conductor, "F1")

        def history() -> bool:
            item = items.load(conductor, "F1")
            item.body += "- 2026-10-06T10:00:00Z r: verdict changes round 1\n"
            item.body += "- 2026-10-06T11:00:00Z r: verdict accept round 1\n"
            item.body += "- 2026-10-06T11:30:00Z i: status ready -> integrated\n"
            items.save(conductor, item)
            return True

        conductor.transact("history", history)
        conductor.sync()
        self.assertEqual(metrics.integrated_since(conductor, metrics.clock.parse("2026-10-06T00:00:00Z")), ["F1"])
        self.assertEqual(metrics.bounce_rate(conductor, metrics.clock.parse("2026-10-06T00:00:00Z")), 0.5)
        log = self.tmp / "waits.log"
        log.write_text("\n".join(json.dumps({"at": f"2026-10-06T1{i}:00:00Z", "slot": 0, "waited_s": w, "item": ""})
                                 for i, w in enumerate([60, 600, 1200])) + "\n")
        self.assertEqual(metrics.slot_wait_median(log, metrics.clock.parse("2026-10-06T00:00:00Z")), 600)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_board.py' -v`
Expected: FAIL with `ImportError: cannot import name 'board' from 'swarmlib'`.

- [ ] **Step 3: Implement.** `swarmlib/board.py`:

```python
"""Generated BOARD.md: human attention first, then items by wave, then agents."""

from __future__ import annotations

from . import agents, claims, clock, frontmatter, items
from .store import Store

STATUS_ORDER = (
    "blocked", "disputed", "in-progress", "claimed", "review", "ready", "open",
    "integrated", "done", "deferred", "wontfix",
)


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _age(started: str) -> str:
    if not started:
        return "-"
    hours = int((clock.now() - clock.parse(started)).total_seconds() // 3600)
    return f"{hours}h"


def render(store: Store) -> str:
    now = clock.now()
    out = ["# Swarm board", "", "Generated by `swarm board --write`. Do not edit by hand.", ""]

    out += ["## Needs Connor", ""]
    human = sorted(store.path("msgs", "human").glob("*.md"))
    for path in human:
        meta, _ = frontmatter.parse(path.read_text())
        out.append(f"- {meta['sent']} {meta['from']} [{meta['item'] or '-'}] {_cell(meta['subject'])}")
    if not human:
        out.append("- nothing")
    out.append("")

    everything, broken = items.all_items(store)
    leases = {c["item"]: c for c in claims.all_claims(store)}
    for wave in sorted({i.meta["wave"] for i in everything}):
        out += [f"## Wave {wave}", "", "| ID | Sev | Status | Owner | Age | Blockers | Title |", "| --- | --- | --- | --- | --- | --- | --- |"]
        rows = sorted(
            (i for i in everything if i.meta["wave"] == wave),
            key=lambda i: (STATUS_ORDER.index(i.status), i.meta["severity"], i.id),
        )
        for item in rows:
            blockers = items.deps_unmet(store, item)
            lease = leases.get(item.id)
            if lease and claims.is_expired(lease, now) and item.status not in items.CLOSED:
                blockers.append("claim expired")
            out.append(
                f"| {item.id} | {item.meta['severity']} | {item.status} | {item.meta['owner'] or '-'} | "
                f"{_age(item.meta['attempts']['started'])} | {_cell(', '.join(blockers) or '-')} | {_cell(item.meta['title'])} |"
            )
        out.append("")
    if broken:
        out += ["## Unparseable items", ""] + [f"- items/{name}" for name in broken] + [""]

    out += ["## Agents", "", "| Agent | Role | Vendor | Model | Status | Heartbeat |", "| --- | --- | --- | --- | --- | --- |"]
    for meta in agents.all_agents(store):
        beat = meta.get("last_heartbeat", "")
        flag = " STALE" if agents.is_stale(meta) else ""
        out.append(
            f"| {meta['id']} | {meta['role']} | {meta['vendor']} | {meta['model']} | {meta['status']} | {beat}{flag} |"
        )
    out.append("")
    return "\n".join(out)


def write(store: Store) -> bool:
    def mutate() -> bool:
        text = render(store)
        path = store.path("BOARD.md")
        if path.exists() and path.read_text() == text:
            return False
        path.write_text(text)
        return True

    return store.transact("board", mutate)
```

`swarmlib/metrics.py`:

```python
"""Section 10 metrics from item logs, local slot-wait records and CI history."""

from __future__ import annotations

import json
import re
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from . import clock, items
from .store import Store

LOG_LINE = re.compile(r"^- (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (\S+): (.*)$", re.M)


def events(item: items.Item) -> list[tuple[datetime, str, str]]:
    return [(clock.parse(ts), who, text) for ts, who, text in LOG_LINE.findall(item.body)]


def integrated_since(store: Store, since: datetime) -> list[str]:
    everything, _ = items.all_items(store)
    return sorted(
        i.id for i in everything
        if any(at >= since and text.startswith("status ready -> integrated") for at, _, text in events(i))
    )


def bounce_rate(store: Store, since: datetime) -> float | None:
    everything, _ = items.all_items(store)
    verdicts = [text for i in everything for at, _, text in events(i) if at >= since and text.startswith("verdict ")]
    if not verdicts:
        return None
    return sum(v.startswith("verdict changes") for v in verdicts) / len(verdicts)


def slot_wait_median(log_path: Path, since: datetime) -> float | None:
    if not log_path.exists():
        return None
    waits = []
    for line in log_path.read_text().splitlines():
        record = json.loads(line)
        if clock.parse(record["at"]) >= since:
            waits.append(float(record["waited_s"]))
    return statistics.median(waits) if waits else None


def report(store: Store, *, hours: int, slot_log: Path, ci_green: float | None) -> str:
    since = clock.now() - timedelta(hours=hours)
    done = integrated_since(store, since)
    bounce = bounce_rate(store, since)
    wait = slot_wait_median(slot_log, since)
    lines = [
        f"Window: last {hours}h",
        f"- Items integrated: {len(done)} ({', '.join(done) or 'none'})",
        f"- Review bounce rate: {'n/a' if bounce is None else f'{bounce:.0%}'} (target under 30%)",
        f"- Median build-slot wait: {'n/a' if wait is None else f'{wait / 60:.1f} min'} (target under 20 min)",
        f"- Hosted CI green rate on beta-next: {'n/a' if ci_green is None else f'{ci_green:.0%}'} (target 80%+)",
    ]
    return "\n".join(lines)
```

- [ ] **Step 4: Run it to verify it passes.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_board.py' -v`
Expected: `Ran 2 tests` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add swarmlib/board.py swarmlib/metrics.py tests/test_board.py
git commit -m "feat(swarm): generated board and spec metrics"
```

### Task 8: Build slots, lane-test CI and review import

**Files:**
- Create: `swarmlib/build.py`, `swarmlib/ci.py`, `swarmlib/reviews.py`
- Test: `tests/test_build_ci.py`

**Interfaces:**
- Consumes: `clock`, `items`, `Store`.
- Produces: `build.slot_dir()`, `slot_count()`, `acquire(count, *, poll=5.0, timeout=None) -> (fd, slot, waited)`, `release(fd)`, `scope_prefix() -> list[str]`, `build_env(base) -> dict`, `record_wait(slot, waited, item)`, `run(command, *, item="") -> int`; `ci.Runner` (callable taking an argv list, returning `CompletedProcess`), `ci.default_runner`, `ci.gh(runner, *args) -> str`, `in_flight(runner)`, `wait_for_capacity(runner, cap, *, poll=30, sleep=...)`, `dispatch(runner, *, item, target_ref, packages, test_filter, features) -> nonce`, `find_run(runner, nonce, ...) -> (run_id, url)`, `watch(runner, run_id) -> bool`, `busy(runner, branch, workflow="CI") -> bool`, `green_rate(runner, branch, workflow="CI")`, `ci.CIError`; `reviews.BOTS`, `fetch(runner, pr)`, `severity_of(body)`, `title_of(body)`, `to_item(store, pr, comment, wave)`, `import_reviews(store, runner, pr, *, bots=BOTS) -> list[str]`.

- [ ] **Step 1: Write the failing test** at `tests/test_build_ci.py`:

```python
import json
import os
import subprocess
import unittest
from unittest import mock

from support import SwarmCase

from swarmlib import build, ci, items, reviews


class BuildTest(SwarmCase):
    def test_slot_exhaustion_waits_then_times_out(self):
        fd, slot, waited = build.acquire(1, poll=0.01)
        self.assertEqual(slot, 0)
        with self.assertRaises(TimeoutError):
            build.acquire(1, poll=0.01, timeout=0.05)
        build.release(fd)
        fd2, _, _ = build.acquire(1, poll=0.01, timeout=1)
        build.release(fd2)

    def test_second_slot_used_when_first_busy(self):
        fd, _, _ = build.acquire(2, poll=0.01)
        fd2, slot, _ = build.acquire(2, poll=0.01, timeout=1)
        self.assertEqual(slot, 1)
        build.release(fd)
        build.release(fd2)

    def test_scope_prefix_respects_switch_and_availability(self):
        with mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0"}):
            self.assertEqual(build.scope_prefix(), [])
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/systemd-run"):
            prefix = build.scope_prefix()
        self.assertEqual(prefix[:3], ["systemd-run", "--user", "--scope"])
        self.assertIn("CPUWeight=20", prefix)
        self.assertIn("MemoryMax=14G", prefix)

    def test_build_env_disables_incremental_and_uses_sccache(self):
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/sccache"):
            env = build.build_env({"PATH": "/bin"})
        self.assertEqual((env["RUSTC_WRAPPER"], env["CARGO_INCREMENTAL"]), ("sccache", "0"))

    def test_run_records_wait(self):
        with mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0"}):
            self.assertEqual(build.run(["true"], item="F1"), 0)
        record = json.loads((build.slot_dir() / "waits.log").read_text().splitlines()[-1])
        self.assertEqual((record["item"], record["slot"]), ("F1", 0))


class FakeGh:
    """Records gh invocations and answers from a script of (prefix, stdout, returncode)."""

    def __init__(self, script):
        self.script, self.calls = script, []

    def __call__(self, args):
        self.calls.append(args)
        for prefix, stdout, code in self.script:
            if args[: len(prefix)] == prefix:
                return subprocess.CompletedProcess(args, code, stdout, "")
        raise AssertionError(f"unexpected gh call {args}")


class CITest(unittest.TestCase):
    def test_dispatch_always_targets_main_and_carries_nonce(self):
        gh = FakeGh([(["gh", "workflow", "run"], "", 0)])
        nonce = ci.dispatch(gh, item="F1", target_ref="lane/F1-x", packages=["chio-kernel", "chio-core"],
                            test_filter="recovery", features="")
        call = gh.calls[0]
        self.assertEqual(call[call.index("--ref") + 1], "main")
        self.assertIn("target_ref=lane/F1-x", call)
        self.assertIn("packages=chio-kernel chio-core", call)
        self.assertIn(f"nonce={nonce}", call)

    def test_find_run_matches_nonce(self):
        runs = [{"databaseId": 1, "displayTitle": "lane-test F0 aaa", "url": "u1"},
                {"databaseId": 2, "displayTitle": "lane-test F1 abc123", "url": "u2"}]
        gh = FakeGh([(["gh", "run", "list"], json.dumps(runs), 0)])
        self.assertEqual(ci.find_run(gh, "abc123", sleep=lambda _s: None), (2, "u2"))

    def test_capacity_counts_active_runs(self):
        runs = [{"status": "queued"}, {"status": "in_progress"}, {"status": "completed"}]
        gh = FakeGh([(["gh", "run", "list"], json.dumps(runs), 0)])
        self.assertEqual(ci.in_flight(gh), 2)

    def test_green_rate_ignores_cancelled(self):
        runs = [{"status": "completed", "conclusion": c} for c in ("success", "failure", "cancelled", "success")]
        gh = FakeGh([(["gh", "run", "list"], json.dumps(runs), 0)])
        self.assertAlmostEqual(ci.green_rate(gh, "integration/beta-next"), 2 / 3)

    def test_gh_failure_raises(self):
        gh = FakeGh([(["gh"], "", 1)])
        with self.assertRaises(ci.CIError):
            ci.in_flight(gh)


class ReviewsTest(SwarmCase):
    COMMENTS = [
        {"id": 11, "user": "chatgpt-codex-connector[bot]", "path": "crates/a/src/lib.rs", "line": 7, "in_reply_to_id": None,
         "html_url": "https://example.invalid/r11",
         "body": "**<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub>  Guard the retry**\n\nDetails."},
        {"id": 12, "user": "greptile-apps[bot]", "path": "crates/b/src/x.rs", "line": 3, "in_reply_to_id": None,
         "html_url": "https://example.invalid/r12", "body": "<img alt=\"P2\" src=\"x.svg\"> **Resync passes amplify lag**"},
        {"id": 13, "user": "bb-connor", "path": "a", "line": 1, "in_reply_to_id": None, "html_url": "u", "body": "human"},
        {"id": 14, "user": "greptile-apps[bot]", "path": "a", "line": 1, "in_reply_to_id": 12, "html_url": "u", "body": "reply"},
    ]

    def test_import_creates_items_once(self):
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        raw = "\n".join(json.dumps(c) for c in self.COMMENTS)
        gh = FakeGh([(["gh", "api"], raw, 0)])
        self.assertEqual(reviews.import_reviews(janitor, gh, 1180), ["R1180-11", "R1180-12"])
        self.assertEqual(reviews.import_reviews(janitor, gh, 1180), [])
        janitor.sync()
        first = items.load(janitor, "R1180-11")
        self.assertEqual((first.meta["severity"], first.meta["tier"]), ("P1", "premium"))
        self.assertEqual(first.meta["title"], "Guard the retry")
        self.assertEqual(items.load(janitor, "R1180-12").meta["title"], "Resync passes amplify lag")

    def test_workers_cannot_import(self):
        worker = self.clone("codex-ws2-worker1")
        with self.assertRaises(reviews.SwarmError):
            reviews.import_reviews(worker, FakeGh([]), 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_build_ci.py' -v`
Expected: FAIL with `ImportError: cannot import name 'build' from 'swarmlib'`.

- [ ] **Step 3: Implement.** `swarmlib/build.py`:

```python
"""Build slots: bounded, low-priority, cached cargo runs on the shared hosts."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from . import clock


def slot_dir() -> Path:
    path = Path(os.environ.get("SWARM_BUILD_DIR", str(Path.home() / ".swarm-build"))).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def slot_count() -> int:
    return max(1, int(os.environ.get("SWARM_BUILD_SLOTS", "2")))


def acquire(count: int, *, poll: float = 5.0, timeout: float | None = None) -> tuple[int, int, float]:
    """Block until one of `count` slots is free. Returns (fd, slot, seconds waited)."""
    started = time.monotonic()
    while True:
        for slot in range(count):
            fd = os.open(slot_dir() / f"slot-{slot}.lock", os.O_RDWR | os.O_CREAT, 0o644)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd, slot, time.monotonic() - started
            except BlockingIOError:
                os.close(fd)
        if timeout is not None and time.monotonic() - started >= timeout:
            raise TimeoutError(f"no build slot free after {timeout:.0f}s")
        time.sleep(poll)


def release(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def scope_prefix() -> list[str]:
    """systemd user scope with low CPU weight and a memory ceiling, when available."""
    if os.environ.get("SWARM_BUILD_CGROUP", "1") == "0" or not shutil.which("systemd-run"):
        return []
    return [
        "systemd-run", "--user", "--scope", "--quiet",
        "-p", f"CPUWeight={os.environ.get('SWARM_BUILD_CPU_WEIGHT', '20')}",
        "-p", f"MemoryMax={os.environ.get('SWARM_BUILD_MEMORY_MAX', '14G')}",
        "--",
    ]


def build_env(base: dict[str, str]) -> dict[str, str]:
    env = dict(base)
    if shutil.which("sccache"):
        env.setdefault("RUSTC_WRAPPER", "sccache")
        env.setdefault("SCCACHE_CACHE_SIZE", "60G")
    env["CARGO_INCREMENTAL"] = "0"
    return env


def record_wait(slot: int, waited: float, item: str) -> None:
    with open(slot_dir() / "waits.log", "a") as log:
        log.write(json.dumps({"at": clock.fmt(clock.now()), "slot": slot, "waited_s": round(waited, 1), "item": item}) + "\n")


def run(command: list[str], *, item: str = "") -> int:
    if not command:
        raise ValueError("swarm build needs a command after --")
    fd, slot, waited = acquire(slot_count())
    record_wait(slot, waited, item)
    try:
        return subprocess.call(scope_prefix() + command, env=build_env(dict(os.environ)))
    finally:
        release(fd)
```

`swarmlib/ci.py`:

```python
"""GitHub Actions lane tests through `gh`. The runner is injectable for tests."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from typing import Callable

Runner = Callable[[list[str]], subprocess.CompletedProcess]
WORKFLOW = "lane-test.yml"
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}


class CIError(RuntimeError):
    pass


def repo_slug() -> str:
    return os.environ.get("SWARM_REPO_SLUG", "bb-connor/arc")


def default_runner(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True)


def gh(runner: Runner, *args: str) -> str:
    proc = runner(["gh", *args])
    if proc.returncode != 0:
        raise CIError(f"gh {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def in_flight(runner: Runner) -> int:
    runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", WORKFLOW,
                         "--json", "status", "--limit", "100"))
    return sum(1 for run in runs if run["status"] in ACTIVE)


def wait_for_capacity(runner: Runner, cap: int, *, poll: float = 30, sleep: Callable[[float], None] = time.sleep) -> None:
    while in_flight(runner) >= cap:
        sleep(poll)


def dispatch(runner: Runner, *, item: str, target_ref: str, packages: list[str], test_filter: str, features: str) -> str:
    nonce = uuid.uuid4().hex[:10]
    gh(
        runner, "workflow", "run", WORKFLOW, "--repo", repo_slug(), "--ref", "main",
        "-f", f"target_ref={target_ref}", "-f", f"item={item}", "-f", f"packages={' '.join(packages)}",
        "-f", f"filter={test_filter}", "-f", f"features={features}", "-f", f"nonce={nonce}",
    )
    return nonce


def find_run(runner: Runner, nonce: str, *, timeout: float = 180, poll: float = 5,
             sleep: Callable[[float], None] = time.sleep) -> tuple[int, str]:
    waited = 0.0
    while waited <= timeout:
        runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", WORKFLOW,
                             "--json", "databaseId,displayTitle,url", "--limit", "50"))
        for run in runs:
            if nonce in run["displayTitle"]:
                return int(run["databaseId"]), run["url"]
        sleep(poll)
        waited += poll
    raise CIError(f"no lane-test run with nonce {nonce} appeared within {timeout:.0f}s")


def watch(runner: Runner, run_id: int) -> bool:
    proc = runner(["gh", "run", "watch", str(run_id), "--repo", repo_slug(), "--exit-status", "--interval", "30"])
    return proc.returncode == 0


def busy(runner: Runner, branch: str, workflow: str = "CI") -> bool:
    """True while a run of `workflow` is active for `branch` (integrator push gate)."""
    runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", workflow,
                         "--branch", branch, "--json", "status", "--limit", "20"))
    return any(run["status"] in ACTIVE for run in runs)


def green_rate(runner: Runner, branch: str, workflow: str = "CI") -> float | None:
    runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", workflow,
                         "--branch", branch, "--json", "status,conclusion", "--limit", "20"))
    finished = [run for run in runs if run["status"] == "completed" and run["conclusion"] != "cancelled"]
    if not finished:
        return None
    return sum(run["conclusion"] == "success" for run in finished) / len(finished)
```

`swarmlib/reviews.py`:

```python
"""Turn review-bot comments on a train PR into swarm items."""

from __future__ import annotations

import json
import re

from . import ci, items
from .store import Store, SwarmError

BOTS = ("chatgpt-codex-connector[bot]", "greptile-apps[bot]")
SEVERITY_RE = re.compile(r"\bP([0-3])\b")
TAG_RE = re.compile(r"<[^>]+>")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")


def fetch(runner: ci.Runner, pr: int) -> list[dict]:
    jq = ".[] | {id, user: .user.login, body, path, line: (.line // .original_line), html_url, in_reply_to_id}"
    raw = ci.gh(runner, "api", "--paginate", "--jq", jq, f"repos/{ci.repo_slug()}/pulls/{pr}/comments")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def severity_of(body: str) -> str:
    match = SEVERITY_RE.search(body)
    return f"P{match.group(1)}" if match else "P2"


def title_of(body: str) -> str:
    for line in body.splitlines():
        text = IMAGE_RE.sub("", TAG_RE.sub("", line)).replace("**", "").replace("`", "").strip(" #*-")
        if text:
            return text[:90]
    return "review finding"


def to_item(store: Store, pr: int, comment: dict, wave: int) -> items.Item:
    severity = severity_of(comment["body"])
    location = f"`{comment['path']}:{comment['line']}`" if comment.get("path") else "the PR"
    brief = (
        "## Brief\n\n"
        f"Review bot {comment['user']} raised this on PR #{pr} at {location} ({comment['html_url']}):\n\n"
        f"{comment['body'].strip()}\n\n"
        "## Acceptance\n\n"
        "- A regression test reproduces the finding, or the item records why the finding is wrong.\n"
        "- The fix passes the owning crate's focused tests and strict Clippy.\n"
        f"- Reply on {comment['html_url']} after integration.\n"
    )
    return items.create(
        store, item_id=f"R{pr}-{comment['id']}", title=title_of(comment["body"]), severity=severity,
        wave=wave, tier="premium" if severity in ("P0", "P1") else "mid",
        paths=[comment["path"]] if comment.get("path") else [], depends_on=[], estimate_hours=3,
        assignee="", brief=brief,
    )


def import_reviews(store: Store, runner: ci.Runner, pr: int, *, bots: tuple[str, ...] = BOTS) -> list[str]:
    if store.role not in ("conductor", "janitor"):
        raise SwarmError("only the conductor or a janitor imports reviews")
    fresh = [c for c in fetch(runner, pr) if c["user"] in bots and not c.get("in_reply_to_id")]
    created: list[str] = []

    def mutate() -> bool:
        created.clear()
        wave = max(store.config()["active_waves"])
        for comment in fresh:
            item = to_item(store, pr, comment, wave)
            if not items.exists(store, item.id):
                items.save(store, item)
                created.append(item.id)
        return bool(created)

    store.transact(f"import reviews from PR {pr}", mutate)
    return list(created)
```

- [ ] **Step 4: Run it to verify it passes.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_build_ci.py' -v`
Expected: `Ran 12 tests` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add swarmlib/build.py swarmlib/ci.py swarmlib/reviews.py tests/test_build_ci.py
git commit -m "feat(swarm): build slots, lane-test dispatch and review import"
```

### Task 9: The `swarm` command

**Files:**
- Create: `swarmlib/cli.py`, `bin/swarm`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: every module above.
- Produces: `swarm` subcommands `register`, `item new`, `list`, `brief`, `claim`, `release`, `reassign`, `heartbeat`, `status`, `submit`, `verdict`, `send`, `inbox`, `wait`, `next`, `board`, `metrics`, `build`, `ci`, `ci-busy`, `import-reviews`, `worktree`, `sweep`, `halt`, `resume`, `config`, `record`, `scan`. Exit codes: 0 ok, 1 nothing found / negative result (`next`, `wait`, `inbox`, `ci`, `ci-busy`, `scan`), 2 refused or failed. Every write renews the caller's claims through `Store.hooks`.

- [ ] **Step 1: Write the failing test** at `tests/test_cli.py`:

```python
import os
import subprocess
import sys
import unittest
from pathlib import Path

from support import BRIEF, SwarmCase

BIN = Path(__file__).resolve().parent.parent / "bin" / "swarm"


class CLITest(SwarmCase):
    def run_cli(self, store, *args):
        env = {**os.environ, "SWARM_HOME": str(store.root), "SWARM_AGENT": store.agent,
               "SWARM_ROLE": store.role, "SWARM_VENDOR": store.vendor}
        return subprocess.run([sys.executable, str(BIN), *args], env=env, capture_output=True, text=True)

    def test_round_trip_and_exit_codes(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        brief = self.tmp / "brief.md"
        brief.write_text(BRIEF)
        registered = self.run_cli(worker, "register", "--machine", "ws2", "--vendor", "codex", "--role", "worker",
                                  "--model", "m", "--tiers", "mid")
        self.assertEqual(registered.returncode, 0, registered.stderr)
        created = self.run_cli(conductor, "item", "new", "N23", "--title", "Constant time", "--paths", "crates/x/**",
                               "--brief-file", str(brief))
        self.assertEqual(created.returncode, 0, created.stderr)
        picked = self.run_cli(worker, "next")
        self.assertEqual((picked.returncode, picked.stdout.strip()), (0, "N23"))
        self.assertEqual(self.run_cli(worker, "next").stdout.strip(), "N23")
        illegal = self.run_cli(worker, "status", "N23", "ready")
        self.assertEqual(illegal.returncode, 2)
        self.assertIn("not a permitted move", illegal.stderr)
        self.assertEqual(self.run_cli(worker, "inbox").returncode, 1)
        self.run_cli(conductor, "send", "codex-ws2-worker1", "--kind", "fyi", "--subject", "hi", "--body", "x")
        self.assertEqual(self.run_cli(worker, "inbox").returncode, 0)
        leak = self.tmp / "leak.txt"
        leak.write_text("sk-" + "a" * 30)
        self.assertEqual(self.run_cli(worker, "scan", str(leak)).returncode, 1)
        self.assertEqual(self.run_cli(worker, "halt", "--reason", "x").returncode, 2)
        recorded = self.run_cli(conductor, "record", "decision", "pilot-roster", "--file", str(brief))
        self.assertEqual((recorded.returncode, recorded.stdout.strip()), (0, "decisions/0001-pilot-roster.md"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_cli.py' -v`
Expected: FAIL; the subprocess cannot find `bin/swarm`, so `register` returns a non-zero code.

- [ ] **Step 3: Implement.** `swarmlib/cli.py`:

```python
"""`swarm` command line. Exit 0 ok, 1 nothing/negative result, 2 refused or failed."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import agents, board, build, ci, claims, clock, gitio, items, lifecycle, metrics, msgs, reviews, secrets, worktree
from .store import Store, SwarmError, halt, record, resume, set_config


def _split(values: list[str] | None) -> list[str]:
    return [part for value in values or [] for part in value.replace(",", " ").split()]


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default)).expanduser()


def cmd_register(store: Store, a: argparse.Namespace) -> int:
    agents.register(store, agent_id=a.id or store.agent, machine=a.machine, vendor=a.vendor, role=a.role,
                    model=a.model, effort=a.effort, tiers=_split(a.tiers))
    return 0


def cmd_item_new(store: Store, a: argparse.Namespace) -> int:
    items.new(store, item_id=a.id, title=a.title, severity=a.severity, wave=a.wave, tier=a.tier,
              paths=_split(a.paths), depends_on=_split(a.depends), estimate_hours=a.estimate,
              assignee=a.assignee, brief=Path(a.brief_file).read_text())
    return 0


def cmd_list(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    everything, broken = items.all_items(store)
    for item in everything:
        if (a.status and item.status != a.status) or (a.owner and item.meta["owner"] != a.owner):
            continue
        print(f"{item.id}\t{item.meta['severity']}\t{item.status}\t{item.meta['owner'] or '-'}\t{item.meta['title']}")
    for name in broken:
        print(f"UNPARSEABLE\titems/{name}", file=sys.stderr)
    return 0


def cmd_brief(store: Store, a: argparse.Namespace) -> int:
    print(lifecycle.brief(store, a.item))
    return 0


def cmd_claim(store: Store, a: argparse.Namespace) -> int:
    claims.claim(store, a.item, _split(a.paths), share=a.share, steal=a.steal, ttl=a.ttl)
    return 0


def cmd_release(store: Store, a: argparse.Namespace) -> int:
    claims.release(store, a.item)
    return 0


def cmd_reassign(store: Store, a: argparse.Namespace) -> int:
    claims.reassign(store, a.item, a.owner, ttl=a.ttl)
    return 0


def cmd_heartbeat(store: Store, a: argparse.Namespace) -> int:
    claims.heartbeat(store)
    return 0


def cmd_status(store: Store, a: argparse.Namespace) -> int:
    lifecycle.status(store, a.item, a.status, a.note or "")
    return 0


def cmd_submit(store: Store, a: argparse.Namespace) -> int:
    commits = lifecycle.submit(store, a.item, Path(a.worktree or Path.cwd()), repo_url=worktree.repo_url(),
                               base_branch=store.config()["base_branch"])
    print(f"submitted {a.item} with {len(commits)} commits")
    return 0


def cmd_verdict(store: Store, a: argparse.Namespace) -> int:
    findings = Path(a.findings_file).read_text() if a.findings_file else ""
    lifecycle.verdict(store, a.item, a.decision, findings)
    return 0


def cmd_send(store: Store, a: argparse.Namespace) -> int:
    body = Path(a.body_file).read_text() if a.body_file else (a.body or "")
    msgs.send(store, a.to, a.kind, a.item or "", a.subject, body)
    return 0


def cmd_inbox(store: Store, a: argparse.Namespace) -> int:
    found = msgs.inbox(store, include_seen=a.all, mark=not a.peek)
    for message in found:
        print(f"== {message['sent']} {message['from']} -> {message['to']} [{message['kind']}] {message['item']}: {message['subject']}")
        print(message["body"].rstrip())
    return 0 if found else 1


def cmd_wait(store: Store, a: argparse.Namespace) -> int:
    found = lifecycle.wait(store, timeout=a.timeout, interval=a.interval)
    for line in found:
        print(line)
    return 0 if found else 1


def cmd_next(store: Store, a: argparse.Namespace) -> int:
    if store.role == "reviewer":
        picked = lifecycle.next_review(store)
    else:
        me = agents.load(store, store.agent) or {}
        picked = lifecycle.next_item(store, _split(a.tiers) or me.get("tiers") or ["mid"])
    if picked:
        print(picked)
    return 0 if picked else 1


def cmd_board(store: Store, a: argparse.Namespace) -> int:
    if a.write:
        board.write(store)
    else:
        store.sync()
        print(board.render(store))
    return 0


def cmd_metrics(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    green = None
    if not a.no_ci:
        green = ci.green_rate(ci.default_runner, store.config()["base_branch"])
    print(metrics.report(store, hours=a.hours, slot_log=build.slot_dir() / "waits.log", ci_green=green))
    return 0


def cmd_build(store: Store, a: argparse.Namespace) -> int:
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    return build.run(command, item=a.item or "")


def cmd_ci(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    item = items.load(store, a.item)
    ref = a.ref or item.meta["branch"]
    if not ref:
        raise SwarmError(f"{a.item} has no branch yet; pass --ref")
    runner = ci.default_runner
    ci.wait_for_capacity(runner, store.config()["ci_max_in_flight"])
    nonce = ci.dispatch(runner, item=a.item, target_ref=ref, packages=_split(a.packages),
                        test_filter=a.filter or "", features=a.features or "")
    run_id, url = ci.find_run(runner, nonce)
    print(url, flush=True)
    passed = ci.watch(runner, run_id)
    lifecycle.record_evidence(
        store, a.item,
        {"kind": "lane-test", "url": url, "conclusion": "success" if passed else "failure", "ref": ref,
         "packages": _split(a.packages), "at": clock.fmt(clock.now())},
        ci_failed=not passed,
    )
    return 0 if passed else 1


def cmd_ci_busy(store: Store, a: argparse.Namespace) -> int:
    return 0 if ci.busy(ci.default_runner, a.branch or store.config()["base_branch"]) else 1


def cmd_import_reviews(store: Store, a: argparse.Namespace) -> int:
    created = reviews.import_reviews(store, ci.default_runner, a.pr)
    for item_id in created:
        print(item_id)
    return 0


def cmd_worktree(store: Store, a: argparse.Namespace) -> int:
    path = worktree.create(
        store, a.item, repo=_env_path("SWARM_REPO", "~/backbay/arc"), lanes=_env_path("SWARM_LANES", "~/lanes/swarm"),
        base_branch=store.config()["base_branch"], review=a.review,
    )
    print(path)
    return 0


def cmd_sweep(store: Store, a: argparse.Namespace) -> int:
    for item_id in lifecycle.sweep(store):
        print(item_id)
    return 0


def cmd_halt(store: Store, a: argparse.Namespace) -> int:
    halt(store, a.scope, a.reason)
    return 0


def cmd_resume(store: Store, a: argparse.Namespace) -> int:
    resume(store, a.scope)
    return 0


def cmd_config(store: Store, a: argparse.Namespace) -> int:
    set_config(store, a.key, a.value)
    return 0


def cmd_record(store: Store, a: argparse.Namespace) -> int:
    print(record(store, a.kind, a.name, Path(a.file).read_text()))
    return 0


def cmd_scan(store: Store, a: argparse.Namespace) -> int:
    dirty = False
    for name in a.files:
        for kind, line in secrets.scan(Path(name).read_text(errors="replace")):
            print(f"{name}:{line}: {kind}")
            dirty = True
    return 1 if dirty else 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swarm", description="Chio swarm coordination")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("register", help="add or refresh an agent in agents/")
    s.add_argument("--id")
    s.add_argument("--machine", required=True)
    s.add_argument("--vendor", required=True, choices=agents.VENDORS)
    s.add_argument("--role", required=True, choices=agents.ROLES)
    s.add_argument("--model", required=True)
    s.add_argument("--effort", default="")
    s.add_argument("--tiers", nargs="*", default=["mid"])
    s.set_defaults(fn=cmd_register)

    s = sub.add_parser("item", help="conductor: create items")
    item_sub = s.add_subparsers(dest="item_command", required=True)
    n = item_sub.add_parser("new")
    n.add_argument("id")
    n.add_argument("--title", required=True)
    n.add_argument("--severity", default="P2", choices=items.SEVERITIES)
    n.add_argument("--wave", type=int, default=1)
    n.add_argument("--tier", default="mid", choices=agents.TIERS)
    n.add_argument("--paths", nargs="*", default=[])
    n.add_argument("--depends", nargs="*", default=[])
    n.add_argument("--estimate", type=float, default=4)
    n.add_argument("--assignee", default="")
    n.add_argument("--brief-file", required=True)
    n.set_defaults(fn=cmd_item_new)

    s = sub.add_parser("list", help="list items")
    s.add_argument("--status", choices=items.STATUSES)
    s.add_argument("--owner")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("brief", help="print an item as a self-contained prompt")
    s.add_argument("item")
    s.set_defaults(fn=cmd_brief)

    s = sub.add_parser("claim", help="claim an item and its paths")
    s.add_argument("item")
    s.add_argument("--paths", nargs="*", default=[])
    s.add_argument("--share", action="store_true")
    s.add_argument("--steal", action="store_true")
    s.add_argument("--ttl", type=int, default=claims.DEFAULT_TTL_MINUTES)
    s.set_defaults(fn=cmd_claim)

    s = sub.add_parser("release", help="drop your claim")
    s.add_argument("item")
    s.set_defaults(fn=cmd_release)

    s = sub.add_parser("reassign", help="conductor: move an item to another owner")
    s.add_argument("item")
    s.add_argument("owner")
    s.add_argument("--ttl", type=int, default=claims.DEFAULT_TTL_MINUTES)
    s.set_defaults(fn=cmd_reassign)

    sub.add_parser("heartbeat", help="renew your claims and heartbeat").set_defaults(fn=cmd_heartbeat)

    s = sub.add_parser("status", help="move an item to a new status")
    s.add_argument("item")
    s.add_argument("status", choices=items.STATUSES)
    s.add_argument("--note")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("submit", help="push your lane branch and request review")
    s.add_argument("item")
    s.add_argument("--worktree")
    s.set_defaults(fn=cmd_submit)

    s = sub.add_parser("verdict", help="reviewer: accept or request changes")
    s.add_argument("item")
    s.add_argument("decision", choices=("accept", "changes"))
    s.add_argument("--findings-file")
    s.set_defaults(fn=cmd_verdict)

    s = sub.add_parser("send", help="post a message")
    s.add_argument("to")
    s.add_argument("--kind", required=True, choices=msgs.KINDS)
    s.add_argument("--item", default="")
    s.add_argument("--subject", required=True)
    s.add_argument("--body")
    s.add_argument("--body-file")
    s.set_defaults(fn=cmd_send)

    s = sub.add_parser("inbox", help="show unread messages")
    s.add_argument("--all", action="store_true")
    s.add_argument("--peek", action="store_true", help="do not mark as read")
    s.set_defaults(fn=cmd_inbox)

    s = sub.add_parser("wait", help="block until a message or item change arrives")
    s.add_argument("--timeout", type=float, default=540)
    s.add_argument("--interval", type=float, default=30)
    s.set_defaults(fn=cmd_wait)

    s = sub.add_parser("next", help="resume or claim the next item for this agent")
    s.add_argument("--tiers", nargs="*")
    s.set_defaults(fn=cmd_next)

    s = sub.add_parser("board", help="render BOARD.md")
    s.add_argument("--write", action="store_true")
    s.set_defaults(fn=cmd_board)

    s = sub.add_parser("metrics", help="section 10 metrics")
    s.add_argument("--hours", type=int, default=24)
    s.add_argument("--no-ci", action="store_true")
    s.set_defaults(fn=cmd_metrics)

    s = sub.add_parser("build", help="run a build command in a build slot")
    s.add_argument("--item")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_build)

    s = sub.add_parser("ci", help="dispatch lane-test.yml for an item and wait")
    s.add_argument("item")
    s.add_argument("--packages", nargs="+", required=True)
    s.add_argument("--filter")
    s.add_argument("--features")
    s.add_argument("--ref")
    s.set_defaults(fn=cmd_ci)

    s = sub.add_parser("ci-busy", help="exit 0 while CI runs on the integration branch")
    s.add_argument("--branch")
    s.set_defaults(fn=cmd_ci_busy)

    s = sub.add_parser("import-reviews", help="turn review-bot comments into items")
    s.add_argument("pr", type=int)
    s.set_defaults(fn=cmd_import_reviews)

    s = sub.add_parser("worktree", help="create the lane (or review) worktree for an item")
    s.add_argument("item")
    s.add_argument("--review", action="store_true")
    s.set_defaults(fn=cmd_worktree)

    sub.add_parser("sweep", help="janitor: block items over their time budget").set_defaults(fn=cmd_sweep)

    s = sub.add_parser("halt", help="conductor: stop the swarm, a role or an agent")
    s.add_argument("--scope", default="all")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_halt)

    s = sub.add_parser("resume", help="conductor: lift a halt")
    s.add_argument("--scope")
    s.set_defaults(fn=cmd_resume)

    s = sub.add_parser("config", help="conductor: set a config.json key (JSON value)")
    s.add_argument("key")
    s.add_argument("value")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("record", help="conductor: write a decision (auto-numbered) or a digest")
    s.add_argument("kind", choices=("decision", "digest"))
    s.add_argument("name", help="decision slug, or digest name such as 2026-10-07-am")
    s.add_argument("--file", required=True)
    s.set_defaults(fn=cmd_record)

    s = sub.add_parser("scan", help="check files for credential-shaped strings")
    s.add_argument("files", nargs="+")
    s.set_defaults(fn=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = Store.from_env()
    store.hooks.append(lambda: claims.renew_mine(store))
    try:
        return int(args.fn(store, args))
    except (SwarmError, gitio.GitError, ci.CIError, FileNotFoundError) as err:
        print(f"swarm: {err}", file=sys.stderr)
        return 2
```

`bin/swarm` (then `chmod +x bin/swarm`):

```python
#!/usr/bin/env python3
"""Entry point for the swarm CLI (works through a symlink in ~/.local/bin)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmlib.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run it to verify it passes.**

Run: `chmod +x bin/swarm && PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_cli.py' -v`
Expected: `Ran 1 test` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add swarmlib/cli.py bin/swarm tests/test_cli.py
git commit -m "feat(swarm): swarm command line"
```

### Task 10: Role guard hooks for lane worktrees

**Files:**
- Create: `hooks/pre-push`, `hooks/post-checkout`, `hooks/post-commit`, `hooks/post-merge`
- Test: `tests/test_hooks.py`

**Interfaces:**
- Consumes: `SWARM_ROLE` and the per-worktree `swarm.item` config that `worktree.create` sets.
- Produces: pushes to `main` and `swarm` always refused; `integration/beta-next` only for role `integrator`; `integration/process-security-m4` only for role `security`; deletions refused; non-fast-forward only to `lane/<this worktree's item>-*`; Git LFS hooks still run (the repository tracks the Swift xcframework with LFS).

- [ ] **Step 1: Write the failing test** at `tests/test_hooks.py`:

```python
import os
import subprocess
import unittest
from pathlib import Path

from support import SwarmCase, commit_all, git

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "pre-push"
ZERO = "0" * 40


class PrePushHookTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "hookrepo"
        git(self.tmp, "init", "--quiet", "--initial-branch=main", str(self.repo))
        (self.repo / "f").write_text("a\n")
        self.a = commit_all(self.repo, "a")
        (self.repo / "f").write_text("b\n")
        self.b = commit_all(self.repo, "b")  # child of a
        git(self.repo, "checkout", "--quiet", "-b", "side", self.a)
        (self.repo / "f").write_text("c\n")
        self.c = commit_all(self.repo, "c")  # sibling of b
        git(self.repo, "config", "swarm.item", "F1")

    def push(self, remote_ref, local, remote, role="worker"):
        env = {**os.environ, "SWARM_ROLE": role, "SWARM_HOOK_SKIP_LFS": "1"}
        line = f"refs/heads/x {local} {remote_ref} {remote}\n"
        return subprocess.run([str(HOOK), "origin", "https://example.invalid/arc.git"], cwd=self.repo,
                              input=line, text=True, capture_output=True, env=env)

    def test_fast_forward_lane_push_allowed(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", self.b, self.a).returncode, 0)

    def test_new_branch_allowed(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", self.b, ZERO).returncode, 0)

    def test_force_push_only_to_own_lane(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", self.c, self.b).returncode, 0)
        denied = self.push("refs/heads/lane/F2-other", self.c, self.b)
        self.assertEqual(denied.returncode, 1)
        self.assertIn("only this worktree's own lane/F1-*", denied.stderr)

    def test_protected_refs(self):
        self.assertEqual(self.push("refs/heads/main", self.b, self.a).returncode, 1)
        self.assertEqual(self.push("refs/heads/swarm", self.b, self.a).returncode, 1)
        self.assertEqual(self.push("refs/heads/integration/beta-next", self.b, self.a).returncode, 1)
        self.assertEqual(self.push("refs/heads/integration/beta-next", self.b, self.a, role="integrator").returncode, 0)
        self.assertEqual(self.push("refs/heads/integration/beta-next", self.c, self.b, role="integrator").returncode, 1)
        self.assertEqual(self.push("refs/heads/integration/process-security-m4", self.b, self.a).returncode, 1)

    def test_deletion_denied(self):
        self.assertEqual(self.push("refs/heads/lane/F1-fix", ZERO, self.a).returncode, 1)

    def test_unknown_remote_sha_treated_as_rewrite(self):
        unknown = "1234567890abcdef1234567890abcdef12345678"
        self.assertEqual(self.push("refs/heads/feature/x", self.b, unknown).returncode, 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_hooks.py' -v`
Expected: FAIL with `FileNotFoundError` for `hooks/pre-push`.

- [ ] **Step 3: Implement.** `hooks/pre-push`:

```bash
#!/usr/bin/env bash
# Swarm role guard for lane worktrees (installed with core.hooksPath by `swarm worktree`).
set -euo pipefail

remote_name="$1"
remote_url="$2"
role="${SWARM_ROLE:-}"
item="$(git config --get swarm.item || true)"
zero="0000000000000000000000000000000000000000"
input="$(cat)"

deny() {
  echo "swarm pre-push: refused: $*" >&2
  exit 1
}

while read -r local_ref local_sha remote_ref remote_sha; do
  [ -n "${remote_ref:-}" ] || continue
  case "$remote_ref" in
    refs/heads/main) deny "agents never push main" ;;
    refs/heads/swarm) deny "only the swarm CLI writes the swarm branch, from ~/swarm" ;;
    refs/heads/integration/beta-next) [ "$role" = integrator ] || deny "only the integrator pushes integration/beta-next" ;;
    refs/heads/integration/process-security-m4) [ "$role" = security ] || deny "only the security pair pushes the #1160 branch" ;;
  esac
  if [ "$local_sha" = "$zero" ]; then
    deny "deleting $remote_ref is not allowed from a swarm worktree"
  fi
  if [ "$remote_sha" != "$zero" ]; then
    if ! git cat-file -e "${remote_sha}^{commit}" 2>/dev/null || ! git merge-base --is-ancestor "$remote_sha" "$local_sha"; then
      case "$remote_ref" in
        refs/heads/lane/"$item"-*) ;;
        *) deny "rewriting $remote_ref (only this worktree's own lane/$item-* branch may be force-pushed)" ;;
      esac
    fi
  fi
done <<< "$input"

if [ "${SWARM_HOOK_SKIP_LFS:-0}" != 1 ] && command -v git-lfs >/dev/null 2>&1; then
  printf '%s\n' "$input" | git lfs pre-push "$remote_name" "$remote_url"
fi
```

`hooks/post-checkout`:

```sh
#!/bin/sh
# Keep Git LFS working in swarm worktrees, whose core.hooksPath points here.
command -v git-lfs >/dev/null 2>&1 || exit 0
exec git lfs post-checkout "$@"
```

`hooks/post-commit`:

```sh
#!/bin/sh
# Keep Git LFS working in swarm worktrees, whose core.hooksPath points here.
command -v git-lfs >/dev/null 2>&1 || exit 0
exec git lfs post-commit "$@"
```

`hooks/post-merge`:

```sh
#!/bin/sh
# Keep Git LFS working in swarm worktrees, whose core.hooksPath points here.
command -v git-lfs >/dev/null 2>&1 || exit 0
exec git lfs post-merge "$@"
```

- [ ] **Step 4: Run it to verify it passes.**

Run: `chmod +x hooks/* && PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_hooks.py' -v`
Expected: `Ran 6 tests` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add hooks tests/test_hooks.py
git commit -m "feat(swarm): pre-push role guard with Git LFS passthrough"
```

### Task 11: The agent runner, prompts and Claude deny rules

**Files:**
- Create: `swarmlib/agent.py`, `bin/swarm-agent`, `prompts/worker.md`, `prompts/docs.md`, `prompts/reviewer.md`, `prompts/janitor.md`, `prompts/conductor.md`, `prompts/integrator.md`, `prompts/event.md`, `agent-config/claude-settings.json`
- Test: `tests/test_agent.py`

**Interfaces:**
- Consumes: everything in `swarmlib`.
- Produces: `agent.Execution(returncode, output)`, `agent.execute(command, cwd, log_path, timeout=4h)`, `vendor_command(meta, prompt, cwd, *, resume_id="", settings=None, usage_file=None) -> list[str]`, `session_id_from(vendor, output) -> str`, `rate_limited(result) -> bool`, `render(template, **fields) -> str`, `Context(store, meta, executor, make_worktree, waiter, runner, prompts_dir, janitor_clock)`, `worker_iteration(ctx) -> "idle" | "done" | "blocked" | "throttled"`, `reviewer_iteration(ctx) -> "idle" | "done" | "no-verdict" | "throttled"`, `janitor_iteration(ctx) -> list[str]`, `session_iteration(ctx, *, wait_timeout=1200) -> "turn" | "failed" | "throttled"`, `launch(store, agent_id)` (sources `~/.swarm/env`, then `~/.swarm/agents/<id>.env` when present), `watchdog_iteration(store, machine, notified, *, has, start) -> list[str]`, `run(agent_id)`, and `swarm-agent run|launch|stop <id>`, `swarm-agent watchdog [--machine M]`. Prompt fields: worker and docs use `agent, role, item_id, worktree, branch, base, paths, brief`; reviewer uses `agent, item_id, worktree, branch, base, brief`; janitor uses `agent, sender, subject, item_id, request`; conductor and integrator use `agent, base`; event uses `events`.

- [ ] **Step 1: Write the failing test** at `tests/test_agent.py`:

```python
import json
import os
import unittest
from pathlib import Path

from support import SwarmCase

from swarmlib import agent, agents, claims, items, lifecycle, msgs
from swarmlib.agent import Context, Execution

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"


class CommandTest(unittest.TestCase):
    def test_vendor_commands(self):
        cwd = Path("/lane")
        claude = agent.vendor_command({"vendor": "claude", "model": "opus"}, "P", cwd, settings=Path("/s.json"), resume_id="abc")
        self.assertEqual(claude[:3], ["claude", "-p", "P"])
        self.assertIn("bypassPermissions", claude)
        self.assertEqual(claude[-2:], ["--resume", "abc"])
        codex = agent.vendor_command({"vendor": "codex", "model": "gpt-6.1-sol", "effort": "max"}, "P", cwd)
        self.assertEqual(codex[:3], ["codex", "exec", "--json"])
        self.assertIn("model_reasoning_effort=max", codex)
        self.assertEqual(codex[-1], "P")
        resumed = agent.vendor_command({"vendor": "codex", "model": "m"}, "P", cwd, resume_id="t1")
        self.assertEqual(resumed[-3:], ["resume", "t1", "P"])
        cursor = agent.vendor_command({"vendor": "cursor", "model": "sonnet"}, "P", cwd)
        self.assertEqual(cursor[cursor.index("--workspace") + 1], "/lane")
        hermes = agent.vendor_command({"vendor": "hermes", "model": "z-ai/glm-5.2"}, "P", cwd, usage_file=Path("/u.json"))
        self.assertEqual(hermes[:3], ["hermes", "-z", "P"])
        self.assertIn("openrouter", hermes)

    def test_rate_limit_only_on_failure(self):
        self.assertTrue(agent.rate_limited(Execution(1, "Error: 429 Too Many Requests")))
        self.assertFalse(agent.rate_limited(Execution(0, "implemented the rate limit guard")))
        self.assertFalse(agent.rate_limited(Execution(1, "compile error")))

    def test_session_ids(self):
        self.assertEqual(agent.session_id_from("claude", 'noise\n{"type":"result","session_id":"s-1"}\n'), "s-1")
        self.assertEqual(agent.session_id_from("codex", '{"type":"thread.started","thread_id":"t-9"}\n{"type":"x"}\n'), "t-9")
        self.assertEqual(agent.session_id_from("claude", "plain text"), "")

    def test_templates_render_with_their_fields(self):
        fields = dict(agent="a", role="worker", item_id="F1", worktree="/w", branch="lane/F1-x", base="b",
                      paths="p", brief="BRIEF", sender="s", subject="s", request="r", events="- e")
        for template in sorted(PROMPTS.glob("*.md")):
            text = agent.render(template, **fields)
            self.assertNotIn("{", text.replace("{{", ""), template.name)

    def test_render_missing_field_is_swarm_error(self):
        with self.assertRaises(agent.SwarmError):
            agent.render(PROMPTS / "worker.md", agent="a")


class LoopTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="gpt-6.1-sol", effort="medium", tiers=["mid"])
        self.lane = self.tmp / "lane"
        self.lane.mkdir()

    def ctx(self, store, meta, executor, **kw):
        return Context(store=store, meta=meta, executor=executor, make_worktree=lambda _i, _r: self.lane,
                       prompts_dir=PROMPTS, **kw)

    def worker_meta(self):
        return agents.load(self.worker, self.worker.agent)

    def test_worker_iteration_hands_off_when_agent_submits(self):
        self.add_item(self.conductor, "F1")
        seen = {}

        def fake(command, cwd, log):
            seen["prompt"] = command[-1]
            lifecycle.status(self.worker, "F1", "review", "submitted by fake agent")
            return Execution(0, "ok")

        self.assertEqual(agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), fake)), "done")
        self.assertIn("You own exactly one work item: F1", seen["prompt"])
        self.assertIn("## Acceptance", seen["prompt"])

    def test_worker_iteration_blocks_when_agent_quits_without_submit(self):
        self.add_item(self.conductor, "F1")
        result = agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), lambda *a: Execution(0, "gave up")))
        self.assertEqual(result, "blocked")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "blocked")

    def test_worker_iteration_throttles_on_usage_cap(self):
        self.add_item(self.conductor, "F1")
        result = agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), lambda *a: Execution(1, "usage limit reached")))
        self.assertEqual(result, "throttled")
        self.worker.sync()
        meta = agents.load(self.worker, self.worker.agent)
        self.assertEqual((meta["status"], meta["throttled_until"]), ("throttled", "2026-10-06T12:30:00Z"))
        self.assertEqual(items.load(self.worker, "F1").status, "in-progress")

    def test_idle_when_nothing_to_do(self):
        self.assertEqual(agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), lambda *a: Execution(0, ""))), "idle")

    def test_reviewer_without_verdict_releases_review(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lifecycle.status(self.worker, "F1", "review")
        reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        agents.register(reviewer, agent_id=reviewer.agent, machine="ws2", vendor="claude", role="reviewer",
                        model="opus", effort="", tiers=["premium"])
        meta = agents.load(reviewer, reviewer.agent)
        self.assertEqual(agent.reviewer_iteration(self.ctx(reviewer, meta, lambda *a: Execution(0, ""))), "no-verdict")
        reviewer.sync()
        self.assertEqual(items.load(reviewer, "F1").meta["review"]["reviewer"], "")

    def test_session_iteration_saves_and_resumes_session(self):
        conductor = self.clone("claude-ws2-conductor-2", role="conductor", vendor="claude")
        agents.register(conductor, agent_id=conductor.agent, machine="ws2", vendor="claude", role="conductor",
                        model="opus", effort="", tiers=["premium"])
        meta = agents.load(conductor, conductor.agent)
        commands = []

        def fake(command, cwd, log):
            commands.append(command)
            return Execution(0, json.dumps({"type": "result", "session_id": "sess-1"}))

        ctx = self.ctx(conductor, meta, fake, waiter=lambda store, timeout: ["item F1: open -> review"])
        self.assertEqual(agent.session_iteration(ctx), "turn")
        self.assertIn("conductor of the Chio swarm", commands[0][2])
        self.assertNotIn("--resume", commands[0])
        agent.session_iteration(ctx)
        self.assertEqual(commands[1][-2:], ["--resume", "sess-1"])
        self.assertIn("item F1: open -> review", commands[1][2])

    def test_janitor_answers_requests_addressed_to_it(self):
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        agents.register(janitor, agent_id=janitor.agent, machine="ws2", vendor="hermes", role="janitor",
                        model="z-ai/glm-5.2", effort="", tiers=["cheap"])
        msgs.send(self.worker, "janitor", "request", "F1", "triage run 42", "why did it fail?")
        meta = agents.load(janitor, janitor.agent)
        done = agent.janitor_iteration(self.ctx(janitor, meta, lambda *a: Execution(0, "flaky network test")))
        self.assertIn("board", done)
        self.assertTrue(any(d.startswith("answered") for d in done))
        replies = msgs.inbox(self.worker)
        self.assertEqual([(m["subject"], m["body"].strip()) for m in replies], [("re: triage run 42", "flaky network test")])

    def test_watchdog_relaunches_missing_sessions_and_flags_stale(self):
        watch = self.clone("watchdog-ws2", role="janitor", vendor="hermes")
        started = []
        actions = agent.watchdog_iteration(watch, "ws2", {}, has=lambda s: False, start=lambda st, a: started.append(a))
        self.assertEqual(started, ["codex-ws2-worker1"])
        self.at("2026-10-06T13:00:00Z")
        actions = agent.watchdog_iteration(watch, "ws2", {}, has=lambda s: True, start=lambda st, a: None)
        self.assertEqual(actions, ["flagged codex-ws2-worker1"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_agent.py' -v`
Expected: FAIL with `ImportError: cannot import name 'agent' from 'swarmlib'`.

- [ ] **Step 3: Write the prompts.** `prompts/worker.md`:

```markdown
You are {agent}, a {role} agent in the Chio swarm. You own exactly one work item: {item_id}.

Read first:
- ~/swarm/PROTOCOL.md. Decision 0001 supersedes any plan text that says "one implementation owner" or forbids subagents.
- CLAUDE.md and AGENTS.md in your worktree: fail closed, no unwrap/expect, no em dashes, conventional commits.

Your worktree is {worktree} on branch {branch}, cut from {base}. Edit only paths your claim covers: {paths}.

Do this, in order:
1. Write a regression test that reproduces the item. Run it and confirm it fails for the stated reason.
2. Implement the smallest correct fix.
3. Run focused checks through the build wrapper, for example
   `swarm build --item {item_id} -- cargo test -p <crate> <filter>` and
   `swarm build --item {item_id} -- cargo clippy -p <crate> --all-targets -- -D warnings`.
   For Linux x86_64-only tests run `swarm ci {item_id} --packages <crate>`.
4. Commit with a conventional message that names the item, for example `fix(kernel): stop X ({item_id})`.
5. Run `swarm submit {item_id}` from the worktree, then stop.

If you need a path outside your claim, an answer from someone, or you are stuck:
`swarm status {item_id} blocked --note "<one line why>"`, then stop.

Never: weaken a test, add #[ignore], add a clippy allow, skip or filter tests, suppress advisories,
edit fixtures to match wrong output, push except through `swarm submit`, or run git reset --hard,
git clean, rm -rf or cargo clean.

{brief}
```

`prompts/docs.md`:

```markdown
You are {agent}, a {role} agent in the Chio swarm (docs lane: documentation, paper and SDK text; prefer prose checks and the docs build over Rust builds). You own exactly one work item: {item_id}.

Read first:
- ~/swarm/PROTOCOL.md. Decision 0001 supersedes any plan text that says "one implementation owner" or forbids subagents.
- CLAUDE.md and AGENTS.md in your worktree: fail closed, no unwrap/expect, no em dashes, conventional commits.

Your worktree is {worktree} on branch {branch}, cut from {base}. Edit only paths your claim covers: {paths}.

Do this, in order:
1. Write a regression test that reproduces the item. Run it and confirm it fails for the stated reason.
2. Implement the smallest correct fix.
3. Run focused checks through the build wrapper, for example
   `swarm build --item {item_id} -- cargo test -p <crate> <filter>` and
   `swarm build --item {item_id} -- cargo clippy -p <crate> --all-targets -- -D warnings`.
   For Linux x86_64-only tests run `swarm ci {item_id} --packages <crate>`.
4. Commit with a conventional message that names the item, for example `fix(kernel): stop X ({item_id})`.
5. Run `swarm submit {item_id}` from the worktree, then stop.

If you need a path outside your claim, an answer from someone, or you are stuck:
`swarm status {item_id} blocked --note "<one line why>"`, then stop.

Never: weaken a test, add #[ignore], add a clippy allow, skip or filter tests, suppress advisories,
edit fixtures to match wrong output, push except through `swarm submit`, or run git reset --hard,
git clean, rm -rf or cargo clean.

{brief}
```

`prompts/reviewer.md`:

```markdown
You are {agent}, a reviewer in the Chio swarm. Review item {item_id}.

The author used a different vendor than you. Your worktree {worktree} is a detached checkout of {branch}.
See the change with `git diff refs/remotes/swarm/{base}...HEAD` and the commits with
`git log --oneline refs/remotes/swarm/{base}..HEAD`.

Check, in order:
1. Does the change do what the brief and acceptance criteria below ask, and nothing else?
2. Is there a regression test that fails without the fix? Run it with `swarm build --item {item_id} -- cargo test -p <crate> <filter>`.
3. Correctness and fail-closed behaviour, error handling, concurrency, and the house rules in CLAUDE.md.
4. Anti-weakening: no new #[ignore], clippy allow, skipped or filtered tests, advisory suppressions, or fixtures edited to match wrong output.

Then record exactly one verdict and stop:
- `swarm verdict {item_id} accept`
- `swarm verdict {item_id} changes --findings-file <file>` where the file lists each P0-P2 finding with file:line, the problem, and the fix you expect.

Do not edit code or push anything.

{brief}
```

`prompts/janitor.md`:

```markdown
You are {agent}, a janitor in the Chio swarm. You handle mechanical work: CI log triage, finding which
commit in a batch broke a run, rebases of non-code files, evidence bookkeeping and reformatting.
You never write fixes for P0 or P1 security items; report what you find instead.

{sender} asked, about item {item_id}: {subject}

{request}

Answer with what you found and the exact commands you ran. Keep it under 60 lines. If the request
needs product code changes, say which item and files, and stop.
```

`prompts/conductor.md`:

```markdown
You are {agent}, the conductor of the Chio swarm. Your job is throughput toward beta without lowering
the evidence bar. You plan, slice, assign, unblock and report. You never write product code.

Read ~/swarm/PROTOCOL.md, the approved design at docs/superpowers/specs/2026-10-06-agent-swarm-design.md,
and `swarm board`. The integration branch is {base}.

Each turn:
1. `swarm inbox` and act on every message: answer requests, resolve blockers (re-slice the item,
   raise its tier, `swarm reassign`, or `swarm send human` when only Connor can decide).
2. Keep at least one open item per idle worker, ordered by the waves in the design. Create items with
   `swarm item new <ID> --title ... --severity ... --tier ... --paths ... --depends ... --brief-file <file>`.
   Write brief files under /tmp/swarm-briefs/ (never inside ~/swarm, which the CLI resets).
   Every brief has `## Brief` and `## Acceptance` sections and cites decision 0001.
3. Serialize hotspot paths through `--depends` so overlapping items never run at once.
4. Record rulings with `swarm record decision <slug> --file <file>`.
5. At about 09:00 and 17:00 local time write a digest (what landed, what is blocked, spend notes,
   `swarm metrics`) with `swarm record digest <yyyy-mm-dd>-am --file <file>` (or `-pm`), and send
   Connor a one-line pointer with `swarm send human --kind fyi --subject "digest <name>"`.

End your turn when the queue is healthy. You will be resumed when something happens.
```

`prompts/integrator.md`:

```markdown
You are {agent}, the integrator of the Chio swarm. You are the only agent that pushes {base}.

Your worktree is the current directory; it tracks {base}. Each turn:
1. Sync: `git fetch "$SWARM_GIT_URL" "+refs/heads/{base}:refs/remotes/swarm/{base}"` then
   `git merge --ff-only refs/remotes/swarm/{base}`.
2. `swarm list --status ready`. If there are 5 or more ready items, or the oldest has waited 2 hours, start a batch.
3. For each ready item, read its branch from `swarm brief <ID>`, then
   `git fetch "$SWARM_GIT_URL" "+refs/heads/<branch>:refs/remotes/swarm/<branch>"` and
   `git merge --no-ff refs/remotes/swarm/<branch>`. On conflict, `git merge --abort` and send it back with
   `swarm status <ID> in-progress --note "conflicts with <files>"`.
4. Run `swarm build -- cargo build --workspace` and `swarm build -- cargo clippy --workspace -- -D warnings`
   and the affected crates' tests. Revert any merge that breaks them and send that item back with the evidence.
5. Before pushing, run `swarm ci-busy`. If it exits 0, a full CI run is in progress: wait, unless this push
   fixes that run's failure.
6. Push once: `git push "$SWARM_GIT_URL" HEAD:refs/heads/{base}`. Then mark each merged item with
   `swarm status <ID> integrated --note "<merge sha>"`.
7. When hosted CI on the train PR fails, ask a janitor to triage (`swarm send janitor --kind request ...`),
   revert the culprit, push the revert, and return the item.

Never force-push, never push main, never merge an item that is not `ready`. End your turn when idle.
```

`prompts/event.md`:

```markdown
Swarm events since your last turn:

{events}

Run `swarm inbox`, check `swarm board`, act per your charter, then end your turn.
```

- [ ] **Step 4: Write the Claude deny rules** at `agent-config/claude-settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Bash(git reset --hard:*)",
      "Bash(git clean:*)",
      "Bash(git push --force:*)",
      "Bash(git push -f:*)",
      "Bash(git push origin --force:*)",
      "Bash(git worktree remove:*)",
      "Bash(git branch -D:*)",
      "Bash(cargo clean:*)",
      "Bash(rm -rf:*)",
      "Bash(rm -fr:*)",
      "Bash(gh pr merge:*)",
      "Bash(gh repo delete:*)",
      "Bash(gh api -X DELETE:*)",
      "Bash(gh api --method DELETE:*)"
    ]
  }
}
```

- [ ] **Step 5: Implement the runner.** `swarmlib/agent.py`:

```python
"""swarm-agent: run one registered agent (worker, docs, reviewer, janitor, conductor, integrator)."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import agents, board, ci, claims, clock, gitio, items, lifecycle, msgs, reviews, worktree
from .store import Halted, Store, SwarmError

RATE_LIMIT_RE = re.compile(
    r"(?i)rate.?limit|usage limit|quota exceeded|too many requests|\b429\b|limit reached|try again (?:at|in)"
)
THROTTLE_MINUTES = 30
ITEM_ROLES = ("worker", "docs")
SESSION_ROLES = ("conductor", "integrator")
REPLY_LIMIT = 6000


@dataclass
class Execution:
    returncode: int
    output: str


Executor = Callable[[list[str], Path, Path], Execution]


def execute(command: list[str], cwd: Path, log_path: Path, timeout: float = 4 * 3600) -> Execution:
    """Run an agent CLI, streaming its output to a log file you can tail."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as log:
        try:
            code = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            code = 124
    return Execution(code, log_path.read_text(errors="replace"))


def logs_root() -> Path:
    return Path(os.environ.get("SWARM_LOG_DIR", str(Path.home() / ".swarm-logs"))).expanduser()


def state_dir() -> Path:
    path = Path(os.environ.get("SWARM_STATE_DIR", str(Path.home() / ".swarm-state"))).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def vendor_command(
    meta: dict, prompt: str, cwd: Path, *, resume_id: str = "", settings: Path | None = None,
    usage_file: Path | None = None,
) -> list[str]:
    vendor, model, effort = meta["vendor"], meta["model"], meta.get("effort", "")
    if vendor == "claude":
        command = ["claude", "-p", prompt, "--model", model, "--permission-mode", "bypassPermissions",
                   "--output-format", "json"]
        if settings is not None:
            command += ["--settings", str(settings)]
        if resume_id:
            command += ["--resume", resume_id]
        return command
    if vendor == "codex":
        command = ["codex", "exec", "--json", "-m", model, "--sandbox", "danger-full-access",
                   "--skip-git-repo-check", "-C", str(cwd)]
        if effort:
            command += ["-c", f"model_reasoning_effort={effort}"]
        if resume_id:
            command += ["resume", resume_id]
        return command + [prompt]
    if vendor == "cursor":
        return ["cursor-agent", "-p", prompt, "--model", model, "--force", "--output-format", "text",
                "--workspace", str(cwd)]
    if vendor == "hermes":
        command = ["hermes", "-z", prompt, "-m", model, "--provider", "openrouter", "--in", str(cwd), "--yolo"]
        if usage_file is not None:
            command += ["--usage-file", str(usage_file)]
        return command
    raise SwarmError(f"unknown vendor {vendor!r}")


def session_id_from(vendor: str, output: str) -> str:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        found = event.get("session_id") or event.get("thread_id")
        if vendor == "codex" and not found and isinstance(event.get("msg"), dict):
            found = event["msg"].get("session_id")
        if found:
            return str(found)
    return ""


def rate_limited(result: Execution) -> bool:
    return result.returncode != 0 and bool(RATE_LIMIT_RE.search(result.output[-2000:]))


def render(template: Path, **fields: str) -> str:
    try:
        return template.read_text().format_map(fields)
    except KeyError as err:
        raise SwarmError(f"{template.name} needs field {err}") from err


def throttle(store: Store) -> str:
    until = clock.fmt(clock.now() + clock.minutes(THROTTLE_MINUTES))
    claims.heartbeat(store, status="throttled", throttled_until=until)
    return "throttled"


@dataclass
class Context:
    store: Store
    meta: dict
    executor: Executor = execute
    make_worktree: Callable[[str, bool], Path] | None = None
    waiter: Callable[..., list[str]] = lifecycle.wait
    runner: ci.Runner = ci.default_runner
    prompts_dir: Path | None = None
    janitor_clock: dict = field(default_factory=dict)

    @property
    def prompts(self) -> Path:
        return self.prompts_dir or self.store.path("prompts")

    @property
    def settings(self) -> Path:
        return self.store.path("agent-config", "claude-settings.json")

    @property
    def logs(self) -> Path:
        return logs_root() / self.meta["id"]

    def worktree_for(self, item_id: str, review: bool = False) -> Path:
        if self.make_worktree is not None:
            return self.make_worktree(item_id, review)
        return worktree.create(
            self.store, item_id,
            repo=Path(os.environ.get("SWARM_REPO", "~/backbay/arc")).expanduser(),
            lanes=Path(os.environ.get("SWARM_LANES", "~/lanes/swarm")).expanduser(),
            base_branch=self.store.config()["base_branch"], review=review,
        )


def worker_iteration(ctx: Context) -> str:
    store, meta = ctx.store, ctx.meta
    picked = lifecycle.next_item(store, meta.get("tiers") or ["mid"])
    if not picked:
        return "idle"
    lane = ctx.worktree_for(picked)
    store.sync()
    item = items.load(store, picked)
    if item.status == "claimed":
        lifecycle.status(store, picked, "in-progress", "work started")
    prompt = render(
        ctx.prompts / f"{meta['role']}.md", agent=meta["id"], role=meta["role"], item_id=picked,
        worktree=str(lane), branch=worktree.lane_branch(item), base=store.config()["base_branch"],
        paths=", ".join(item.meta["paths"]) or "none listed", brief=lifecycle.brief(store, picked),
    )
    log = ctx.logs / f"{picked}-{clock.stamp()}.log"
    result = ctx.executor(vendor_command(meta, prompt, lane, settings=ctx.settings), lane, log)
    if rate_limited(result):
        return throttle(store)
    store.sync()
    after = items.load(store, picked)
    if after.status == "in-progress" and after.meta["owner"] == meta["id"]:
        lifecycle.status(store, picked, "blocked", f"agent exited ({result.returncode}) without submitting; log {log}")
        return "blocked"
    return "done"


def reviewer_iteration(ctx: Context) -> str:
    store, meta = ctx.store, ctx.meta
    picked = lifecycle.next_review(store)
    if not picked:
        return "idle"
    view = ctx.worktree_for(picked, True)
    store.sync()
    item = items.load(store, picked)
    prompt = render(
        ctx.prompts / "reviewer.md", agent=meta["id"], item_id=picked, worktree=str(view),
        branch=item.meta["branch"], base=store.config()["base_branch"], brief=lifecycle.brief(store, picked),
    )
    log = ctx.logs / f"review-{picked}-{clock.stamp()}.log"
    result = ctx.executor(vendor_command(meta, prompt, view, settings=ctx.settings), view, log)
    if rate_limited(result):
        return throttle(store)
    store.sync()
    after = items.load(store, picked)
    if after.status == "review" and after.meta["review"]["reviewer"] == meta["id"]:
        def mutate() -> bool:
            fresh = items.load(store, picked)
            if fresh.status != "review" or fresh.meta["review"]["reviewer"] != meta["id"]:
                return False
            fresh.meta["review"]["reviewer"] = ""
            fresh.log(store.agent, f"released review without a verdict (exit {result.returncode}); log {log}")
            items.save(store, fresh)
            msgs.write(store, "conductor", "blocker", picked, f"review of {picked} ended without a verdict", str(log))
            return True

        store.transact(f"unreview {picked}", mutate)
        return "no-verdict"
    return "done"


def _lead_janitor(store: Store) -> str:
    janitors = sorted(a["id"] for a in agents.all_agents(store) if a["role"] == "janitor" and a["status"] == "active")
    return janitors[0] if janitors else ""


def janitor_iteration(ctx: Context) -> list[str]:
    store, meta, done = ctx.store, ctx.meta, []
    now = time.monotonic()
    if now - ctx.janitor_clock.get("board", -1e9) >= 600:
        lifecycle.sweep(store)
        board.write(store)
        ctx.janitor_clock["board"] = now
        done.append("board")
    pr = store.config()["train_pr"]
    if pr and now - ctx.janitor_clock.get("reviews", -1e9) >= 3600:
        reviews.import_reviews(store, ctx.runner, int(pr))
        ctx.janitor_clock["reviews"] = now
        done.append("reviews")
    lead = _lead_janitor(store) == meta["id"]
    for message in msgs.inbox(store):
        if message["kind"] != "request" or (message["to"] != meta["id"] and not lead):
            continue
        cwd = Path(os.environ.get("SWARM_REPO", "~/backbay/arc")).expanduser()
        prompt = render(ctx.prompts / "janitor.md", agent=meta["id"], sender=message["from"],
                        subject=message["subject"], item_id=message["item"] or "-", request=message["body"])
        stamp = clock.stamp()
        result = ctx.executor(
            vendor_command(meta, prompt, cwd, usage_file=ctx.logs / f"usage-{stamp}.json"), cwd,
            ctx.logs / f"request-{stamp}.log",
        )
        reply = result.output[-REPLY_LIMIT:].strip() or f"(no output, exit {result.returncode})"
        msgs.send(store, message["from"], "fyi", message["item"], f"re: {message['subject']}", reply)
        done.append(f"answered {message['key']}")
    return done


def session_iteration(ctx: Context, *, wait_timeout: float = 1200) -> str:
    store, meta = ctx.store, ctx.meta
    events = ctx.waiter(store, timeout=wait_timeout)
    sid_path = state_dir() / f"{meta['id']}.session"
    sid = sid_path.read_text().strip() if sid_path.exists() else ""
    if sid:
        prompt = render(ctx.prompts / "event.md", events="\n".join(f"- {e}" for e in events) or "- periodic check, no new events")
    else:
        prompt = render(ctx.prompts / f"{meta['role']}.md", agent=meta["id"], base=store.config()["base_branch"])
    cwd = Path(os.environ.get("SWARM_SESSION_DIR", str(store.root))).expanduser()
    result = ctx.executor(
        vendor_command(meta, prompt, cwd, resume_id=sid, settings=ctx.settings), cwd,
        ctx.logs / f"session-{clock.stamp()}.log",
    )
    if rate_limited(result):
        return throttle(store)
    new_sid = session_id_from(meta["vendor"], result.output)
    if new_sid:
        sid_path.write_text(new_sid)
    elif sid and result.returncode != 0:
        sid_path.unlink(missing_ok=True)  # resume failed: start fresh from the charter next turn
    msgs.inbox(store, mark=True)  # the turn saw these events; do not replay them
    claims.heartbeat(store)
    return "turn" if result.returncode == 0 else "failed"


def tmux_has(session: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", session], capture_output=True).returncode == 0


def launch(store: Store, agent_id: str) -> None:
    meta = agents.load(store, agent_id)
    if meta is None:
        raise SwarmError(f"{agent_id} is not registered")
    env_file = Path(os.environ.get("SWARM_ENV_FILE", "~/.swarm/env")).expanduser()
    agent_env = env_file.parent / "agents" / f"{agent_id}.env"  # optional per-agent overrides
    exports = " ".join(f"{k}={shlex.quote(v)}" for k, v in
                       (("SWARM_AGENT", agent_id), ("SWARM_ROLE", meta["role"]), ("SWARM_VENDOR", meta["vendor"])))
    inner = (
        f"set -a; . {shlex.quote(str(env_file))}; "
        f"if [ -f {shlex.quote(str(agent_env))} ]; then . {shlex.quote(str(agent_env))}; fi; set +a; "
        f"export {exports}; exec swarm-agent run {shlex.quote(agent_id)}"
    )
    subprocess.run(["tmux", "new-session", "-d", "-s", f"swarm-{agent_id}", "bash", "-lc", inner], check=True)


def watchdog_iteration(
    store: Store, machine: str, notified: dict, *, has: Callable[[str], bool] = tmux_has,
    start: Callable[[Store, str], None] = launch,
) -> list[str]:
    store.sync()
    actions = []
    for meta in agents.all_agents(store):
        if meta["machine"] != machine or meta["status"] == "stopped":
            continue
        if not has(f"swarm-{meta['id']}"):
            start(store, meta["id"])
            actions.append(f"launched {meta['id']}")
        elif agents.is_stale(meta) and time.monotonic() - notified.get(meta["id"], -1e9) > 3600:
            msgs.send(store, meta["id"], "fyi", "", "heartbeat stale",
                      "Your runner is alive but has not checked in for 30+ minutes. Finish or block your item.")
            msgs.send(store, "conductor", "blocker", "", f"{meta['id']} silent",
                      f"{meta['id']} on {machine}: tmux session alive, heartbeat {meta['last_heartbeat']}.")
            notified[meta["id"]] = time.monotonic()
            actions.append(f"flagged {meta['id']}")
    return actions


def run(agent_id: str) -> int:
    store = Store.from_env()
    if store.agent != agent_id:
        raise SwarmError(f"SWARM_AGENT is {store.agent!r}; expected {agent_id!r}")
    store.hooks.append(lambda: claims.renew_mine(store))
    ctx: Context | None = None
    failures = 0
    while True:
        try:
            store.sync()
            if store.halt_reason() is not None:
                time.sleep(60)
                continue
            meta = agents.load(store, agent_id)
            if meta is None:
                raise SwarmError(f"{agent_id} is not registered")
            if meta["status"] == "stopped":
                time.sleep(300)
                continue
            until = meta.get("throttled_until")
            if until and clock.parse(until) > clock.now():
                time.sleep(300)
                continue
            if meta["status"] == "throttled":
                claims.heartbeat(store, status="active", throttled_until="")
            if ctx is None:
                ctx = Context(store=store, meta=meta)
            ctx.meta = meta
            role = meta["role"]
            if role in ITEM_ROLES:
                outcome = worker_iteration(ctx)
            elif role == "reviewer":
                outcome = reviewer_iteration(ctx)
            elif role == "janitor":
                outcome = "busy" if janitor_iteration(ctx) else "idle"
            elif role in SESSION_ROLES:
                outcome = session_iteration(ctx)
            else:
                raise SwarmError(f"swarm-agent does not run role {role!r}")
            print(f"{clock.fmt(clock.now())} {agent_id}: {outcome}", flush=True)
            if outcome == "idle":
                lifecycle.wait(store, timeout=60 if role == "janitor" else 540)
            elif outcome == "failed":
                failures += 1
                time.sleep(min(30 * 2 ** failures, 1800))
                continue
            failures = 0
        except Halted:
            time.sleep(60)
        except (SwarmError, gitio.GitError, ci.CIError, OSError) as err:
            failures += 1
            print(f"{clock.fmt(clock.now())} {agent_id}: error: {err}", file=sys.stderr, flush=True)
            time.sleep(min(30 * 2 ** failures, 1800))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="swarm-agent")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("run", "launch", "stop"):
        sub.add_parser(name).add_argument("agent")
    watch = sub.add_parser("watchdog")
    watch.add_argument("--machine", default=os.environ.get("SWARM_MACHINE", socket.gethostname().split(".")[0]))
    watch.add_argument("--interval", type=float, default=120)
    args = p.parse_args(argv)
    store = Store.from_env()
    try:
        if args.command == "run":
            return run(args.agent)
        if args.command == "launch":
            store.sync()
            launch(store, args.agent)
            return 0
        if args.command == "stop":
            return subprocess.run(["tmux", "kill-session", "-t", f"swarm-{args.agent}"]).returncode
        notified: dict = {}
        while True:
            for action in watchdog_iteration(store, args.machine, notified):
                print(f"{clock.fmt(clock.now())} watchdog: {action}", flush=True)
            time.sleep(args.interval)
    except (SwarmError, gitio.GitError) as err:
        print(f"swarm-agent: {err}", file=sys.stderr)
        return 2
```

`bin/swarm-agent` (then `chmod +x bin/swarm-agent`):

```python
#!/usr/bin/env python3
"""Entry point for swarm-agent (works through a symlink in ~/.local/bin)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmlib.agent import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run it to verify it passes.**

Run: `chmod +x bin/swarm-agent && PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_agent.py' -v`
Expected: `Ran 13 tests` and `OK`.

- [ ] **Step 7: Commit.**

```bash
git add swarmlib/agent.py bin/swarm-agent prompts agent-config tests/test_agent.py
git commit -m "feat(swarm): agent runner, role prompts, watchdog and Claude deny rules"
```

### Task 12: Workstation cleanup inventory and machine installer

**Files:**
- Create: `ops/worktree_inventory.py`, `ops/install.sh`
- Test: `tests/test_inventory.py`

**Interfaces:**
- Consumes: `gitio`.
- Produces: `worktree_inventory.Worktree`, `classify(wt, keep, main_path) -> (action, reason)` with actions `keep`, `remove`, `drop-target`; `collect(repo, url) -> list[Worktree]`; `apply(repo, plan_tsv, url) -> int` (re-verifies each line and only removes clean, pushed worktrees); `ops/install.sh` creates `~/swarm`, `~/.local/bin/swarm`, `~/.local/bin/swarm-agent`, `~/.swarm/env` (mode 600) and state directories; it honors `SWARM_MACHINE`.

- [ ] **Step 1: Write the failing test** at `tests/test_inventory.py`:

```python
import os
import sys
import unittest
from pathlib import Path

from support import SwarmCase, commit_all, git

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ops"))

import worktree_inventory as inv  # noqa: E402


def wt(**kw):
    base = dict(path="/w", branch="b", head="h", age_days=30, dirty=0, pushed=True, target_gb=5)
    base.update(kw)
    return inv.Worktree(**base)


class ClassifyTest(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(inv.classify(wt(), [], "/main")[0], "remove")
        self.assertEqual(inv.classify(wt(age_days=2), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(dirty=3), [], "/main"), ("drop-target", "3 uncommitted files; only build output removed"))
        self.assertEqual(inv.classify(wt(dirty=3, age_days=10), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(pushed=False, target_gb=0.2), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(path="/main"), [], "/main")[0], "keep")
        self.assertEqual(inv.classify(wt(path="/lanes/integration"), ["/lanes/integ*"], "/main"), ("keep", "protected"))


class CollectTest(SwarmCase):
    def test_collect_and_apply_only_remove_clean_pushed(self):
        arc, repo = self.make_arc()
        old = {"GIT_COMMITTER_DATE": "2026-09-01T00:00:00Z", "GIT_AUTHOR_DATE": "2026-09-01T00:00:00Z"}
        clean, dirty = self.tmp / "clean", self.tmp / "dirty"
        git(repo, "worktree", "add", "-q", "-b", "old-clean", str(clean))
        git(repo, "worktree", "add", "-q", "-b", "old-dirty", str(dirty))
        for path in (clean, dirty):
            (path / "f.txt").write_text("x\n")
            os.environ.update(old)
            commit_all(path, "old work")
            for key in old:
                del os.environ[key]
            git(path, "push", "-q", str(arc), "HEAD")
        (dirty / "untracked.txt").write_text("y\n")
        rows = {Path(w.path).name: inv.classify(w, [], os.path.realpath(repo))[0] for w in inv.collect(repo, str(arc))}
        self.assertEqual(rows, {"repo": "keep", "clean": "remove", "dirty": "keep"})
        plan = self.tmp / "plan.tsv"
        plan.write_text(f"remove\tr\t0\t35\t{clean}\told-clean\nremove\tr\t0\t35\t{dirty}\told-dirty\n")
        self.assertEqual(inv.apply(repo, plan, str(arc)), 0)
        self.assertFalse(clean.exists())
        self.assertTrue(dirty.exists())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_inventory.py' -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'worktree_inventory'`.

- [ ] **Step 3: Implement.** `ops/worktree_inventory.py` (then `chmod +x`):

```python
#!/usr/bin/env python3
"""List git worktrees with a cleanup recommendation. Read-only unless --apply is given.

  ops/worktree_inventory.py --repo ~/backbay/arc --keep '~/lanes/integration*' > plan.tsv
  # delete the lines you do not approve, then:
  ops/worktree_inventory.py --repo ~/backbay/arc --apply plan.tsv
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmlib import gitio  # noqa: E402

STALE_DAYS = 7
TARGET_STALE_DAYS = 14
TARGET_MIN_GB = 1.0


@dataclass
class Worktree:
    path: str
    branch: str
    head: str
    age_days: float
    dirty: int
    pushed: bool
    target_gb: float


def classify(wt: Worktree, keep: list[str], main_path: str) -> tuple[str, str]:
    if wt.path == main_path or any(fnmatch.fnmatch(wt.path, os.path.expanduser(p)) for p in keep):
        return "keep", "protected"
    if wt.dirty or not wt.pushed:
        reason = f"{wt.dirty} uncommitted files" if wt.dirty else "unpushed commits"
        if wt.age_days >= TARGET_STALE_DAYS and wt.target_gb >= TARGET_MIN_GB:
            return "drop-target", f"{reason}; only build output removed"
        return "keep", reason
    if wt.age_days >= STALE_DAYS:
        return "remove", f"clean, pushed, {wt.age_days:.0f}d since last commit"
    return "keep", "recent"


def _git(repo: str, *args: str) -> str:
    return gitio.run(Path(repo), *args).stdout


def _dir_gb(path: Path) -> float:
    if not path.is_dir():
        return 0.0
    proc = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True)
    return int(proc.stdout.split()[0]) / 1024 / 1024 if proc.returncode == 0 and proc.stdout else 0.0


def remote_heads(repo: Path, url: str | None) -> set[str]:
    if not url:
        return set()
    proc = gitio.run(repo, *gitio.auth_args(), "ls-remote", url, "refs/heads/*", check=False)
    return {line.split()[0] for line in proc.stdout.splitlines() if line.strip()} if proc.returncode == 0 else set()


def collect(repo: Path, url: str | None) -> list[Worktree]:
    heads = remote_heads(repo, url)
    found, entry = [], {}
    for line in _git(str(repo), "worktree", "list", "--porcelain").splitlines() + [""]:
        if line:
            key, _, value = line.partition(" ")
            entry[key] = value
            continue
        if "worktree" in entry and "bare" not in entry and Path(entry["worktree"]).is_dir():
            path = os.path.realpath(entry["worktree"])
            head = entry.get("HEAD", "")
            stamp = int(_git(path, "log", "-1", "--format=%ct").strip() or "0")
            dirty = len([x for x in _git(path, "status", "--porcelain").splitlines() if x.strip()])
            contained = _git(path, "for-each-ref", "--contains", head, "refs/remotes").strip()
            found.append(Worktree(
                path=path, branch=entry.get("branch", "detached").removeprefix("refs/heads/"), head=head,
                age_days=(time.time() - stamp) / 86400, dirty=dirty, pushed=head in heads or bool(contained),
                target_gb=_dir_gb(Path(path) / "target"),
            ))
        entry = {}
    return found


def apply(repo: Path, plan: Path, url: str | None) -> int:
    current = {wt.path: wt for wt in collect(repo, url)}
    main_path = os.path.realpath(_git(str(repo), "rev-parse", "--show-toplevel").strip())
    failures = 0
    for line in plan.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        action, _, _, _, raw_path, *_ = line.split("\t")
        path = os.path.realpath(raw_path)
        wt = current.get(path)
        if wt is None or classify(wt, [], main_path)[0] != action:
            print(f"skip {path}: state changed since the inventory", file=sys.stderr)
            continue
        if action == "remove":
            proc = gitio.run(repo, "worktree", "remove", path, check=False)
            print(f"{'removed' if proc.returncode == 0 else 'FAILED'} {path} {proc.stderr.strip()}")
            failures += proc.returncode != 0
        elif action == "drop-target":
            shutil.rmtree(Path(path) / "target")
            print(f"dropped {path}/target")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, type=lambda s: Path(s).expanduser())
    p.add_argument("--keep", action="append", default=[], help="glob of worktree paths never to touch")
    p.add_argument("--url", default=os.environ.get("SWARM_GIT_URL", "https://github.com/bb-connor/arc.git"))
    p.add_argument("--apply", type=Path, help="approved TSV produced by a previous run")
    args = p.parse_args(argv)
    if args.apply:
        return apply(args.repo, args.apply, args.url)
    main_path = os.path.realpath(_git(str(args.repo), "rev-parse", "--show-toplevel").strip())
    rows = [(classify(wt, args.keep, main_path), wt) for wt in collect(args.repo, args.url)]
    print("# action\treason\ttarget_gb\tage_days\tpath\tbranch")
    for (action, reason), wt in sorted(rows, key=lambda r: (r[0][0], -r[1].target_gb)):
        print(f"{action}\t{reason}\t{wt.target_gb:.1f}\t{wt.age_days:.0f}\t{wt.path}\t{wt.branch}")
    freed = sum(wt.target_gb for (action, _), wt in rows if action in ("remove", "drop-target"))
    print(f"# at least {freed:.1f} GB of build output reclaimable", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

`ops/install.sh` (then `chmod +x`):

```bash
#!/usr/bin/env bash
# Per-machine setup for the Chio swarm. Safe to re-run.
set -euo pipefail

SWARM_HOME="${SWARM_HOME:-$HOME/swarm}"
SWARM_GIT_URL="${SWARM_GIT_URL:-https://github.com/bb-connor/arc.git}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "install.sh: missing $1" >&2; exit 1; }; }
need git
need python3
need tmux
need gh
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "install.sh: python3 >= 3.11 required" >&2; exit 1; }

if [ ! -d "$SWARM_HOME/.git" ]; then
  git clone --quiet --single-branch --branch swarm "$SWARM_GIT_URL" "$SWARM_HOME"
fi
mkdir -p "$HOME/.local/bin" "$HOME/.swarm" "$HOME/.swarm-state" "$HOME/.swarm-build" "$HOME/.swarm-logs"
ln -sf "$SWARM_HOME/bin/swarm" "$HOME/.local/bin/swarm"
ln -sf "$SWARM_HOME/bin/swarm-agent" "$HOME/.local/bin/swarm-agent"

if [ ! -f "$HOME/.swarm/env" ]; then
  (
    umask 077
    cat > "$HOME/.swarm/env" <<ENV
# Chio swarm environment, sourced by swarm-agent. Keep this file mode 600 and out of git.
GH_TOKEN=
SWARM_EMAIL=
SWARM_MACHINE=${SWARM_MACHINE:-$(hostname -s)}
SWARM_HOME=$SWARM_HOME
SWARM_REPO=$HOME/backbay/arc
SWARM_LANES=$HOME/lanes/swarm
SWARM_GIT_URL=$SWARM_GIT_URL
PATH=$HOME/.local/bin:$PATH
ENV
  )
  echo "install.sh: wrote $HOME/.swarm/env; set GH_TOKEN (machine user token) and SWARM_EMAIL"
fi
echo "install.sh: ok, swarm at $(git -C "$SWARM_HOME" log -1 --format=%h)"
```

- [ ] **Step 4: Run it to verify it passes.**

Run: `chmod +x ops/*.py ops/*.sh && bash -n ops/install.sh && PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_inventory.py' -v`
Expected: `Ran 2 tests` and `OK`.

- [ ] **Step 5: Commit.**

```bash
git add ops tests/test_inventory.py
git commit -m "feat(swarm): worktree cleanup inventory and per-machine installer"
```

### Task 13: Protocol, first decision, defaults, and publishing the branch

**Files:**
- Create: `PROTOCOL.md`, `README.md`, `decisions/0001-swarm-supersedes-single-owner.md`, `config.json`, `agents/.keep`, `items/.keep`, `claims/.keep`, `msgs/.keep`, `digests/.keep`

- [ ] **Step 1: Write `PROTOCOL.md`:**

```markdown
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
```

- [ ] **Step 2: Write `README.md`:**

```markdown
# swarm branch

Coordination store and tooling for the Chio agent swarm. Orphan branch: nothing
here is product code, and no workflow runs on pushes to it.

- `PROTOCOL.md`: rules for every agent. `decisions/`: conductor rulings.
- `bin/swarm`, `bin/swarm-agent`, `swarmlib/`: the CLI and runner (Python 3.11+, standard library only).
- `items/`, `claims/`, `agents/`, `msgs/`, `digests/`, `BOARD.md`: live state. Written only by the CLI.
- `ops/install.sh`: per-machine setup. `ops/worktree_inventory.py`: cleanup inventory.

Tests: `PYTHONPATH=. python3 -m unittest discover -s tests`
```

- [ ] **Step 3: Write `decisions/0001-swarm-supersedes-single-owner.md`:**

```markdown
# 0001: The swarm protocol supersedes single-owner plan rules

- Date: 2026-10-06
- Decided by: Connor (approved design `docs/superpowers/specs/2026-10-06-agent-swarm-design.md`)

## Context

The #1173 and #1174 plans say "use one implementation owner" and "the user
prohibits subagents". Those rules prevented uncoordinated parallel edits
before a coordination mechanism existed.

## Decision

For work dispatched through the swarm, the swarm protocol replaces those
instructions:

- one owner per item, enforced by `claims/<ID>.json`;
- path claims keep owners off each other's files, and hotspot items are
  serialized through `depends_on`;
- every change gets a cross-vendor review before the integrator merges it;
- the evidence bar is unchanged: test first, no weakened checks, hosted CI on
  the integration branch, Connor approves every merge to `main`.

Agents working outside the swarm (the security pair until #1160 lands) keep
following their existing plans.
```

- [ ] **Step 4: Write `config.json`:**

```json
{
  "active_waves": [1],
  "base_branch": "integration/beta-next",
  "ci_max_in_flight": 10,
  "train_pr": 0
}
```

- [ ] **Step 5: Add the state directories and run every check.**

```bash
for d in agents items claims msgs digests; do touch "$d/.keep"; done
grep -rl $'\xe2\x80\x94' . --exclude-dir=.git && echo "EM DASH FOUND" || echo "no em dashes"
test ! -e .github && echo "no .github directory"
PYTHONPATH=. python3 -m unittest discover -s tests
```

Expected: `no em dashes`, `no .github directory`, then `Ran 84 tests` and `OK`.

- [ ] **Step 6: Commit and publish.**

```bash
git add PROTOCOL.md README.md decisions config.json agents items claims msgs digests
git commit -m "docs(swarm): protocol, decision 0001 and default config"
git push origin swarm
```

- [ ] **Step 7: Verify the push started no CI.** Wait two minutes, then:

```bash
gh run list --repo bb-connor/arc --branch swarm --limit 5
```

Expected: no runs listed. If any run appears, cancel it with `gh run cancel <id>`, find which workflow's `on.push` matched, and stop to report it.

### Task 14: `lane-test.yml` on `main`

**Files:**
- Create (on a branch of `bb-connor/arc` off `main`): `.github/workflows/lane-test.yml`

- [ ] **Step 1: Branch from `main`.**

```bash
cd /Users/connor/backbay/arc
git fetch origin
git switch -c ci/lane-test-workflow origin/main
```

- [ ] **Step 2: Write `.github/workflows/lane-test.yml`:**

```yaml
name: Lane test
run-name: lane-test ${{ inputs.item }} ${{ inputs.nonce }}

# Dispatched by the swarm CLI (`swarm ci`) on `main`; it checks out the lane
# ref itself because lane branches do not carry this workflow file.

on:
  workflow_dispatch:
    inputs:
      target_ref:
        description: Branch or commit to test
        required: true
        type: string
      item:
        description: Swarm item ID
        required: true
        type: string
      packages:
        description: Space-separated cargo packages
        required: true
        type: string
      filter:
        description: Optional test name filter
        required: false
        default: ""
        type: string
      features:
        description: Optional comma-separated cargo features
        required: false
        default: ""
        type: string
      nonce:
        description: Correlation token from the swarm CLI
        required: true
        type: string

concurrency:
  group: lane-test-${{ inputs.item }}
  cancel-in-progress: true

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  CHIO_CI_RUSTFLAGS: "-D warnings -C link-arg=-Wl,--threads=1"

jobs:
  test:
    name: Lane test
    runs-on: ubuntu-24.04
    timeout-minutes: 120
    steps:
      - name: Validate inputs
        env:
          ITEM: ${{ inputs.item }}
          PACKAGES: ${{ inputs.packages }}
          FILTER: ${{ inputs.filter }}
          FEATURES: ${{ inputs.features }}
        run: |
          set -euo pipefail
          [[ "$ITEM" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "bad item"; exit 1; }
          [[ "$PACKAGES" =~ ^[A-Za-z0-9_\ -]+$ ]] || { echo "bad packages"; exit 1; }
          [[ "$FILTER" =~ ^[A-Za-z0-9_:.\ -]*$ ]] || { echo "bad filter"; exit 1; }
          [[ "$FEATURES" =~ ^[A-Za-z0-9_,/\ -]*$ ]] || { echo "bad features"; exit 1; }

      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
        with:
          ref: ${{ inputs.target_ref }}

      - name: Install Rust toolchain
        run: |
          set -euo pipefail
          rustup toolchain install --profile minimal
          rustup show active-toolchain

      - name: Install protobuf compiler
        run: |
          set -euo pipefail
          export DEBIAN_FRONTEND=noninteractive
          sudo rm -f /etc/apt/sources.list.d/azure-cli.list /etc/apt/sources.list.d/azure-cli.sources \
            /etc/apt/sources.list.d/microsoft-prod.list /etc/apt/sources.list.d/microsoft-prod.sources
          for attempt in 1 2 3; do
            if timeout 180s sudo apt-get update && timeout 180s sudo apt-get install -y protobuf-compiler; then
              exit 0
            fi
            sleep $((attempt * 10))
          done
          exit 1

      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32
        with:
          shared-key: lane-test

      - name: Test
        env:
          PACKAGES: ${{ inputs.packages }}
          FILTER: ${{ inputs.filter }}
          FEATURES: ${{ inputs.features }}
          RUSTFLAGS: "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0"
        run: |
          set -euo pipefail
          args=()
          for package in $PACKAGES; do args+=(-p "$package"); done
          if [ -n "$FEATURES" ]; then args+=(--features "$FEATURES"); fi
          filter=()
          if [ -n "$FILTER" ]; then filter+=("$FILTER"); fi
          cargo test --locked "${args[@]}" -- "${filter[@]}" 2>&1 | tee lane-test.log

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        if: always()
        with:
          name: lane-test-${{ inputs.item }}-${{ inputs.nonce }}
          path: lane-test.log
          if-no-files-found: ignore
```

- [ ] **Step 3: Validate it locally.**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/lane-test.yml')); print('yaml ok')"
grep -c $'\xe2\x80\x94' .github/workflows/lane-test.yml || true
```

Expected: `yaml ok` and `0`.

- [ ] **Step 4: Commit, push and open the PR.**

```bash
git add .github/workflows/lane-test.yml
git commit -m "ci: add dispatchable lane-test workflow for swarm lanes"
git push -u origin ci/lane-test-workflow
gh pr create --base main --title "ci: add dispatchable lane-test workflow for swarm lanes" --body "Adds the on-demand Linux x86_64 test workflow the agent swarm dispatches per item (design: docs/superpowers/specs/2026-10-06-agent-swarm-design.md section 7.3). Always dispatched on main; checks out target_ref itself; inputs validated before use; read-only token; per-item concurrency.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

- [ ] **Step 5 (Connor): Review and merge the PR** once its required checks pass.

- [ ] **Step 6: Smoke-test both outcomes** after the merge:

```bash
gh workflow run lane-test.yml --repo bb-connor/arc --ref main -f target_ref=main -f item=SMOKE-GREEN -f packages=chio-http-core -f nonce=smokegreen1
gh workflow run lane-test.yml --repo bb-connor/arc --ref main -f target_ref=main -f item=SMOKE-RED -f packages=no-such-crate -f nonce=smokered1
sleep 30
gh run list --repo bb-connor/arc --workflow lane-test.yml --limit 2 --json displayTitle,status,conclusion,url
```

Expected, once both finish (re-run the last command until `status` is `completed`): `lane-test SMOKE-GREEN smokegreen1` concludes `success`, and `lane-test SMOKE-RED smokered1` concludes `failure` with `package ID specification` in its log (`gh run view <id> --log | grep -m1 'package ID'`).

---

# Phase 2: machines

### Task 15: Install on workstation-2

- [ ] **Step 1: Clone and install.**

```bash
git clone --quiet --single-branch --branch swarm https://github.com/bb-connor/arc.git ~/swarm
SWARM_MACHINE=ws2 ~/swarm/ops/install.sh
```

Expected: `install.sh: wrote /home/connor/.swarm/env; set GH_TOKEN ...` and `install.sh: ok, swarm at <sha>`.

- [ ] **Step 2: Fill in `~/.swarm/env`.** Edit it with an editor (never `echo` the token on a command line). Set `GH_TOKEN=` to the machine-user token from Task 2, `SWARM_EMAIL=bb-chio-swarm@users.noreply.github.com`, and put Codex's node and the agent CLIs on PATH:

```bash
PATH=/home/connor/.local/bin:/home/connor/.bun/bin:/home/connor/.local/share/mise/installs/node/lts/bin:/usr/local/bin:/usr/bin:/bin
```

Then `chmod 600 ~/.swarm/env`.

- [ ] **Step 3: Verify every agent CLI headless.** Load the env first: `set -a; . ~/.swarm/env; set +a`.

```bash
codex exec --help | grep -E -- '--json|--sandbox|--skip-git-repo-check|-C, --cd'
codex exec resume --help | head -5
claude --version && claude -p "Reply with exactly OK" --model sonnet --output-format json | grep -o '"session_id":"[^"]*"'
hermes -z "Reply with exactly OK" -m z-ai/glm-5.2 --provider openrouter
```

Expected: the four codex flags are listed; `codex exec resume` prints usage; Claude prints a `session_id`; Hermes prints `OK`. If `codex exec resume` is not a valid command or takes its options in a different position, edit `vendor_command` in `swarmlib/agent.py` to match the help text, update `test_vendor_commands` to the same argv, rerun `tests/test_agent.py`, and commit `fix(swarm): match codex exec resume syntax` on the `swarm` branch before continuing.

- [ ] **Step 4: Verify the Claude deny rules hold under bypass mode.**

```bash
mkdir -p /tmp/denycheck && cd /tmp/denycheck && git init -q
claude -p "Run exactly this shell command and report its output: git clean -n" --model sonnet \
  --permission-mode bypassPermissions --settings ~/swarm/agent-config/claude-settings.json --output-format text
cd ~ && rm -rf /tmp/denycheck
```

Expected: the reply says the command was denied by permission settings. If it ran, stop: the deny list is not enforced and the plan's safety rules depend on it.

- [ ] **Step 5: Verify the build slot wrapper.**

```bash
SWARM_AGENT=connor swarm build --item SMOKE -- bash -c 'cat /proc/self/cgroup; echo RUSTC_WRAPPER=$RUSTC_WRAPPER CARGO_INCREMENTAL=$CARGO_INCREMENTAL'
tail -1 ~/.swarm-build/waits.log
sccache --show-stats | head -3
```

Expected: a cgroup line containing `run-u` and `.scope`, `RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0`, and a `waits.log` record with `"item": "SMOKE"`.

- [ ] **Step 6: Run the full suite on Linux.**

```bash
cd ~/swarm && PYTHONPATH=. python3 -m unittest discover -s tests
```

Expected: `Ran 84 tests` and `OK`.

- [ ] **Step 7: Start the watchdog.**

```bash
tmux new-session -d -s swarm-watchdog 'set -a; . ~/.swarm/env; set +a; export SWARM_AGENT=watchdog-ws2 SWARM_ROLE=janitor SWARM_VENDOR=hermes; exec swarm-agent watchdog --machine ws2'
sleep 5; tmux capture-pane -pt swarm-watchdog | tail -3
```

Expected: no error output (it has no registered agents to launch yet).

### Task 16: Clean up workstation-2

Frees build capacity. Never touches anything uncommitted or unpushed, and only removes what Connor approves.

- [ ] **Step 1: Inventory, protecting every active lane.** On workstation-2 (`ssh ws2`), with `~/swarm` installed by Task 15:

```bash
python3 ~/swarm/ops/worktree_inventory.py --repo ~/backbay/arc \
  --keep '/home/connor/lanes/*' --keep '/home/connor/.cache/*' \
  --keep '/home/connor/backbay/arc-agentic-work-plan' > ~/swarm-cleanup.tsv
column -t -s $'\t' ~/swarm-cleanup.tsv | less -S
df -h /
```

Expected: a table of `keep`, `remove` and `drop-target` rows, and a reclaimable-GB total on stderr.

- [ ] **Step 2 (Connor): Approve.** Delete from `~/swarm-cleanup.tsv` every `remove` or `drop-target` line you do not want applied. Keep the header line or remove it; comment lines are ignored.

- [ ] **Step 3: Apply and measure.**

```bash
python3 ~/swarm/ops/worktree_inventory.py --repo ~/backbay/arc --apply ~/swarm-cleanup.tsv
git -C ~/backbay/arc worktree prune
df -h /
```

Expected: one `removed` or `dropped` line per approved row (rows whose state changed since the inventory print `skip`), and more free space than before.

- [ ] **Step 4 (Connor): Grow the boot volume.** In the Oracle Cloud console: Compute, Instances, workstation-2, Boot volume, Edit, size 500 GB, Save. Then on workstation-2:

```bash
findmnt -no SOURCE,FSTYPE /
sudo dd iflag=direct if=/dev/sda of=/dev/null count=1
echo 1 | sudo tee /sys/class/block/sda/device/rescan
sudo growpart /dev/sda 1
sudo resize2fs /dev/sda1
df -h /
```

Expected: `findmnt` shows `/dev/sda1 ext4` (if it shows `xfs`, run `sudo xfs_growfs /` instead of `resize2fs`), and `df` shows about 490 GB total.

### Task 17: Install on the Macs

- [ ] **Step 1: This MacBook Air.**

```bash
command -v git-lfs >/dev/null || brew install git-lfs
git clone --quiet --single-branch --branch swarm https://github.com/bb-connor/arc.git ~/swarm
SWARM_MACHINE=air ~/swarm/ops/install.sh
```

Fill `~/.swarm/env` as in Task 15 Step 2, with `PATH=$HOME/.local/bin:$HOME/.bun/bin:/opt/homebrew/bin:/usr/bin:/bin`. The Air never runs Rust builds: leave `SWARM_BUILD_SLOTS` unset and assign it only `docs` agents.

- [ ] **Step 2: Verify on the Air.**

```bash
set -a; . ~/.swarm/env; set +a
cursor-agent --help | grep -E -- '--print|--force|--workspace'
cd ~/swarm && PYTHONPATH=. python3 -m unittest discover -s tests
```

Expected: the three flags are listed, then `Ran 84 tests` and `OK`.

- [ ] **Step 3 (Connor): Authorize this Mac's key on the MacBook Pro.** On the Pro: append the Air's `~/.ssh/id_ed25519.pub` to `~/.ssh/authorized_keys`.

- [ ] **Step 4: Inventory the Pro.**

```bash
ssh connor@connors-macbook-pro-1 'sysctl -n machdep.cpu.brand_string; echo $(( $(sysctl -n hw.memsize) / 1073741824 ))GB; df -h ~ | tail -1'
```

If it reports an M-series chip with 32 GB or more, repeat Steps 1-2 there with `SWARM_MACHINE=pro` and `SWARM_BUILD_SLOTS=1` in its env; it takes cross-platform Rust lanes only. Otherwise it takes docs lanes only. Record which with `swarm record decision macbook-pro-lanes --file /tmp/swarm-briefs/pro.md` (as conductor, see Task 18) once the roster exists.

---

# Phase 3: pilot and scale-up

### Task 18: Integration branch, roster and pilot items

Run on workstation-2 with `set -a; . ~/.swarm/env; set +a` loaded. Commands marked "as conductor" use `SWARM_AGENT=connor SWARM_ROLE=conductor SWARM_VENDOR=claude` (Connor acting as conductor until the conductor agent starts).

- [ ] **Step 1: Create `integration/beta-next` at #1160's current head.**

```bash
cd ~/backbay/arc
HELPER='!f() { test "$1" = get || exit 0; echo username=x-access-token; echo "password=$GH_TOKEN"; }; f'
git -c credential.helper= -c "credential.helper=$HELPER" fetch "$SWARM_GIT_URL" integration/process-security-m4
git -c credential.helper= -c "credential.helper=$HELPER" push "$SWARM_GIT_URL" FETCH_HEAD:refs/heads/integration/beta-next
git ls-remote "$SWARM_GIT_URL" refs/heads/integration/beta-next refs/heads/integration/process-security-m4
```

Expected: both refs print the same SHA.

- [ ] **Step 2: Create the integrator's worktree** (in the same shell, so `$HELPER` is still set) with the role hook and a token-backed credential helper scoped to that worktree:

```bash
git -C ~/backbay/arc fetch "$SWARM_GIT_URL" "+refs/heads/integration/beta-next:refs/remotes/swarm/integration/beta-next"
git -C ~/backbay/arc worktree add -b integrator/beta-next ~/lanes/swarm/integrator refs/remotes/swarm/integration/beta-next
cd ~/lanes/swarm/integrator
git config --worktree core.hooksPath ~/swarm/hooks
git config --worktree user.name codex-ws2-integrator
git config --worktree user.email "$SWARM_EMAIL"
git config --worktree --add credential.helper ''
git config --worktree --add credential.helper "$HELPER"
```

Expected: `git -C ~/lanes/swarm/integrator config --worktree --get-all credential.helper` prints an empty line and the helper.

- [ ] **Step 2b: Give the two session agents their working directories.** `swarm-agent launch` sources `~/.swarm/agents/<id>.env` after `~/.swarm/env` when it exists:

```bash
mkdir -p ~/.swarm/agents /tmp/swarm-briefs
printf 'SWARM_SESSION_DIR=/home/connor/lanes/swarm/integrator\n' > ~/.swarm/agents/codex-ws2-integrator.env
printf 'SWARM_SESSION_DIR=/home/connor/backbay/arc\n' > ~/.swarm/agents/claude-ws2-conductor.env
chmod 600 ~/.swarm/agents/*.env
```

- [ ] **Step 3: Register the six pilot agents (as conductor).** Two Codex workers and a Claude reviewer keep every pilot review cross-vendor.

```bash
export SWARM_AGENT=connor SWARM_ROLE=conductor SWARM_VENDOR=claude
swarm halt --scope all --reason "pilot not started"
swarm register --id claude-ws2-conductor --machine ws2 --vendor claude --role conductor --model opus --tiers premium
swarm register --id codex-ws2-integrator --machine ws2 --vendor codex --role integrator --model gpt-6.1-sol --effort max --tiers premium
swarm register --id codex-ws2-worker1 --machine ws2 --vendor codex --role worker --model gpt-6.1-sol --effort medium --tiers mid
swarm register --id codex-ws2-worker2 --machine ws2 --vendor codex --role worker --model gpt-6.1-sol --effort medium --tiers mid
swarm register --id claude-ws2-reviewer1 --machine ws2 --vendor claude --role reviewer --model opus --tiers premium
swarm register --id hermes-ws2-janitor1 --machine ws2 --vendor hermes --role janitor --model z-ai/glm-5.2 --tiers cheap
swarm board
```

Expected: the Agents table lists all six as `active`. The halt, set first, keeps the agents the watchdog launches idle until Task 19.

- [ ] **Step 4: Write the four pilot briefs.** `/tmp/brief-N23.md`:

```markdown
## Brief

The kernel stop's emergency handlers compare the `X-Admin-Token` header with `==`
(`authorize` in `crates/platform/chio-http-core/src/emergency.rs`, `Some(token) if token == self.expected_admin_token`),
which leaks timing. The sidecar control-credential precedent (`docs/security/sidecar-control-authority.md`)
requires a constant-time comparison. Source: #1174 umbrella defect N23 (spec 8 S18). Decision 0001 applies.

Compare the token bytes in constant time with `subtle::ConstantTimeEq` (`subtle = "2"` is already a
workspace dependency; add `subtle = { workspace = true }` to chio-http-core if it is not listed).
Keep `admin_token_usable` and keep failing closed on a missing header. Do not mount the handlers:
that is N22, a separate item.

## Acceptance

- Unit tests: the right token is accepted; a wrong token of the same length, a wrong token of a
  different length, an empty token and a missing header are each rejected with `Unauthorized`.
- No `==` comparison of the admin token remains in `emergency.rs`.
- `cargo test -p chio-http-core` and `cargo clippy -p chio-http-core --all-targets -- -D warnings` pass.
```

`/tmp/brief-D6.md`:

```markdown
## Brief

`ContainmentGuard` (`crates/security/chio-security-kernel/src/containment.rs`) and
`CapabilitySetSuspensionGuard` (`crates/security/chio-security-kernel/src/capability_set_suspension.rs`)
inherit the `Guard` default `requires_dispatch_revalidation() -> false`
(`crates/kernel/chio-kernel/src/kernel/mod.rs`). A containment or suspension applied after admission
therefore does not stop a call that has not yet committed dispatch. Source: #1174 umbrella defect D6;
design in `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` section 4.2 item 6
(branch docs/ftl-lessons-specs-20261004). Decision 0001 applies.

Override `requires_dispatch_revalidation` to return `true` in both guards, and implement
`revalidate_before_dispatch` as a repeat of each guard's read-only lookup that fails closed: a lookup
error or a now-active containment or suspension returns an error. Do not consume quota or approvals
again.

## Acceptance

- Regression tests: a containment applied between admission and dispatch denies at dispatch; a
  capability-set suspension applied in the same window denies; a lookup failure during revalidation
  denies; with neither applied, dispatch proceeds.
- Existing guard tests pass unchanged.
- `cargo test -p chio-security-kernel` and `cargo clippy -p chio-security-kernel --all-targets -- -D warnings` pass.
```

`/tmp/brief-D8.md`:

```markdown
## Brief

The Gemini adapter mints `request_id: format!("gemini_{}_call", call.name)`
(`crates/protocol/chio-gemini-tools-adapter/src/adapter.rs`), so two calls to the same function in
one turn share a request id, and durable admission keeps that replay key for the namespace lifetime.
Source: #1174 umbrella defect D8; spec 6 (`docs/superpowers/specs/2026-10-04-opaque-adapter-context-design.md`,
branch docs/ftl-lessons-specs-20261004) rule 1. Decision 0001 applies.

Make every lifted call's request id unique per payload and stable for a retried payload: derive it
from a per-payload lift identifier plus the call's index within the payload (spec 6 rule 1), not from
the function name alone. Keep `received_at` out of the identity. Scope: the Gemini adapter only; the
Ollama half of spec 6 phase 1 is a separate item.

## Acceptance

- Regression test: one payload with two calls to the same function yields two distinct request ids.
- Lifting the same payload twice yields the same ids (retry stability).
- `cargo test -p chio-gemini-tools-adapter` and strict Clippy for that crate pass.
```

`/tmp/brief-N3.md`:

```markdown
## Brief

Receipts for caged, long-lived `AdaptedMcpServer` tools carry no `native_launch`, because
`AdaptedMcpServer` (`crates/protocol/chio-mcp-adapter/src/server.rs`) does not override
`prepared_native_launch_receipt` (default in `crates/kernel/chio-kernel/src/runtime/connection.rs`),
even though it retains its spawn-time enforcement receipt (`native_enforcement_receipt`). Source:
#1174 umbrella defect N3; spec 7 (`docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md`,
branch docs/ftl-lessons-specs-20261004) section 5.1 rules 3 and 4. Decision 0001 applies.

Override `prepared_native_launch_receipt` for `AdaptedMcpServer` to return the retained spawn-time
receipt while the child is alive. Once the transport has recorded the cage `Exited` receipt,
delivery preparation must fail so dispatch denies instead of proceeding unreferenced.

## Acceptance

- Regression tests: a call through a live caged adapted server produces a receipt whose
  `native_launch` references the spawn receipt; after the child exits, dispatch is denied.
- Uncaged adapted servers are unchanged (no `native_launch`).
- `cargo test -p chio-mcp-adapter` and strict Clippy for that crate pass.
```

- [ ] **Step 5: Create the items (as conductor).**

```bash
swarm item new N23 --title "Compare the emergency admin token in constant time" --severity P2 --tier mid \
  --paths 'crates/platform/chio-http-core/src/emergency.rs' 'crates/platform/chio-http-core/Cargo.toml' --estimate 2 --brief-file /tmp/brief-N23.md
swarm item new D6 --title "Revalidate overlay guards before dispatch" --severity P1 --tier mid \
  --paths 'crates/security/chio-security-kernel/src/containment.rs' 'crates/security/chio-security-kernel/src/capability_set_suspension.rs' --estimate 4 --brief-file /tmp/brief-D6.md
swarm item new D8 --title "Mint unique Gemini request ids per call" --severity P2 --tier mid \
  --paths 'crates/protocol/chio-gemini-tools-adapter/**' --estimate 3 --brief-file /tmp/brief-D8.md
swarm item new N3 --title "Bind native_launch for caged adapted MCP servers" --severity P2 --tier mid \
  --paths 'crates/protocol/chio-mcp-adapter/src/**' --estimate 4 --brief-file /tmp/brief-N3.md
swarm list
```

Expected: four `open` items.

### Task 19: Run the pilot

- [ ] **Step 1: Start the agents and lift the halt (as conductor).** The watchdog launches every registered `ws2` agent that has no `tmux` session.

```bash
swarm resume
sleep 150
tmux ls | grep swarm-
swarm board | sed -n '/## Agents/,$p'
```

Expected: seven sessions (`swarm-watchdog` plus six agents) and fresh heartbeats.

- [ ] **Step 2: Rehearse the kill switch once.**

```bash
swarm halt --scope role:worker --reason "kill switch drill"
sleep 120
swarm board | grep -E 'codex-ws2-worker'
swarm resume --scope role:worker
```

Expected: during the halt the workers make no new claims (their log lines in `tmux capture-pane -pt swarm-codex-ws2-worker1` stop advancing); after resume they continue.

- [ ] **Step 3: Watch the first item through the lifecycle.** Check every 30 minutes until one item is `integrated`:

```bash
swarm list
ls ~/.swarm-logs/*/ | tail
swarm metrics --no-ci
```

Expected order for each item (swarm v2): `claimed`, `in-progress`, `submitted`, then `integrated` when the integrator's `swarm check-train --land` lands it (or `in-progress` with a `## Check train` section when it fails). If an item goes `blocked`, read its log section with `swarm brief <ID>` and the agent log path in its item log, then fix the brief or the process and `swarm status <ID> open` (as conductor).

- [ ] **Step 4: Open the standing train PR after the integrator's first push.**

```bash
URL=$(gh pr create --repo bb-connor/arc --base main --head integration/beta-next --draft \
  --title "train: integration/beta-next" \
  --body "Standing train PR for swarm-integrated items on top of #1160. Connor merges; agents never do. Items: see BOARD.md on the swarm branch.

🤖 Generated with [Claude Code](https://claude.com/claude-code)")
echo "$URL"
swarm config train_pr "${URL##*/}"
```

Expected: a draft PR authored by `bb-chio-swarm`, and `ci.yml` checks start on it. The janitor imports bot findings from it hourly.

- [ ] **Step 5: Evaluate the exit criteria** after at least three items reach `integrated`:

```bash
swarm metrics
gh run list --repo bb-connor/arc --workflow CI --branch integration/beta-next --limit 5
git -C ~/lanes/integration log -1 --format='%h %cr'
```

Pilot passes when all hold: three or more items `integrated`; the latest hosted CI run on the train PR is green; no claim was ever held by two agents (check `git log --oneline origin/swarm -- claims/` shows no `taking over from` except deliberate steals); no lost work (every `integrated` item's commits are reachable from `integration/beta-next`); and the security pair's integration lane kept committing at its usual pace during the pilot (compare `git -C ~/lanes/integration log --since=yesterday --oneline | wc -l` with the day before). Write the result to `/tmp/swarm-briefs/pilot.md` and record it with `swarm record digest "$(date +%F)-pilot" --file /tmp/swarm-briefs/pilot.md`, then `swarm send human --kind fyi --subject "pilot result" --body "see digests"`. If any criterion fails, halt, fix, and repeat this task before Task 20.

- [ ] **Step 6: Know how to talk to the conductor directly.** To open its session interactively (for example from your phone through Remote Control), pause its runner first so two processes never drive one session:

```bash
swarm halt --scope agent:claude-ws2-conductor --reason "Connor at the wheel"
cd ~/backbay/arc && claude --resume "$(cat ~/.swarm-state/claude-ws2-conductor.session)"
# when done: exit claude, then
swarm resume --scope agent:claude-ws2-conductor
```

### Task 20: Scale to about 12 agents and decide on the build box

- [ ] **Step 1: Add the kernel and docs lanes (as conductor).**

```bash
swarm register --id codex-ws2-worker3 --machine ws2 --vendor codex --role worker --model gpt-6.1-sol --effort max --tiers premium mid
swarm register --id claude-ws2-worker4 --machine ws2 --vendor claude --role worker --model opus --tiers premium mid
swarm register --id codex-ws2-reviewer2 --machine ws2 --vendor codex --role reviewer --model gpt-6.1-sol --effort max --tiers premium
swarm register --id cursor-air-docs1 --machine air --vendor cursor --role docs --model sonnet --tiers mid
swarm register --id hermes-ws2-janitor2 --machine ws2 --vendor hermes --role janitor --model z-ai/glm-5.2 --tiers cheap
```

Then start the Air's watchdog (`tmux new-session -d -s swarm-watchdog 'set -a; . ~/.swarm/env; set +a; export SWARM_AGENT=watchdog-air SWARM_ROLE=janitor SWARM_VENDOR=hermes; exec swarm-agent watchdog --machine air'`). The conductor agent creates the wave 1 items (B1-B3, review findings, G2, G3) per spec section 6.5, serializing hotspots with `--depends`.

- [ ] **Step 2: Apply the build-box trigger daily for two days.**

```bash
swarm metrics --hours 24
cat /proc/pressure/cpu | head -1
```

If on two consecutive days the median build-slot wait exceeds 20 minutes, or `avg300` CPU pressure stays above 30, send Connor the numbers with `swarm send human --kind request --subject "build box trigger fired"` and write a follow-up plan for the Oracle E5 box (spec section 7.6). Otherwise record "no box needed" in the day's digest.

- [ ] **Step 3: Run one cloud lane end to end (as conductor).** Pick an open docs or SDK item that needs no workspace Rust build (call it `<ID>`):

```bash
swarm reassign <ID> cloud:claude-1 --ttl 480
swarm status <ID> in-progress --note "running in a Claude cloud session"
swarm brief <ID> > /tmp/swarm-briefs/<ID>-cloud.md
printf '\n\nStart from integration/beta-next (git fetch origin integration/beta-next && git checkout -b work FETCH_HEAD). When done, push your commits to a branch and print its name.\n' >> /tmp/swarm-briefs/<ID>-cloud.md
claude --cloud "$(cat /tmp/swarm-briefs/<ID>-cloud.md)"
```

When the session reports its branch (it may be named `claude/...` rather than `lane/...`), register it:

```bash
LANE=$(swarm worktree <ID>)
git -C "$LANE" fetch "$SWARM_GIT_URL" "<cloud-branch>"
git -C "$LANE" merge --no-edit FETCH_HEAD
swarm submit <ID> --worktree "$LANE"
```

Expected: the item moves to `review` with the cloud commits on `lane/<ID>-<slug>`, and the normal review and integration path takes over. Record any friction as a decision.

- [ ] **Step 4: After #1160 merges**, import the remaining `coord/pr1160` board rows as items (one `swarm item new` per open row, briefs from the row text), register the security pair's agents with role `security`, and set `swarm config active_waves "[1, 2]"` once #1173 and the recovery branch have also landed.
