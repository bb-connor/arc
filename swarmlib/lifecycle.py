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
        if (store.role == "integrator" and old == "in-progress" and new_status == "submitted" and owner
                and owner != store.agent and not owner.startswith("cloud:")):
            msgs.write(store, owner, "fyi", item_id, f"{item_id} fixed in place by the integrator",
                       (note or "see item log") + "\n\nFetch your lane branch before you push to it again.")
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


def _remote_head(worktree: Path, repo_url: str, branch: str) -> str:
    """The lane branch's commit on the remote, fetched locally, or "" when it is not there."""
    fetched = gitio.run(worktree, *gitio.auth_args(), "fetch", "--quiet", repo_url,
                        f"+refs/heads/{branch}:refs/remotes/swarm/{branch}", check=False)
    return gitio.out(worktree, "rev-parse", f"refs/remotes/swarm/{branch}") if fetched.returncode == 0 else ""


def submit(store: Store, item_id: str, worktree: Path, *, repo_url: str, base_branch: str) -> list[str]:
    """Push the lane branch and queue the item for the next check train."""
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
    remote = _remote_head(worktree, repo_url, branch)
    if remote:
        contained = gitio.run(worktree, "merge-base", "--is-ancestor", remote, "HEAD", check=False).returncode == 0
        last = item.meta["commits"][-1:]
        if not contained and not (last and remote.startswith(last[0])):
            raise SwarmError(f"{branch} has commits you do not have (the integrator may have fixed it in place); "
                             f"run `git pull --rebase \"$SWARM_GIT_URL\" {branch}` and submit again")
    # Rewriting your own last submission is fine; the lease refuses if anyone pushed since we looked.
    gitio.run(worktree, *gitio.auth_args(), "push", "--quiet", f"--force-with-lease=refs/heads/{branch}:{remote}",
              repo_url, f"HEAD:refs/heads/{branch}")
    vendor = owner.split(":", 1)[1].split("-", 1)[0] if on_behalf else store.vendor

    def mutate() -> bool:
        fresh = items.load(store, item_id)
        if fresh.status != "in-progress":
            raise SwarmError(f"{item_id} moved to {fresh.status} while submitting")
        fresh.meta.update(branch=branch, commits=[c[:12] for c in commits], author_vendor=vendor, status="submitted")
        fresh.log(store.agent, f"status in-progress -> submitted: {len(commits)} commits on {branch}")
        items.save(store, fresh)
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


PR_REVIEW_BRIEF = """## Brief

Review the whole diff of PR #{pr} ({base}...{branch}) at the commit under review, as one change.
Item reviews already covered each lane; look for what they cannot see: interactions between
items, inconsistent invariants, missing tests across crate boundaries, and anything that would
make main worse than before. Decision 0001 applies.

## Acceptance

- `swarm verdict PR{pr} accept` only if you find no P0, P1 or P2 problem in the whole diff.
- Otherwise `swarm verdict PR{pr} changes --findings-file <file>` listing each finding with file:line.
"""


def request_pr_review(store: Store, pr: int, *, head: str, branch: str, author_vendor: str, base: str = "main") -> bool:
    """Open (or re-open for a new head) the whole-PR review item PR<n>. False if already requested."""
    if store.role not in ("conductor", "integrator"):
        raise SwarmError("only the integrator or the conductor requests a whole-PR review")
    item_id = f"PR{pr}"

    def mutate() -> bool:
        if items.exists(store, item_id):
            item = items.load(store, item_id)
            if item.meta["commits"] == [head[:12]] and item.status in ("review", "ready"):
                return False
        else:
            item = items.create(
                store, item_id=item_id, title=f"Whole-diff review of PR #{pr}", severity="P1",
                wave=max(store.config()["active_waves"]), tier="premium", paths=[], depends_on=[],
                estimate_hours=2, assignee="", brief=PR_REVIEW_BRIEF.format(pr=pr, base=base, branch=branch),
            )
        item.meta.update(status="review", owner=store.agent, branch=branch, commits=[head[:12]],
                         author_vendor=author_vendor, review_base=base)
        item.meta["review"].update(verdict="", reviewer="", round=0)
        item.log(store.agent, f"review requested for {base}...{branch} at {head[:12]}")
        items.save(store, item)
        msgs.write(store, "reviewer", "request", item_id, f"review PR #{pr}", f"Whole diff {base}...{branch} at {head[:12]}.")
        return True

    return store.transact(f"review-pr {pr}", mutate)


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
    digest_every: float | None = None, sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    """Block until a new message or a change to the caller's items. [] on timeout.

    With `digest_every`, routine events are held until that many seconds have passed and returned
    together; a `blocker` message or a subject containing URGENT still returns at once.
    """
    store.sync()
    before = _snapshot(store)
    waited = since_beat = 0.0
    while True:
        messages = msgs.inbox(store, mark=False, sync=False)
        events = [f"message from {m['from']} [{m['kind']}] {m['item']}: {m['subject']}" for m in messages]
        after = _snapshot(store)
        events += [f"item {key}: {before.get(key)} -> {value}" for key, value in after.items() if before.get(key) != value]
        urgent = any(m["kind"] == "blocker" or "URGENT" in m["subject"].upper() for m in messages)
        due = digest_every is None or waited >= digest_every
        if (events and (due or urgent)) or waited >= timeout:
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
