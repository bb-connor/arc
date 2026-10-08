"""Agent merge gate: a PR reaches main only when it is green, reviewed, and free of open P0-P2 findings."""

from __future__ import annotations

import json
import re

from . import agents, ci, items, msgs, reviews
from .store import Store, SwarmError

REQUIRED_CHECKS = (
    "Build, lint, test",
    "MSRV build and test",
    "cargo-vet (locked supply-chain audit)",
    "cargo-deny (supply-chain bans/advisories/licenses)",
)
CODEX_BOT = "chatgpt-codex-connector[bot]"
BLOCKING = ("P0", "P1", "P2")
FIXED = ("integrated", "done")
WONTFIX_LINE = re.compile(r"status \S+ -> wontfix(?::\s*(\S.*))?$", re.M)
MERGE_ROLES = ("conductor", "integrator")


def _jsonl(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def pull(runner: ci.Runner, pr: int) -> dict:
    return json.loads(ci.gh(runner, "api", f"repos/{ci.repo_slug()}/pulls/{pr}"))


def check_failures(runner: ci.Runner, sha: str) -> list[str]:
    jq = ".check_runs[] | {name, status, conclusion, started_at}"
    runs = _jsonl(ci.gh(runner, "api", "--paginate", "--jq", jq,
                        f"repos/{ci.repo_slug()}/commits/{sha}/check-runs?per_page=100"))
    reasons = []
    for name in REQUIRED_CHECKS:
        attempts = sorted((r for r in runs if r["name"] == name), key=lambda r: r.get("started_at") or "")
        if not attempts:
            reasons.append(f"required check '{name}' has not run on {sha[:7]}")
        elif attempts[-1]["status"] != "completed":
            reasons.append(f"required check '{name}' is still {attempts[-1]['status']}")
        elif attempts[-1]["conclusion"] != "success":
            reasons.append(f"required check '{name}' concluded {attempts[-1]['conclusion']}")
    return reasons


def codex_reviewed(runner: ci.Runner, pr: int, sha: str) -> bool:
    jq = ".[] | {user: .user.login, body}"
    comments = _jsonl(ci.gh(runner, "api", "--paginate", "--jq", jq, f"repos/{ci.repo_slug()}/issues/{pr}/comments"))
    return any(
        line.startswith("|") and f"`{sha[:7]}`" in line and "Completed" in line
        for comment in comments if comment["user"] == CODEX_BOT
        for line in comment["body"].splitlines()
    )


def finding_failures(store: Store, runner: ci.Runner, pr: int) -> list[str]:
    reasons = []
    for comment in reviews.fetch(runner, pr):
        severity = reviews.severity_of(comment["body"])
        if comment["user"] not in reviews.BOTS or comment.get("in_reply_to_id") or severity not in BLOCKING:
            continue
        item_id = f"R{pr}-{comment['id']}"
        if not items.exists(store, item_id):
            reasons.append(f"{severity} finding not imported as {item_id}: {comment['html_url']}")
            continue
        item = items.load(store, item_id)
        if item.status in FIXED:
            continue
        if item.status == "wontfix":
            decisions = WONTFIX_LINE.findall(item.body)
            if decisions and decisions[-1].strip():
                continue
            reasons.append(f"{item_id} is wontfix without a recorded reason")
            continue
        reasons.append(f"{item_id} is {item.status}")
    return reasons


def review_failures(store: Store, pr: int, sha: str) -> list[str]:
    item_id = f"PR{pr}"
    if not items.exists(store, item_id):
        return [f"no whole-PR review item {item_id}; run `swarm review-pr {pr}`"]
    item = items.load(store, item_id)
    reviewed = item.meta["commits"][-1] if item.meta["commits"] else "nothing"
    if reviewed != sha[:12]:
        return [f"{item_id} reviewed {reviewed}, not head {sha[:12]}; run `swarm review-pr {pr}`"]
    review = item.meta["review"]
    if review["verdict"] != "accept" or item.status not in ("ready", "integrated", "done"):
        return [f"{item_id} has no accepted review of {sha[:12]} (status {item.status}, verdict {review['verdict'] or 'none'})"]
    reviewer = agents.load(store, review["reviewer"]) if review["reviewer"] else None
    if reviewer is None or reviewer.get("vendor") == item.meta["author_vendor"]:
        return [f"{item_id} was not reviewed cross-vendor"]
    return []


def gate(store: Store, runner: ci.Runner, pr: int) -> tuple[str, list[str]]:
    """Return (head SHA, reasons the PR may not merge). No reasons means mergeable."""
    store.sync()
    info = pull(runner, pr)
    sha = info["head"]["sha"]
    reasons = []
    if info["state"] != "open":
        reasons.append(f"PR #{pr} is {info['state']}")
    if info["base"]["ref"] != "main":
        reasons.append(f"PR #{pr} targets {info['base']['ref']}, not main")
    reasons += check_failures(runner, sha)
    if not codex_reviewed(runner, pr, sha):
        reasons.append(f"Codex review has not completed on {sha[:7]}")
    reasons += finding_failures(store, runner, pr)
    reasons += review_failures(store, pr, sha)
    return sha, reasons


def merge(store: Store, runner: ci.Runner, pr: int) -> str:
    """Merge PR `pr` on its gated head commit. Never uses --admin."""
    if store.role not in MERGE_ROLES:
        raise SwarmError("only the integrator or the conductor merges")
    sha, reasons = gate(store, runner, pr)
    if reasons:
        raise SwarmError(f"PR #{pr} is not mergeable:\n  " + "\n  ".join(reasons))
    if pull(runner, pr).get("draft"):
        ci.gh(runner, "pr", "ready", str(pr), "--repo", ci.repo_slug())
    ci.gh(runner, "pr", "merge", str(pr), "--repo", ci.repo_slug(), "--merge", "--match-head-commit", sha)
    msgs.send(store, "human", "fyi", f"PR{pr}", f"merged PR #{pr}",
              f"{store.agent} merged PR #{pr} at {sha} after the merge gate passed.")
    return sha
