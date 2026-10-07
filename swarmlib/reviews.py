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
