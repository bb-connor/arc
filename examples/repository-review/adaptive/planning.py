"""Validate model plans and provide an explicit deterministic inventory mode."""

import html
import json
from collections import defaultdict

from .common import bounded_text


def parse_plan(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("model plan contains duplicate JSON keys")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("model plan contains a non-finite number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def validate_plan(plan, paths, maximum):
    if not isinstance(plan, dict) or set(plan) != {"reviews"}:
        raise ValueError("review plan must contain only reviews")
    reviews = plan["reviews"]
    if not isinstance(reviews, list) or not 1 <= len(reviews) <= maximum:
        raise ValueError("review plan exceeds its worker limit")
    available = set(paths)
    covered = set()
    normalized = []
    for index, review in enumerate(reviews, 1):
        if not isinstance(review, dict) or set(review) != {"paths", "focus"}:
            raise ValueError("each review requires only paths and focus")
        selected = review["paths"]
        if (
            not isinstance(selected, list)
            or not selected
            or len(selected) > 128
            or any(not isinstance(path, str) for path in selected)
            or len(set(selected)) != len(selected)
            or not set(selected) <= available
        ):
            raise ValueError(
                "review paths must be unique members of the mediated change inventory"
            )
        focus = bounded_text(review["focus"], 1000, "review focus")
        covered.update(selected)
        normalized.append({"slot": index, "paths": selected, "focus": focus})
    if covered != available:
        raise ValueError("review plan leaves changed paths unassigned")
    return normalized


def inventory_plan(paths, maximum):
    groups = defaultdict(list)
    for path in sorted(paths):
        parts = path.split("/")
        group = (
            "/".join(parts[:3])
            if parts[0] == "crates" and len(parts) >= 3
            else (parts[0] if len(parts) > 1 else "root")
        )
        groups[group].append(path)
    buckets = [[] for _ in range(min(maximum, len(groups)))]
    for group in sorted(groups, key=lambda key: (-len(groups[key]), key)):
        min(buckets, key=len).extend(groups[group])
    return {
        "reviews": [
            {
                "paths": sorted(paths),
                "focus": "Inventory the assigned changes and test paths; do not infer semantic correctness.",
            }
            for paths in buckets
        ]
    }


def inventory_text(inventory, task, limit):
    files = {file["path"]: file for file in inventory["files"]}
    lines = ["Deterministic change inventory. No model review or tests were run.", ""]
    for path in task["paths"]:
        file = files[path]
        safe_path = html.escape(json.dumps(path, ensure_ascii=False))
        before = file["base"].get("lines", file["base"].get("reason", "omitted"))
        after = file["head"].get("lines", file["head"].get("reason", "omitted"))
        lines.append(
            f"- {safe_path}: {file['status']}; base {before}; head {after}; test-path heuristic {file['test_path']}."
        )
    return bounded_text("\n".join(lines), limit, "inventory review")
