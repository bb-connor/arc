#!/usr/bin/env python3
"""Validate landing-ledger coverage and identities, not security correctness."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.PIPE)


def requirement_ids(value: object, path: str, kind: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        errors.append(f"invalid {kind} requirement identities: {path}")
        return []
    if len(set(value)) != len(value):
        errors.append(f"duplicate {kind} requirement identities: {path}")
    return value


def full_commit(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def repair_checkpoint(repair: dict, identity: str, errors: list[str]) -> str | None:
    paths = repair.get("files")
    valid_paths = (isinstance(paths, list) and bool(paths)
                   and all(isinstance(path, str) and bool(path) for path in paths))
    if "checkpoint" in repair:
        checkpoint = repair["checkpoint"]
        if not full_commit(checkpoint) or not valid_paths:
            errors.append("repair requires an exact checkpoint and files: " + identity)
            return None
        return checkpoint

    commits = repair.get("commits")
    head, tree = repair.get("observed_source_head"), repair.get("observed_source_tree")
    if (not valid_paths or not full_commit(head) or not full_commit(tree)
            or not isinstance(commits, list) or not commits
            or any(not full_commit(commit) for commit in commits)
            or len(set(commits)) != len(commits)):
        errors.append("modern repair requires exact commits, head, tree and files: " + identity)
        return None
    try:
        actual_tree = git("rev-parse", head + "^{tree}").decode().strip()
        if actual_tree != tree:
            errors.append("modern repair tree differs from its recorded head: " + identity)
            return None
        for commit in commits:
            git("merge-base", "--is-ancestor", commit, head)
    except subprocess.CalledProcessError:
        errors.append("modern repair commits or head are not retained: " + identity)
        return None
    return head


def check(path: Path) -> list[str]:
    ledger = json.loads(path.read_text())
    errors = []
    rows = ledger["requirements"]
    identities = [row["id"] for row in rows]
    if len(set(identities)) != len(identities):
        errors.append("duplicate requirement identity")
    by_id = {row["id"]: row for row in rows}
    queue = ledger["active_landing_prs"]
    if len(queue) > 2 or len(set(queue)) != len(queue):
        errors.append("active landing queue exceeds two distinct PRs")
    reference = ledger["reference_commit"]
    if git("rev-parse", ledger["reference_tag"] + "^{}").decode().strip() != reference:
        errors.append("archive reference does not match preserved source")
    for source in ledger["sources"]:
        raw = git("show", source["commit"] + ":" + source["path"])
        if hashlib.sha256(raw).hexdigest() != source["sha256"]:
            errors.append("source hash mismatch: " + source["path"])
        expected = requirement_ids(source.get("requirement_ids"), source["path"], "primary", errors)
        associated = requirement_ids(source.get("evidence_requirement_ids", []),
                                     source["path"], "evidence", errors)
        for identity in associated:
            if identity not in by_id:
                errors.append(f"unknown evidence requirement: {identity}: {source['path']}")
        lines = raw.decode().splitlines()
        for identity in expected:
            if identity not in by_id:
                errors.append("missing requirement: " + identity)
                continue
            row = by_id[identity]
            location = row["source"]
            if location["path"] != source["path"]:
                errors.append(f"requirement points at different source: {identity}: "
                              f"{location['path']} != {source['path']}")
                continue
            if "line" in location:
                number = location["line"]
                if type(number) is not int or not 1 <= number <= len(lines):
                    errors.append(f"invalid requirement source line: {identity}: "
                                  f"{source['path']}:{number!r} (1..{len(lines)})")
                    continue
                line = lines[number - 1]
                if hashlib.sha256(line.encode()).hexdigest() != location["line_sha256"]:
                    errors.append("requirement source line mismatch: " + identity)
        if source["path"].endswith("process-security-review-dispositions.json"):
            threads = json.loads(raw)["records"]
            recorded = {by_id[i]["source"]["thread"] for i in expected if i in by_id}
            if recorded != {r["thread"] for r in threads}:
                errors.append("inherited review thread coverage differs")
        elif source["path"].endswith(".md"):
            # Independently enumerate named findings and all non-code checkboxes.
            fence = False
            represented = {by_id[i]["source"]["line"] for i in expected if i in by_id}
            represented.update(n for i in expected if i in by_id
                               for n in by_id[i]["source"].get("additional_lines", []))
            for number, line in enumerate(lines, 1):
                if line.startswith("```"):
                    fence = not fence
                    continue
                if fence:
                    continue
                finding = re.match(r"(?:#{1,5}\s+|\*\*)[A-Z]{1,3}\d+(?:\.\d+)?[.,: ]", line)
                checkbox = re.match(r"\s*- \[[ xX]\]\s+", line)
                if (finding or checkbox) and number not in represented:
                    errors.append(f"unrepresented obligation: {source['path']}:{number}")
    for row in rows:
        if row["landing_unit"] not in ledger["landing_units"]:
            errors.append("unknown landing unit: " + row["id"])
        if row["landing_pr"] != ledger["landing_units"].get(row["landing_unit"]):
            errors.append("landing PR differs from unit: " + row["id"])
        if not row["main_ancestry_verified"] and not row["remaining_acceptance"]:
            errors.append("unlanded requirement has no remaining acceptance: " + row["id"])
        if row["main_ancestry_verified"]:
            commit = row.get("main_commit")
            if not commit or subprocess.run(
                ["git", "merge-base", "--is-ancestor", commit, "origin/main"], cwd=ROOT,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode:
                errors.append("unproven main ancestry: " + row["id"])
        repair = row["source_repair"]
        if isinstance(repair, str):
            try:
                git("cat-file", "-e", reference + ":" + repair)
            except subprocess.CalledProcessError:
                errors.append("missing repair record: " + repair)
        elif isinstance(repair, dict):
            checkpoint = repair_checkpoint(repair, row["id"], errors)
            if checkpoint is None:
                continue
            for repair_path in repair["files"]:
                try:
                    git("cat-file", "-e", checkpoint + ":" + repair_path)
                except subprocess.CalledProcessError:
                    errors.append("missing pinned repair record: " + row["id"] + ":" + repair_path)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path,
                        default=ROOT / "docs/security/landing-ledger.json")
    args = parser.parse_args()
    try:
        errors = check(args.path)
    except (OSError, ValueError, KeyError, IndexError, subprocess.CalledProcessError) as error:
        print(f"invalid landing ledger: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Landing ledger coverage and identities verified; this is not runtime or merge qualification.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
