#!/usr/bin/env python3
"""Validate the Computer design documents and their pinned source evidence.

Run from any directory. Pinned Git objects must already be available locally;
this checker performs no network access and executes no proposed examples.
"""

import ast
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path


CONTRACT_CASE_COUNTS = {1: 6, 2: 9, 3: 11, 4: 15, 5: 11}


def validate_sources(evidence, root, pinned_links=()):
    """Check mandatory canonical sources, independently of incidental Git objects."""
    errors = []
    records = 0
    checks = 0
    known = set()
    manifests = {}
    missing_commits = set()
    for view in evidence["views"].values():
        head = view["head"]
        hosted = view.get("hosted_source_commit")
        # A recorded equivalent selects the published source deterministically.
        # It never makes that source optional, even when head == hosted.
        if hosted and view.get("hosted_source_commit_matches_recorded_files") is True:
            commits = (hosted,)
        else:
            commits = tuple(sorted({head, hosted} - {None}))
        for record in view["sources"]:
            records += 1
            if record.get("inspection") == "manifest_inventory":
                manifests[record["crate_name"]] = record["crate_group"]
            for commit in commits:
                known.add((commit, record["path"]))
                if commit in missing_commits:
                    continue
                result = subprocess.run(
                    ["git", "show", f"{commit}:{record['path']}"],
                    cwd=root, capture_output=True, check=False,
                )
                if result.returncode:
                    exists = subprocess.run(
                        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                        cwd=root, capture_output=True, check=False,
                    )
                    if exists.returncode:
                        missing_commits.add(commit)
                        errors.append(f"Missing pinned Git object {commit}; fetch it before checking")
                    else:
                        errors.append(f"Missing source {commit}:{record['path']}")
                    continue
                checks += 1
                data = result.stdout
                if hashlib.sha256(data).hexdigest() != record["sha256"]:
                    errors.append(f"Source hash mismatch: {commit}:{record['path']}")
                if len(data.splitlines()) != record["lines"]:
                    errors.append(f"Source line count mismatch: {commit}:{record['path']}")
                if record.get("inspection") == "manifest_inventory":
                    package_name = tomllib.loads(data.decode())["package"]["name"]
                    if package_name != record["crate_name"]:
                        errors.append(f"Manifest package-name mismatch: {record['path']}")
                    if Path(record["path"]).parts[1] != record["crate_group"]:
                        errors.append(f"Manifest group mismatch: {record['path']}")

    for target in pinned_links:
        if target not in known:
            errors.append(f"Pinned document link lacks evidence: {target}")
    return records, checks, manifests, errors


def main():
    directory = Path(__file__).resolve().parent
    root = directory.parents[2]
    errors = []
    document_hashes = {}
    syntax_count = 0
    local_links = 0
    pinned_links = []
    cases = set()
    profiles = {}
    expected_cases = {
        f"C{contract}-{number:02d}"
        for contract, count in CONTRACT_CASE_COUNTS.items()
        for number in range(1, count + 1)
    }

    documents = sorted(directory.glob("*.md")) + sorted((directory / "research").glob("*.md"))
    for document in documents:
        source = document.read_text()
        document_hashes[str(document.relative_to(directory))] = hashlib.sha256(source.encode()).hexdigest()
        if "\u2014" in source:
            errors.append(f"{document.relative_to(directory)}: em dash")
        if re.search(r"\b(?:TODO|TBD|FIXME)\b", source):
            errors.append(f"{document.relative_to(directory)}: unresolved placeholder")
        if any(line != line.rstrip() for line in source.splitlines()):
            errors.append(f"{document.relative_to(directory)}: trailing whitespace")
        if len(re.findall(r"^```", source, re.MULTILINE)) % 2:
            errors.append(f"{document.relative_to(directory)}: unbalanced fences")
        for target in re.findall(r"\]\(([^)]+)\)", source):
            if "://" not in target and not target.startswith("#"):
                local_links += 1
                if not (document.parent / target.split("#")[0]).exists():
                    errors.append(f"{document.relative_to(directory)}: missing local link {target}")
        pinned_links.extend(
            re.findall(
                r"https://github.com/bb-connor/arc/blob/([0-9a-f]{40})/([^\s)#]+)",
                source,
            )
        )
        for snippet in re.findall(r"```python\n(.*?)\n```", source, re.DOTALL):
            try:
                compile(snippet, document.name, "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
                syntax_count += 1
            except SyntaxError as error:
                errors.append(f"{document.relative_to(directory)}: {error}")
        if document.name == "ACCEPTANCE.md":
            listed = re.findall(r"^\| (C[1-5]-\d{2}) \|", source, re.MULTILINE)
            cases = set(listed)
            if len(listed) != len(cases):
                errors.append("ACCEPTANCE.md: duplicate case IDs")
            profiles = dict(re.findall(
                r"^\| (C[1-5]-\d{2}) \| (Computer-0|Both|Later funded) \|",
                source, re.MULTILINE,
            ))
        contract = re.match(r"0([1-5])-", document.name)
        if contract:
            number = int(contract.group(1))
            expected_range = f"Acceptance: **C{number}-01 through C{number}-{CONTRACT_CASE_COUNTS[number]:02d}**"
            if expected_range not in source:
                errors.append(f"{document.name}: incomplete acceptance range")

    if cases != expected_cases:
        errors.append(f"Acceptance case mismatch: {sorted(cases ^ expected_cases)}")
    if set(profiles) != cases:
        errors.append("ACCEPTANCE.md: every case needs a recognized qualification profile")
    if {case for case, profile in profiles.items() if profile == "Later funded"} != {"C4-06", "C4-08"}:
        errors.append("ACCEPTANCE.md: funded cases must remain outside Computer-0")
    if syntax_count != 2:
        errors.append(f"Expected two proposed Python examples; found {syntax_count}")

    # D23: `&` composes in parallel and `|` in sequence, with no parentheses.
    expression = ast.parse("a & b & c | d | e", mode="eval").body
    precedence_ok = (
        isinstance(expression, ast.BinOp)
        and isinstance(expression.op, ast.BitOr)
        and isinstance(expression.left, ast.BinOp)
        and isinstance(expression.left.op, ast.BitOr)
        and isinstance(expression.left.left, ast.BinOp)
        and isinstance(expression.left.left.op, ast.BitAnd)
        and isinstance(expression.left.left.left, ast.BinOp)
        and isinstance(expression.left.left.left.op, ast.BitAnd)
    )
    if not precedence_ok:
        errors.append("Unexpected Python composition precedence")

    evidence_path = directory / "research" / "source-evidence.json"
    evidence = json.loads(evidence_path.read_text())
    records, checks, manifests, source_errors = validate_sources(evidence, root, pinned_links)
    errors.extend(source_errors)
    if len(manifests) != 158 or len(set(manifests.values())) != 12:
        errors.append("Manifest inventory does not cover 158 distinct crates in 12 groups")

    result = {
        "schema": "chio.computer.design-check.v1",
        "design_revision": 5,
        "document_sha256": document_hashes,
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "validator_regression_sha256": hashlib.sha256((directory / "test_validate.py").read_bytes()).hexdigest(),
        "source_evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "python_examples_syntax_checked": syntax_count,
        "operator_precedence_checked": precedence_ok,
        "local_links_checked": local_links,
        "pinned_source_links_checked": len(pinned_links),
        "source_records": records,
        "source_objects_hash_and_line_count_checked": checks,
        "source_selection": "canonical-published-equivalent-or-required-pins",
        "distinct_crate_manifests": len(manifests),
        "crate_groups": len(set(manifests.values())),
        "proposed_acceptance_cases": len(cases),
        "acceptance_cases_by_profile": {
            profile: sum(value == profile for value in profiles.values())
            for profile in ("Computer-0", "Both", "Later funded")
        },
        "runtime_tests_run": False,
        "api_implemented": False,
        "errors": errors,
    }
    (directory / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "document_sha256"}, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
