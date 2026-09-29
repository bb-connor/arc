#!/usr/bin/env python3
"""Forbid new ambient wall-clock reads and independent clock traits in the TCB.

The inventory includes fixtures as well as production. It pins existing debt
by file and function; moving or adding a call requires a real migration. The
native shared adapter is the sole permanent wall-clock exception. This gate
does not claim that the inventoried remaining production calls are migrated.
"""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "scripts/security-clock-inventory.json"
ROOTS = ("crates/security/", "crates/kernel/", "crates/guards/",
         "crates/platform/chio-control-plane/", "crates/platform/chio-store-sqlite/",
         "crates/protocol/chio-mcp-edge/", "crates/protocol/chio-mcp-adapter/",
         "crates/protocol/chio-a2a-adapter/", "crates/protocol/chio-openai-adapter/",
         "crates/protocol/chio-mcp-remote/", "crates/protocol/chio-a2a-edge/")
ADAPTER = "crates/security/chio-security-types/src/clock/system.rs"
PORT = "crates/security/chio-security-types/src/clock.rs"
spec = importlib.util.spec_from_file_location("negative_assertions", ROOT / "scripts/check-negative-assertions.py")
lexer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lexer
spec.loader.exec_module(lexer)


def sites(path, source):
    scanned = lexer.blank_rust_noise(source)
    functions = [(m.start(), m.group(1)) for m in lexer.FN_ITEM.finditer(scanned)]
    names = {"SystemTime", "Utc"} | set(re.findall(r"\b(?:SystemTime|Utc)\s+as\s+(\w+)", scanned))
    calls = re.compile(r"\b(?:" + "|".join(sorted(names)) + r")\s*::\s*now\s*\(")
    result = Counter()
    for match in calls.finditer(scanned):
        if path != ADAPTER:
            result[f"{path}::{lexer.enclosing_function(functions, match.start())}"] += 1
    for match in re.finditer(r"\btrait\s+(\w*Clock)\b", scanned):
        if path != PORT:
            result[f"{path}::trait {match.group(1)}"] += 1
    return result


def inventory(root):
    paths = subprocess.check_output(["git", "-C", str(root), "ls-files", "--cached",
                                    "--others", "--exclude-standard", "crates/*.rs", "crates/*.inc"], text=True)
    found = Counter()
    for path in set(paths.splitlines()):
        if path.startswith(ROOTS) and (root / path).is_file():
            found.update(sites(path, (root / path).read_text()))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ratchet", action="store_true")
    args = parser.parse_args()
    baseline = json.loads(INVENTORY.read_text())
    found = inventory(args.root)
    allowed = Counter(baseline["sites"])
    added = found - allowed
    if added:
        for key, count in sorted(added.items()):
            print(f"new clock bypass: {key} (+{count})", file=sys.stderr)
        raise SystemExit(1)
    if args.ratchet:
        baseline["sites"] = dict(sorted(found.items()))
        INVENTORY.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"Security clock inventory: {sum(found.values())} remaining sites, no additions")


if __name__ == "__main__":
    main()
