#!/usr/bin/env python3
"""Every workspace manifest must select the full fuzz inventory."""

import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
workflow = (root / ".github/workflows/cflite_pr.yml").read_text()
matches = re.findall(r"if grep -qE '([^']+)' changed\.txt; then", workflow)
assert len(matches) == 1, "fuzz inventory fallback must have one explicit selector"
selector = re.compile(matches[0])
paths = subprocess.check_output(["git", "ls-files", "--", "*Cargo.toml"], cwd=root, text=True).splitlines()
assert len(paths) > 100, "manifest discovery unexpectedly omitted workspace members"
for path in paths + ["crates/future/new-member/Cargo.toml", "Cargo.lock", "fuzz/target-map.toml"]:
    assert selector.search(path), f"manifest/control edit does not select full fuzz inventory: {path}"
for path in ["docs/Cargo.toml.example", "src/Cargo.toml.rs", "crates/core/chio-core/src/lib.rs"]:
    assert not selector.search(path), f"non-manifest edit unexpectedly selected full inventory: {path}"
assert 'fired=("${targets[@]}")' in workflow
print(f"fuzz manifest selection passed ({len(paths)} tracked manifests plus future-member controls)")
