#!/usr/bin/env python3
"""Every workspace manifest must select the full fuzz inventory."""

import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[2]
workflow = (root / ".github/workflows/cflite_pr.yml").read_text()
matches = re.findall(r"if grep -qE '([^']+)' changed\.txt; then", workflow)
assert len(matches) == 1, "fuzz inventory fallback must have one explicit selector"
selector = re.compile(matches[0])
paths = subprocess.check_output(
    ["git", "ls-files", "--", "*Cargo.toml"], cwd=root, text=True
).splitlines()
assert len(paths) > 100, "manifest discovery unexpectedly omitted workspace members"
for path in paths + [
    "crates/future/new-member/Cargo.toml",
    "crates/guards/chio-data-guards/redactors/default/Cargo.toml",
    "Cargo.lock",
    "fuzz/target-map.toml",
]:
    assert selector.search(path), (
        f"manifest/control edit does not select full fuzz inventory: {path}"
    )
for path in [
    "docs/Cargo.toml.example",
    "src/Cargo.toml.rs",
    "crates/core/chio-core/src/lib.rs",
]:
    assert not selector.search(path), (
        f"non-manifest edit unexpectedly selected full inventory: {path}"
    )
assert 'fired=("${targets[@]}")' in workflow
# Execute the owning fallback and output projection with the real target-map
# inventory. A matching predicate alone does not prove all targets are emitted.
inventory = sorted(
    tomllib.loads((root / "fuzz/target-map.toml").read_text())["targets"]
)
assert inventory, "fuzz target inventory must not be empty"
fallback_start = workflow.index("          if grep -qE '")
fallback_end = workflow.index("          fired_count=", fallback_start)
fallback = "\n".join(
    line[10:] for line in workflow[fallback_start:fallback_end].splitlines()
)
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    for path in [
        "crates/guards/chio-data-guards/redactors/default/Cargo.toml",
        "crates/future/deep/new/member/Cargo.toml",
    ]:
        (directory / "changed.txt").write_text(path + "\n")
        subprocess.run(
            [
                "bash",
                "-euc",
                'targets=("$@"); fired=()\n' + fallback,
                "fuzz-selector",
                *inventory,
            ],
            cwd=directory,
            check=True,
            capture_output=True,
            text=True,
        )
        assert (directory / "fired.txt").read_text().splitlines() == inventory, path
    (directory / "changed.txt").write_text("docs/Cargo.toml.example\n")
    subprocess.run(
        [
            "bash",
            "-euc",
            'targets=("$@"); fired=()\n' + fallback,
            "fuzz-selector",
            *inventory,
        ],
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )
    assert (directory / "fired.txt").read_text() == ""
print(
    f"fuzz manifest selection passed ({len(paths)} tracked manifests plus future-member controls)"
)
print(f"nested manifest fallback emitted all {len(inventory)} owning targets")
