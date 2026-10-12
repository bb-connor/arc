#!/usr/bin/env python3
"""Regression cases for the documentation-only pull request classifier."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/classify-docs-only-pr.py"
spec = importlib.util.spec_from_file_location("classify_docs_only_pr", SCRIPT)
assert spec and spec.loader
classifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(classifier)


def entries(*paths: str, mode: str = "100644") -> list[tuple[str, str, str]]:
    return [(mode, mode, path) for path in paths]


def unreferenced(_: list[str]) -> bool:
    return False


for paths, expected in [
    (("docs/guide/install-notes.md",), True),
    (("docs/a.md", "crates/core/chio-core/ARCHITECTURE.md"), True),
    (("README.md",), True),
    ((), False),
    (("docs/a.md", "docs/a.json"), False),
    (("docs/a.md", "crates/core/chio-core/src/lib.rs"), False),
    (("spec/PROTOCOL.md",), False),
    (("formal/MAPPING.md",), False),
    (("third_party/crmf-chio/README.md",), False),
    (("tests/conformance/README.md",), False),
    ((".github/pull_request_template.md",), False),
    (("docs/notes.MD",), False),
    (("docs/../spec/PROTOCOL.md",), False),
]:
    assert classifier.classify(entries(*paths), unreferenced) is expected, paths

assert not classifier.classify(entries("docs/a.md", mode="120000"), unreferenced)
assert not classifier.classify([("000000", "160000", "docs/a.md")], unreferenced)
assert classifier.classify([("100644", "000000", "docs/removed.md")], unreferenced)
assert not classifier.classify(
    entries("docs/a.md", "docs/chio-wall/README.md"),
    lambda paths: "docs/chio-wall/README.md" in paths,
)
assert classifier.reference_needles("docs/chio-wall/README.md") == [
    "chio-wall/README.md",
    "docs/chio-wall/README.md",
]
assert classifier.reference_needles("README.md") == ["README.md"]
assert classifier.owning_package(
    "crates/core/chio-core/docs/notes.md", {"crates/core/chio-core/Cargo.toml"}
) == "crates/core/chio-core"
assert classifier.owning_package("docs/notes.md", {"Cargo.toml"}) is None
assert classifier.parse_raw_diff(
    ":100644 100644 aaaaaaa bbbbbbb M\0docs/a b.md\0:000000 100644 0000000 ccccccc A\0README.md\0"
) == [("100644", "100644", "docs/a b.md"), ("000000", "100644", "README.md")]
for malformed in ["docs/a.md\0", ":100644 100644 a b M\0docs/a.md"]:
    try:
        classifier.parse_raw_diff(malformed)
    except ValueError:
        continue
    raise AssertionError(f"malformed raw diff accepted: {malformed!r}")
assert classifier.parse_raw_diff("") == []


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True, stdout=subprocess.PIPE, text=True,
    ).stdout.strip()


def run(repo: Path, head: str, event: str = "pull_request") -> str:
    env = {**os.environ, "EVENT_NAME": event, "PR_HEAD_SHA": head}
    env.pop("GITHUB_OUTPUT", None)
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=repo, env=env,
        check=True, stdout=subprocess.PIPE, text=True,
    )
    return result.stdout.splitlines()[-1].split(" ", 1)[0]


with tempfile.TemporaryDirectory() as temporary:
    repo = Path(temporary)
    git(repo, "init", "-q", "-b", "main")
    (repo / "crates/demo/src").mkdir(parents=True)
    (repo / "crates/demo/Cargo.toml").write_text('readme = "README.md"\n')
    (repo / "crates/demo/src/lib.rs").write_text("pub fn f() {}\n")
    (repo / "crates/demo/README.md").write_text("demo\n")
    (repo / "crates/demo/GUIDE.md").write_text("guide\n")
    (repo / "docs").mkdir()
    (repo / "docs/free.md").write_text("free\n")
    (repo / "docs/pinned.md").write_text("pinned\n")
    (repo / "check.py").write_text('open("docs/pinned.md")\n')
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")

    def merge_of(*edits: str) -> str:
        git(repo, "checkout", "-q", "-B", "topic", base)
        for path in edits:
            with (repo / path).open("a") as handle:
                handle.write("edit\n")
        git(repo, "commit", "-q", "-am", "topic")
        head = git(repo, "rev-parse", "HEAD")
        git(repo, "checkout", "-q", "--detach", base)
        git(repo, "commit", "-q", "--allow-empty", "-m", "base advance")
        git(repo, "merge", "-q", "--no-ff", "-m", "merge", head)
        return head

    head = merge_of("docs/free.md", "crates/demo/README.md", "crates/demo/GUIDE.md")
    assert run(repo, head) == "docs_only=true"
    assert run(repo, head, event="push") == "docs_only=false"
    assert run(repo, "0" * 40) == "docs_only=false"
    assert run(repo, merge_of("docs/pinned.md")) == "docs_only=false"
    assert run(repo, merge_of("docs/free.md", "crates/demo/src/lib.rs")) == "docs_only=false"
    (repo / "crates/demo/src/lib.rs").write_text('#![doc = include_str!("../README.md")]\n')
    git(repo, "commit", "-q", "-am", "include readme")
    base = git(repo, "rev-parse", "HEAD")
    assert run(repo, merge_of("crates/demo/README.md")) == "docs_only=false"
    assert run(repo, merge_of("crates/demo/GUIDE.md")) == "docs_only=true"

print("docs-only classifier regressions passed")
