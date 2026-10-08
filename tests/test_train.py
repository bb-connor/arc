import json
import unittest
from pathlib import Path

from support import SwarmCase, commit_all, git

from swarmlib import train

WORKSPACE = {
    "Cargo.toml": '[workspace]\nmembers = ["crates/a", "crates/b"]\n',
    "crates/a/Cargo.toml": '[package]\nname = "crate-a"\nversion = "0.1.0"\n',
    "crates/a/src/lib.rs": "pub fn a() -> u32 {\n    1\n}\n",
    "crates/b/Cargo.toml": '[package]\nname = "crate-b"\nversion = "0.1.0"\n',
    "crates/b/src/lib.rs": "pub fn b() -> u32 {\n    2\n}\n",
}


def write_tree(root: Path, files: dict) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def compiler_error(file_name, message="cannot find value `x`"):
    return json.dumps({"reason": "compiler-message", "message": {
        "level": "error", "message": message, "rendered": f"error: {message}\n --> {file_name}:2:5\n",
        "spans": [{"file_name": file_name, "is_primary": True}]}})


class WorkspaceCase(SwarmCase):
    """An arc remote whose integration branch holds a two-crate workspace, plus lane-branch helpers."""

    def setUp(self):
        super().setUp()
        self.arc, self.repo = self.make_arc()
        self.author = self.tmp / "author"
        git(self.tmp, "clone", "--quiet", "--branch", "integration/beta-next", str(self.arc), str(self.author))
        write_tree(self.author, WORKSPACE)
        commit_all(self.author, "workspace")
        git(self.author, "push", "--quiet", "origin", "integration/beta-next")

    def push_lane(self, branch: str, files: dict) -> str:
        git(self.author, "checkout", "--quiet", "-B", branch, "origin/integration/beta-next")
        write_tree(self.author, files)
        head = commit_all(self.author, f"work on {branch}")
        git(self.author, "push", "--quiet", "--force", "origin", branch)
        return head


class CrateMapTest(unittest.TestCase):
    def test_package_name_and_crate_lookup(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        write_tree(root, WORKSPACE)
        self.assertEqual(train.crate_of(root, "crates/a/src/lib.rs"), "crate-a")
        self.assertEqual(train.crate_of(root, "crates/b/Cargo.toml"), "crate-b")
        self.assertIsNone(train.crate_of(root, "Cargo.toml"))  # workspace manifest, no [package]
        self.assertIsNone(train.crate_of(root, "docs/notes.md"))


class DiagnosticsTest(unittest.TestCase):
    def test_errors_only_with_primary_span_files(self):
        warning = json.dumps({"reason": "compiler-message", "message": {
            "level": "warning", "message": "unused", "rendered": "warning: unused",
            "spans": [{"file_name": "crates/a/src/lib.rs", "is_primary": True}]}})
        output = "\n".join([
            "   Compiling crate-a v0.1.0",
            compiler_error("crates/b/src/lib.rs"),
            warning,
            compiler_error("/work/train/crates/a/src/lib.rs", "mismatched types"),
            json.dumps({"reason": "build-finished", "success": False}),
        ])
        found = train.diagnostics(output, Path("/work/train"))
        self.assertEqual([f for f, _ in found], ["crates/b/src/lib.rs", "crates/a/src/lib.rs"])
        self.assertIn("mismatched types", found[1][1])


class AttributionTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.root = Path(tempfile.mkdtemp())
        write_tree(self.root, WORKSPACE)
        self.a = train.Lane("A", "lane/A-x", "w1", changed=["crates/a/src/lib.rs"], merged=True)
        self.b = train.Lane("B", "lane/B-x", "w2", changed=["crates/b/src/lib.rs"], merged=True)
        self.c = train.Lane("C", "lane/C-x", "w3", changed=["crates/a/src/lib.rs"], conflict=["crates/a/src/lib.rs"])

    def test_file_then_crate_then_unattributed(self):
        per_lane, loose = train.attribute(
            [self.a, self.b, self.c], self.root,
            [("crates/b/src/lib.rs", "E1"), ("crates/a/src/other.rs", "E2"), ("tools/x.rs", "E3")],
            {"crate-a": "test a::t failed"},
        )
        self.assertEqual(per_lane, {"B": ["E1"], "A": ["E2", "test a::t failed"]})
        self.assertEqual(loose, ["E3"])  # C never merged, so it is never blamed


class ComposeTest(WorkspaceCase):
    def test_merges_clean_lanes_and_reports_conflicts(self):
        self.push_lane("lane/A-a", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    10\n}\n"})
        self.push_lane("lane/B-b", {"crates/b/src/lib.rs": "pub fn b() -> u32 {\n    20\n}\n"})
        self.push_lane("lane/C-c", {"crates/a/src/lib.rs": "pub fn a() -> u32 {\n    11\n}\n"})
        lanes = [train.Lane("A", "lane/A-a", "w1"), train.Lane("B", "lane/B-b", "w2"),
                 train.Lane("C", "lane/C-c", "w3"), train.Lane("D", "lane/D-missing", "w4")]
        workdir = self.tmp / "train-1"
        base = train.compose(self.repo, workdir, "integration/beta-next", lanes,
                             repo_url=str(self.arc), identity="codex-ws2-integrator")
        self.assertEqual(base, git(self.arc, "rev-parse", "integration/beta-next"))
        self.assertEqual([lane.merged for lane in lanes], [True, True, False, False])
        self.assertEqual(lanes[0].changed, ["crates/a/src/lib.rs"])
        self.assertEqual(lanes[2].conflict, ["crates/a/src/lib.rs"])
        self.assertEqual(lanes[3].conflict, ["(branch not on remote)"])
        self.assertIn("10", (workdir / "crates/a/src/lib.rs").read_text())
        self.assertIn("20", (workdir / "crates/b/src/lib.rs").read_text())
        self.assertEqual(git(workdir, "status", "--porcelain"), "")  # aborted merge leaves a clean tree


if __name__ == "__main__":
    unittest.main()
