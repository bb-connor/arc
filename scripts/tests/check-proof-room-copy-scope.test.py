#!/usr/bin/env python3
"""Keep historical source evidence distinct from scanned release copy."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
script = (ROOT / "scripts/check-chio-proof-room-release-truth.sh").read_text()
source = script.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
namespace = {}
exec(compile(source.split("\ntruth_doc = read_truth", 1)[0], str(ROOT / "scripts/check-chio-proof-room-release-truth.sh"), "exec"), namespace)
SNAPSHOTS = (
    Path("docs/reviews/artifacts/2026-09-29-native-clock-test-ownership/kernel-source-before.json"),
    Path("docs/market/open-agent-work/execution/15-native-integration-evidence.json"),
)
copy_check = compile(
    "for path, line_no, line in iter_doc_lines(configured_docs(DEFAULT_DOCS)):"
    + source.split("for path, line_no, line in iter_doc_lines(configured_docs(DEFAULT_DOCS)):", 1)[1].split("\nif failures:", 1)[0],
    "release-copy-check",
    "exec",
)


def copy_failures(paths):
    namespace["failures"] = []
    with patch.dict(os.environ, {"CHIO_PROOF_ROOM_RELEASE_DOCS": os.pathsep.join(map(str, paths))}):
        exec(copy_check, namespace)
    return namespace["failures"]


class ReleaseCopyScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="chio-proof-copy-scope-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        namespace["ROOT"] = self.root

    def write(self, relative, text):
        document = self.root / relative
        document.parent.mkdir(parents=True, exist_ok=True)
        document.write_text(text)
        return document

    def test_committed_source_snapshot_is_preserved_as_evidence(self):
        for snapshot in SNAPSHOTS:
            with self.subTest(path=snapshot):
                target = self.write(snapshot, "")
                shutil.copyfile(ROOT / snapshot, target)
                self.assertEqual(copy_failures([target]), [])

    def test_source_snapshot_cannot_be_replaced_with_marketing_copy(self):
        for snapshot in SNAPSHOTS:
            with self.subTest(path=snapshot):
                target = self.write(snapshot, json.dumps({"summary": "Chio ships ACP support."}))
                with self.assertRaisesRegex(SystemExit, "source-snapshot-digest-mismatch"):
                    copy_failures([target])

    def test_review_plan_and_adjacent_json_claims_remain_enforced(self):
        for relative in [
            "docs/reviews/2026-10-01-review.md",
            "docs/superpowers/plans/2026-10-01-plan.md",
            "docs/reviews/artifacts/2026-09-29-native-clock-test-ownership/marketing.json",
            "docs/release/kernel-source-before.json",
            "docs/market/open-agent-work/execution/marketing.json",
            "docs/release/15-native-integration-evidence.json",
        ]:
            with self.subTest(path=relative):
                target = self.write(relative, "Chio ships ACP support. Chio is the universal agent protocol.\n")
                failures = copy_failures([target])
                self.assertTrue(any("bare_acp" in failure for failure in failures))
                self.assertTrue(any("universal_protocol_overclaim" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
