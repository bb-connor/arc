#!/usr/bin/env python3
"""Negative controls for private package provenance and upstream advisories."""

import copy
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "npm_forks", ROOT / "scripts/check-npm-tooling-forks.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
FORKS = json.loads((ROOT / CHECK.RECORD).read_text())["forks"]


class ToolingSourceTests(unittest.TestCase):
    def test_exact_repair_does_not_accept_another_advisory(self):
        for record in FORKS:
            CHECK.verify_advisories(
                record, {"vulns": [{"id": record["fixed_advisory"]}]}
            )
            with self.assertRaises(ValueError):
                CHECK.verify_advisories(
                    record, {"vulns": [{"id": "GHSA-unrepaired-advisory"}]}
                )

    def test_archive_paths_and_member_types_cannot_escape(self):
        for name, kind in [
            ("/package/file", tarfile.REGTYPE),
            ("package/../file", tarfile.REGTYPE),
            ("package/link", tarfile.SYMTYPE),
        ]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                archive.addfile(entry)
            with self.subTest(name=name), self.assertRaises(ValueError):
                CHECK.unpack(data.getvalue())

    def test_registry_resolution_or_missing_tool_requires_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "sdks/typescript"
            directory.mkdir(parents=True)
            for name in ("package.json", "package-lock.json"):
                shutil.copyfile(ROOT / "sdks/typescript" / name, directory / name)
            CHECK.verify_resolution(root, FORKS)
            original = json.loads((directory / "package-lock.json").read_text())
            for fork in FORKS:
                for changed in ("registry", "missing", "bytes"):
                    lock = copy.deepcopy(original)
                    key = "node_modules/" + fork["upstream_name"]
                    if changed == "registry":
                        lock["packages"][key]["resolved"] = fork["upstream_url"]
                    elif changed == "missing":
                        del lock["packages"][key]
                    else:
                        lock["packages"][key]["integrity"] = "sha512-changed"
                    (directory / "package-lock.json").write_text(json.dumps(lock))
                    with (
                        self.subTest(package=key, changed=changed),
                        self.assertRaises(ValueError),
                    ):
                        CHECK.verify_resolution(root, FORKS)

    def test_changed_archive_and_patch_are_rejected_before_reconstruction(self):
        for fork in FORKS:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for field in ("archive", "patch"):
                    path = root / fork[field]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / fork[field], path)
                upstream = b"source control"
                record = {**fork, "upstream_integrity": CHECK.integrity(upstream)}
                archive = root / fork["archive"]
                archive.write_bytes(archive.read_bytes() + b"tampered")
                with self.assertRaisesRegex(ValueError, "archive changed"):
                    CHECK.verify_fork(root, record, upstream)
                shutil.copyfile(ROOT / fork["archive"], archive)
                (root / fork["patch"]).write_text("changed repair")
                with self.assertRaisesRegex(ValueError, "repair changed"):
                    CHECK.verify_fork(root, record, upstream)


if __name__ == "__main__":
    unittest.main()
