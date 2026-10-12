"""Hermetic source-evidence regressions; requires Git, no historical repo objects."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import validate


class SourceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="chio-computer-validation-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.full = cls.root / "full"
        cls.full.mkdir()
        cls.git(cls.full, "init", "-q", "--initial-branch=main")
        cls.data = b"retained source evidence\n"
        (cls.full / "source.txt").write_bytes(cls.data)
        cls.git(cls.full, "add", "source.txt")
        cls.commit(cls.full, "first")
        cls.local = cls.git(cls.full, "rev-parse", "HEAD").decode().strip()
        (cls.full / "other.txt").write_text("unrelated change\n")
        cls.git(cls.full, "add", "other.txt")
        cls.commit(cls.full, "published")
        cls.published = cls.git(cls.full, "rev-parse", "HEAD").decode().strip()
        cls.shallow = cls.root / "shallow"
        cls.git(cls.root, "clone", "-q", "--depth=1", cls.full.as_uri(), str(cls.shallow))

    @staticmethod
    def git(root, *args):
        return subprocess.run(
            ["git", *args], cwd=root, capture_output=True, check=True,
        ).stdout

    @classmethod
    def commit(cls, root, message):
        cls.git(
            root, "-c", "user.name=Validator Test", "-c",
            "user.email=validator@example.invalid", "-c", "commit.gpgsign=false",
            "-c", f"core.hooksPath={cls.root / 'no-hooks'}",
            "commit", "-q", "-m", message,
        )

    def evidence(self, head=None, hosted=None, equivalent=True):
        return {"views": {"fixture": {
            "head": head or self.local,
            "hosted_source_commit": hosted or self.published,
            "hosted_source_commit_matches_recorded_files": equivalent,
            "sources": [{
                "path": "source.txt",
                "sha256": hashlib.sha256(self.data).hexdigest(),
                "lines": 1,
            }],
        }}}

    def test_missing_published_commits_equal_to_heads_fail(self):
        evidence = {"views": {}}
        for missing in ("a" * 40, "b" * 40):
            evidence["views"][missing] = self.evidence(missing, missing)["views"]["fixture"]
        records, checks, _, errors = validate.validate_sources(evidence, self.full)
        self.assertEqual((records, checks), (2, 0))
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("Missing pinned Git object" in error for error in errors))

    def test_missing_published_source_never_falls_back_to_local(self):
        _, checks, _, errors = validate.validate_sources(
            self.evidence(hosted="a" * 40), self.full,
        )
        self.assertEqual(checks, 0)
        self.assertEqual(len(errors), 1)
        self.assertIn("Missing pinned Git object", errors[0])

    def test_empty_views_still_check_required_pins(self):
        for head, hosted, equivalent in (
            ("a" * 40, "a" * 40, True),
            (self.local, "b" * 40, True),
            ("c" * 40, None, False),
        ):
            with self.subTest(head=head, hosted=hosted):
                evidence = {"views": {"empty": {
                    "head": head, "hosted_source_commit": hosted,
                    "hosted_source_commit_matches_recorded_files": equivalent,
                    "sources": [],
                }}}
                records, checks, _, errors = validate.validate_sources(evidence, self.full)
                self.assertEqual((records, checks), (0, 0))
                self.assertEqual(len(errors), 1)
                self.assertIn("Missing pinned Git object", errors[0])
                self.assertIn(hosted or head, errors[0])

    def partial_clone(self, name):
        client = self.root / name
        self.git(self.full, "config", "uploadpack.allowFilter", "true")
        self.git(
            self.root, "-c", "protocol.file.allow=always", "clone", "-q",
            "--no-checkout", "--depth=1", "--filter=blob:none",
            self.full.as_uri(), str(client),
        )
        return client

    def assert_missing_without_fetch(self, client, evidence, object_id, error):
        def present():
            return subprocess.run(
                ["git", "--no-lazy-fetch", "cat-file", "-e", object_id],
                cwd=client, capture_output=True, check=False,
            ).returncode == 0

        self.assertFalse(present(), "fixture must omit the promised object")
        trace = self.root / f"{client.name}-trace.jsonl"
        # The checker must override an environment that permits lazy fetches.
        with patch.dict(os.environ, {"GIT_NO_LAZY_FETCH": "0", "GIT_TRACE2_EVENT": str(trace)}):
            _, checks, _, errors = validate.validate_sources(evidence, client)
        self.assertEqual(checks, 0)
        self.assertEqual(errors, [error])
        self.assertFalse(present(), "validation must not materialize missing objects")
        events = [json.loads(line) for line in trace.read_text().splitlines()]
        self.assertFalse(any(
            event.get("event") == "child_start" and "fetch" in event.get("argv", [])
            for event in events
        ), "validation must not invoke a promisor fetch")

    def test_partial_clone_missing_blob_is_not_fetched(self):
        client = self.partial_clone("partial-blob")
        blob = self.git(self.full, "rev-parse", f"{self.published}:source.txt").decode().strip()
        self.assert_missing_without_fetch(
            client, self.evidence(), blob,
            f"Missing source {self.published}:source.txt",
        )

    def test_partial_clone_empty_view_missing_commit_is_not_fetched(self):
        client = self.partial_clone("partial-commit")
        evidence = self.evidence(head=self.local, hosted=self.local)
        evidence["views"]["fixture"]["sources"] = []
        self.assert_missing_without_fetch(
            client, evidence, self.local,
            f"Missing pinned Git object {self.local}; fetch it before checking",
        )

    def test_output_is_independent_of_unpublished_object_availability(self):
        present = subprocess.run(
            ["git", "cat-file", "-e", f"{self.local}^{{commit}}"],
            cwd=self.shallow, capture_output=True, check=False,
        )
        self.assertNotEqual(present.returncode, 0)
        evidence = self.evidence()
        full = validate.validate_sources(evidence, self.full)
        shallow = validate.validate_sources(evidence, self.shallow)
        self.assertEqual(full, shallow)
        self.assertEqual(full, (1, 1, {}, []))

    def test_unverified_replacement_does_not_make_head_optional(self):
        _, checks, _, errors = validate.validate_sources(
            self.evidence(equivalent=False), self.shallow,
        )
        self.assertEqual(checks, 1)
        self.assertEqual(len(errors), 1)
        self.assertIn(self.local, errors[0])

    def test_published_bytes_and_line_count_are_still_verified(self):
        evidence = self.evidence()
        record = evidence["views"]["fixture"]["sources"][0]
        record.update(sha256="0" * 64, lines=99)
        _, checks, _, errors = validate.validate_sources(evidence, self.full)
        self.assertEqual(checks, 1)
        self.assertTrue(any("Source hash mismatch" in error for error in errors))
        self.assertTrue(any("Source line count mismatch" in error for error in errors))

    def test_missing_file_in_present_commit_fails(self):
        evidence = self.evidence()
        evidence["views"]["fixture"]["sources"][0]["path"] = "absent.txt"
        _, checks, _, errors = validate.validate_sources(evidence, self.full)
        self.assertEqual(checks, 0)
        self.assertEqual(errors, [f"Missing source {self.published}:absent.txt"])

    def test_document_links_must_target_verified_sources(self):
        evidence = self.evidence()
        _, _, _, errors = validate.validate_sources(
            evidence, self.full,
            [(self.published, "source.txt"), (self.local, "source.txt")],
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("Pinned document link lacks evidence", errors[0])
        self.assertIn(self.local, errors[0])


if __name__ == "__main__":
    unittest.main()
