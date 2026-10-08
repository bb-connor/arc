#!/usr/bin/env python3
"""Owning checker Originals. Root runs these before any producer/checker repair."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

CHECKER_PATH = Path(os.environ.get(
    "LEDGER_CHECKER_PATH", str(Path(__file__).resolve().parents[1] / "check-security-landing-ledger.py")
))
spec = importlib.util.spec_from_file_location("ledger_original_owner", CHECKER_PATH)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

REFERENCE = "a" * 40
TREE = "b" * 40
IDENTITY = "fixture:original"
ORIGIN_PATH = "fixture-origin.json"
EVIDENCE_PATH = "fixture-evidence.json"
ORIGIN = b'{\n  "kind": "primary",\n  "subject": "original"\n}\n'
EVIDENCE = b'{"kind":"later-evidence"}\n'
LINE = 3


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture():
    row = {
        "id": IDENTITY,
        "source": {"path": ORIGIN_PATH, "line": LINE,
                   "line_sha256": digest(ORIGIN.decode().splitlines()[LINE - 1].encode()),
                   "checkpoint": REFERENCE},
        "landing_unit": "foundation", "landing_pr": 1160,
        "main_ancestry_verified": False, "source_repair": None,
        "remaining_acceptance": ["Final acceptance pending"],
    }
    primary = {"path": ORIGIN_PATH, "commit": REFERENCE,
               "sha256": digest(ORIGIN), "requirement_ids": [IDENTITY]}
    later = {"path": EVIDENCE_PATH, "commit": REFERENCE,
             "sha256": digest(EVIDENCE), "requirement_ids": [],
             "evidence_requirement_ids": [IDENTITY]}
    return {"requirements": [row], "sources": [primary, later],
            "active_landing_prs": [1160], "reference_commit": REFERENCE,
            "reference_tag": "ledger-fixture", "landing_units": {"foundation": 1160}}


def fake_git(*args):
    if args == ("rev-parse", "ledger-fixture^{}"):
        return (REFERENCE + "\n").encode()
    if args == ("rev-parse", REFERENCE + "^{tree}"):
        return (TREE + "\n").encode()
    if args == ("show", REFERENCE + ":" + ORIGIN_PATH):
        return ORIGIN
    if args == ("show", REFERENCE + ":" + EVIDENCE_PATH):
        return EVIDENCE
    if args == ("cat-file", "-e", REFERENCE + ":src/repair.rs"):
        return b""
    if args == ("merge-base", "--is-ancestor", REFERENCE, REFERENCE):
        return b""
    raise AssertionError(f"unprovided Git fixture command: {args!r}")


def run_check(data):
    with tempfile.TemporaryDirectory(prefix="ledger-original-") as folder:
        path = Path(folder) / "ledger.json"
        path.write_text(json.dumps(data))
        with mock.patch.object(checker, "git", side_effect=fake_git):
            return checker.check(path)


class LedgerOriginalTests(unittest.TestCase):
    def test_valid_origin_and_explicit_later_evidence_association_remain_accepted(self):
        self.assertEqual(run_check(fixture()), [])

    def test_unknown_explicit_evidence_association_is_refused(self):
        data = fixture()
        data["sources"][1]["evidence_requirement_ids"] = ["fixture:missing"]
        errors = run_check(data)
        self.assertTrue(any("fixture:missing" in error for error in errors), errors)

    def test_primary_path_mismatch_reports_identity_and_paths_without_indexing_foreign_line(self):
        data = fixture()
        data["sources"][0] = {
            "path": EVIDENCE_PATH, "commit": REFERENCE,
            "sha256": digest(EVIDENCE), "requirement_ids": [IDENTITY]}
        errors = run_check(data)
        self.assertTrue(any(IDENTITY in error and ORIGIN_PATH in error
                            and EVIDENCE_PATH in error for error in errors), errors)

    def test_out_of_range_origin_line_reports_identity_path_and_line_without_exception(self):
        data = fixture()
        data["requirements"][0]["source"]["line"] = 880
        errors = run_check(data)
        self.assertTrue(any(IDENTITY in error and ORIGIN_PATH in error
                            and "880" in error for error in errors), errors)

    def test_zero_and_boolean_origin_lines_do_not_acquire_python_index_semantics(self):
        for line, hashed_line in [(0, ORIGIN.decode().splitlines()[-1]),
                                  (True, ORIGIN.decode().splitlines()[0])]:
            with self.subTest(line=line):
                data = fixture()
                data["requirements"][0]["source"].update(
                    line=line, line_sha256=digest(hashed_line.encode()))
                errors = run_check(data)
                self.assertTrue(any(IDENTITY in error for error in errors), errors)

    def test_genuine_primary_line_hash_mismatch_still_refuses(self):
        data = fixture()
        data["requirements"][0]["source"]["line_sha256"] = "0" * 64
        self.assertTrue(any(IDENTITY in error for error in run_check(data)))

    def test_exact_modern_repair_snapshot_used_by_the_new_producer_is_supported(self):
        data = fixture()
        data["requirements"][0]["source_repair"] = {
            "commits": [REFERENCE], "observed_source_head": REFERENCE,
            "observed_source_tree": TREE, "files": ["src/repair.rs"],
            "application": "Source integrated; final acceptance pending",
            "scope": "Metadata correspondence only"}
        self.assertEqual(run_check(data), [])


def modern_repair():
    return {"commits": [REFERENCE], "observed_source_head": REFERENCE,
            "observed_source_tree": TREE, "files": ["src/repair.rs"],
            "application": "Source integrated; final acceptance pending",
            "scope": "Metadata correspondence only"}


class LedgerRefusalControls(unittest.TestCase):
    def test_evidence_associations_cannot_replace_primary_markdown_finding_coverage(self):
        data = fixture()
        path = "fixture-origin.md"
        raw = b"- [ ] first obligation\n- [ ] second obligation\n"
        data["requirements"][0]["source"] = {
            "path": path, "line": 1, "additional_lines": [2],
            "line_sha256": digest(raw.decode().splitlines()[0].encode()),
            "checkpoint": REFERENCE}
        data["sources"] = [{"path": path, "commit": REFERENCE,
                            "sha256": digest(raw), "requirement_ids": [],
                            "evidence_requirement_ids": [IDENTITY]}]

        def reads(*args):
            if args == ("show", REFERENCE + ":" + path):
                return raw
            return fake_git(*args)

        with tempfile.TemporaryDirectory(prefix="ledger-markdown-") as folder:
            ledger = Path(folder) / "ledger.json"
            ledger.write_text(json.dumps(data))
            with mock.patch.object(checker, "git", side_effect=reads):
                errors = checker.check(ledger)
        self.assertTrue(any("unrepresented obligation" in error and ":2" in error
                            for error in errors), errors)

    def test_duplicate_evidence_associations_refuse(self):
        data = fixture()
        data["sources"][1]["evidence_requirement_ids"] = [IDENTITY, IDENTITY]
        self.assertTrue(any("duplicate" in error for error in run_check(data)))

    def test_malformed_evidence_associations_refuse(self):
        for value in [IDENTITY, None, {}, [True], [7], [""]]:
            with self.subTest(value=value):
                data = fixture()
                data["sources"][1]["evidence_requirement_ids"] = value
                self.assertTrue(run_check(data))

    def test_evidence_file_hash_mismatch_still_refuses(self):
        data = fixture()
        data["sources"][1]["sha256"] = "0" * 64
        self.assertTrue(any(EVIDENCE_PATH in error for error in run_check(data)))

    def test_invalid_or_duplicate_modern_commits_refuse(self):
        for commits in [[], ["short"], [True], [REFERENCE, REFERENCE]]:
            with self.subTest(commits=commits):
                data = fixture()
                data["requirements"][0]["source_repair"] = modern_repair()
                data["requirements"][0]["source_repair"]["commits"] = commits
                self.assertTrue(any(IDENTITY in error for error in run_check(data)))

    def test_modern_tree_must_match_the_recorded_head(self):
        data = fixture()
        data["requirements"][0]["source_repair"] = modern_repair()
        data["requirements"][0]["source_repair"]["observed_source_tree"] = "c" * 40
        self.assertTrue(any(IDENTITY in error for error in run_check(data)))

    def test_unretained_modern_commit_refuses(self):
        data = fixture()
        foreign = "c" * 40
        data["requirements"][0]["source_repair"] = modern_repair()
        data["requirements"][0]["source_repair"]["commits"] = [foreign]

        def reads(*args):
            if args == ("merge-base", "--is-ancestor", foreign, REFERENCE):
                raise subprocess.CalledProcessError(1, ["git", *args])
            return fake_git(*args)

        with tempfile.TemporaryDirectory(prefix="ledger-ancestry-") as folder:
            ledger = Path(folder) / "ledger.json"
            ledger.write_text(json.dumps(data))
            with mock.patch.object(checker, "git", side_effect=reads):
                errors = checker.check(ledger)
        self.assertTrue(any(IDENTITY in error for error in errors), errors)

    def test_missing_modern_file_refuses(self):
        data = fixture()
        data["requirements"][0]["source_repair"] = modern_repair()
        data["requirements"][0]["source_repair"]["files"] = ["src/missing.rs"]

        def reads(*args):
            if args == ("cat-file", "-e", REFERENCE + ":src/missing.rs"):
                raise subprocess.CalledProcessError(1, ["git", *args])
            return fake_git(*args)

        with tempfile.TemporaryDirectory(prefix="ledger-file-") as folder:
            ledger = Path(folder) / "ledger.json"
            ledger.write_text(json.dumps(data))
            with mock.patch.object(checker, "git", side_effect=reads):
                errors = checker.check(ledger)
        self.assertTrue(any(IDENTITY in error for error in errors), errors)

    def test_malformed_modern_files_refuse(self):
        for paths in [[], "src/repair.rs", [False], [""]]:
            with self.subTest(paths=paths):
                data = fixture()
                data["requirements"][0]["source_repair"] = modern_repair()
                data["requirements"][0]["source_repair"]["files"] = paths
                self.assertTrue(any(IDENTITY in error for error in run_check(data)))

    def test_malformed_legacy_checkpoint_cannot_fall_back_to_modern_metadata(self):
        data = fixture()
        data["requirements"][0]["source_repair"] = modern_repair()
        data["requirements"][0]["source_repair"]["checkpoint"] = "not-a-commit"
        self.assertTrue(any(IDENTITY in error for error in run_check(data)))

    def test_valid_legacy_checkpoint_and_files_remain_accepted(self):
        data = fixture()
        data["requirements"][0]["source_repair"] = {
            "checkpoint": REFERENCE, "files": ["src/repair.rs"]}
        self.assertEqual(run_check(data), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
