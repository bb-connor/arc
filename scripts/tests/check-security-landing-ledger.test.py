#!/usr/bin/env python3
"""Owning checker Originals. Root runs these before any producer/checker repair."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
