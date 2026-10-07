#!/usr/bin/env python3
"""Calibrate historical protocol classification through the actual copy loop."""
import ast
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import proof_room_historical_protocols as provenance

BARE_ACP = re.compile(r"(?<![A-Za-z0-9_-])ACP(?![A-Za-z0-9_-])")
PATHS = {*provenance.HISTORICAL_LINE_PROTOCOLS, provenance.LEDGER}


def scanner(root, paths, classify=None):
    script = (ROOT / "scripts/check-chio-proof-room-release-truth.sh").read_text()
    payload = script.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(payload)
    constants = {"DEFAULT_DOCS", "DEFAULT_CLAIM_DOCS", "DEFAULT_DOC_EXCLUDES",
                 "HISTORICAL_SOURCE_SNAPSHOTS", "ALLOW_CONTEXT_RE", "CLAUSE_BOUNDARY_RE",
                 "CLAIM_PATTERNS", "COPY_STOP_PATTERNS"}
    definitions = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))
                   or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in constants
                                                           for target in node.targets)]
    context = {}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), "release-copy-definitions", "exec"), context)
    context.update(ROOT=root, truth={key: False for key in context["CLAIM_PATTERNS"]}, failures=[])
    context["configured_docs"] = lambda defaults: paths
    if classify is not None:
        context["typed_historical_protocol"] = classify
    loop = next(node for node in tree.body if isinstance(node, ast.For)
                and "DEFAULT_DOCS" in ast.unparse(node.iter))
    exec(compile(ast.Module(body=[loop], type_ignores=[]), "release-copy-loop", "exec"), context)
    return context["failures"]


class HistoricalProtocolCalibration(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory(prefix="chio-historical-protocol-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        paths = []
        for relative in sorted(PATHS):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
            paths.append(target)
        return root, paths

    def test_exact_historical_references_are_classified(self):
        root, paths = self.fixture()
        self.assertEqual(scanner(root, paths), [])

    def test_a_classified_line_mutation_is_refused(self):
        root, paths = self.fixture()
        path = root / next(iter(provenance.HISTORICAL_SOURCE_SHA256))
        lines = path.read_text().splitlines()
        number = next(i for i, line in enumerate(lines) if BARE_ACP.search(line))
        lines[number] += " GA release is available."
        path.write_text("\n".join(lines) + "\n")
        self.assertTrue(scanner(root, [path]))

    def test_duplicate_historical_line_cannot_become_current_copy(self):
        root, paths = self.fixture()
        path = root / next(iter(provenance.HISTORICAL_SOURCE_SHA256))
        source = path.read_text()
        line = next(line for line in source.splitlines() if BARE_ACP.search(line))
        path.write_text(source + "\n" + line + "\n")
        self.assertTrue(scanner(root, [path]))

    def test_added_current_bare_claim_is_refused(self):
        root, paths = self.fixture()
        path = root / "docs/new-current-claim.md"
        path.write_text("Chio ships ACP authority.\n")
        self.assertTrue(scanner(root, [path]))

    def test_ledger_provenance_and_unique_field_context_are_required(self):
        root, paths = self.fixture()
        path = root / provenance.LEDGER
        original = path.read_text()
        document = json.loads(original)
        state = document["current_requirement_states"][provenance.REQUIREMENT_ID]
        for mutate in ("identity", "duplicate-summary", "scope", "moved-field"):
            with self.subTest(mutation=mutate):
                altered = json.loads(original)
                if mutate == "identity":
                    altered["current_requirement_states"][provenance.REQUIREMENT_ID]["historical_source_identity"]["checkpoint"] = "0" * 40
                elif mutate == "duplicate-summary":
                    altered["new_current_summary"] = provenance.REQUIREMENT
                elif mutate == "scope":
                    altered["current_view_refresh_488_observations_20261007"]["source_basis"]["source"] = "unreviewed source"
                else:
                    changed = altered["current_requirement_states"][provenance.REQUIREMENT_ID]
                    changed["new_current_summary"] = changed.pop("requirement")
                path.write_text(json.dumps(altered, indent=2) + "\n")
                self.assertTrue(scanner(root, [path]))
        path.write_text(original)

    def test_other_stop_patterns_and_release_truth_remain_active(self):
        root, paths = self.fixture()
        path = root / "docs/classified-overclaim-control.md"
        path.write_text("ACP. GA release is available. Chio is the universal agent protocol.\n")
        errors = scanner(root, [path], classify=lambda *args: "ACP-Client")
        self.assertTrue(any("unavailable: public_release" in error for error in errors))
        self.assertTrue(any("universal_protocol_overclaim" in error for error in errors))
        self.assertFalse(any("copy-forbidden: bare_acp" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
