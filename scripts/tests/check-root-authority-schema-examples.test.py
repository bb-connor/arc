#!/usr/bin/env python3
"""Self-test for scripts/check-root-authority-schema-examples.py."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-root-authority-schema-examples.py"
WIRE = "spec/schemas/chio-wire/v1"
EXAMPLES = f"{WIRE}/root_authority/examples"
SCHEMAS = {
    "root-anchor": "root_authority/root-anchor.schema.json",
    "delegation-context": "root_authority/delegation-context.schema.json",
    "root-policy": "root_authority/root-policy.schema.json",
    "enterprise-provider-identity": "root_authority/enterprise-provider-identity.schema.json",
    "idp-key-snapshot": "root_authority/idp-key-snapshot.schema.json",
    "verifier-trust": "root_authority/verifier-trust.schema.json",
    "revocation-request": "root_authority/revocation-request.schema.json",
    "presentation": "capability/presentation.schema.json",
    "disclosure": "receipt/disclosure.schema.json",
    "settlement-closure": "receipt/settlement-closure.schema.json",
}


def schema_for(stem: str) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["name"],
        "additionalProperties": False,
        "properties": {
            "schema": {"const": f"chio.{stem}.v1"},
            "name": {"type": "string"},
        },
    }


def valid_instance(stem: str) -> dict:
    return {"schema": f"chio.{stem}.v1", "name": "ok"}


class RootAuthorityExampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-root-authority-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        for stem, rel in SCHEMAS.items():
            self.write(f"{WIRE}/{rel}", schema_for(stem))
            self.write(f"{EXAMPLES}/valid/{stem}.json", valid_instance(stem))
        self.write(
            f"{EXAMPLES}/invalid/root-policy.extra-member.json",
            {**valid_instance("root-policy"), "extra": 1},
        )
        self.write(
            f"{EXAMPLES}/invalid-expectations.json",
            {"root-policy.extra-member.json": {"path": "", "keyword": "additionalProperties"}},
        )

    def write(self, rel: str, contents: object) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(contents), encoding="utf-8")

    def remove(self, rel: str) -> None:
        (self.root / rel).unlink()

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "scripts/check-root-authority-schema-examples.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, message: str) -> subprocess.CompletedProcess[str]:
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        return result

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok valid   root-policy.json", result.stdout)
        self.assertIn("ok invalid root-policy.extra-member.json: (root): additionalProperties", result.stdout)
        self.assertIn(
            "root-authority schema examples: 10 valid and 1 invalid examples behave as expected",
            result.stdout,
        )

    def test_green_variant_example_selects_schema_by_stem(self) -> None:
        self.write(f"{EXAMPLES}/valid/root-policy.alg-es256.json", valid_instance("root-policy"))
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok valid   root-policy.alg-es256.json", result.stdout)

    def test_red_schema_file_missing(self) -> None:
        self.remove(f"{WIRE}/receipt/disclosure.schema.json")
        self.assert_red("missing schema receipt/disclosure.schema.json")

    def test_red_no_valid_examples(self) -> None:
        for stem in SCHEMAS:
            self.remove(f"{EXAMPLES}/valid/{stem}.json")
        self.assert_red("no examples under")

    def test_red_no_invalid_examples(self) -> None:
        self.remove(f"{EXAMPLES}/invalid/root-policy.extra-member.json")
        self.assert_red("no examples under")

    def test_red_unknown_stem(self) -> None:
        self.write(f"{EXAMPLES}/valid/mystery.json", valid_instance("root-policy"))
        self.assert_red("no schema for stem 'mystery'")

    def test_red_valid_example_fails_schema(self) -> None:
        self.write(f"{EXAMPLES}/valid/presentation.json", {"schema": "chio.presentation.v1"})
        self.assert_red(
            "valid example presentation.json fails capability/presentation.schema.json: "
            "'name' is a required property"
        )

    def test_red_valid_example_misses_pinned_schema_value(self) -> None:
        self.write(f"{EXAMPLES}/valid/verifier-trust.json", {"name": "ok"})
        result = self.assert_red(
            "valid example verifier-trust.json does not carry schema chio.verifier-trust.v1"
        )
        self.assertIn(
            "schema root_authority/verifier-trust.schema.json has no passing valid example",
            result.stderr,
        )

    def test_red_schema_without_passing_valid_example(self) -> None:
        self.remove(f"{EXAMPLES}/valid/settlement-closure.json")
        self.assert_red(
            "schema receipt/settlement-closure.schema.json has no passing valid example"
        )

    def test_red_invalid_example_without_expectation(self) -> None:
        self.write(
            f"{EXAMPLES}/invalid/root-policy.second.json",
            {**valid_instance("root-policy"), "extra": 1},
        )
        self.assert_red("invalid example root-policy.second.json is not paired with an expectation")

    def test_red_expectation_without_invalid_example(self) -> None:
        self.write(
            f"{EXAMPLES}/invalid-expectations.json",
            {
                "root-policy.extra-member.json": {"path": "", "keyword": "additionalProperties"},
                "root-policy.gone.json": {"path": "", "keyword": "required"},
            },
        )
        self.assert_red("invalid example root-policy.gone.json is not paired with an expectation")

    def test_red_invalid_example_validates(self) -> None:
        self.write(f"{EXAMPLES}/invalid/root-policy.extra-member.json", valid_instance("root-policy"))
        self.assert_red("invalid example root-policy.extra-member.json validates against")

    def test_red_invalid_example_fails_at_wrong_keyword(self) -> None:
        self.write(
            f"{EXAMPLES}/invalid-expectations.json",
            {"root-policy.extra-member.json": {"path": "", "keyword": "required"}},
        )
        self.assert_red(
            "invalid example root-policy.extra-member.json fails at (root) (additionalProperties), "
            "expected (root) (required)"
        )

    def test_red_invalid_example_fails_at_wrong_path(self) -> None:
        self.write(
            f"{EXAMPLES}/invalid-expectations.json",
            {"root-policy.extra-member.json": {"path": "/name", "keyword": "additionalProperties"}},
        )
        self.assert_red("expected /name (additionalProperties)")

    def test_green_invalid_example_pinned_at_nested_path(self) -> None:
        self.write(
            f"{EXAMPLES}/invalid/root-policy.extra-member.json",
            {"schema": "chio.root-policy.v1", "name": 7},
        )
        self.write(
            f"{EXAMPLES}/invalid-expectations.json",
            {"root-policy.extra-member.json": {"path": "/name", "keyword": "type"}},
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok invalid root-policy.extra-member.json: /name: type", result.stdout)


if __name__ == "__main__":
    unittest.main()
