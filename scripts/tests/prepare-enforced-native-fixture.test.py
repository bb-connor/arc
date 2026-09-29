#!/usr/bin/env python3
"""Portable fixture validation; these tests do not qualify a native host."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "native_fixture", Path(__file__).parents[1] / "prepare-enforced-native-fixture.py"
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureTests(unittest.TestCase):
    def test_grants_exclude_authority_ancestors_children_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "authority"
            protected.mkdir()
            secret = protected / "secret"
            secret.touch()
            alias = root / "alias"
            alias.symlink_to(protected)
            for grant in [root, protected, secret, alias, Path("/")]:
                with self.assertRaisesRegex(ValueError, "(authority|non-root)"):
                    fixture.validate_grants([grant], [protected])
            tools = root / "tool data"
            tools.mkdir()
            self.assertEqual(
                fixture.validate_grants([tools, tools], [protected]), [tools]
            )

    def test_empty_and_multiline_grants_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "explicit"):
            fixture.validate_grants([], [])
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "two\nlines"
            invalid.touch()
            with self.assertRaisesRegex(ValueError, "line separators"):
                fixture.validate_grants([invalid], [])


if __name__ == "__main__":
    unittest.main()
