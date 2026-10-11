#!/usr/bin/env python3
"""Portable fixture validation; these tests do not qualify a native host."""

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "native_fixture", Path(__file__).parents[1] / "prepare-enforced-native-fixture.py"
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureTests(unittest.TestCase):
    def run_native_stdio(self, body):
        source = (
            Path(__file__).resolve().parents[2]
            / "crates/products/chio-cli/tests/support/native_mcp_stdio.py"
        ).read_text()
        result = subprocess.run(
            [sys.executable, "-c", source + "\n" + textwrap.dedent(body)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_stdio_retains_fragmented_and_buffered_lines(self):
        self.run_native_stdio('''
            reader, writer = os.pipe()
            stream = NativeStdio(reader)
            os.write(writer, b"first\\nse")
            assert stream.readline() == "first\\n"
            os.write(writer, b"cond\\nthird\\nlast")
            os.close(writer)
            assert list(stream) == ["second\\n", "third\\n", "last"]
            assert stream.readline() == ""
            os.close(reader)
        ''')

    def test_native_stdio_progresses_idle_timers_in_deadline_order(self):
        self.run_native_stdio('''
            reader, writer = os.pipe()
            stream = NativeStdio(reader)
            observed = []
            stream.schedule(0.01, lambda: observed.append("later"))
            stream.schedule(0, lambda: observed.append("first"))
            stream.schedule(0.02, lambda: os.write(writer, b"wake\\n"))
            assert stream.readline() == "wake\\n"
            assert observed == ["first", "later"]
            os.close(writer)
            os.close(reader)
        ''')

    def test_native_stdio_progresses_timers_during_sleep_and_busy_input(self):
        self.run_native_stdio('''
            reader, writer = os.pipe()
            stream = NativeStdio(reader)
            observed = []
            stream.schedule(0.01, lambda: observed.append("during delay"))
            stream.sleep(0.02)
            assert observed == ["during delay"]
            os.write(writer, b"buffered\\nmore\\n")
            assert stream.readline() == "buffered\\n"
            stream.schedule(0, lambda: observed.append("before buffered input"))
            assert stream.readline() == "more\\n"
            assert observed == ["during delay", "before buffered input"]
            os.close(writer)
            os.close(reader)
        ''')

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
