#!/usr/bin/env python3
"""Exercise the real builder across the nested-container selection boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = set(tomllib.loads((ROOT / "fuzz/target-map.toml").read_text())["targets"])
BUILDERS = (".clusterfuzzlite/build.sh", "fuzz/oss-fuzz/build.sh")


class BuilderTests(unittest.TestCase):
    def build(self, builder=BUILDERS[0], *, environment=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "chio"
            (source / "fuzz").mkdir(parents=True)
            output = directory / "output"
            output.mkdir()
            binaries = directory / "bin"
            binaries.mkdir()
            # Only the expensive compiler is replaced. Selection, validation,
            # fail-fast behavior and copying the resulting binaries are real.
            compiler = binaries / "cargo"
            compiler.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "if sys.argv[1:] == ['metadata', '--locked', '--format-version', '1', '--no-deps']:\n"
                "    sys.exit(0)\n"
                "assert sys.argv[1:4] == ['+nightly', 'fuzz', 'build'], sys.argv\n"
                "with open(os.environ['BUILD_RECORD'], 'a') as stream:\n"
                "    stream.write(json.dumps(sys.argv[4:]) + '\\n')\n"
                "target = pathlib.Path('target/x86_64-unknown-linux-gnu/release') / sys.argv[4]\n"
                "target.parent.mkdir(parents=True, exist_ok=True)\n"
                "target.write_text(sys.argv[4])\n"
            )
            compiler.chmod(0o755)
            record = directory / "build.jsonl"
            env = {
                "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                "SRC": str(directory),
                "OUT": str(output),
                "SANITIZER": "address",
                "BUILD_RECORD": str(record),
                **(environment or {}),
            }
            result = subprocess.run(
                ["bash", str(ROOT / builder)],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            calls = (
                [json.loads(line) for line in record.read_text().splitlines()]
                if record.exists()
                else []
            )
            return (
                result,
                calls,
                {path.name: path.read_text() for path in output.iterdir()},
            )

    def test_both_builders_export_the_complete_owned_inventory(self):
        for builder in BUILDERS:
            with self.subTest(builder=builder):
                result, calls, outputs = self.build(builder)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(set(outputs), INVENTORY)
                self.assertEqual(len(calls), len(INVENTORY))

    def test_local_environment_selection_preserves_required_features(self):
        result, calls, outputs = self.build(
            environment={
                "CHIO_CFLITE_TARGETS": "response_authority_protocol,response_lifecycle"
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            set(outputs), {"response_authority_protocol", "response_lifecycle"}
        )
        for call in calls:
            self.assertEqual(
                call[1:], ["--features", call[0], "--release", "--sanitizer", "address"]
            )


class ExportSelectionTests(unittest.TestCase):
    def select(self, selection=None, *, invalid_binary=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "build-out"
            output.mkdir()
            for name in INVENTORY:
                binary = output / name
                binary.write_text(name)
                binary.chmod(0o755)
            support = output / "canonical_json.options"
            support.write_text("[libfuzzer]\n")
            if invalid_binary == "missing":
                (output / "frost_round2_envelope").unlink()
            elif invalid_binary == "not_executable":
                (output / "frost_round2_envelope").chmod(0o644)
            elif invalid_binary == "symlink":
                (output / "frost_round2_envelope").unlink()
                (output / "frost_round2_envelope").symlink_to("canonical_json")
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            arguments = [
                sys.executable,
                str(ROOT / ".clusterfuzzlite/select-targets.py"),
                "--output",
                str(output),
            ]
            if selection is not None:
                selected = directory / "fired.txt"
                selected.write_text(selection)
                arguments += ["--selection", str(selected)]
            result = subprocess.run(
                arguments, capture_output=True, text=True, timeout=10
            )
            after = {path.name: path.read_bytes() for path in output.iterdir()}
            return result, before, after

    def test_default_requires_and_preserves_the_full_export(self):
        result, before, after = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, after)

    def test_subset_retains_exactly_the_requested_binaries_and_support_files(self):
        result, _, after = self.select("frost_round2_envelope\ncanonical_json\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            set(after),
            {"canonical_json", "frost_round2_envelope", "canonical_json.options"},
        )

    def test_invalid_selection_does_not_partially_prune_the_export(self):
        for selection in (
            "",
            " \n",
            "canonical_json\nunknown\n",
            "../other\n",
            "canonical_json\ncanonical_json\n",
        ):
            with self.subTest(selection=selection):
                result, before, after = self.select(selection)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, after)

    def test_incomplete_or_substituted_build_is_rejected_before_pruning(self):
        for fault in ("missing", "not_executable", "symlink"):
            with self.subTest(fault=fault):
                result, before, after = self.select(
                    "canonical_json\n", invalid_binary=fault
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
