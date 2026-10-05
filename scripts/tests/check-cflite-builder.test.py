#!/usr/bin/env python3
"""Exercise the real builder across the nested-container selection boundary."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = set(tomllib.loads((ROOT / "fuzz/target-map.toml").read_text())["targets"])
BUILDERS = (".clusterfuzzlite/build.sh", "fuzz/oss-fuzz/build.sh")


class BuilderTests(unittest.TestCase):
    def build(self, builder=BUILDERS[0], *, selection=None, environment=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "chio"
            (source / "fuzz").mkdir(parents=True)
            (source / ".clusterfuzzlite").mkdir()
            if selection is not None:
                (source / ".clusterfuzzlite/selected-targets.txt").write_text(selection)
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

    def test_file_handoff_survives_a_clean_nested_container_environment(self):
        result, calls, outputs = self.build(
            selection="frost_round2_envelope\ncanonical_json\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(outputs), {"frost_round2_envelope", "canonical_json"})
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(
                call[1:], ["--features", "", "--release", "--sanitizer", "address"]
            )

    def test_invalid_file_selection_builds_nothing(self):
        for selection in ("", " \n", "canonical_json\nunknown\n", "../other\n"):
            with self.subTest(selection=selection):
                result, calls, outputs = self.build(selection=selection)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(outputs, {})

    def test_file_and_environment_selection_cannot_disagree(self):
        for name in ("CHIO_CFLITE_TARGET", "CHIO_CFLITE_TARGETS"):
            with self.subTest(name=name):
                result, calls, outputs = self.build(
                    selection="canonical_json\n",
                    environment={name: "manifest_roundtrip"},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(outputs, {})

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


if __name__ == "__main__":
    unittest.main()
