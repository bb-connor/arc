#!/usr/bin/env python3
"""Self-test for scripts/check-corpus-metadata.sh."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-corpus-metadata.sh"
HEADER = "check-corpus-metadata: validation failed:"
SEED_A = b"seed-a"
SEED_B = b"seed-b"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seed(**fields: str) -> str:
    base = {
        "target": "wasm_guard_escape",
        "path": "fuzz/corpus/wasm_guard_escape/a",
        "sha256": sha(SEED_A),
        "source": "hand_curated_coverage",
    }
    base.update(fields)
    return "\n[[seed]]\n" + "".join(f'{k} = "{v}"\n' for k, v in base.items() if v is not None)


class CorpusMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-corpus-metadata-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        self.file("fuzz/corpus/wasm_guard_escape/a", SEED_A)
        self.file("fuzz/corpus/wasm_guard_escape/b", SEED_B)
        self.metadata(self.green_seeds())

    @staticmethod
    def green_seeds() -> str:
        return seed() + seed(
            path="fuzz/corpus/wasm_guard_escape/b",
            sha256=sha(SEED_B),
            source="adversarial_curated",
            **{"class": "clock_rewound", "threat_id": "t_clock_01"},
        )

    def file(self, rel: str, data: bytes) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def metadata(self, seeds: str, header: str = "schema_version = 1\n") -> None:
        self.file("fuzz/corpus_metadata.toml", (header + seeds).encode())

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-corpus-metadata.sh"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_errors(self, *errors: str) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        lines = result.stderr.strip().splitlines()
        self.assertEqual(lines[0], HEADER)
        self.assertEqual(lines[1:], [f"  - {error}" for error in errors])

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "check-corpus-metadata: ok (2 seeds indexed across 1 corpora)")

    def test_green_hidden_corpus_files_are_ignored(self) -> None:
        self.file("fuzz/corpus/wasm_guard_escape/.gitkeep", b"")
        self.assertEqual(self.run_check().returncode, 0)

    def test_red_schema_version(self) -> None:
        self.metadata(self.green_seeds(), "schema_version = 2\n")
        self.assert_errors("schema_version must be 1, got 2")

    def test_red_no_seed_entries(self) -> None:
        self.metadata("")
        self.assert_errors(
            "[[seed]] entries are required",
            "corpus file 'fuzz/corpus/wasm_guard_escape/a' has no [[seed]] entry",
            "corpus file 'fuzz/corpus/wasm_guard_escape/b' has no [[seed]] entry",
        )

    def test_red_missing_required_field(self) -> None:
        self.metadata(seed(target="") + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B)))
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("  - seed[0]: 'target' must be a non-empty string", result.stderr)

    def test_red_duplicate_path(self) -> None:
        self.metadata(seed() + seed() + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B)))
        self.assert_errors("seed[1]: duplicate path 'fuzz/corpus/wasm_guard_escape/a' (also at seed[0])")

    def test_red_path_missing_on_disk(self) -> None:
        gone = "fuzz/corpus/wasm_guard_escape/gone"
        self.metadata(self.green_seeds() + seed(path=gone))
        self.assert_errors(
            f"seed[2]: path '{gone}' does not exist on disk",
            f"[[seed]] references missing file '{gone}'",
        )

    def test_red_sha256_mismatch(self) -> None:
        self.metadata(seed(sha256=sha(b"other")) + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B)))
        self.assert_errors(f"seed[0]: sha256 mismatch (metadata={sha(b'other')}, on-disk={sha(SEED_A)})")

    def test_red_sha256_malformed(self) -> None:
        for bad in ("abc", sha(SEED_A).upper()):
            with self.subTest(bad):
                self.metadata(seed(sha256=bad) + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B)))
                self.assert_errors("seed[0]: sha256 must be 64 lowercase hex chars")

    def test_red_unknown_source(self) -> None:
        self.metadata(seed(source="guess") + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B)))
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("seed[0]: source 'guess' not in", result.stderr)

    def test_red_unknown_class(self) -> None:
        self.metadata(
            seed(**{"class": "made_up", "threat_id": "t1"})
            + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B))
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("seed[0]: class 'made_up' not in", result.stderr)

    def test_red_class_without_threat_id(self) -> None:
        self.metadata(
            seed(**{"class": "future_dated"}) + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B))
        )
        self.assert_errors("seed[0]: class without threat_id is not allowed")

    def test_red_threat_id_without_class(self) -> None:
        self.metadata(seed(threat_id="t1") + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B)))
        self.assert_errors("seed[0]: threat_id without class is not allowed")

    def test_red_threat_id_shape(self) -> None:
        cases = {
            "T1": "seed[0]: threat_id 'T1' must start with a lowercase letter",
            "1abc": "seed[0]: threat_id '1abc' must start with a lowercase letter",
            "t-1": "seed[0]: threat_id 't-1' must use [a-z0-9_]",
        }
        for threat, message in cases.items():
            with self.subTest(threat):
                self.metadata(
                    seed(**{"class": "replayed_nonce", "threat_id": threat})
                    + seed(path="fuzz/corpus/wasm_guard_escape/b", sha256=sha(SEED_B))
                )
                self.assert_errors(message)

    def test_red_corpus_file_without_entry(self) -> None:
        self.file("fuzz/corpus/other_target/new", b"new")
        self.assert_errors("corpus file 'fuzz/corpus/other_target/new' has no [[seed]] entry")

    def test_red_missing_inputs(self) -> None:
        (self.root / "fuzz/corpus_metadata.toml").unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("corpus_metadata.toml missing", result.stderr)
        self.metadata(self.green_seeds())
        shutil.rmtree(self.root / "fuzz/corpus")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("fuzz/corpus missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
