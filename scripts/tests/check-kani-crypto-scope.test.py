#!/usr/bin/env python3
"""Mutation controls for the explicit crypto assumption and unproved obligations."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-kani-crypto-scope.py"


class CryptoScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        paths = [
            ".kani/harnesses.toml",
            "formal/assumptions.toml",
            "formal/rust-verification/crypto-proof-scope.toml",
        ]
        for crate in ("chio-weights", "chio-attest-verify"):
            paths += [
                f"crates/trust/{crate}/{suffix}"
                for suffix in (
                    "Cargo.toml",
                    "src/lib.rs",
                    "src/kani_public_harnesses.rs",
                    "src/kani_crypto_research.rs",
                )
            ]
        for rel in paths:
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if (ROOT / rel).exists():
                shutil.copyfile(ROOT / rel, dest)

    def check(self, accepted):
        result = subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(self.root)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            result.returncode == 0, accepted, result.stdout + result.stderr
        )
        if not accepted:
            self.assertIn("crypto proof scope:", result.stderr)

    def replace(self, rel, old, new):
        path = self.root / rel
        source = path.read_text()
        self.assertIn(old, source)
        path.write_text(source.replace(old, new))

    def test_current_contract(self):
        self.check(True)

    def test_mandatory_attestation_domain_and_checks_cannot_be_weakened(self):
        rel = "crates/trust/chio-attest-verify/src/kani_public_harnesses.rs"
        path = self.root / rel
        original = path.read_text()
        mutations = (
            ("let kernel_seed = kani::any::<u8>();", "let kernel_seed = 0u8;"),
            ("let flip_index = kani::any::<u8>();", "let flip_index = 0u8;"),
            ("(flip_index as usize) < receipt_root.len()", "flip_index < 4"),
            ("assert_eq!(first, second);", ""),
            ("assert_eq!(*byte, 0);", ""),
            ("assert_eq!(via_context, first);", ""),
            (
                "let kernel_seed = kani::any::<u8>();",
                "let kernel_seed = kani::any::<u8>();\n    kani::assume(kernel_seed < 4);",
            ),
            (
                "pub fn public_expect_report_data_determinism_and_binding()",
                "#[kani::stub(expect_report_data, assumed_report_data)]\n"
                "pub fn public_expect_report_data_determinism_and_binding()",
            ),
        )
        for before, after in mutations:
            with self.subTest(mutation=before, replacement=after):
                path.write_text(original)
                self.replace(rel, before, after)
                self.check(False)
        path.write_text(original)

    def test_mandatory_weights_domain_and_checks_cannot_be_weakened(self):
        rel = "crates/trust/chio-weights/src/kani_public_harnesses.rs"
        path = self.root / rel
        original = path.read_text()
        for before, after in (
            ("let bytes: [u8; 4] = kani::any();", "let bytes = [0u8; 4];"),
            ("let bytes: [u8; 4] = kani::any();", "let bytes: [u8; 2] = kani::any();"),
            ("assert_eq!(first, second);", ""),
        ):
            with self.subTest(mutation=before, replacement=after):
                path.write_text(original)
                self.replace(rel, before, after)
                self.check(False)
        path.write_text(original)

    def test_mandatory_fixture_cannot_ignore_the_symbolic_key_seed(self):
        self.replace(
            "crates/trust/chio-attest-verify/src/kani_public_harnesses.rs",
            "fn public_key(seed: u8)",
            "fn public_key(_symbolic_seed: u8)",
        )
        path = self.root / "crates/trust/chio-attest-verify/src/kani_public_harnesses.rs"
        source = path.read_text()
        marker = "fn public_key(_symbolic_seed: u8)"
        start = source.index("{", source.index(marker)) + 1
        path.write_text(source[:start] + "\n    let seed = 0u8;" + source[start:])
        self.check(False)

    def test_research_cannot_be_mandatory(self):
        self.replace(
            ".kani/harnesses.toml",
            "public_weights_hash_of_determinism_and_shape",
            "public_weights_hash_of_determinism_and_tampering",
        )
        self.check(False)

    def test_research_feature_cannot_be_enabled_in_gate(self):
        self.replace(
            ".kani/harnesses.toml",
            'features = ["kani"]',
            'features = ["kani", "kani-research"]',
        )
        self.check(False)

    def test_research_cannot_be_enabled_by_default(self):
        self.replace(
            "crates/trust/chio-weights/Cargo.toml",
            "default = []",
            'default = ["kani-research"]',
        )
        self.check(False)

    def test_indirect_research_feature_cannot_reach_gate(self):
        self.replace(
            "crates/trust/chio-attest-verify/Cargo.toml",
            "default = []",
            'default = ["extra"]\nextra = ["kani-research"]',
        )
        self.check(False)

    def test_dependency_research_feature_cannot_reach_gate(self):
        for dependency in ("chio-attest-verify", "chio-attest-verify?"):
            with self.subTest(dependency=dependency):
                path = self.root / "crates/trust/chio-weights/Cargo.toml"
                original = path.read_text()
                path.write_text(
                    original.replace(
                        "default = []", f'default = ["{dependency}/kani-research"]'
                    )
                )
                self.check(False)
                path.write_text(original)

    def test_research_cannot_be_aliased_by_another_feature(self):
        self.replace(
            "crates/trust/chio-attest-verify/Cargo.toml",
            "default = []",
            'default = []\nresearch-alias = ["kani-research"]',
        )
        self.check(False)

    def test_missing_assumption_refused(self):
        self.replace("formal/assumptions.toml", "ASSUME-SHA256", "REMOVED-SHA256")
        self.check(False)

    def test_unproved_cannot_be_marked_proved(self):
        self.replace(
            "formal/rust-verification/crypto-proof-scope.toml",
            'status = "unproved"',
            'status = "proved"',
        )
        self.check(False)

    def test_original_inequality_cannot_be_dropped(self):
        self.replace(
            "crates/trust/chio-weights/src/kani_crypto_research.rs",
            "assert_ne!(first, tampered_digest);",
            "",
        )
        self.check(False)

    def test_original_must_be_opt_in(self):
        self.replace(
            "crates/trust/chio-attest-verify/src/lib.rs",
            '#[cfg(all(kani, feature = "kani-research"))]',
            "#[cfg(kani)]",
        )
        self.check(False)

    def test_portable_real_hash_feature_cannot_be_removed(self):
        self.replace("crates/trust/chio-weights/Cargo.toml", '"sha2/force-soft", ', "")
        self.check(False)


if __name__ == "__main__":
    unittest.main()
