#!/usr/bin/env python3
"""Self-test for scripts/check-workspace-layering.sh."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-workspace-layering.sh"
DOMAIN = (
    "crates/core/chio-core/Cargo.toml",
    "crates/platform/chio-manifest/Cargo.toml",
    "crates/trust/chio-did/Cargo.toml",
    "crates/guards/chio-guards/Cargo.toml",
    "crates/guards/chio-policy/Cargo.toml",
    "crates/trust/chio-reputation/Cargo.toml",
    "crates/trust/chio-credentials/Cargo.toml",
    "crates/kernel/chio-kernel/Cargo.toml",
)
HOSTED = "crates/platform/chio-finding-hosted-edge/Cargo.toml"
CLEAN = '[package]\nname = "demo"\n\n[dependencies]\nserde = "1"\nchio-core-types = { path = "../../core/chio-core-types" }\n'


class WorkspaceLayeringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-layering-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        for rel in (*DOMAIN, HOSTED):
            self.write(rel, CLEAN)

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def append(self, rel: str, line: str) -> None:
        path = self.root / rel
        path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-workspace-layering.sh"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "workspace layering checks passed")

    def test_green_transport_dependencies_allowed_in_other_crates(self) -> None:
        self.write("crates/products/chio-cli/Cargo.toml", '[dependencies]\nclap = "4"\naxum = "0.7"\n')
        self.assertEqual(self.run_check().returncode, 0)

    def test_red_path_dependency_on_top_of_stack_crate(self) -> None:
        for target in ("chio-cli", "chio-control-plane", "chio-hosted-mcp"):
            with self.subTest(target):
                manifest = DOMAIN[0]
                self.write(manifest, CLEAN)
                self.append(manifest, f'top = {{ path = "../../products/{target}" }}')
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"blocked workspace dependency found in {manifest}", result.stderr)
                self.assertIn(f'path = "../../products/{target}"', result.stderr)

    def test_red_transport_dependency_in_each_domain_crate(self) -> None:
        for manifest in DOMAIN:
            for dep in ("clap", "axum", "reqwest"):
                with self.subTest(manifest=manifest, dep=dep):
                    self.write(manifest, CLEAN)
                    self.append(manifest, f'{dep} = "1"')
                    result = self.run_check()
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(
                        f"blocked transport/runtime dependency found in {manifest}", result.stderr
                    )
                    self.assertIn(f'{dep} = "1"', result.stderr)

    def test_red_concrete_storage_in_hosted_edge(self) -> None:
        self.append(HOSTED, 'chio-finding-market-store-postgres = { path = "../x" }')
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"concrete storage dependency found in {HOSTED}", result.stderr)

    def test_red_reports_every_violation(self) -> None:
        self.append(DOMAIN[0], 'reqwest = "0.12"')
        self.append(DOMAIN[7], 'axum = "0.7"')
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"found in {DOMAIN[0]}", result.stderr)
        self.assertIn(f"found in {DOMAIN[7]}", result.stderr)


if __name__ == "__main__":
    unittest.main()
