#!/usr/bin/env python3
"""Exercise cross-package controls with the real pinned mutation engine."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "control_packages_checker", ROOT / "scripts/check-security-adversarial-evidence.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load adversarial evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class ControlPackageTests(unittest.TestCase):
    def test_baseline_runs_the_same_consumer_control_as_the_mutant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="chio-mutants-control-") as raw:
            root = Path(raw).resolve()
            files = {
                "Cargo.toml": '[workspace]\nmembers = ["owner", "consumer"]\nresolver = "2"\n',
                "owner/Cargo.toml": '[package]\nname = "fixture-owner"\nversion = "0.1.0"\nedition = "2021"\n',
                "owner/src/lib.rs": "pub fn permits() -> bool { true }\n",
                "consumer/Cargo.toml": (
                    '[package]\nname = "fixture-consumer"\nversion = "0.1.0"\nedition = "2021"\n'
                    '[dependencies]\nfixture-owner = { path = "../owner" }\n'
                ),
                "consumer/tests/control.rs": (
                    "#[test]\nfn exact_consumer_control() { assert!(fixture_owner::permits()); }\n"
                ),
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            environment = dict(os.environ)
            environment.pop("CHIO_ENTERPRISE_SECURITY_RUNNER", None)
            environment.update({
                "CARGO_TARGET_DIR": str(root / "target"),
                "CARGO_NET_OFFLINE": "true",
                "CARGO_INCREMENTAL": "0",
                "CARGO_BUILD_JOBS": "1",
            })
            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"], cwd=root,
                env=environment, check=True, capture_output=True,
            )
            outcomes_path = CHECKER.run_campaign(
                root,
                {
                    "id": "cross_package_control", "package": "fixture-owner",
                    "source": "owner/src/lib.rs", "function": "permits",
                    "minimum_caught": 1,
                    "mutant": {"genre": "FnValue", "replacement": "false"},
                },
                {
                    "id": "consumer_control", "package": "fixture-consumer",
                    "features": [], "target_kind": "test", "target": "control",
                    "test_name": "exact_consumer_control",
                },
                root / "campaign-output", environment,
            )
            outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))
            baseline = next(row for row in outcomes["outcomes"] if row["scenario"] == "Baseline")
            log = (outcomes_path.parent / baseline["log_path"]).read_text(encoding="utf-8")
            self.assertIn("test exact_consumer_control ... ok", log)
            self.assertIn("test result: ok. 1 passed;", log)
            self.assertEqual(outcomes["caught"], 1)
            self.assertEqual(outcomes["timeout"], 0)
            self.assertEqual((root / "owner/src/lib.rs").read_text(), files["owner/src/lib.rs"])


if __name__ == "__main__":
    unittest.main()
