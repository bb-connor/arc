#!/usr/bin/env python3
"""Self-test for scripts/check-sre-metrics-registry.sh."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-sre-metrics-registry.sh"
SNAPSHOT = "crates/observability/chio-metrics-spec/metrics.snapshot"
KERNEL_SRC = "crates/kernel/chio-kernel/src/lib.rs"
SCAN_DIRS = (
    "crates/observability/chio-metrics-spec",
    "crates/kernel/chio-kernel/src",
    "crates/protocol/chio-mcp-edge/src",
    "crates/protocol/chio-acp-edge/src",
    "crates/protocol/chio-a2a-edge/src",
    "crates/platform/chio-http-core/src",
    "crates/platform/chio-finding-hosted-edge/src",
    "crates/economy/chio-anchor/src",
    "crates/trust/chio-federation/src",
    "crates/trust/chio-pheromone-relay/src",
    "crates/guards/chio-wasm-guards/src",
    "crates/observability/chio-siem",
    "deploy/prometheus",
    ".github/workflows",
    "docs/operator-runbook",
)
REGISTRY = "chio@requests_total|counter\nchio@queue_depth|gauge\nchio@latency_seconds|histogram\n"


MARK = "chio@"


class SreMetricsRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-sre-metrics-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        for directory in SCAN_DIRS:
            self.write(f"{directory}/.keep", "")
        self.write(SNAPSHOT, REGISTRY)
        self.git("init", "-q", "--initial-branch=main")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text.replace(MARK, "chio_"), encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        self.git("add", "-A")
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-sre-metrics-registry.sh"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_unregistered(self, result: subprocess.CompletedProcess[str], *names: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(
            result.stderr.strip().splitlines(),
            [
                *(f"unregistered Chio metric name: {name.replace(MARK, 'chio_')}" for name in names),
                "add new metric names to crates/observability/chio-metrics-spec before using them",
            ],
        )

    def test_green_registered_metrics(self) -> None:
        self.write(KERNEL_SRC, 'counter("chio@requests_total"); gauge("chio@queue_depth");\n')
        self.write("deploy/prometheus/rules.yml", "expr: rate(chio@latency_seconds[5m])\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "SRE metric registry gate passed")

    def test_green_no_metric_names_at_all(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_green_names_without_a_metric_suffix_are_ignored(self) -> None:
        self.write(KERNEL_SRC, 'let x = "chio@session"; let y = "chio@requests_total_extra_word";\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_red_unregistered_metric_in_source(self) -> None:
        self.write(KERNEL_SRC, 'counter("chio@unknown_total");\n')
        self.assert_unregistered(self.run_check(), "chio@unknown_total")

    def test_red_each_metric_suffix(self) -> None:
        names = ["chio@a_seconds", "chio@b_total", "chio@c_depth", "chio@d_bytes", "chio@e_ready", "chio@f_size"]
        self.write(KERNEL_SRC, "\n".join(names) + "\n")
        self.assert_unregistered(self.run_check(), *sorted(names))

    def test_red_unregistered_metric_in_dashboard_workflow_and_runbook(self) -> None:
        self.write("deploy/prometheus/rules.yml", "expr: chio@dash_total\n")
        self.write(".github/workflows/x.yml", "run: echo chio@flow_depth\n")
        self.write("docs/operator-runbook/ops.md", "watch chio@book_bytes\n")
        self.assert_unregistered(
            self.run_check(), "chio@book_bytes", "chio@dash_total", "chio@flow_depth"
        )

    def test_red_only_unregistered_names_are_reported(self) -> None:
        self.write(KERNEL_SRC, 'chio@requests_total chio@new_total\n')
        self.assert_unregistered(self.run_check(), "chio@new_total")

    def test_red_registry_prefix_is_not_a_match(self) -> None:
        self.write(KERNEL_SRC, 'chio@requests_total_bytes\n')
        self.assert_unregistered(self.run_check(), "chio@requests_total_bytes")


if __name__ == "__main__":
    unittest.main()
