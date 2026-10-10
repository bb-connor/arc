#!/usr/bin/env python3
"""Exercise consumer job dependencies and the actual binary transfer scripts."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
JOBS = yaml.safe_load((ROOT / ".github/workflows/process-workers.yml").read_text())[
    "jobs"
]
MEMBERS = (
    "chio",
    "chio-docker-adapter",
    "chio-repository-adapter",
    "chio-broker-mcp",
    "chio-secret-broker-test",
)


def step(job, name):
    return next(item for item in JOBS[job]["steps"] if item.get("name") == name)


def shell(script, directory, environment):
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=directory,
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
    )


class ProcessConsumerJobsTests(unittest.TestCase):
    def test_failed_postgres_assignment_retains_only_public_denial_evidence(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/postgres-job-swarm.yml").read_text()
        )
        upload = next(
            item for item in workflow["jobs"]["native"]["steps"]
            if item.get("name") == "Preserve only nonsecret qualification evidence"
        )
        self.assertEqual(
            upload["if"], "${{ always() && env.CHIO_JOB_FIXTURE_ROOT != '' }}"
        )
        public = {
            "qualification/kernel.pub",
            "qualification/operator-1/receipts.ndjson",
            "qualification/operator-1/verification.json",
            "resource-component/component.json",
        }
        private = {
            "qualification/host-config.json",
            "qualification/host.log",
            "qualification/root/connection.json",
            "qualification/resources/assign.credential",
            "qualification/operator-1/request.json",
            "qualification/operator-1/response.json",
            "qualification/operator-1/logical-request.json",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in public | private:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            selected = set()
            prefix = "${{ env.CHIO_JOB_FIXTURE_ROOT }}/"
            for pattern in upload["with"]["path"].splitlines():
                self.assertTrue(pattern.startswith(prefix))
                selected.update(
                    str(path.relative_to(root))
                    for path in root.glob(pattern.removeprefix(prefix))
                    if path.is_file()
                )
            self.assertEqual(selected, public)
            self.assertFalse((root / "qualification/qualification.json").exists())

    def test_build_and_execution_have_separate_bounded_jobs(self):
        for job in ("host-tests", "consumer-binaries", "installed-consumers"):
            self.assertEqual(JOBS[job]["runs-on"], "ubuntu-24.04")
            self.assertEqual(JOBS[job]["timeout-minutes"], 90)
            self.assertNotIn("continue-on-error", JOBS[job])
            checkout = JOBS[job]["steps"][0]
            self.assertEqual(
                checkout["with"],
                {"ref": "${{ github.sha }}", "persist-credentials": False},
            )
        self.assertEqual(JOBS["installed-consumers"]["needs"], ["consumer-binaries"])
        fixture = step(
            "installed-consumers",
            "Qualify enforcing host and prepare native consumer fixture",
        )
        self.assertEqual(
            fixture,
            {
                "name": "Qualify enforcing host and prepare native consumer fixture",
                "id": "native_fixture",
                "uses": "./.github/actions/enforced-native-fixture",
            },
        )
        steps = JOBS["installed-consumers"]["steps"]
        self.assertLess(
            steps.index(
                step(
                    "installed-consumers", "Verify and install prepared native binaries"
                )
            ),
            steps.index(fixture),
        )

    def test_required_result_rejects_every_non_success_dependency(self):
        job = JOBS["host"]
        self.assertEqual(job["name"], "MCP process host and enforced native recovery")
        self.assertEqual(
            set(job["needs"]),
            {"host-tests", "consumer-binaries", "installed-consumers", "workers"},
        )
        self.assertEqual(
            job["if"],
            "${{ always() && (github.event_name != 'workflow_dispatch' || !inputs.optimized_comparison) }}",
        )
        self.assertNotIn("continue-on-error", job)
        check = step("host", "Require every process qualification result")
        self.assertEqual(set(check), {"name", "env", "run"})
        expected = {
            "HOST_TESTS": "host-tests",
            "BINARIES": "consumer-binaries",
            "CONSUMERS": "installed-consumers",
            "WORKERS": "workers",
        }
        self.assertEqual(
            check["env"],
            {
                key: "${{ needs['" + value + "'].result }}"
                for key, value in expected.items()
            },
        )
        healthy = dict.fromkeys(expected, "success")
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(shell(check["run"], temporary, healthy).returncode, 0)
            for key in healthy:
                for result in ("failure", "cancelled", "skipped", "", "unknown"):
                    with self.subTest(dependency=key, result=result):
                        self.assertNotEqual(
                            shell(
                                check["run"], temporary, {**healthy, key: result}
                            ).returncode,
                            0,
                        )

    def test_transfer_requires_the_same_run_archive_digest(self):
        pack = step("consumer-binaries", "Package prepared native binaries")
        restore = step(
            "installed-consumers", "Verify and install prepared native binaries"
        )
        self.assertEqual(
            JOBS["consumer-binaries"]["outputs"],
            {
                "archive_sha256": "${{ steps.bundle.outputs.sha256 }}",
                "artifact_id": "${{ steps.prepared_artifact.outputs.artifact-id }}",
            },
        )
        self.assertEqual(
            restore["env"],
            {
                "EXPECTED_SHA256": "${{ needs['consumer-binaries'].outputs.archive_sha256 }}"
            },
        )
        download = step("installed-consumers", "Download prepared native binaries")
        self.assertEqual(
            download["with"],
            {
                "artifact-ids": "${{ needs['consumer-binaries'].outputs.artifact_id }}",
                "path": "${{ runner.temp }}/prepared-native-binaries",
                "merge-multiple": True,
            },
        )
        with tempfile.TemporaryDirectory(prefix="consumer binaries ") as temporary:
            directory = Path(temporary)
            producer = directory / "producer"
            consumer = directory / "consumer"
            producer.mkdir()
            consumer.mkdir()
            (producer / "target/docker-release").mkdir(parents=True)
            environment = {
                "RUNNER_TEMP": str(producer),
                "GITHUB_OUTPUT": str(producer / "output"),
            }
            for name, key in zip(
                MEMBERS,
                (
                    None,
                    "CHIO_DOCKER_ADAPTER",
                    "CHIO_REPOSITORY_ADAPTER",
                    "CHIO_BROKER_MCP_TOOL",
                    "CHIO_BROKER_TEST_BINARY",
                ),
                strict=True,
            ):
                path = producer / (
                    "target/docker-release/chio" if key is None else name
                )
                path.write_bytes(b"#!/bin/sh\nexit 0\n" + name.encode())
                path.chmod(0o755)
                if key is not None:
                    environment[key] = str(path)
            packed = shell(pack["run"], producer, environment)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            archive = producer / "native-consumer-binaries.tar.gz"
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual((producer / "output").read_text(), f"sha256={digest}\n")
            download_dir = consumer / "prepared-native-binaries"
            # download-artifact d3f86a1 uses a flat directory only for a
            # named download or merge-multiple, even for a single artifact ID.
            if not (
                download["with"].get("name")
                or download["with"].get("merge-multiple", False)
            ):
                download_dir /= "native-consumer-binaries-fixture"
            download_dir.mkdir(parents=True)
            received = download_dir / archive.name
            received.write_bytes(archive.read_bytes())
            exports = consumer / "environment"
            environment = {
                "RUNNER_TEMP": str(consumer),
                "GITHUB_ENV": str(exports),
                "EXPECTED_SHA256": digest,
            }
            for bad_digest in ("", "0" * 64, "not-a-digest"):
                exports.write_text("RETAINED=original\n")
                result = shell(
                    restore["run"],
                    consumer,
                    {**environment, "EXPECTED_SHA256": bad_digest},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(exports.read_text(), "RETAINED=original\n")
                self.assertFalse((consumer / "target").exists())
            received.write_bytes(archive.read_bytes() + b"substituted")
            self.assertNotEqual(
                shell(restore["run"], consumer, environment).returncode, 0
            )
            self.assertFalse((consumer / "target").exists())
            self.assertEqual(exports.read_text(), "RETAINED=original\n")
            received.write_bytes(archive.read_bytes())
            exports.write_text("")
            result = shell(restore["run"], consumer, environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = dict(
                line.split("=", 1) for line in exports.read_text().splitlines()
            )
            self.assertEqual(
                set(paths),
                {
                    "CHIO_DOCKER_ADAPTER",
                    "CHIO_REPOSITORY_ADAPTER",
                    "CHIO_BROKER_MCP_TOOL",
                    "CHIO_BROKER_TEST_BINARY",
                },
            )
            installed = [
                consumer / "target/docker-release/chio",
                *(Path(path) for path in paths.values()),
            ]
            self.assertEqual({path.name for path in installed}, set(MEMBERS))
            for path in installed:
                self.assertTrue(os.access(path, os.X_OK))
                self.assertEqual(
                    path.read_bytes(), b"#!/bin/sh\nexit 0\n" + path.name.encode()
                )


if __name__ == "__main__":
    unittest.main()
