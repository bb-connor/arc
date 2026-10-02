#!/usr/bin/env python3
"""Host-independent hostile mutations of native fixture and target wiring."""

import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "native_protocol_ci", ROOT / "scripts/check-native-protocol-ci.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
LIVE = (
    yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text()),
    yaml.safe_load((ROOT / ".github/workflows/process-workers.yml").read_text()),
    yaml.safe_load((ROOT / ".github/actions/enforced-native-fixture/action.yml").read_text()),
)
CONSUMERS = (
    (0, "check", "Workspace tests"),
    (0, "msrv", "MSRV workspace lane"),
    (1, "host-tests", CHECKER.PROTOCOL_NAME),
)


class NativeProtocolCiTests(unittest.TestCase):
    def rejected(self, documents, expected):
        with self.assertRaisesRegex(CHECKER.ContractError, expected):
            CHECKER.validate(*documents)

    def test_live_contract(self):
        CHECKER.validate(*LIVE)

    def test_every_lane_requires_adjacent_unconditional_fixture(self):
        for document, job_id, consumer in CONSUMERS:
            for mutation in ("remove", "move", "conditional", "soft_fail", "replace", "env"):
                with self.subTest(job=job_id, mutation=mutation):
                    changed = copy.deepcopy(LIVE)
                    job = changed[document]["jobs"][job_id]
                    index, _ = CHECKER.named_step(job, consumer)
                    fixture = job["steps"][index - 1]
                    if mutation == "remove":
                        del job["steps"][index - 1]
                    elif mutation == "move":
                        job["steps"].insert(index, {"run": "unset CHIO_CAGE_INIT"})
                    elif mutation == "conditional":
                        fixture["if"] = False
                    elif mutation == "soft_fail":
                        fixture["continue-on-error"] = True
                    elif mutation == "replace":
                        fixture["uses"] = "./.github/actions/prepared-native-broker"
                    else:
                        fixture.setdefault("env", {})["CHIO_CAGE_READ_PATHS_FILE"] = "/tmp/broad"
                    self.rejected(changed, "qualified fixture must run unconditionally")

    def test_cross_target_or_container_cannot_claim_host_qualification(self):
        for document, job_id, _ in CONSUMERS:
            for runner in ("macos-latest", "ubuntu-24.04-arm", {"group": "arbitrary"}):
                with self.subTest(job=job_id, runner=runner):
                    changed = copy.deepcopy(LIVE)
                    changed[document]["jobs"][job_id]["runs-on"] = runner
                    self.rejected(changed, "Linux x86_64 host runner")
            changed = copy.deepcopy(LIVE)
            changed[document]["jobs"][job_id]["container"] = "ubuntu:24.04"
            self.rejected(changed, "Linux x86_64 host runner")

    def test_containing_jobs_cannot_skip_or_tolerate_native_failure(self):
        for document, job_id, _ in CONSUMERS:
            for key, value in (("if", False), ("continue-on-error", True)):
                with self.subTest(job=job_id, key=key):
                    changed = copy.deepcopy(LIVE)
                    changed[document]["jobs"][job_id][key] = value
                    self.rejected(changed, "containing job can skip or tolerate native failure")

    def test_consumer_cannot_skip_or_override_authority(self):
        for document, job_id, consumer in CONSUMERS:
            for key in ("if", "continue-on-error"):
                changed = copy.deepcopy(LIVE)
                _, step = CHECKER.named_step(changed[document]["jobs"][job_id], consumer)
                step[key] = True
                self.rejected(changed, "cannot be skipped or tolerate failure")
            for location in ("workflow", "job", "step"):
                changed = copy.deepcopy(LIVE)
                job = changed[document]["jobs"][job_id]
                _, step = CHECKER.named_step(job, consumer)
                owner = {"workflow": changed[document], "job": job, "step": step}[location]
                owner.setdefault("env", {})["CHIO_CAGE_EXECUTION_UID"] = "0"
                self.rejected(changed, "overrides qualified fixture authority")

    def test_all_native_targets_and_real_enforcement_are_required(self):
        for text in (
            " --test mcp_auth_server",
            " --test mcp_serve ",
            " --test mcp_serve_http",
            " --test conformance_cli",
            " --features real-linux-enforcement",
            " --no-fail-fast",
        ):
            with self.subTest(removed=text):
                changed = copy.deepcopy(LIVE)
                _, step = CHECKER.named_step(changed[1]["jobs"]["host-tests"], CHECKER.PROTOCOL_NAME)
                self.assertIn(text, step["run"])
                step["run"] = step["run"].replace(text, " ", 1)
                self.rejected(changed, "target set must execute every required target")

    def test_static_report_cannot_clear_runtime_before_protocol_targets(self):
        changed = copy.deepcopy(LIVE)
        job = changed[1]["jobs"]["host-tests"]
        protocol_index, _ = CHECKER.named_step(job, CHECKER.PROTOCOL_NAME)
        report_index, _ = CHECKER.named_step(
            job, "Native MCP and worker recovery under enforced authority"
        )
        report = job["steps"].pop(report_index)
        job["steps"].insert(protocol_index - 1, report)
        self.rejected(changed, "must precede static report setup")

    def test_action_cannot_omit_probe_or_replace_bounded_authority(self):
        for index, old, new in (
            (0, 'test "$(uname -s):$(uname -m)" = "Linux:x86_64"', ":"),
            (0, "x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"),
            (1, "sudo env", "env"),
            (1, "1 passed; 0 failed", "0 passed; 0 failed"),
            (2, '"${runtime_read_grants[@]}"', '--read-path "$GITHUB_WORKSPACE"'),
            (2, '"CHIO_CAGE_RUNTIME_FILES_FILE": manifest["runtime_files_file"],', ""),
        ):
            with self.subTest(step=index, mutation=old):
                changed = copy.deepcopy(LIVE)
                step = changed[2]["runs"]["steps"][index]
                self.assertIn(old, step["run"])
                step["run"] = step["run"].replace(old, new, 1)
                self.rejected(changed, "changes reviewed host, runtime or authority")

    def test_fixture_forwards_exact_runtime_paths_as_distinct_grants(self):
        run = LIVE[2]["runs"]["steps"][2]["run"]
        body = run[run.index("runtime_read_grants=()"):run.index('python3 - "$RUNNER_TEMP')]
        with tempfile.TemporaryDirectory(prefix="native argument test ") as temporary:
            directory = Path(temporary)
            runtime = directory / "native-python-runtime"
            runtime.mkdir()
            helper = directory / "chio-cage-init"
            helper.touch()
            grants = [
                runtime / "stdlib.zip",
                runtime / "extension with spaces.so",
                runtime / "literal $(false).so",
            ]
            (runtime / "read-paths.txt").write_text(
                "".join(f"{path}\n" for path in grants)
            )
            capture = directory / "arguments"
            # Capture argv only. The privileged host probe and authority
            # preparation retain their real platform requirements.
            harness = 'python3() { printf "%s\\0" "$@" > "$CAPTURE"; }\n' + body
            subprocess.run(
                ["bash", "-euo", "pipefail", "-c", harness],
                check=True,
                env={
                    **os.environ,
                    "CAPTURE": str(capture),
                    "RUNNER_TEMP": str(directory),
                    "GITHUB_ENV": str(directory / "env"),
                },
            )
            actual = capture.read_bytes().decode().split("\0")[:-1]
            self.assertEqual(actual[:3], ["scripts/prepare-enforced-native-fixture.py", "--helper", str(helper)])
            self.assertEqual(
                actual[-2 * len(grants):],
                [value for grant in grants for value in ("--read-path", str(grant))],
            )

    def test_terminal_evidence_check_works_without_ripgrep(self):
        # Exercise only the terminal evidence check with base runner tools.
        # Native isolation remains the responsibility of the real host probe.
        command = LIVE[2]["runs"]["steps"][1]["run"].splitlines()[-1]
        grep = shutil.which("grep")
        self.assertIsNotNone(grep)
        with tempfile.TemporaryDirectory(prefix="native probe evidence ") as temporary:
            directory = Path(temporary)
            binaries = directory / "bin"
            binaries.mkdir()
            (binaries / "grep").symlink_to(grep)
            for outcome, expected in (
                ("test result: ok. 1 passed; 0 failed; 0 ignored", 0),
                ("test result: ok. 0 passed; 0 failed; 0 ignored", 1),
                ("test result: FAILED. 0 passed; 1 failed; 0 ignored", 1),
            ):
                with self.subTest(outcome=outcome):
                    (directory / "native-discovery.log").write_text(outcome + "\n")
                    result = subprocess.run(
                        ["/bin/bash", "-euo", "pipefail", "-c", command],
                        capture_output=True,
                        text=True,
                        env={"PATH": str(binaries), "RUNNER_TEMP": str(directory)},
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_contract_and_negative_checks_remain_enrolled(self):
        for document, job_id, name in (
            (0, "check", "Workspace structural gates"),
            (1, "host-tests", "Default kernel and worker dependency boundary"),
        ):
            for script in (
                "scripts/check-native-protocol-ci.py",
                "scripts/tests/check-native-protocol-ci.test.py",
                "scripts/tests/prepare-enforced-native-fixture.test.py",
            ):
                changed = copy.deepcopy(LIVE)
                _, step = CHECKER.named_step(changed[document]["jobs"][job_id], name)
                step["run"] = step["run"].replace("python3 " + script, "true")
                self.rejected(changed, "omits required contract check")


if __name__ == "__main__":
    unittest.main()
