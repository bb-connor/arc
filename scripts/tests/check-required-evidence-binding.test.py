#!/usr/bin/env python3
"""Execute the actual evidence binding step without remote operations."""

import copy
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load(
    (ROOT / ".github/workflows/enterprise-hardening.yml").read_text()
)
BINDING = next(
    step
    for step in WORKFLOW["jobs"]["committed-linux-evidence"]["steps"]
    if step.get("id") == "evidence"
)
SOURCE = "1" * 40
SPEC = importlib.util.spec_from_file_location(
    "security_ci", ROOT / "scripts/check-security-ci-contract.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
EVIDENCE_JOB = CHECKER.load_workflow(
    ROOT / ".github/workflows/enterprise-hardening.yml"
)["jobs"]["committed-linux-evidence"]


class RequiredEvidenceTests(unittest.TestCase):
    def test_complete_reviewed_evidence_job_matches_its_source_contract(self):
        CHECKER.validate_job_digest(
            EVIDENCE_JOB,
            CHECKER.EXPECTED_TRUST_JOB_DIGESTS[
                ("enterprise-hardening", "committed-linux-evidence")
            ],
            "enterprise-hardening committed-linux-evidence",
        )
        changed = copy.deepcopy(EVIDENCE_JOB)
        changed["steps"][-1]["run"] = "exit 0\n"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.validate_job_digest(
                changed,
                CHECKER.EXPECTED_TRUST_JOB_DIGESTS[
                    ("enterprise-hardening", "committed-linux-evidence")
                ],
                "enterprise-hardening committed-linux-evidence",
            )

    def run_binding(self, evidence):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            environment = {
                "PATH": os.defpath,
                "AUTHORIZED_SOURCE_SHA": SOURCE,
                "SOURCE_SHA": SOURCE,
                "SOURCE_REPOSITORY": "owner/repo",
                "GITHUB_REPOSITORY": "owner/repo",
                "EVIDENCE_SHA": evidence,
                "GITHUB_OUTPUT": str(output),
            }
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", BINDING["run"]],
                env=environment,
                capture_output=True,
                text=True,
            )
            return result.returncode, output.read_text() if output.exists() else ""

    def test_missing_evidence_cannot_succeed_for_authorized_source(self):
        code, output = self.run_binding("")
        self.assertNotEqual(code, 0)
        self.assertNotIn("verify=", output)

    def test_malformed_and_same_source_evidence_fail(self):
        for evidence in ["bad", SOURCE]:
            code, output = self.run_binding(evidence)
            self.assertNotEqual(code, 0)
            self.assertNotIn("verify=", output)

    def test_distinct_valid_evidence_requires_strict_verification(self):
        self.assertEqual(self.run_binding("2" * 40), (0, "verify=true\n"))

    def test_source_contract_rejects_bootstrap_or_caller_substitution(self):
        CHECKER.validate_committed_evidence_binding(EVIDENCE_JOB)
        for mutation in ("empty", "caller", "skip"):
            job = copy.deepcopy(EVIDENCE_JOB)
            step = next(step for step in job["steps"] if step.get("id") == "evidence")
            if mutation == "empty":
                step["run"] = step["run"].replace(
                    '[[ "${EVIDENCE_SHA}" =~ ^[0-9a-f]{40}$ ]]', "true"
                )
            elif mutation == "caller":
                step["env"]["EVIDENCE_SHA"] = "${{ inputs.source_sha }}"
            else:
                step["run"] = (
                    'echo "verify=false" >> "${GITHUB_OUTPUT}"\nexit 0\n' + step["run"]
                )
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(CHECKER.ContractError),
            ):
                CHECKER.validate_committed_evidence_binding(job)

    def test_final_gate_requires_actual_strict_verification(self):
        final = next(
            step
            for step in EVIDENCE_JOB["steps"]
            if step.get("name") == "Require committed Linux evidence verification"
        )
        self.assertEqual(final["if"], "${{ always() }}")
        self.assertEqual(
            final["env"], {"VERIFIED": "${{ steps.strict.outputs.verified }}"}
        )
        for verified, success in [("true", True), ("false", False), ("", False)]:
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", final["run"]],
                env={"PATH": os.defpath, "VERIFIED": verified},
                capture_output=True,
            )
            self.assertEqual(result.returncode == 0, success)


if __name__ == "__main__":
    unittest.main()
