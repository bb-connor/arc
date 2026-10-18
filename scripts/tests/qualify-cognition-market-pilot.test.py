#!/usr/bin/env python3
"""Exercise the tamper-refusal checks of the cognition-market pilot qualification."""

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "qualify-cognition-market-pilot.py"
SPEC = importlib.util.spec_from_file_location("cognition_market_pilot", SCRIPT)
PILOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PILOT
SPEC.loader.exec_module(PILOT)

PROOF_CODE = "urn:chio:error:cli:other"
PROOF_MESSAGE = (
    "finding operator bundle artifact failed verification: "
    "finding_id does not match the canonical artifact body"
)
PURCHASE_CODE = "urn:chio:error:transport:invalid-request-shape"
PURCHASE_MESSAGE = "purchase record body or embedded signature is invalid"
TYPESCRIPT_ACCEPTED = getattr(PILOT, "TYPESCRIPT_ACCEPTED", 1)
EXACT_STDERR = f"error [{PROOF_CODE}]: {PROOF_MESSAGE}\n"


def completed(returncode, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout="", stderr=stderr)


class TamperedProofTests(unittest.TestCase):
    def check(self, rust, typescript):
        def fake_run(command, **_kwargs):
            return rust if command[0] == "/chio" else typescript

        body = json.dumps(
            {"bundle": {"finding": {"descriptor": {"topic": "t"}}}}
        ).encode()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            PILOT, "run", fake_run
        ), mock.patch.object(
            PILOT.urllib.request, "urlopen", return_value=io.BytesIO(body)
        ):
            return PILOT.tampered_proof_rejected(
                Path("/chio"),
                Path("/profile"),
                {"endpoint": "http://x", "bearerToken": "t"},
                "finding",
                Path(directory),
            )

    def test_exact_refusal_passes(self):
        result = self.check(completed(1, EXACT_STDERR), completed(0))
        self.assertEqual(
            result, {"rustRejected": True, "typescriptRejected": True}
        )

    def test_crash_or_usage_error_fails_with_exit_and_stderr(self):
        for returncode, stderr in (
            (-11, "segmentation fault"),
            (127, "chio: No such file or directory"),
            (2, "error: unrecognized subcommand 'verify-bundle'"),
            (1, "error [urn:chio:error:cli:io]: proof bundle read failed\n"),
        ):
            with self.subTest(returncode=returncode):
                with self.assertRaises(RuntimeError) as raised:
                    self.check(completed(returncode, stderr), completed(0))
                self.assertIn(f"exited {returncode}", str(raised.exception))
                self.assertIn(stderr, str(raised.exception))

    def test_typescript_crash_fails_with_exit_and_stderr(self):
        for returncode in (1, 4):
            with self.subTest(returncode=returncode):
                with self.assertRaises(RuntimeError) as raised:
                    self.check(
                        completed(1, EXACT_STDERR),
                        completed(returncode, "chio command failed: spawn ENOENT"),
                    )
                self.assertIn(f"exited {returncode}", str(raised.exception))
                self.assertIn("spawn ENOENT", str(raised.exception))

    def test_accepted_tamper_fails_qualification(self):
        result = self.check(
            completed(0), completed(TYPESCRIPT_ACCEPTED)
        )
        self.assertEqual(
            result, {"rustRejected": False, "typescriptRejected": False}
        )
        self.assertFalse(all(result.values()))


class ExactRefusalTests(unittest.TestCase):
    def test_purchase_terminal_refusal(self):
        stderr = f"error [{PURCHASE_CODE}]: {PURCHASE_MESSAGE}\n"
        self.assertTrue(
            PILOT.exact_refusal(completed(1, stderr), "purchase", PILOT.PURCHASE_REFUSAL)
        )
        self.assertFalse(
            PILOT.exact_refusal(completed(0), "purchase", PILOT.PURCHASE_REFUSAL)
        )
        with self.assertRaises(RuntimeError):
            PILOT.exact_refusal(
                completed(1, EXACT_STDERR), "purchase", PILOT.PURCHASE_REFUSAL
            )

    def test_json_error_report_matches(self):
        stderr = json.dumps({"code": PROOF_CODE, "message": PROOF_MESSAGE})
        self.assertTrue(
            PILOT.exact_refusal(completed(1, stderr), "proof", PILOT.PROOF_REFUSAL)
        )


if __name__ == "__main__":
    unittest.main()
