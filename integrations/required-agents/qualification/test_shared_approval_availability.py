"""Legacy approval qualification must remain unavailable, without dispatch."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import shared_kernel


class ApprovalWorkflowAvailabilityTests(unittest.TestCase):
    cases = (
        "approval-workflow", "bounded-approval-workflow", "approved-grant-budget",
        "approved-unknown-after-dispatch",
    )

    def test_unmigrated_workflows_report_unavailable_before_any_command(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "chio"
            binary.write_bytes(b"identity fixture, never executed")
            output = Path(directory) / "output"
            arguments = ["shared_kernel.py", "--binary", str(binary), "--output", str(output),
                         "--cases", ",".join(self.cases)]
            with patch.object(shared_kernel.sys, "argv", arguments), \
                    patch.object(shared_kernel, "run", side_effect=AssertionError("external command")) as run, \
                    patch.object(shared_kernel, "Runtime") as runtime, \
                    contextlib.redirect_stdout(io.StringIO()):
                code = shared_kernel.main()
            self.assertEqual(code, 1)
            run.assert_not_called()
            runtime.assert_not_called()
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual({row["case"] for row in manifest["cases"]}, set(self.cases))
            for result in manifest["cases"]:
                self.assertEqual(result["status"], "unavailable")
                self.assertFalse(result["dispatchAttempted"])
                self.assertIn("external signer", result["reason"])
                self.assertIn("activated", result["reason"])

    def test_direct_legacy_entrypoints_refuse_before_runtime_access(self):
        for function in (shared_kernel.approval_workflow_case,
                         shared_kernel.bounded_approval_workflow_case,
                         shared_kernel.approved_budget_case,
                         shared_kernel.approved_unknown_case):
            with self.subTest(function=function.__name__):
                runtime = Mock()
                runtime.start.side_effect = AssertionError("legacy runtime was touched")
                with self.assertRaisesRegex(RuntimeError, "external signer"):
                    function(runtime)
                self.assertEqual(runtime.mock_calls, [])

    def test_unavailable_workflows_do_not_become_passes_in_a_mixed_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "chio"
            binary.write_bytes(b"identity fixture")
            output = Path(directory) / "output"
            arguments = ["shared_kernel.py", "--binary", str(binary), "--output", str(output),
                         "--cases", "authority-replay,approval-workflow"]
            with patch.object(shared_kernel.sys, "argv", arguments), \
                    patch.object(shared_kernel, "run", return_value="test metadata"), \
                    patch.object(shared_kernel, "validate_resource_image", return_value={}), \
                    patch.object(shared_kernel, "Runtime") as runtime, \
                    patch.object(shared_kernel, "basic_cases"), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = shared_kernel.main()
            self.assertEqual(code, 1)
            self.assertEqual(runtime.call_count, 1)
            cases = json.loads((output / "manifest.json").read_text())["cases"]
            self.assertEqual([(row["case"], row["status"]) for row in cases],
                             [("authority-replay", "passed"), ("approval-workflow", "unavailable")])


if __name__ == "__main__":
    unittest.main()
