"""Optimized execution must retain actual framework acceptance checks."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


class OptimizedHostAcceptanceTest(unittest.TestCase):
    def test_native_host_does_not_receive_ambient_provider_credentials(self):
        import host_acceptance
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            def launch(argv, **options):
                environment = options["env"]
                if any(name in environment for name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                                                         "OPENROUTER_API_KEY", "PYTHONPATH"]):
                    raise AssertionError("native process received ambient provider inputs")
                raise RuntimeError("test.native_launch_boundary")
            with patch.dict(os.environ, {"OPENAI_API_KEY":"synthetic-key", "ANTHROPIC_API_KEY":"synthetic-key",
                                         "OPENROUTER_API_KEY":"synthetic-key", "PYTHONPATH":"shadow"}), \
                 patch.object(sys, "argv", ["host_acceptance", "--checkout", str(Path.cwd()),
                                             "--evidence", str(evidence)]), \
                 patch.object(host_acceptance.subprocess, "Popen", launch):
                with self.assertRaisesRegex(RuntimeError, "test.native_launch_boundary"):
                    host_acceptance.main()

    def test_revoked_native_result_cannot_qualify_under_optimization(self):
        code = '''
import asyncio
from host_acceptance import graph_case
from chio_sdk.recovery_host import RecoveryHostOutcome
class Session:
    async def execute(self, choice):
        return RecoveryHostOutcome("complete", "command", "workflow")
async def revoked():
    pass
asyncio.run(graph_case(Session(), revoked))
'''
        environment = {**os.environ, "OTEL_SDK_DISABLED":"true", "CREWAI_DISABLE_TELEMETRY":"true"}
        if "PYTHONPATH" in environment:
            environment["PYTHONPATH"] = os.pathsep.join(str(Path(value).resolve())
                for value in environment["PYTHONPATH"].split(os.pathsep) if value)
        result = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True, text=True,
                                cwd=Path(__file__).parent, env=environment, timeout=30)
        self.assertNotEqual(result.returncode, 0, "optimized acceptance trusted revoked completion")
        self.assertIn("qualification.host_revoked", result.stderr)


if __name__ == "__main__":
    unittest.main()
