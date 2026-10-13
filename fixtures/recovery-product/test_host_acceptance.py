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
        import owned_native_process
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
                 patch.object(owned_native_process.subprocess, "Popen", launch):
                with self.assertRaisesRegex(RuntimeError, "test.native_launch_boundary"):
                    host_acceptance.main()

    def test_revoked_native_result_cannot_qualify_under_optimization(self):
        code = '''
import asyncio
import json
from pathlib import Path
import socket
import sys
root = Path(sys.argv[1])
for path in reversed([root / "fixtures/recovery-product",
    root / "sdks/python/chio-sdk-python/src", root / "sdks/python/chio-langgraph/src",
    root / "sdks/python/chio-adapter-base/src"]):
    sys.path.insert(0, str(path))
network_attempts = []
def deny(*args, **kwargs):
    network_attempts.append("network")
    raise RuntimeError("optimized host check forbids network I/O")
socket.socket.connect = socket.socket.connect_ex = socket.getaddrinfo = deny
import httpx
from host_acceptance import graph_case
from chio_sdk.recovery_host import RecoveryHostSession
corpus = json.loads((root / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
response = json.loads(next(row["wire"] for row in corpus["vectors"]
    if row["contract"] == "command_result" and row["valid"]))
calls = []
def serve(request):
    calls.append(request)
    return httpx.Response(200, json=response)
session = RecoveryHostSession("http://localhost:1", "synthetic-capability-canary",
    {"resume": b"{}"}, max_tool_actions=3, transport=httpx.MockTransport(serve))
async def revoked():
    # A faulty native endpoint keeps reporting completion after revocation.
    pass
try:
    asyncio.run(graph_case(session, revoked))
finally:
    if len(calls) != 3 or session.attempts != 3 or network_attempts:
        raise RuntimeError("optimized host check did not reach revoked response")
    print(json.dumps({"requests": len(calls), "network_attempts": network_attempts}))
'''
        environment = {name: value for name, value in os.environ.items()
                       if name in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}}
        environment.update({"OTEL_SDK_DISABLED": "true", "CREWAI_DISABLE_TELEMETRY": "true",
                            "CREWAI_TESTING": "true", "CREWAI_TRACING_ENABLED": "false",
                            "LITELLM_LOCAL_MODEL_COST_MAP": "True"})
        result = subprocess.run([sys.executable, "-I", "-O", "-c", code,
                                 str(Path(__file__).resolve().parents[2])], capture_output=True, text=True,
                                cwd=Path(__file__).parent, env=environment, timeout=30)
        self.assertNotEqual(result.returncode, 0, "optimized acceptance trusted revoked completion")
        self.assertIn("qualification.host_revoked", result.stderr)
        self.assertIn('"requests": 3, "network_attempts": []', result.stdout)
        self.assertNotIn("canary", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
