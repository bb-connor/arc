"""Operator-side metadata review supplies the gateway's scoped environment."""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import host
from chio_process.launch import NativeDemoProvisionError


class GatewaySurfaceReview(unittest.TestCase):
    def test_provision_failure_preserves_only_allowlisted_ci_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            gateway = directory / "gateway"
            gateway.write_text(
                f"#!{sys.executable}\n"
                "import json,sys\n"
                "for line in sys.stdin:\n"
                " request=json.loads(line)\n"
                " if 'id' not in request: continue\n"
                " result={'tools':[]} if request['method']=='tools/list' else {}\n"
                " print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}))\n"
            )
            chio = directory / "chio"
            chio.write_text(
                f"#!{sys.executable}\n"
                "import os,sys\n"
                "sys.stderr.write('CHIO_JOB_DATABASE_URL is required; '+"
                "os.environ['CHIO_JOB_DATABASE_URL'])\n"
                "sys.exit(7)\n"
            )
            for executable in (gateway, chio):
                executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            environment = {
                **os.environ,
                "CHIO_JOB_DATABASE_URL": "postgres://worker:private-password@localhost/jobs",
            }
            with self.assertRaises(NativeDemoProvisionError):
                host.prepare(chio, gateway, "tenant", directory, environment)
            path = directory / "launch-diagnostics.json"
            self.assertTrue(path.is_file(), "failed native setup left no CI diagnostic")
            diagnostic = json.loads(path.read_text())
            self.assertEqual(diagnostic["stage"], "native_demo_provision")
            self.assertEqual(diagnostic["exit_status"], 7)
            self.assertIn("CHIO_JOB_DATABASE_URL is required", diagnostic["diagnostic"])
            self.assertNotIn("private-password", path.read_text())
            self.assertNotIn(environment["CHIO_JOB_DATABASE_URL"], path.read_text())
            self.assertEqual(
                set(diagnostic), {"schema", "stage", "exit_status", "diagnostic"}
            )

    def test_scoped_gateway_emits_reviewed_tools_without_resource_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            gateway = directory / "gateway"
            methods = directory / "methods.json"
            gateway.write_text(
                f"#!{sys.executable}\n"
                "import json,os,sys\n"
                "from pathlib import Path\n"
                "if os.environ.get('CHIO_JOB_DATABASE_URL')!='private-database-url': sys.exit(16)\n"
                "if sys.argv[1:]!=['worker','tenant']: sys.exit(17)\n"
                "seen=[]\n"
                "for line in sys.stdin:\n"
                " request=json.loads(line); seen.append(request['method'])\n"
                " if 'id' not in request: continue\n"
                " if request['method']=='initialize': result={'protocolVersion':'2025-11-25'}\n"
                " elif request['method']=='tools/list': result={'tools':[{'name':'task','inputSchema':{'type':'object'}}]}\n"
                " else: sys.exit(18)\n"
                " print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)\n"
                f"Path({str(methods)!r}).write_text(json.dumps(seen))\n"
            )
            gateway.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            fixture = host.review_tool_surface(
                [str(gateway), "worker", "tenant"],
                directory,
                {**os.environ, "CHIO_JOB_DATABASE_URL": "private-database-url"},
                "worker",
            )
            self.assertEqual(
                json.loads(fixture.read_text()),
                {"tools": [{"name": "task", "inputSchema": {"type": "object"}}]},
            )
            self.assertEqual(
                json.loads(methods.read_text()),
                ["initialize", "notifications/initialized", "tools/list"],
            )
            self.assertNotIn("private-database-url", fixture.read_text())


if __name__ == "__main__":
    unittest.main()
