"""Optimized controller execution must preserve native safety refusal."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class CliAcceptanceTest(unittest.TestCase):
    def test_optimized_controller_refuses_a_second_effect(self):
        root = Path(__file__).resolve().parents[2]
        code = r'''
import importlib.util,json,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
root=Path(sys.argv[1])
sys.path.insert(0,str(root/"fixtures/recovery-product"))
spec=importlib.util.spec_from_file_location("cli_fixture",root/"fixtures/recovery-product/cli_acceptance.py")
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
with tempfile.TemporaryDirectory() as temp:
    output=Path(temp)/"evidence";cli=Path(temp)/"chio";cli.write_text("synthetic")
    sequence=iter([0,9,0])
    def run(command,**kwargs):
        if command[0]==str(cli.resolve()):
            if command[-2:] != ["--operator-key","ab"*32]:
                raise AssertionError("independently supplied operator key was not passed to the actual CLI")
            result=next(sequence)
            return SimpleNamespace(returncode=result,stdout=b"{}",stderr=b"recovery.restart_required" if result else b"")
        if command[0]=="scp":
            name=Path(command[-1])
            data={"capability.json":"synthetic","workflow.json":"synthetic-workflow",
                  "native-evidence.json":{"effects":2,"report":{},"tree_calls":3}}[name.name]
            name.write_text(json.dumps(data))
        return SimpleNamespace(returncode=0)
    class Process:
        def __init__(self,*args,**kwargs):self.stopped=False
        def poll(self):return 0 if self.stopped else None
        def wait(self,**kwargs):self.stopped=True;return 0
        def terminate(self):self.stopped=True
    with patch.object(fixture.subprocess,"run",run),patch.object(fixture.subprocess,"Popen",Process),\
         patch.object(fixture.time,"sleep",lambda _:None),patch.object(sys,"argv",[
            "cli_acceptance","--ssh-config",str(Path(temp)/"ssh"),"--checkout",
            "/var/tmp/native-candidate","--cli",str(cli),"--evidence",str(output),
            "--operator-key","ab"*32]):
        try:
            fixture.main()
        except ValueError as error:
            if str(error)!="qualification.cli_native_effect_count":raise
        else:
            raise SystemExit("optimized CLI controller accepted a second effect")
'''
        result = subprocess.run([sys.executable, "-O", "-B", "-c", code, str(root)],
                                cwd=root, env=dict(os.environ), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
