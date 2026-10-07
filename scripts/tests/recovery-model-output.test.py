"""Model command output must not rewrite source-tree evidence."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "docs/architecture/recoverable-agent-runtime/model/run.py"


class ModelOutputTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name).resolve()
        self.models = self.repo / "docs/architecture/recoverable-agent-runtime/model"
        self.models.mkdir(parents=True)
        shutil.copyfile(RUNNER, self.models / "run.py")
        for name in ["recovery", "review", "third"]:
            (self.models / (name + ".rs")).write_text('fn main() {\n    println!("bounded model fixture");\n}\n')
        for name in ["results.txt", "review-results.txt", "third-results.txt", "evidence.json"]:
            (self.models / name).write_bytes(b"retained-original-record\n")
        self.before = self.pins()

    def pins(self):
        return {path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in self.models.iterdir()}

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, "-B", str(self.models / "run.py"), *map(str, arguments)],
                              cwd=self.repo, capture_output=True, text=True, timeout=60)

    def test_explicit_output_keeps_all_source_evidence_bytes_unchanged(self):
        output = self.repo / "target/model-acceptance"
        result = self.invoke("--output", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pins(), self.before, "explicit output still rewrote source-tree records")
        record = json.loads((output / "evidence.json").read_bytes())
        self.assertEqual([row["name"] for row in record["runs"]], ["ownership", "review", "third"])
        self.assertTrue(all(row["exit_code"] == 0 for row in record["runs"]))

    def test_implicit_source_tree_publication_is_refused(self):
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0, "implicit source-tree publication remains enabled")
        self.assertEqual(self.pins(), self.before)

    def test_compiler_uses_captured_bytes_during_a_transient_live_source_swap(self):
        code = '''
import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("model_runner",sys.argv[1])
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
original=runner.subprocess.run
def swap(command,**options):
    if command[0]=="rustc" and "recovery.rs" in command:
        live=runner.ROOT/"recovery.rs";data=live.read_bytes()
        live.write_text('fn main() { println!("substituted live input"); }')
        try: return original(command,**options)
        finally: live.write_bytes(data)
    return original(command,**options)
runner.subprocess.run=swap
sys.argv=[sys.argv[1],"--output",sys.argv[2]]
runner.main()
'''
        output = self.repo / "target/transient-model-input"
        result = subprocess.run([sys.executable,"-B","-c",code,str(self.models/"run.py"),str(output)],
                                cwd=self.repo,capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn("substituted live input",(output/"results.txt").read_text())
        self.assertEqual(self.pins(),self.before)


if __name__ == "__main__":
    unittest.main()
