"""Source controls with a Python-only cargo test double; no Rust tools run."""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
if "--source-root" in sys.argv:
    index = sys.argv.index("--source-root")
    ROOT = Path(sys.argv[index + 1]).resolve()
    del sys.argv[index:index + 2]

SHIM = r'''
import os
from pathlib import Path
import sys

if sys.argv[1:] == ["kani", "--version", "--verbose"]:
    print("Kani Rust Verifier 0.68.0 (kani-0.68.0) (cargo plugin)")
    print("using rustc 1.100.0-nightly (8925ea358 2026-08-20) "
          "(commit 8925ea35 2026-08-20) with LLVM 23.1.0")
    print("CBMC 6.11.0")
    raise SystemExit(0)
if sys.argv[1:2] != ["kani"] or "--harness" not in sys.argv:
    raise SystemExit(99)
with Path(os.environ["KANI_CONTROL_CALLS"]).open("a") as out:
    out.write(repr(sys.argv[1:]) + "\n")
mode = os.environ["KANI_CONTROL_MODE"]
harness = sys.argv[sys.argv.index("--harness") + 1]
if mode == "compile-failure":
    print("error: internal compiler error: Kani unexpectedly panicked at "
          "kani-compiler/src/intrinsics.rs:243:17", file=sys.stderr)
    raise SystemExit(101)
if mode == "empty":
    raise SystemExit(0)
if mode == "wrong-harness":
    harness += "_other"
print("Checking harness " + harness + "...")
if mode == "zero-proofs":
    print("Complete - 0 successfully verified harnesses, 0 failures, 0 total.")
elif mode == "failed-proof":
    print("Complete - 0 successfully verified harnesses, 1 failures, 1 total.")
elif mode != "no-summary":
    if mode == "panic-with-summary":
        print("error: internal compiler error: Kani unexpectedly panicked")
    print("Complete - 1 successfully verified harnesses, 0 failures, 1 total.")
    if mode == "duplicate-summary":
        print("Complete - 1 successfully verified harnesses, 0 failures, 1 total.")
'''


class PublicResultControls(unittest.TestCase):
    def run_gate(self, mode, lane="pr", list_only=False):
        with tempfile.TemporaryDirectory(prefix="kani-public-source-control-") as tmp:
            root = Path(tmp)
            paths = [
                "scripts/check-kani-public-core.sh",
                "scripts/check-kani-toolchain.sh",
                "formal/rust-verification/kani-public-harnesses.toml",
                "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs",
            ]
            helper = "scripts/check-kani-harness-result.py"
            if (ROOT / helper).exists():
                paths.append(helper)
            for rel in paths:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / rel, path)
            binary = root / "bin"
            binary.mkdir()
            cargo = binary / "cargo"
            cargo.write_text("#!" + sys.executable + "\n" + textwrap.dedent(SHIM))
            cargo.chmod(0o755)
            env = dict(os.environ)
            for key in ("KANI_PUBLIC_HARNESSES_MANIFEST", "KANI_PUBLIC_HARNESSES_SOURCE",
                        "CHIO_KANI_VERSION", "BASH_ENV", "ENV"):
                env.pop(key, None)
            env.update(PATH=str(binary) + os.pathsep + env.get("PATH", ""),
                       KANI_CONTROL_MODE=mode, KANI_CONTROL_CALLS=str(root / "calls"),
                       TMPDIR=str(root), PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(
                ["bash", str(root / paths[0]), "--lane", lane,
                 *(["--list"] if list_only else [])],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
            )
            calls = (root / "calls").read_text() if (root / "calls").exists() else ""
            return result, calls

    def test_empty_success_is_not_a_proof(self):
        result, calls = self.run_gate("empty")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(calls.splitlines()), 1)
        self.assertNotIn("Kani public core harnesses passed", result.stdout)

    def test_compile_failure_preserves_exit_and_full_diagnostic(self):
        result, calls = self.run_gate("compile-failure")
        self.assertEqual(result.returncode, 101)
        self.assertIn("intrinsics.rs:243:17", result.stdout + result.stderr)
        self.assertEqual(len(calls.splitlines()), 1)
        self.assertNotIn("Kani public core harnesses passed", result.stdout)

    def test_ambiguous_and_failed_results_refuse(self):
        for mode in ("zero-proofs", "failed-proof", "no-summary", "wrong-harness",
                     "panic-with-summary", "duplicate-summary"):
            with self.subTest(mode=mode):
                result, calls = self.run_gate(mode)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(len(calls.splitlines()), 1)
                self.assertNotIn("Kani public core harnesses passed", result.stdout)

    def test_exact_selection_and_complete_lane_with_synthetic_results(self):
        import ast

        result, calls = self.run_gate("success")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = [ast.literal_eval(line) for line in calls.splitlines()]
        manifest = tomllib.loads((ROOT / "formal/rust-verification/kani-public-harnesses.toml").read_text())
        names = manifest["lanes"]["pr"]["harnesses"]
        self.assertEqual(len(commands), len(names))
        for command, name in zip(commands, names):
            self.assertIn("--exact", command)
            self.assertEqual(command[command.index("--harness") + 1],
                             "kani_public_harnesses::" + name)
            self.assertEqual("--no-unwinding-checks" in command,
                             name not in manifest["unwinding_checks"])
            self.assertNotIn("--no-default-features", command)

    def test_empty_execution_lane_and_unknown_lane_refuse_without_proof(self):
        for lane in ("nightly_only", "unknown"):
            with self.subTest(lane=lane):
                result, calls = self.run_gate("success", lane)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, "")

    def test_listing_is_not_proof_execution(self):
        result, calls = self.run_gate("success", list_only=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, "")
        self.assertNotIn("harnesses passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
