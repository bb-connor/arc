#!/usr/bin/env python3

import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPOSITORY_ROOT / "scripts/check-committed-linux-evidence.py"
EVIDENCE_DIRECTORY = Path("audits/evidence/enterprise-linux")
FILES = {
    "enterprise-migration-binding-digest.txt",
    "enterprise-migration-canary.json",
    "enterprise-migration-canary.json.sha256",
}
PUBLIC_KEY = "ab" * 32
DIGEST = "11" * 32


FAKE_VERIFIER = r"""#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("--evidence-directory", type=Path, required=True)
parser.add_argument("--runner-public-key", required=True)
parser.add_argument("--expected-source-commit", required=True)
parser.add_argument("--expected-runner-name", required=True)
parser.add_argument("--expected-runner-os", required=True)
parser.add_argument("--expected-runner-arch", required=True)
parser.add_argument("--expected-runner-labels-digest", required=True)
parser.add_argument("--expected-configuration-digest", required=True)
parser.add_argument("--expected-inventory-digest", required=True)
parser.add_argument("--expected-runner-contract-digest", required=True)
parser.add_argument("--expected-key-log-transparency-digest", required=True)
parser.add_argument("--expected-broker-boundary-digest", required=True)
parser.add_argument("--expected-cage-enforcement-digest", required=True)
parser.add_argument("--expected-committed-adversarial-evidence-digest", required=True)
parser.add_argument("--expected-linux-adversarial-controls-digest", required=True)
parser.add_argument("--expected-migration-state-store-digest", required=True)
parser.add_argument("--expected-binding-digest", required=True)
parser.add_argument("--generated-at-not-before-unix-ms", required=True)
parser.add_argument("--generated-at-not-after-unix-ms", required=True)
args = parser.parse_args()
if args.command != "verify-committed-linux-evidence":
    print("wrong verifier command", file=sys.stderr)
    raise SystemExit(1)
if args.runner_public_key != "abababababababababababababababababababababababababababababababab":
    print("pinned key substitution", file=sys.stderr)
    raise SystemExit(1)
artifact = args.evidence_directory / "enterprise-migration-canary.json"
if artifact.read_text(encoding="utf-8") != args.expected_source_commit:
    print("source mismatch or corrupt artifact", file=sys.stderr)
    raise SystemExit(1)
print("0x" + "cd" * 32)
"""


def run(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments), cwd=cwd, check=False, capture_output=True, text=True
    )


class CommittedLinuxEvidenceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="chio-committed-linux-evidence-"
        )
        self.root = Path(self.temporary.name)
        self.assertEqual(run("git", "init", "-b", "main", cwd=self.root).returncode, 0)
        self.assertEqual(
            run(
                "git", "config", "user.name", "Evidence Test", cwd=self.root
            ).returncode,
            0,
        )
        self.assertEqual(
            run(
                "git",
                "config",
                "user.email",
                "evidence@example.invalid",
                cwd=self.root,
            ).returncode,
            0,
        )
        self.verifier = self.root.parent / f"{self.root.name}-fake-verifier.py"
        self.verifier.write_text(FAKE_VERIFIER, encoding="utf-8")
        self.verifier.chmod(0o700)
        self.verifier_sha256 = hashlib.sha256(self.verifier.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        self.verifier.unlink(missing_ok=True)
        self.temporary.cleanup()

    def commit(self, message: str) -> str:
        self.assertEqual(run("git", "add", "-A", cwd=self.root).returncode, 0)
        result = run("git", "commit", "-m", message, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        resolved = run("git", "rev-parse", "HEAD", cwd=self.root)
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        return resolved.stdout.strip()

    def create_source(self, *, extra_evidence_file: bool = False) -> str:
        (self.root / "source.txt").write_text("source\n", encoding="utf-8")
        if extra_evidence_file:
            directory = self.root / EVIDENCE_DIRECTORY
            directory.mkdir(parents=True)
            (directory / "extra.json").write_text("{}\n", encoding="utf-8")
        return self.commit("source")

    def create_evidence(
        self,
        source_commit: str,
        *,
        omitted: str | None = None,
        artifact_source: str | None = None,
        outside_change: bool = False,
        executable_artifact: bool = False,
    ) -> str:
        directory = self.root / EVIDENCE_DIRECTORY
        directory.mkdir(parents=True, exist_ok=True)
        for name in FILES:
            if name == omitted:
                continue
            if name == "enterprise-migration-canary.json":
                content = (
                    artifact_source if artifact_source is not None else source_commit
                )
            elif name == "enterprise-migration-canary.json.sha256":
                content = f"{DIGEST}  enterprise-migration-canary.json\n"
            else:
                content = f"0x{DIGEST}\n"
            path = directory / name
            path.write_text(content, encoding="utf-8")
            if executable_artifact and name == "enterprise-migration-canary.json":
                path.chmod(0o755)
        if outside_change:
            (self.root / "outside.txt").write_text("not evidence\n", encoding="utf-8")
        return self.commit("evidence")

    def checker_arguments(
        self,
        source_commit: str,
        evidence_commit: str,
        *,
        public_key: str = PUBLIC_KEY,
        verifier_sha256: str | None = None,
        verifier: Path | None = None,
    ) -> list[str]:
        digest_arguments = [
            "--expected-runner-labels-digest",
            "--expected-configuration-digest",
            "--expected-inventory-digest",
            "--expected-runner-contract-digest",
            "--expected-key-log-transparency-digest",
            "--expected-broker-boundary-digest",
            "--expected-cage-enforcement-digest",
            "--expected-committed-adversarial-evidence-digest",
            "--expected-linux-adversarial-controls-digest",
            "--expected-migration-state-store-digest",
            "--expected-binding-digest",
        ]
        arguments = [
            "python3",
            str(CHECKER),
            "--root",
            str(self.root),
            "--verifier",
            str(verifier if verifier is not None else self.verifier),
            "--verifier-sha256",
            verifier_sha256 if verifier_sha256 is not None else self.verifier_sha256,
            "--source-commit",
            source_commit,
            "--evidence-commit",
            evidence_commit,
            "--runner-public-key",
            public_key,
            "--expected-runner-name",
            "chio-enterprise-x64",
            "--expected-runner-os",
            "Linux",
            "--expected-runner-arch",
            "X64",
        ]
        for argument in digest_arguments:
            arguments.extend([argument, DIGEST])
        arguments.extend(
            [
                "--generated-at-not-before-unix-ms",
                "1",
                "--generated-at-not-after-unix-ms",
                "2",
            ]
        )
        return arguments

    def check(
        self,
        source_commit: str,
        evidence_commit: str,
        *,
        public_key: str = PUBLIC_KEY,
        verifier_sha256: str | None = None,
        verifier: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            *self.checker_arguments(
                source_commit,
                evidence_commit,
                public_key=public_key,
                verifier_sha256=verifier_sha256,
                verifier=verifier,
            ),
            cwd=self.root,
        )

    def test_exact_evidence_only_descendant_passes(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source)
        result = self.check(source, evidence)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("committed Linux evidence verified", result.stdout)

    def test_missing_file_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(
            source, omitted="enterprise-migration-canary.json.sha256"
        )
        result = self.check(source, evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inventory is not exact", result.stderr)

    def test_extra_file_fails(self) -> None:
        source = self.create_source(extra_evidence_file=True)
        evidence = self.create_evidence(source)
        result = self.check(source, evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inventory is not exact", result.stderr)

    def test_stale_or_corrupt_artifact_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source, artifact_source="0" * 40)
        result = self.check(source, evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source mismatch or corrupt artifact", result.stderr)

    def test_pinned_key_substitution_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source)
        result = self.check(source, evidence, public_key="ff" * 32)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pinned key substitution", result.stderr)

    def test_verifier_substitution_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source)
        result = self.check(source, evidence, verifier_sha256="00" * 32)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verifier SHA-256 does not match the pin", result.stderr)

    def test_relative_verifier_is_resolved_against_repository_root(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source)
        relative_verifier = Path("trusted-verifier.py")
        verifier = self.root / relative_verifier
        verifier.write_text(FAKE_VERIFIER, encoding="utf-8")
        verifier.chmod(0o700)
        verifier_sha256 = hashlib.sha256(verifier.read_bytes()).hexdigest()
        result = self.check(
            source,
            evidence,
            verifier_sha256=verifier_sha256,
            verifier=relative_verifier,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_data_tree_mode_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source, executable_artifact=True)
        result = self.check(source, evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tree mode is not 100644", result.stderr)

    def test_non_evidence_descendant_change_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source, outside_change=True)
        result = self.check(source, evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the evidence surface", result.stderr)

    def test_dirty_evidence_surface_fails(self) -> None:
        source = self.create_source()
        evidence = self.create_evidence(source)
        artifact = self.root / EVIDENCE_DIRECTORY / "enterprise-migration-canary.json"
        artifact.write_text("dirty", encoding="utf-8")
        result = self.check(source, evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("working-tree changes", result.stderr)


class VerifierSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("snapshot_checker", CHECKER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        self.checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checker)

    def exercise(self, replace_path: bool) -> None:
        file_only_os = SimpleNamespace(
            **{name: value for name, value in vars(os).items() if name != "memfd_create"}
        )
        original = b"#!/usr/bin/env python3\nprint('original pinned bytes')\n"
        with mock.patch.object(self.checker, "os", file_only_os):
            descriptor, executable, directory = self.checker.immutable_verifier_snapshot(
                original
            )
        try:
            self.assertIsNotNone(directory)
            if replace_path:
                path = directory / "chio-enterprise-evidence"
                path.unlink()
                path.write_text("#!/usr/bin/env python3\nprint('substituted bytes')\n")
                path.chmod(0o500)
            result = subprocess.run(
                [str(executable)],
                pass_fds=(descriptor,),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "original pinned bytes\n")
        finally:
            os.close(descriptor)
            shutil.rmtree(directory)

    def test_file_snapshot_executes_without_a_writable_descriptor(self) -> None:
        self.exercise(False)

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "descriptor paths require procfs")
    def test_file_snapshot_keeps_verified_inode_after_path_replacement(self) -> None:
        self.exercise(True)


if __name__ == "__main__":
    unittest.main()
