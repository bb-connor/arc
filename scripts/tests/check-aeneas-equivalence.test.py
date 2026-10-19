#!/usr/bin/env python3
"""Self-test for scripts/check-aeneas-equivalence.sh pin and digest checks."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-aeneas-equivalence.sh"

TAG = "build-test-tag"
MATHLIB_REV = "0123456789abcdef"
HOST_TOOLCHAIN = "leanprover/lean4:v4.0.0"
SOURCE_REL = "crates/demo/src/formal.rs"
WORK_DIR = "target/formal/aeneas-production"
SNAPSHOT_DIR = "formal/lean4/Chio/FormalDemo"
MODULE_REL = "formal/lean4/Chio/Chio/Proofs/AeneasGeneratedEquivalence.lean"
VENDOR_ROOT = "formal/lean4/vendor/aeneas"
PROOF = (
    "theorem f_equiv : True := trivial\n"
    "#print axioms f_equiv\n"
)


def architecture() -> str:
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


def toml_list(values: list[str]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.arch = architecture()
        self.runtime = {"aeneas": "a" * 64, "charon": "b" * 64, "charon-driver": "c" * 64}
        self.registry_extra = ""
        self.write_all()

    def path(self, relative: str) -> Path:
        return self.root / relative

    def write(self, relative: str, text: str) -> None:
        target = self.path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def read(self, relative: str) -> str:
        return self.path(relative).read_text(encoding="utf-8")

    def write_all(self) -> None:
        self.write(SOURCE_REL, "pub fn f() {}\n")
        self.write_registry()
        self.write("formal/aeneas/negative-tests.toml", "schema = \"x\"\n")
        for name in (
            "scripts/install-aeneas-toolchain.py",
            "scripts/vendor-aeneas-lean.sh",
            "scripts/tests/aeneas-equivalence.test.sh",
            "scripts/tests/snapshot-aeneas-generated.test.sh",
        ):
            self.write(name, "# fixture\n")
        self.write("scripts/snapshot-aeneas-generated.sh", "#!/usr/bin/env bash\nexit 0\n")
        self.path("scripts/snapshot-aeneas-generated.sh").chmod(0o755)
        self.write("scripts/check-aeneas-production.sh", "#!/usr/bin/env bash\nexit 0\n")
        self.path("scripts/check-aeneas-production.sh").chmod(0o755)
        shutil.copy2(SCRIPT, self.path("scripts/check-aeneas-equivalence.sh"))
        for name in ("nightly.yml", "release-qualification.yml"):
            self.write(f".github/workflows/{name}", f"env:\n  CHIO_AENEAS_RELEASE_TAG: {TAG}\n")
        self.write("formal/lean4/Chio/lean-toolchain", HOST_TOOLCHAIN + "\n")
        self.write("formal/lean4/Chio/lakefile.lean", "-- fixture\n")
        self.write_lake_manifest()
        self.write_vendor({"Aeneas/Basic.lean": "namespace Aeneas\n"})
        self.write(MODULE_REL, PROOF)
        self.write("formal/lean4/Chio/Chio.lean", "import Chio.Proofs.AeneasGeneratedEquivalence\n")
        self.write("formal/proof-manifest.toml", f"root_modules = [{json.dumps(MODULE_REL)}]\n")
        self.write_generated()
        self.write_toolchain_report()

    def write_registry(self, **overrides: str) -> None:
        fields = {
            "schema": "chio.aeneas-production.v1",
            "vendor_release_tag": TAG,
            "targets_status": "generated_equivalence",
            "functions": toml_list(["f"]),
            "theorems": toml_list(["f|Chio.Demo.f_equiv"]),
            "arch": self.arch,
            "interpreter_repair": "none",
        }
        fields.update(overrides)
        self.write(
            "formal/aeneas/production.toml",
            f'''schema = "{fields["schema"]}"
source = "{SOURCE_REL}"
equivalence_module = "{MODULE_REL}"
artifact_report = "target/formal/aeneas-production/equivalence-artifacts.json"
negative_registry = "formal/aeneas/negative-tests.toml"
vendor_manifest = "{VENDOR_ROOT}/VENDOR.toml"
vendor_release_tag = "{fields["vendor_release_tag"]}"
{self.registry_extra}
[[sources]]
id = "demo"
path = "{SOURCE_REL}"
namespace = "Chio.Demo"
work_dir = "{WORK_DIR}"
generated_module = "FormalDemo"
snapshot_dir = "{SNAPSHOT_DIR}"

[[toolchains]]
architecture = "{fields["arch"]}"
archive_asset = "aeneas-linux.tar.gz"
archive_sha256 = "{"d" * 64}"
aeneas_runtime_sha256 = "{self.runtime["aeneas"]}"
charon_runtime_sha256 = "{self.runtime["charon"]}"
charon_driver_runtime_sha256 = "{self.runtime["charon-driver"]}"
interpreter_repair = "{fields["interpreter_repair"]}"

[[targets]]
name = "demo"
source = "demo"
status = "{fields["targets_status"]}"
functions = {fields["functions"]}
equivalence_theorems = {fields["theorems"]}
''',
        )

    def write_lake_manifest(self, aeneas_dir: str = "../vendor/aeneas", rev: str = MATHLIB_REV) -> None:
        self.write(
            "formal/lean4/Chio/lake-manifest.json",
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "aeneas",
                            "type": "path",
                            "dir": aeneas_dir,
                            "configFile": "lakefile.lean",
                        },
                        {
                            "name": "mathlib",
                            "type": "git",
                            "url": "https://github.com/leanprover-community/mathlib4.git",
                            "rev": rev,
                            "inputRev": rev,
                        },
                    ]
                }
            ),
        )

    def write_vendor(
        self,
        files: dict[str, str],
        *,
        schema: str = "chio.aeneas-vendor.v1",
        release_tag: str = TAG,
        host: str = HOST_TOOLCHAIN,
        digest: str | None = None,
    ) -> None:
        vendor_root = self.path(VENDOR_ROOT)
        if vendor_root.exists():
            shutil.rmtree(vendor_root)
        for relative, text in files.items():
            self.write(f"{VENDOR_ROOT}/{relative}", text)
        h = hashlib.sha256()
        for path in sorted(p for p in vendor_root.rglob("*") if p.is_file()):
            relative_path = path.relative_to(vendor_root)
            h.update(relative_path.as_posix().encode("utf-8"))
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
        self.write(
            f"{VENDOR_ROOT}/VENDOR.toml",
            f'''schema = "{schema}"
release_tag = "{release_tag}"
host_lean_toolchain = "{host}"
mathlib_revision = "{MATHLIB_REV}"
revision = "deadbeef"
content_sha256 = "{digest or h.hexdigest()}"
''',
        )

    def write_generated(self) -> None:
        source_hash = hashlib.sha256(self.path(SOURCE_REL).read_bytes()).hexdigest()
        for name in ("Funs.lean", "Types.lean"):
            self.write(f"{WORK_DIR}/lean/{name}", f"-- generated {name}\n")
            self.write(f"{SNAPSHOT_DIR}/{name}", f"-- generated {name}\n")
        self.write(f"{WORK_DIR}/source.sha256", source_hash + "\n")

    def write_toolchain_report(self, **overrides: object) -> None:
        report = {
            "schema": "chio.aeneas-toolchain.v1",
            "architecture": self.arch,
            "releaseTag": TAG,
            "archiveAsset": "aeneas-linux.tar.gz",
            "archiveSha256": "d" * 64,
            "interpreterRepair": "none",
            "runtimeSha256": self.runtime,
        }
        report.update(overrides)
        self.write(f"{WORK_DIR}/toolchain.json", json.dumps(report))

    def install_lake(self, output: str = "lean ok", rc: int = 0) -> Path:
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        lake = bin_dir / "lake"
        lake.write_text(f"#!/bin/sh\ncat <<'EOT'\n{output}\nEOT\nexit {rc}\n", encoding="utf-8")
        lake.chmod(lake.stat().st_mode | stat.S_IXUSR)
        return bin_dir

    def run(self, lake_output: str = "lean ok", lake_rc: int = 0) -> subprocess.CompletedProcess[str]:
        bin_dir = self.install_lake(lake_output, lake_rc)
        env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        return subprocess.run(
            ["bash", str(self.path("scripts/check-aeneas-equivalence.sh"))],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )


class AeneasEquivalenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="aeneas-equivalence-")
        self.addCleanup(self.directory.cleanup)
        self.fx = Fixture(Path(self.directory.name))

    def assert_red(self, message: str, **run_kwargs: object) -> subprocess.CompletedProcess[str]:
        result = self.fx.run(**run_kwargs)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("gate passed", result.stdout)
        return result

    def test_green_writes_artifact_report(self) -> None:
        result = self.fx.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Aeneas generated equivalence gate passed", result.stdout)
        report = json.loads(self.fx.read(WORK_DIR + "/equivalence-artifacts.json"))
        self.assertEqual(report["schema"], "chio.aeneas-equivalence-artifacts.v1")
        self.assertEqual(report["registeredEquivalenceTheorems"], {"f": "Chio.Demo.f_equiv"})
        self.assertEqual(report["vendor"]["releaseTag"], TAG)
        self.assertEqual(
            report["sha256"][SOURCE_REL],
            hashlib.sha256(self.fx.path(SOURCE_REL).read_bytes()).hexdigest(),
        )

    def test_stale_stamp_delegates_to_production_gate(self) -> None:
        self.fx.write(WORK_DIR + "/source.sha256", "0" * 64 + "\n")
        self.fx.write(
            "scripts/check-aeneas-production.sh",
            "#!/usr/bin/env bash\necho delegated-to-production\nexit 0\n",
        )
        result = self.fx.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("delegated-to-production", result.stdout)
        self.assertNotIn("gate passed", result.stdout)

    def test_registry_schema_mismatch(self) -> None:
        self.fx.write_registry(schema="chio.aeneas-production.v0")
        self.assert_red("Aeneas equivalence registry schema mismatch")

    def test_external_models_refused(self) -> None:
        self.fx.registry_extra = "[[external_models]]\nname = \"x\"\n"
        self.fx.write_registry()
        self.assert_red("Aeneas equivalence must not depend on handwritten externals")

    def test_vendor_schema_mismatch(self) -> None:
        self.fx.write_vendor({"Aeneas/Basic.lean": "namespace Aeneas\n"}, schema="other")
        self.assert_red("Aeneas vendor manifest schema mismatch")

    def test_workflow_tag_missing(self) -> None:
        self.fx.write(".github/workflows/nightly.yml", "env: {}\n")
        self.assert_red("Aeneas release tag missing or duplicated in .github/workflows/nightly.yml")

    def test_workflow_tag_duplicated(self) -> None:
        self.fx.write(
            ".github/workflows/nightly.yml",
            f"a:\n  CHIO_AENEAS_RELEASE_TAG: {TAG}\nb:\n  CHIO_AENEAS_RELEASE_TAG: {TAG}\n",
        )
        self.assert_red("Aeneas release tag missing or duplicated")

    def test_release_tag_mismatch(self) -> None:
        self.fx.write_registry(vendor_release_tag="build-other")
        self.assert_red("Aeneas release tag mismatch")

    def test_host_toolchain_mismatch(self) -> None:
        self.fx.write_vendor({"Aeneas/Basic.lean": "namespace Aeneas\n"}, host="leanprover/lean4:v9")
        self.assert_red("Aeneas vendor host toolchain mismatch")

    def test_vendor_em_dash(self) -> None:
        self.fx.write_vendor({"Aeneas/Basic.lean": "-- a \N{EM DASH} b\n"})
        self.assert_red("Aeneas vendored support contains non-ASCII dash")

    def test_vendor_placeholder_proof(self) -> None:
        self.fx.write_vendor({"Aeneas/Basic.lean": "theorem t : True := by sorry\n"})
        self.assert_red("Aeneas runtime support contains placeholder proof")

    def test_vendor_meta_placeholder_allowed(self) -> None:
        self.fx.write_vendor(
            {"Aeneas/Basic.lean": "namespace Aeneas\n", "AeneasMeta/Tool.lean": "-- sorry\n"}
        )
        result = self.fx.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_vendor_import_closure_incomplete(self) -> None:
        self.fx.write_vendor({"Aeneas/Basic.lean": "import Aeneas.Missing\n"})
        self.assert_red("Aeneas vendor import closure is incomplete: ['Aeneas.Missing']")

    def test_vendor_content_hash_mismatch(self) -> None:
        self.fx.write_vendor({"Aeneas/Basic.lean": "namespace Aeneas\n"}, digest="0" * 64)
        self.assert_red("Aeneas vendored support content hash mismatch")

    def test_lake_manifest_aeneas_binding(self) -> None:
        self.fx.write_lake_manifest(aeneas_dir="../elsewhere")
        self.assert_red("Lake manifest does not bind the vendored Aeneas path package")

    def test_lake_manifest_mathlib_revision(self) -> None:
        self.fx.write_lake_manifest(rev="ffff")
        self.assert_red("Lake manifest does not bind the vendored Aeneas Mathlib revision")

    def test_equivalence_module_placeholder(self) -> None:
        self.fx.write(MODULE_REL, PROOF + "theorem g : True := by sorry\n")
        self.assert_red("Generated equivalence module contains a placeholder proof")

    def test_axiom_report_missing(self) -> None:
        self.fx.write(MODULE_REL, "theorem f_equiv : True := trivial\n")
        self.assert_red(
            "Generated equivalence axiom-report coverage mismatch; missing=['f_equiv'] extra=[]"
        )

    def test_target_not_equivalence_checked(self) -> None:
        self.fx.write_registry(targets_status="pilot")
        self.assert_red("Aeneas target is not equivalence-checked: demo")

    def test_theorem_count_mismatch(self) -> None:
        self.fx.write_registry(functions=toml_list(["f", "g"]))
        self.assert_red("Aeneas theorem count mismatch for demo")

    def test_malformed_theorem_row(self) -> None:
        self.fx.write_registry(theorems=toml_list(["f"]))
        self.assert_red("Malformed or duplicate generated equivalence theorem row: f")

    def test_duplicate_theorem_row(self) -> None:
        self.fx.write_registry(
            functions=toml_list(["f", "f"]),
            theorems=toml_list(["f|Chio.Demo.f_equiv", "f|Chio.Demo.f_equiv"]),
        )
        self.assert_red("Malformed or duplicate generated equivalence theorem row")

    def test_theorem_missing_from_module(self) -> None:
        self.fx.write_registry(theorems=toml_list(["f|Chio.Demo.absent"]))
        self.assert_red("Generated equivalence theorem missing for f: Chio.Demo.absent")

    def test_theorem_inventory_incomplete(self) -> None:
        self.fx.write_registry(theorems=toml_list(["g|Chio.Demo.f_equiv"]))
        self.assert_red("Aeneas generated equivalence theorem inventory is incomplete")

    def test_root_import_missing(self) -> None:
        self.fx.write("formal/lean4/Chio/Chio.lean", "-- none\n")
        self.assert_red("Generated Aeneas equivalence module is not root-imported exactly once")

    def test_root_import_duplicated(self) -> None:
        line = "import Chio.Proofs.AeneasGeneratedEquivalence\n"
        self.fx.write("formal/lean4/Chio/Chio.lean", line + line)
        self.assert_red("Generated Aeneas equivalence module is not root-imported exactly once")

    def test_module_absent_from_proof_manifest(self) -> None:
        self.fx.write("formal/proof-manifest.toml", "root_modules = []\n")
        self.assert_red("Generated Aeneas equivalence module is absent from proof manifest roots")

    def test_no_toolchain_row_for_architecture(self) -> None:
        self.fx.write_registry(arch="riscv64")
        self.assert_red(f"Expected one Aeneas toolchain row for {self.fx.arch}")

    def test_toolchain_report_mismatch(self) -> None:
        self.fx.write_toolchain_report(archiveSha256="e" * 64)
        self.assert_red("Aeneas generated output toolchain report mismatch for archiveSha256")

    def test_toolchain_runtime_hash_mismatch(self) -> None:
        self.fx.write_toolchain_report(runtimeSha256={**self.fx.runtime, "charon": "0" * 64})
        self.assert_red("Aeneas generated output toolchain report mismatch for runtimeSha256")

    def test_artifact_symlink_refused(self) -> None:
        target = self.fx.path("formal/aeneas/negative-tests.toml")
        real = self.fx.path("formal/aeneas/real.toml")
        target.rename(real)
        target.symlink_to(real)
        self.assert_red(
            "Aeneas equivalence artifact is not a regular file: formal/aeneas/negative-tests.toml"
        )

    def test_artifact_missing_refused(self) -> None:
        self.fx.path("scripts/vendor-aeneas-lean.sh").unlink()
        self.assert_red(
            "Aeneas equivalence artifact is not a regular file: scripts/vendor-aeneas-lean.sh"
        )

    def test_incomplete_proof_in_lean_log(self) -> None:
        result = self.fx.run(lake_output="declaration uses 'sorry'")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Aeneas generated equivalence depends on an incomplete proof", result.stderr)
        self.assertNotIn("gate passed", result.stdout)

    def test_lake_failure_fails_gate(self) -> None:
        result = self.fx.run(lake_output="build failed", lake_rc=1)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("gate passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
