#!/usr/bin/env python3
"""Require reachable receipt witnesses even when Kani exits successfully."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = "kani_public_harnesses::proof_target"


def result() -> dict:
    return {
        "verification_results": {
            "summary": {
                "total_harnesses": 1,
                "executed": 1,
                "successful": 1,
                "failed": 0,
                "status": "completed",
            },
            "results": [
                {
                    "harness_id": HARNESS,
                    "status": "Success",
                    "checks": [
                        {
                            "id": 1,
                            "function": HARNESS,
                            "status": "Satisfied",
                            "description": "proof_target",
                            "category": "cover",
                        }
                    ],
                }
            ],
        },
    }


class ReachabilityTests(unittest.TestCase):
    runner_kind = "multi"

    def run_proof(
        self,
        document: dict | str | None,
        *,
        require_cover: str = "true",
        unwinding: str = "true",
        cargo_exit: int = 0,
        memcmp: str | None = None,
        key_eq: str | None = None,
        key_hex: str | None = None,
        config_extra: str = "",
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="chio-kani-reachability-") as raw:
            work = Path(raw)
            manifest = work / "manifest.toml"
            manifest.write_text(f"""schema = "chio.kani.multi-crate.v1"
[[harness]]
crate = "fake-crate"
harness = "proof_target"
default_unwind = 8
timeout_secs = 10
lane = "pr"
unwinding_checks = {unwinding}
require_cover = {require_cover}
{config_extra}
""")
            if memcmp is not None:
                with manifest.open("a") as stream:
                    stream.write(f"memcmp_unwind = {memcmp}\n")
            if key_eq is not None:
                with manifest.open("a") as stream:
                    stream.write(f"public_key_eq_unwind = {key_eq}\n")
            if key_hex is not None:
                with manifest.open("a") as stream:
                    stream.write(f"public_key_hex_unwind = {key_hex}\n")
            source = work / "source.rs"
            source.write_text("#[kani::proof]\npub fn proof_target() {}\n")
            if self.runner_kind == "core":
                covers = (
                    '["proof_target"]'
                    if require_cover == "true"
                    else "[]"
                    if require_cover == "false"
                    else require_cover
                )
                checks = '["proof_target"]' if unwinding == "true" else "[]"
                manifest.write_text(f"""schema = "chio.kani-public-harnesses.v1"
crate = "chio-kernel-core"
script = "scripts/check-kani-public-core.sh"
unwinding_checks = {checks}
cover_required = {covers}
memcmp_unwind = {"{}" if memcmp is None else '{ "proof_target" = ' + memcmp + " }"}
public_key_eq_unwind = {"{}" if key_eq is None else '{ "proof_target" = ' + key_eq + " }"}
{config_extra}
harness_groups = []
covered_symbols = []
[lanes.pr]
description = "test"
harnesses = ["proof_target"]
[lanes.nightly_only]
description = "reserved"
harnesses = []
""")
            fixture = work / "result.json"
            if document is not None:
                fixture.write_text(
                    document if isinstance(document, str) else json.dumps(document)
                )
            cargo = work / "cargo"
            cargo.write_text("""#!/usr/bin/env python3
import os,pathlib,shutil,sys
args=sys.argv[1:]
if "--version" in args:
 print("cargo-kani 0.68.0");sys.exit(0)
if "--exact" not in args or args[args.index("--harness")+1]!="kani_public_harnesses::proof_target":
 sys.exit(19)
if "--list-goto-functions" in args:
 if "--export-json" in args or "--default-unwind" in args:
  sys.exit(22)
 print("<chio_core_types::PublicKey as core::cmp::PartialEq>::eq /* _RNvPublicKeyEq */")
 print("chio_core_types::PublicKey::to_hex /* _RNvPublicKeyHex */")
 sys.exit(0)
if "--cbmc-args" in args:
 delimiter=args.index("--cbmc-args")
 expected=[]
 if os.environ["KANI_TEST_KEY_EQ"]:
  expected.append("_RNvPublicKeyEq:8")
 if os.environ["KANI_TEST_KEY_HEX"]:
  expected.append("_RNvPublicKeyHex:"+os.environ["KANI_TEST_KEY_HEX"])
 if not expected:
  expected=["memcmp.0:66"]
 overrides=args[delimiter+1:]
 if "--default-unwind" in args or "--export-json" not in args[:delimiter] or len(overrides)!=2 or overrides[0]!="--unwindset" or set(overrides[1].split(","))!=set(expected):
  sys.exit(20)
elif os.environ["KANI_TEST_KEY_EQ"] or os.environ["KANI_TEST_KEY_HEX"]:
 sys.exit(23)
if "--export-json" in args and pathlib.Path(os.environ["KANI_TEST_RESULT"]).exists():
 shutil.copyfile(os.environ["KANI_TEST_RESULT"],args[args.index("--export-json")+1])
sys.exit(int(os.environ["KANI_TEST_EXIT"]))
""")
            cargo.chmod(0o755)
            env = os.environ | {
                "PATH": str(work) + os.pathsep + os.environ["PATH"],
                "KANI_MANIFEST": str(manifest),
                "KANI_TEST_RESULT": str(fixture),
                "KANI_TEST_EXIT": str(cargo_exit),
                "KANI_TEST_KEY_EQ": key_eq or "",
                "KANI_TEST_KEY_HEX": key_hex or "",
                "KANI_PUBLIC_HARNESSES_MANIFEST": str(manifest),
                "KANI_PUBLIC_HARNESSES_SOURCE": str(source),
            }
            runner = (
                "scripts/run-kani-manifest.sh"
                if self.runner_kind == "multi"
                else "scripts/check-kani-public-core.sh"
            )
            return subprocess.run(
                ["bash", str(ROOT / runner), "--lane", "pr"],
                check=False,
                env=env,
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=20,
            )

    def test_reachable_witness_passes(self) -> None:
        observed = self.run_proof(result())
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)

    def test_unknown_configuration_keys_refuse(self) -> None:
        for extra in ("unknown_profile = 17\n", "unknown_profile = [1, 2, 3]\n"):
            with self.subTest(extra=extra):
                observed = self.run_proof(result(), config_extra=extra)
                self.assertNotEqual(observed.returncode, 0)

    def test_successful_exit_cannot_hide_unreachable_witness(self) -> None:
        for status in (
            "Unreachable",
            "Unsatisfiable",
            "Undetermined",
            "Success",
            "Failure",
        ):
            with self.subTest(status=status):
                document = result()
                document["verification_results"]["results"][0]["checks"][0][
                    "status"
                ] = status
                observed = self.run_proof(document)
                self.assertNotEqual(
                    observed.returncode, 0, observed.stdout + observed.stderr
                )

    def test_missing_or_malformed_result_refuses(self) -> None:
        for document in (
            None,
            "",
            "{}",
            "not json",
            '{"verification_results":{},"verification_results":{}}',
        ):
            with self.subTest(document=document):
                self.assertNotEqual(self.run_proof(document).returncode, 0)

    def test_result_must_bind_exactly_one_harness_and_witness(self) -> None:
        mutations = []
        d = result()
        d["verification_results"]["results"][0]["harness_id"] = "wrong"
        mutations.append(d)
        d = result()
        d["verification_results"]["results"][0]["checks"] = []
        mutations.append(d)
        d = result()
        d["verification_results"]["results"][0]["checks"] *= 2
        mutations.append(d)
        d = result()
        d["verification_results"]["results"][0]["checks"][0]["function"] = "wrong"
        mutations.append(d)
        d = result()
        d["verification_results"]["results"][0]["checks"][0]["description"] = "wrong"
        mutations.append(d)
        d = result()
        d["verification_results"]["results"] *= 2
        mutations.append(d)
        for field, value in (
            ("executed", 0),
            ("total_harnesses", 0),
            ("failed", 1),
            ("successful", False),
            ("status", "Partial"),
        ):
            d = result()
            d["verification_results"]["summary"][field] = value
            mutations.append(d)
        for d in mutations:
            with self.subTest(document=d):
                self.assertNotEqual(self.run_proof(d).returncode, 0)

    def test_other_checks_cannot_hide_a_failure(self) -> None:
        for status in ("Failure", "Undetermined", "Error", "Satisfied", "unknown"):
            with self.subTest(status=status):
                document = result()
                document["verification_results"]["results"][0]["checks"].append(
                    {
                        "id": 2,
                        "function": HARNESS,
                        "status": status,
                        "description": "assertion",
                        "category": "assertion",
                    }
                )
                self.assertNotEqual(self.run_proof(document).returncode, 0)

    def test_memcmp_override_keeps_export_flags_with_kani(self) -> None:
        observed = self.run_proof(result(), memcmp="66")
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)

    def test_public_key_recursion_bound_is_discovered_for_exact_harness(self) -> None:
        observed = self.run_proof(result(), key_eq="8")
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)

    def test_invalid_public_key_bounds_refuse(self) -> None:
        for bound in ("0", "-1", "true", '"8"', "4294967296"):
            with self.subTest(bound=bound):
                self.assertNotEqual(
                    self.run_proof(result(), key_eq=bound).returncode, 0
                )
        self.assertNotEqual(
            self.run_proof(result(), key_eq="8", require_cover="false").returncode, 0
        )
        self.assertNotEqual(
            self.run_proof(result(), key_eq="8", memcmp="66").returncode, 0
        )

    def test_invalid_memcmp_overrides_refuse(self) -> None:
        for bound in ("0", "-1", "true", '"66"', "4294967296"):
            with self.subTest(bound=bound):
                self.assertNotEqual(
                    self.run_proof(result(), memcmp=bound).returncode, 0
                )
        self.assertNotEqual(
            self.run_proof(result(), memcmp="66", require_cover="false").returncode, 0
        )

    def test_cover_requires_complete_unwinding_checks(self) -> None:
        self.assertNotEqual(self.run_proof(result(), unwinding="false").returncode, 0)

    def test_cover_requirement_must_be_boolean(self) -> None:
        self.assertNotEqual(
            self.run_proof(result(), require_cover='"true"').returncode, 0
        )

    def test_underlying_kani_failure_is_preserved(self) -> None:
        self.assertEqual(self.run_proof(result(), cargo_exit=17).returncode, 17)


class CoreReachabilityTests(ReachabilityTests):
    runner_kind = "core"


class HexProfileTests(unittest.TestCase):
    def test_checked_leaf_hex_bound_accepts_zero(self) -> None:
        observed = ReachabilityTests().run_proof(result(), key_hex="0")
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)

    def test_key_hex_bound_uses_fresh_function_identifier(self) -> None:
        observed = ReachabilityTests().run_proof(result(), key_hex="1")
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)

    def test_invalid_or_conflicting_hex_profiles_refuse(self) -> None:
        run = ReachabilityTests().run_proof
        for bound in ("-1", "true", '"1"', "4294967296"):
            with self.subTest(bound=bound):
                self.assertNotEqual(run(result(), key_hex=bound).returncode, 0)
        for extra in ({"key_eq": "8"}, {"memcmp": "66"}, {"require_cover": "false"}):
            with self.subTest(extra=extra):
                self.assertNotEqual(run(result(), key_hex="1", **extra).returncode, 0)


class WorkflowScopeTests(unittest.TestCase):
    def test_shared_runner_changes_select_both_proof_lanes_and_metadata(self) -> None:
        workflow = (ROOT / ".github/workflows/formal-pr-smoke.yml").read_text()
        block = (
            "          set_output() {"
            + workflow.split("          set_output() {", 1)[1]
        )
        script = textwrap.dedent(block.split("\n\n  fuzz-corpus-smoke-pr:", 1)[0])
        paths = (
            "scripts/check-kani-cover.py",
            "scripts/check-kani-function-bound.py",
            "scripts/run-kani-with-cover.sh",
            "scripts/check-kani-public-harnesses.py",
            "scripts/tests/check-kani-public-harnesses.test.py",
            "scripts/tests/run-kani-reachability.test.py",
            "scripts/tests/run-kani-function-bound.test.py",
        )
        with tempfile.TemporaryDirectory(prefix="chio-kani-scope-") as raw:
            work = Path(raw)
            changed, output = work / "changed", work / "output"
            for path in (*paths, "docs/unrelated.md"):
                with self.subTest(path=path):
                    changed.write_text(path + "\n")
                    output.write_text("")
                    completed = subprocess.run(
                        ["bash", "-euc", 'changed="$KANI_TEST_CHANGED"\n' + script],
                        check=False,
                        env=os.environ
                        | {
                            "KANI_TEST_CHANGED": str(changed),
                            "GITHUB_OUTPUT": str(output),
                        },
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    values = dict(
                        line.split("=", 1) for line in output.read_text().splitlines()
                    )
                    for lane in ("kani_core", "kani_manifest", "metadata"):
                        self.assertEqual(
                            values[lane], "true" if path in paths else "false"
                        )


class P256ManifestProfileTests(unittest.TestCase):
    def invoke(
        self, value="true", hex_bound=None, *, extra="", cover="true", unwinding="true"
    ):
        with tempfile.TemporaryDirectory() as raw:
            manifest = Path(raw) / "manifest.toml"
            hex_line = (
                f"public_key_hex_unwind = {hex_bound}\n"
                if hex_bound is not None
                else ""
            )
            manifest.write_text(f"""schema = "chio.kani.multi-crate.v1"
[[harness]]
crate = "chio-attest-verify"
harness = "public_expect_report_data_determinism_and_binding"
default_unwind = 136
timeout_secs = 1800
lane = "pr"
features = ["kani"]
unwinding_checks = {unwinding}
require_cover = {cover}
{hex_line}p256_encoder_bounds = {value}
{extra}
""")
            return subprocess.run(
                ["bash", str(ROOT / "scripts/run-kani-manifest.sh"), "--dry-run"],
                env=os.environ | {"KANI_MANIFEST": str(manifest)},
                text=True,
                capture_output=True,
                check=False,
            )

    def test_checked_standalone_profile_is_forwarded(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--p256-encoder-bounds --", result.stdout)
        self.assertNotIn("--public-key-hex-unwind", result.stdout)
        self.assertNotIn("--no-unwinding-checks", result.stdout)
        self.assertNotIn("--default-unwind", result.stdout)

    def test_malformed_profile_is_refused(self):
        for value in ("1", '"true"', "[]"):
            with self.subTest(value=value):
                self.assertNotEqual(self.invoke(value).returncode, 0)

    def test_stale_hex_other_overrides_or_disabled_checks_are_refused(self):
        for kwargs in (
            {"hex_bound": "0"},
            {"hex_bound": "1"},
            {"extra": "public_key_eq_unwind = 8"},
            {"extra": "memcmp_unwind = 136"},
            {"cover": "false"},
            {"unwinding": "false"},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertNotEqual(self.invoke(**kwargs).returncode, 0)


if __name__ == "__main__":
    unittest.main()
