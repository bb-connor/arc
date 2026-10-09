#!/usr/bin/env python3
"""Exercise fresh function discovery and the subsequent strict cover gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/run-kani-with-cover.sh"
SELECTOR = ROOT / "scripts/check-kani-function-bound.py"
HARNESS = "kani_public_harnesses::proof_target"
FUNCTION = "<chio_core_types::PublicKey as core::cmp::PartialEq>::eq"
SYMBOL = "_RNvXs0_NtCsFresh_15chio_core_types6crypto9PublicKey9PartialEq2eq"
LISTING = f"CBMC 6.11.0\n\n{FUNCTION} /* {SYMBOL} */\n"
HEX_FUNCTION = "chio_core_types::PublicKey::to_hex"
HEX_SYMBOL = "_RNvMs1_NtCsFresh_15chio_core_types6crypto9PublicKey6to_hex"
HEX_LISTING = f"{HEX_FUNCTION} /* {HEX_SYMBOL} */\n"
ENCODER_FUNCTION = "chio_core_types::crypto::encoding::fill_prefixed_hex"
ENCODER_SYMBOL = "_RNvNtNtCsFresh_15chio_core_types6crypto8encoding17fill_prefixed_hex"
ENCODER_LOOPS = f"""Loop {ENCODER_SYMBOL}.9:
  file crates/core/chio-core-types/src/crypto/encoding.rs line 70 column 5 function {ENCODER_FUNCTION}

Loop {ENCODER_SYMBOL}.2:
  file crates/core/chio-core-types/src/crypto/encoding.rs line 67 column 5 function {ENCODER_FUNCTION}

"""
ENCODER_BOUNDS = f"{ENCODER_SYMBOL}.2:6,{ENCODER_SYMBOL}.9:66"
SHA_FUNCTION = "sha2::sha256::soft::compress"
SHA_SYMBOL = "_RNvNtNtCsFresh_4sha26sha2564soft8compress"
SHA_SOURCE = "/portable/registry/src/sha2-0.10.9/src/sha256/soft.rs"
SHA_LOOPS = f"""Loop {SHA_SYMBOL}.7:
  file {SHA_SOURCE} line 212 column 9 function {SHA_FUNCTION}

Loop {SHA_SYMBOL}.3:
  file {SHA_SOURCE} line 211 column 5 function {SHA_FUNCTION}

"""
SHA_BOUNDS = f"{SHA_SYMBOL}.3:3,{SHA_SYMBOL}.7:17"
PAD_FUNCTION = (
    "sha2::digest::block_buffer::BlockBuffer::<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UInt<"
    "sha2::digest::typenum::UTerm, sha2::digest::typenum::B1>"
    ", sha2::digest::typenum::B0>"
    ", sha2::digest::typenum::B0>"
    ", sha2::digest::typenum::B0>"
    ", sha2::digest::typenum::B0>"
    ", sha2::digest::typenum::B0>"
    ", sha2::digest::typenum::B0>"
    ", sha2::digest::block_buffer::Eager>::digest_pad::<"
    "{closure@<sha2::Sha256VarCore as sha2::digest::core_api::"
    "VariableOutputCore>::finalize_variable_core::{closure#0}}>"
)
PAD_SYMBOL = "_RINvCsFresh_12block_buffer11BlockBuffer10digest_pad6Sha256"
PAD_SOURCE = "/portable/registry/src/block-buffer-0.10.4/src/lib.rs"
PAD_LOOPS = f"""Loop {PAD_SYMBOL}.5:
  file {PAD_SOURCE} line 301 column 9 function {PAD_FUNCTION}

"""
PAD_BOUNDS = f"{PAD_SYMBOL}.5:65"
P256_LOOPS = ENCODER_LOOPS + SHA_LOOPS + PAD_LOOPS
P256_BOUNDS = f"{ENCODER_BOUNDS},{SHA_BOUNDS},{PAD_BOUNDS}"


def result(cover_status: str = "Satisfied") -> dict:
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
                            "status": cover_status,
                            "description": "proof_target",
                            "category": "cover",
                        },
                        {
                            "id": 2,
                            "function": HARNESS,
                            "status": "Success",
                            "description": "recursion unwinding assertion",
                            "category": "unwind",
                        },
                    ],
                }
            ],
        }
    }


class FunctionBoundTests(unittest.TestCase):
    def run_wrapper(
        self,
        *,
        listing: str = LISTING,
        diagnostic_exit: int = 0,
        proof_exit: int = 0,
        bound: str | None = "8",
        extra: tuple[str, ...] = (),
        document: dict | None = None,
        separator: bool = True,
        profile: str = "eq",
        profile_options: tuple[str, ...] | None = None,
        encoder_loops: str = P256_LOOPS,
        loop_exit: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        with tempfile.TemporaryDirectory(prefix="chio-kani-function-bound-") as raw:
            work = Path(raw)
            tool = work / "fake-kani"
            calls = work / "calls.jsonl"
            fixture = work / "proof.json"
            fixture.write_text(json.dumps(result() if document is None else document))
            tool.write_text("""#!/usr/bin/env python3
import json,os,pathlib,shutil,sys
args=sys.argv[1:]
with pathlib.Path(os.environ['KANI_TEST_CALLS']).open('a') as stream:
 stream.write(json.dumps(args)+'\\n')
if '--list-goto-functions' in args:
 print(os.environ['KANI_TEST_LISTING'])
 sys.exit(int(os.environ['KANI_TEST_DIAGNOSTIC_EXIT']))
if '--show-loops' in args:
 print(os.environ['KANI_TEST_ENCODER_LOOPS'])
 sys.exit(int(os.environ['KANI_TEST_LOOP_EXIT']))
if '--export-json' in args:
 shutil.copyfile(os.environ['KANI_TEST_RESULT'],args[args.index('--export-json')+1])
sys.exit(int(os.environ['KANI_TEST_PROOF_EXIT']))
""")
            tool.chmod(0o755)
            command = ["bash", str(WRAPPER), HARNESS]
            options = []
            if profile_options is not None:
                options.extend(profile_options)
            else:
                if bound is not None:
                    options.extend([f"--public-key-{profile}-unwind", bound])
            if options:
                command.extend(options)
                if separator:
                    command.append("--")
            command.extend(
                [
                    str(tool),
                    "-p",
                    "fake-crate",
                    "--lib",
                    "--harness",
                    HARNESS,
                    "--exact",
                ]
            )
            command.extend(extra)
            env = os.environ | {
                "KANI_TEST_CALLS": str(calls),
                "KANI_TEST_LISTING": listing,
                "KANI_TEST_DIAGNOSTIC_EXIT": str(diagnostic_exit),
                "KANI_TEST_PROOF_EXIT": str(proof_exit),
                "KANI_TEST_RESULT": str(fixture),
                "KANI_TEST_ENCODER_LOOPS": encoder_loops,
                "KANI_TEST_LOOP_EXIT": str(loop_exit),
            }
            observed = subprocess.run(
                command,
                check=False,
                env=env,
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=20,
            )
            recorded = (
                [json.loads(line) for line in calls.read_text().splitlines()]
                if calls.exists()
                else []
            )
            return observed, recorded

    def test_standalone_p256_profile_uses_only_fresh_complete_loop_ids(self) -> None:
        observed, calls = self.run_wrapper(
            listing="",
            diagnostic_exit=29,
            profile_options=("--p256-encoder-bounds",),
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][-1], "--show-loops")
        self.assertEqual(calls[-1][-2:], ["--unwindset", P256_BOUNDS])
        self.assertEqual(calls[-1].count("--cbmc-args"), 1)
        self.assertLess(
            calls[-1].index("--export-json"), calls[-1].index("--cbmc-args")
        )
        for call in calls:
            self.assertNotIn("--list-goto-functions", call)
            self.assertNotIn("--default-unwind", call)
            self.assertNotIn("--no-unwinding-checks", call)
            self.assertIn("--exact", call)

    def test_standalone_p256_profile_preserves_failures_and_requires_complete_loops(
        self,
    ) -> None:
        for loops, loop_exit, proof_exit, document, exit_code, count in (
            (P256_LOOPS, 23, 0, result(), 23, 1),
            (P256_LOOPS, 0, 19, result(), 19, 2),
            (P256_LOOPS, 0, 0, result("Unreachable"), 1, 2),
            (ENCODER_LOOPS + SHA_LOOPS, 0, 0, result(), 1, 1),
        ):
            with self.subTest(loop_exit=loop_exit, proof_exit=proof_exit, loops=loops):
                observed, calls = self.run_wrapper(
                    profile_options=("--p256-encoder-bounds",),
                    encoder_loops=loops,
                    loop_exit=loop_exit,
                    proof_exit=proof_exit,
                    document=document,
                )
                self.assertEqual(observed.returncode, exit_code, observed.stderr)
                self.assertEqual(len(calls), count)

    def test_standalone_p256_profile_refuses_overrides_before_preparation(self) -> None:
        for extra in (
            ("--default-unwind", "136"),
            ("--cbmc-args", "--unwindset", "other.0:0"),
            ("--no-unwinding-checks",),
            ("--no-unwinding-assertions",),
            ("--export-json", "foreign.json"),
            ("--output-format", "old"),
            ("--",),
        ):
            with self.subTest(extra=extra):
                observed, calls = self.run_wrapper(
                    profile_options=("--p256-encoder-bounds",), extra=extra
                )
                self.assertEqual(observed.returncode, 2, observed.stderr)
                self.assertEqual(calls, [])

    def test_standalone_p256_cover_cannot_hide_failed_checked_obligation(self) -> None:
        document = result()
        check = document["verification_results"]["results"][0]["checks"][1]
        check["description"] = "bounded hex-byte consumer must use P-256"
        check["status"] = "Failure"
        observed, calls = self.run_wrapper(
            profile_options=("--p256-encoder-bounds",), document=document
        )
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_p256_encoder_profile_combines_fresh_hex_and_loop_ids(self) -> None:
        for options in (
            ("--public-key-hex-unwind", "0", "--p256-encoder-bounds"),
            ("--p256-encoder-bounds", "--public-key-hex-unwind", "0"),
        ):
            with self.subTest(options=options):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING, profile_options=options
                )
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(len(calls), 3)
                self.assertEqual(calls[0][-1], "--list-goto-functions")
                self.assertEqual(calls[1][-1], "--show-loops")
                self.assertEqual(
                    calls[-1][-2:], ["--unwindset", f"{HEX_SYMBOL}:0,{P256_BOUNDS}"]
                )
                for call in calls:
                    self.assertNotIn("--default-unwind", call)
                    self.assertNotIn("--no-unwinding-checks", call)
                    self.assertIn("--exact", call)
                self.assertLess(
                    calls[-1].index("--export-json"), calls[-1].index("--cbmc-args")
                )

    def test_p256_encoder_profile_preserves_diagnostic_proof_and_cover_failures(
        self,
    ) -> None:
        options = ("--public-key-hex-unwind", "0", "--p256-encoder-bounds")
        for loop_exit, proof_exit, document, exit_code, count in (
            (23, 0, result(), 23, 2),
            (0, 19, result(), 19, 3),
            (0, 0, result("Unsatisfiable"), 1, 3),
        ):
            with self.subTest(loop_exit=loop_exit, proof_exit=proof_exit):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING,
                    profile_options=options,
                    loop_exit=loop_exit,
                    proof_exit=proof_exit,
                    document=document,
                )
                self.assertEqual(observed.returncode, exit_code, observed.stderr)
                self.assertEqual(len(calls), count)

    def test_p256_encoder_profile_rejects_missing_duplicate_wrong_source_or_unsafe_loops(
        self,
    ) -> None:
        options = ("--public-key-hex-unwind", "0", "--p256-encoder-bounds")
        for listing in (
            "",
            ENCODER_LOOPS.split("Loop " + ENCODER_SYMBOL + ".2:")[0],
            ENCODER_LOOPS + ENCODER_LOOPS,
            ENCODER_LOOPS.replace("line 67", "line 55"),
            ENCODER_LOOPS.replace(
                "crates/core/chio-core-types", "crates/trust/chio-core-types"
            ),
            ENCODER_LOOPS.replace(ENCODER_FUNCTION, "other::fill_prefixed_hex"),
            ENCODER_LOOPS.replace(".2:", ".9:"),
            ENCODER_LOOPS.replace(".2:", ".02:"),
            ENCODER_LOOPS.replace(".2:", ".4294967296:"),
            ENCODER_LOOPS.replace(".2:", ".2,memcmp.0:0:"),
            ENCODER_LOOPS.replace("line 67 column 5", "line unknown column 5"),
            ENCODER_LOOPS.replace(".2:", "OtherEncoder.2:"),
            ENCODER_LOOPS.replace(
                f"line 67 column 5 function {ENCODER_FUNCTION}",
                f"line 67 column 5 function {ENCODER_FUNCTION}\n  file other.rs line unknown function {ENCODER_FUNCTION}",
            ),
            ENCODER_LOOPS
            + f"Loop {ENCODER_SYMBOL}.3:\n  file crates/core/chio-core-types/src/crypto/encoding.rs line 60 function {ENCODER_FUNCTION}\n",
            ENCODER_LOOPS + "Loop ",
        ):
            with self.subTest(listing=listing):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING,
                    profile_options=options,
                    encoder_loops=listing + SHA_LOOPS + PAD_LOOPS,
                )
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(len(calls), 2)

    def test_p256_sha_profile_selects_roles_from_refreshed_ids(self) -> None:
        fresh = "_RNvNtNtCsDifferent_4sha26sha2564soft8compress"
        loops = (
            SHA_LOOPS.replace(SHA_SYMBOL, fresh)
            .replace(".7:", ".29:")
            .replace(".3:", ".1:")
        )
        observed, calls = self.run_wrapper(
            listing=HEX_LISTING,
            profile_options=("--public-key-hex-unwind", "0", "--p256-encoder-bounds"),
            encoder_loops=loops + ENCODER_LOOPS + PAD_LOOPS,
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(
            calls[-1][-2:],
            [
                "--unwindset",
                f"{HEX_SYMBOL}:0,{ENCODER_BOUNDS},{fresh}.1:3,{fresh}.29:17,{PAD_BOUNDS}",
            ],
        )

    def test_p256_sha_profile_requires_sha_even_when_encoder_is_complete(self) -> None:
        observed, calls = self.run_wrapper(
            listing=HEX_LISTING,
            profile_options=("--public-key-hex-unwind", "0", "--p256-encoder-bounds"),
            encoder_loops=ENCODER_LOOPS + PAD_LOOPS,
        )
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_p256_sha_profile_rejects_partial_duplicate_unknown_or_malformed_loops(
        self,
    ) -> None:
        for listing in (
            SHA_LOOPS.split("Loop " + SHA_SYMBOL + ".3:")[0],
            SHA_LOOPS[SHA_LOOPS.index("Loop " + SHA_SYMBOL + ".3:") :],
            SHA_LOOPS + SHA_LOOPS,
            SHA_LOOPS.replace("line 211", "line 210"),
            SHA_LOOPS.replace("sha2-0.10.9", "sha2-0.11.0"),
            SHA_LOOPS.replace("/sha256/soft.rs", "/sha512/soft.rs"),
            SHA_LOOPS.replace(SHA_FUNCTION, "sha2::sha512::soft::compress"),
            SHA_LOOPS.replace(".3:", ".7:"),
            SHA_LOOPS.replace(".3:", ".03:"),
            SHA_LOOPS.replace(".3:", ".4294967296:"),
            SHA_LOOPS.replace(".3:", ".3,memcmp.0:0:"),
            SHA_LOOPS.replace("line 211 column 5", "line unknown column 5"),
            SHA_LOOPS.replace(".3:", ":"),
            SHA_LOOPS.replace(".3:", "OtherSha.3:"),
            SHA_LOOPS.replace(
                f"line 211 column 5 function {SHA_FUNCTION}",
                f"line 211 column 5 function {SHA_FUNCTION}\n  file other.rs line unknown function {SHA_FUNCTION}",
            ),
            SHA_LOOPS
            + f"Loop {SHA_SYMBOL}.8:\n  file {SHA_SOURCE} line 213 function {SHA_FUNCTION}\n",
            SHA_LOOPS.replace(SHA_SYMBOL, ENCODER_SYMBOL),
            SHA_LOOPS + "Loop ",
        ):
            with self.subTest(listing=listing):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING,
                    profile_options=(
                        "--public-key-hex-unwind",
                        "0",
                        "--p256-encoder-bounds",
                    ),
                    encoder_loops=ENCODER_LOOPS + listing + PAD_LOOPS,
                )
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(len(calls), 2)

    def test_p256_sha_loop_unwinding_failure_cannot_hide_behind_cover(self) -> None:
        document = result()
        check = document["verification_results"]["results"][0]["checks"][1]
        check["description"] = "SHA outer block loop unwinding assertion"
        check["status"] = "Failure"
        observed, calls = self.run_wrapper(
            listing=HEX_LISTING,
            profile_options=("--public-key-hex-unwind", "0", "--p256-encoder-bounds"),
            document=document,
        )
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(len(calls), 3)

    def test_p256_pad_profile_selects_universal_u64_bound_from_fresh_id(self) -> None:
        fresh = "_RINvCsDifferent_12block_buffer11BlockBuffer10digest_pad6Sha256"
        loops = PAD_LOOPS.replace(PAD_SYMBOL, fresh).replace(".5:", ".23:")
        observed, calls = self.run_wrapper(
            listing=HEX_LISTING,
            profile_options=("--public-key-hex-unwind", "0", "--p256-encoder-bounds"),
            encoder_loops=loops + SHA_LOOPS + ENCODER_LOOPS,
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(
            calls[-1][-2:],
            [
                "--unwindset",
                f"{HEX_SYMBOL}:0,{ENCODER_BOUNDS},{SHA_BOUNDS},{fresh}.23:65",
            ],
        )

    def test_p256_pad_profile_requires_complete_padding_record(self) -> None:
        observed, calls = self.run_wrapper(
            listing=HEX_LISTING,
            profile_options=("--public-key-hex-unwind", "0", "--p256-encoder-bounds"),
            encoder_loops=ENCODER_LOOPS + SHA_LOOPS,
        )
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_p256_pad_profile_rejects_unknown_instantiation_or_malformed_record(
        self,
    ) -> None:
        u32_function = PAD_FUNCTION.replace(
            "sha2::digest::typenum::UInt<", "", 1
        ).replace(", sha2::digest::typenum::B0>", "", 1)
        for listing in (
            PAD_LOOPS + PAD_LOOPS,
            PAD_LOOPS.replace(PAD_FUNCTION, u32_function),
            PAD_LOOPS.replace("Eager", "Lazy"),
            PAD_LOOPS.replace("Sha256VarCore", "Sha512VarCore"),
            PAD_LOOPS.replace("block-buffer-0.10.4", "block-buffer-0.10.3"),
            PAD_LOOPS.replace("line 301", "line 302"),
            PAD_LOOPS.replace(".5:", ".05:"),
            PAD_LOOPS.replace(".5:", ".4294967296:"),
            PAD_LOOPS.replace(".5:", ".5,memcmp.0:0:"),
            PAD_LOOPS.replace("line 301 column 9", "line unknown column 9"),
            f"Loop {PAD_SYMBOL}.5:\n\n",
            PAD_LOOPS.replace(
                f"function {PAD_FUNCTION}",
                f"function {PAD_FUNCTION}\n  file other.rs line 301 function {PAD_FUNCTION}",
            ),
            PAD_LOOPS.replace(PAD_SYMBOL, SHA_SYMBOL),
            PAD_LOOPS
            + f"Loop {PAD_SYMBOL}.6:\n  file {PAD_SOURCE} line 303 function {PAD_FUNCTION}\n",
        ):
            with self.subTest(listing=listing):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING,
                    profile_options=(
                        "--public-key-hex-unwind",
                        "0",
                        "--p256-encoder-bounds",
                    ),
                    encoder_loops=ENCODER_LOOPS + SHA_LOOPS + listing,
                )
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(len(calls), 2)

    def test_p256_encoder_profile_refuses_eq_and_conflicting_options(
        self,
    ) -> None:
        for options in (
            ("--public-key-eq-unwind", "8", "--p256-encoder-bounds"),
            (
                "--public-key-hex-unwind",
                "0",
                "--p256-encoder-bounds",
                "--p256-encoder-bounds",
            ),
            ("--public-key-hex-unwind", "0", "--p256-encoder-bounds", "6,66"),
        ):
            with self.subTest(options=options):
                observed, calls = self.run_wrapper(profile_options=options)
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(calls, [])
        observed, calls = self.run_wrapper(
            profile_options=("--p256-encoder-bounds",), separator=False
        )
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(calls, [])
        for extra in (
            ("--no-unwinding-checks",),
            ("--default-unwind", "136"),
            ("--cbmc-args", "--unwindset", "other.0:0"),
            ("--p256-encoder-bounds",),
        ):
            observed, calls = self.run_wrapper(
                listing=HEX_LISTING,
                profile_options=(
                    "--public-key-hex-unwind",
                    "0",
                    "--p256-encoder-bounds",
                ),
                extra=extra,
            )
            self.assertNotEqual(observed.returncode, 0)
            self.assertEqual(calls, [])

    def test_p256_loop_selector_refuses_nonregular_oversized_and_ambiguous_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="chio-p256-loop-diagnostic-") as raw:
            work = Path(raw)
            valid = work / "loops.log"
            valid.write_text("Loop unrelated.0:\n\n" + P256_LOOPS)
            observed = subprocess.run(
                [sys.executable, str(SELECTOR), str(valid), "--p256-encoder-bounds"],
                check=False,
                text=True,
                capture_output=True,
                timeout=20,
            )
            self.assertEqual(observed.returncode, 0, observed.stderr)
            self.assertEqual(observed.stdout.strip(), P256_BOUNDS)
            link = work / "link.log"
            link.symlink_to(valid)
            bad_utf8 = work / "bad.log"
            bad_utf8.write_bytes(b"\xff")
            big = work / "big.log"
            with big.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            for path in (work, link, bad_utf8, big, work / "missing.log"):
                invalid = subprocess.run(
                    [sys.executable, str(SELECTOR), str(path), "--p256-encoder-bounds"],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
                self.assertNotEqual(invalid.returncode, 0)
            for extra in (("0",), ("6,66",), ("--function", "public-key-to-hex")):
                invalid = subprocess.run(
                    [
                        sys.executable,
                        str(SELECTOR),
                        str(valid),
                        "--p256-encoder-bounds",
                        *extra,
                    ],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
                self.assertNotEqual(invalid.returncode, 0)

    def test_profile_bounds_and_duplicate_options_refuse_before_preparation(
        self,
    ) -> None:
        for options in (
            ("--public-key-eq-unwind", "1", "--public-key-eq-unwind", "1"),
            ("--public-key-hex-unwind", "0", "--public-key-eq-unwind", "1"),
            ("--public-key-eq-unwind", "0"),
            ("--public-key-hex-unwind", "-1"),
        ):
            with self.subTest(options=options):
                observed, calls = self.run_wrapper(profile_options=options)
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(calls, [])

    def test_hex_recursion_zero_is_accepted_but_equality_zero_is_not(self) -> None:
        observed, calls = self.run_wrapper(
            profile="hex", bound="0", listing=HEX_LISTING
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(calls[-1][-1], f"{HEX_SYMBOL}:0")
        with tempfile.TemporaryDirectory(prefix="chio-kani-zero-bound-") as raw:
            diagnostic = Path(raw) / "functions.log"
            diagnostic.write_text(LISTING + HEX_LISTING)
            for function, expected_exit in (
                ("public-key-to-hex", 0),
                ("public-key-eq", 1),
            ):
                with self.subTest(function=function):
                    observed = subprocess.run(
                        [
                            sys.executable,
                            str(SELECTOR),
                            str(diagnostic),
                            "0",
                            "--function",
                            function,
                        ],
                        check=False,
                        text=True,
                        capture_output=True,
                        timeout=20,
                    )
                    self.assertEqual(
                        observed.returncode, expected_exit, observed.stderr
                    )

    def test_fresh_symbol_bounds_only_recursion_then_requires_cover(self) -> None:
        observed, calls = self.run_wrapper(extra=("--features", "kani"))
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)
        self.assertEqual(len(calls), 2)
        diagnostic, proof = calls
        for arguments in calls:
            self.assertEqual(arguments[arguments.index("--harness") + 1], HARNESS)
            self.assertIn("--exact", arguments)
            self.assertEqual(arguments[arguments.index("--features") + 1], "kani")
            self.assertNotIn("--no-unwinding-checks", arguments)
            self.assertNotIn("--default-unwind", arguments)
            self.assertNotIn("--unwind", arguments)
        self.assertEqual(diagnostic[diagnostic.index("--output-format") + 1], "old")
        self.assertEqual(
            diagnostic[diagnostic.index("--cbmc-args") + 1 :],
            ["--list-goto-functions"],
        )
        self.assertNotIn("--export-json", diagnostic)
        self.assertNotIn("--output-format", proof)
        self.assertLess(proof.index("--export-json"), proof.index("--cbmc-args"))
        self.assertEqual(
            proof[proof.index("--cbmc-args") + 1 :],
            ["--unwindset", f"{SYMBOL}:8"],
        )
        self.assertIn("Kani reachable witness verified", observed.stdout)

    def test_current_symbol_is_selected_instead_of_a_saved_identifier(self) -> None:
        fresh = "_RNvDifferentCompiler9PublicKey9PartialEq2eq"
        observed, calls = self.run_wrapper(listing=f"{FUNCTION} /* {fresh} */\n")
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(calls[-1][-1], f"{fresh}:8")

    def test_hex_profile_selects_hex_function_and_preserves_proof_gate(self) -> None:
        observed, calls = self.run_wrapper(
            listing=LISTING + HEX_LISTING, profile="hex", bound="1"
        )
        self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)
        self.assertEqual(len(calls), 2)
        diagnostic, proof = calls
        self.assertEqual(diagnostic[diagnostic.index("--output-format") + 1], "old")
        self.assertEqual(
            diagnostic[diagnostic.index("--cbmc-args") + 1 :],
            ["--list-goto-functions"],
        )
        self.assertNotIn("--export-json", diagnostic)
        self.assertLess(proof.index("--export-json"), proof.index("--cbmc-args"))
        self.assertEqual(
            proof[proof.index("--cbmc-args") + 1 :],
            ["--unwindset", f"{HEX_SYMBOL}:1"],
        )
        for arguments in calls:
            self.assertIn("--exact", arguments)
            self.assertNotIn("--no-unwinding-checks", arguments)
            self.assertNotIn("--default-unwind", arguments)
            self.assertNotIn("--unwind", arguments)
        self.assertIn("Kani reachable witness verified", observed.stdout)

    def test_selector_has_closed_function_choices_and_defaults_to_equality(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="chio-kani-function-selector-") as raw:
            diagnostic = Path(raw) / "functions.log"
            diagnostic.write_text(LISTING + HEX_LISTING)
            for function, expected in (
                (None, f"{SYMBOL}:1"),
                ("public-key-eq", f"{SYMBOL}:1"),
                ("public-key-to-hex", f"{HEX_SYMBOL}:1"),
                ("arbitrary-function", None),
            ):
                with self.subTest(function=function):
                    command = [sys.executable, str(SELECTOR), str(diagnostic), "1"]
                    if function is not None:
                        command.extend(["--function", function])
                    observed = subprocess.run(
                        command,
                        check=False,
                        text=True,
                        capture_output=True,
                        timeout=20,
                    )
                    if expected is None:
                        self.assertNotEqual(observed.returncode, 0)
                    else:
                        self.assertEqual(observed.returncode, 0, observed.stderr)
                        self.assertEqual(observed.stdout.strip(), expected)

    def test_hex_profile_refuses_missing_duplicate_unavailable_or_unsafe_function(
        self,
    ) -> None:
        for listing in (
            LISTING,
            HEX_LISTING + HEX_LISTING,
            f"{HEX_FUNCTION} /* {HEX_SYMBOL}, body not available */\n",
            f"{HEX_FUNCTION} /* {HEX_SYMBOL},memcmp.0:0 */\n",
        ):
            with self.subTest(listing=listing):
                observed, calls = self.run_wrapper(listing=listing, profile="hex")
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(len(calls), 1)

    def test_hex_profile_preserves_failure_and_still_requires_cover(self) -> None:
        for diagnostic_exit, proof_exit, document, expected_exit, count in (
            (23, 0, result(), 23, 1),
            (0, 19, result(), 19, 2),
            (0, 0, result("Unsatisfiable"), 1, 2),
        ):
            with self.subTest(diagnostic=diagnostic_exit, proof=proof_exit):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING,
                    profile="hex",
                    diagnostic_exit=diagnostic_exit,
                    proof_exit=proof_exit,
                    document=document,
                )
                self.assertEqual(observed.returncode, expected_exit, observed.stderr)
                self.assertEqual(len(calls), count)

    def test_diagnostic_success_cannot_replace_actual_proof_success(self) -> None:
        observed, calls = self.run_wrapper(proof_exit=19)
        self.assertEqual(observed.returncode, 19, observed.stderr)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("Kani reachable witness verified", observed.stdout)

    def test_diagnostic_failure_preserves_exit_and_stops_before_proof(self) -> None:
        observed, calls = self.run_wrapper(diagnostic_exit=23)
        self.assertEqual(observed.returncode, 23, observed.stderr)
        self.assertEqual(len(calls), 1)

    def test_successful_proof_still_requires_reachable_cover(self) -> None:
        observed, calls = self.run_wrapper(document=result("Unsatisfiable"))
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("not reachable", observed.stderr)

    def test_failed_recursion_check_cannot_hide_behind_reachable_cover(self) -> None:
        document = result()
        document["verification_results"]["results"][0]["checks"][1]["status"] = (
            "Failure"
        )
        observed, calls = self.run_wrapper(document=document)
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_missing_duplicate_or_unavailable_function_stops_before_proof(self) -> None:
        listings = (
            "CBMC 6.11.0\n",
            f"{FUNCTION} /* {SYMBOL} */\n{FUNCTION} /* {SYMBOL} */\n",
            f"{FUNCTION} /* {SYMBOL} */\n{FUNCTION} /* _RNvOther */\n",
            f"{FUNCTION} /* {SYMBOL}, body not available */\n",
            f"wrong::{FUNCTION} /* {SYMBOL} */\n",
        )
        for listing in listings:
            with self.subTest(listing=listing):
                observed, calls = self.run_wrapper(listing=listing)
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(len(calls), 1)

    def test_function_identifier_cannot_inject_options_or_other_bounds(self) -> None:
        for symbol in (
            "_RNvEq:0",
            "_RNvEq,memcmp.0:0",
            "_RNvEq.0",
            "--no-unwinding-assertions",
            "_RNvEq;false",
            "_RNvEq space",
            "$(false)",
        ):
            with self.subTest(symbol=symbol):
                observed, calls = self.run_wrapper(
                    listing=f"{FUNCTION} /* {symbol} */\n"
                )
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(len(calls), 1)

    def test_invalid_bound_or_missing_separator_refuses_before_diagnostic(self) -> None:
        for bound in ("0", "-1", "true", "8:0", "4294967296", "99999999999999999999"):
            with self.subTest(bound=bound):
                observed, calls = self.run_wrapper(bound=bound)
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(calls, [])
        observed, calls = self.run_wrapper(separator=False)
        self.assertNotEqual(observed.returncode, 0)
        self.assertEqual(calls, [])

    def test_conflicting_argument_composition_refuses_before_diagnostic(self) -> None:
        for extra in (
            ("--cbmc-args", "--unwindset", "memcmp.0:66"),
            ("--cbmc-args=--unwindset",),
            ("--default-unwind", "66"),
            ("--default-unwind=66",),
            ("--unwind", "66"),
            ("--unwind=66",),
            ("--no-unwinding-checks",),
            ("--output-format", "old"),
            ("--output-format=old",),
            ("--export-json", "caller.json"),
            ("--public-key-eq-unwind", "1"),
            ("--public-key-hex-unwind", "1"),
        ):
            with self.subTest(extra=extra):
                observed, calls = self.run_wrapper(extra=extra)
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(calls, [])

    def test_hex_profile_refuses_conflicting_composition_before_diagnostic(
        self,
    ) -> None:
        for extra in (
            ("--cbmc-args", "--unwindset", "memcmp.0:132"),
            ("--default-unwind", "132"),
            ("--no-unwinding-checks",),
            ("--public-key-eq-unwind", "1"),
        ):
            with self.subTest(extra=extra):
                observed, calls = self.run_wrapper(
                    listing=HEX_LISTING, profile="hex", extra=extra
                )
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(calls, [])

    def test_unprofiled_cbmc_arguments_keep_existing_cover_behavior(self) -> None:
        observed, calls = self.run_wrapper(
            bound=None, extra=("--cbmc-args", "--unwindset", "memcmp.0:66")
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(len(calls), 1)
        proof = calls[0]
        self.assertLess(proof.index("--export-json"), proof.index("--cbmc-args"))
        self.assertEqual(
            proof[proof.index("--cbmc-args") + 1 :],
            ["--unwindset", "memcmp.0:66"],
        )


if __name__ == "__main__":
    unittest.main()
