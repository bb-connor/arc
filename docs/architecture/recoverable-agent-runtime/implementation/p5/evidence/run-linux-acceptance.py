#!/usr/bin/env python3
"""Required real Linux acceptance. Cross compilation cannot satisfy this gate."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import time
from inventory import source_binding

ROOT = Path(__file__).resolve().parents[6]
EVIDENCE = Path(__file__).resolve().parent
TARGET = ROOT / "target/recovery-p5-linux"
MODES = ["error", "log", "progress", "stream", "file", "callback", "wrong-predicate", "overflow", "hang"]
TESTS = [
    "p5_linux_fixed_environment_rejects_parent_controlled_channels",
    "p5_linux_unknown_input_provenance_withholds_a_correct_projection",
    "p5_linux_useful_decision_exact_authority_and_parent_join_before_first_byte",
    "p5_linux_channel_canaries_never_reach_parent_or_bypass_projection",
    "p5_linux_duplicate_launch_and_cancel_preserve_the_observation_and_consumed_slot",
    "p5_linux_launch_cutpoints_never_duplicate_measurement_or_reset_observation",
    "p5_linux_return_cutpoints_reopen_the_native_writer_without_second_disclosure",
    "p5_linux_valid_signatures_cannot_authorize_cross_parent_epoch_or_stale_returns",
    "p5_linux_absolute_deadline_kills_a_held_handle_without_parent_io",
    "p5_linux_parent_cancellation_withholds_returns_before_and_after_native_join",
]

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    # Retained executables must not be group-writable, including on hosts whose
    # interactive Cargo build otherwise inherits umask 002.
    os.umask(0o022)
    started = time.time()
    log = EVIDENCE / "linux-acceptance.log"
    result = {"id": "linux-acceptance", "actual_command": ["python3", str(Path(__file__).relative_to(ROOT))],
              "cwd": ".", "required_for_phase_exit": True, "required_for_local_phase_acceptance": False,
              "host": {"system": platform.system(), "machine": platform.machine()},
              "started_unix_seconds": int(started), "status": "failed", "exit_code": 1}
    images = []
    result["source_binding"] = source_binding()
    def run(command, environment, stream):
        stream.write((json.dumps({"command": command}) + "\n").encode()); stream.flush()
        subprocess.run(command, cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT, check=True)
    try:
        with log.open("wb") as stream:
            if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
                result.update(status="blocked", exit_code=64,
                    reason="Real Linux x86_64 is required; this host cannot prove cage enforcement")
                stream.write((result["reason"] + "\n").encode())
                return_code = 64
            else:
                for tool in ["cargo", "cc", "readelf", "sha256sum"]:
                    if shutil.which(tool) is None:
                        raise RuntimeError("required Linux tool absent: " + tool)
                result["kernel"] = platform.release()
                result["toolchain"] = {
                    name: subprocess.check_output(command, text=True).strip()
                    for name, command in {
                        "rustc": ["rustc", "--version", "--verbose"],
                        "cargo": ["cargo", "--version"],
                        "cc": ["cc", "--version"],
                        "readelf": ["readelf", "--version"],
                    }.items()
                }
                result["build_profile"] = {
                    name: os.environ.get(name, "default")
                    for name in ["CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"]
                }
                challenge = secrets.token_hex(32)
                result["cage_challenge"] = challenge
                environment = {**os.environ, "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
                    "TMPDIR": str(Path(os.environ.get("TMPDIR", "/tmp")).resolve()),
                    "CHIO_CAGE_EVIDENCE_CHALLENGE": challenge,
                    "CARGO_TARGET_DIR": str(TARGET / "cage-lab")}
                run(["bash", "crates/security/chio-cage/scripts/check-linux-enforcement.sh"], environment, stream)
                static = TARGET / "static"
                environment["CARGO_TARGET_DIR"] = str(static)
                build = ["cargo", "build", "--offline", "--locked", "--target", "x86_64-unknown-linux-musl", "-p", "chio-cage"]
                run([*build, "--bin", "chio-cage-init", "--bin", "chio-confined-reader"], environment, stream)
                binaries = static / "x86_64-unknown-linux-musl/debug"
                canaries = TARGET / "images"
                canaries.mkdir(parents=True, exist_ok=True)
                for mode in MODES:
                    run([*build, "--example", "confined-return-canary"], {**environment, "CHIO_P5_CANARY_MODE": mode}, stream)
                    image = canaries / mode
                    shutil.copyfile(binaries / "examples/confined-return-canary", image)
                    image.chmod(0o755)
                for image in [binaries / "chio-cage-init", binaries / "chio-confined-reader", *[canaries / m for m in MODES]]:
                    header = subprocess.check_output(["readelf", "-hW", str(image)], text=True)
                    program = subprocess.check_output(["readelf", "-lW", str(image)], text=True)
                    dynamic = subprocess.check_output(["readelf", "-dW", str(image)], text=True)
                    if not re.search(r"Type:\s+DYN\b", header) or re.search(r"\bINTERP\b", program) or re.search(r"\(NEEDED\)", dynamic):
                        raise RuntimeError("image is not an interpreter-free static PIE: " + str(image))
                    images.append({"path": str(image.relative_to(ROOT)), "sha256": digest(image)})
                environment.update(CHIO_CAGE_TEST_HELPER=str(binaries / "chio-cage-init"),
                    CHIO_P5_READER=str(binaries / "chio-confined-reader"), CHIO_P5_CANARY_DIR=str(canaries))
                # Use the normal target for the host acceptance executable.
                environment["CARGO_TARGET_DIR"] = str(TARGET / "host")
                tests = ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", "p5_linux_", "--"]
                inventory = subprocess.check_output([*tests, "--list"], cwd=ROOT, env=environment, text=True)
                observed = [line.split(": test")[0].rsplit("::", 1)[-1] for line in inventory.splitlines() if line.endswith(": test")]
                if sorted(observed) != sorted(TESTS):
                    raise RuntimeError("required P5 Linux test inventory differs")
                stream.write(inventory.encode()); stream.flush()
                run([*tests, "--test-threads=1"], environment, stream)
                result.update(status="passed", exit_code=0, linux_tests=len(TESTS), measured_images=images)
                return_code = 0
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        result["reason"] = str(error)
        with log.open("ab") as stream:
            stream.write((str(error) + "\n").encode())
        return_code = 1
    result.update(duration_seconds=round(time.time()-started, 3), log="evidence/"+log.name, log_sha256=digest(log))
    if source_binding()!=result["source_binding"]:
        result.update(status="failed",exit_code=1,reason="source changed during Linux acceptance")
        return_code=1
    (EVIDENCE / "linux-acceptance.result.json").write_text(json.dumps(result, indent=2)+"\n")
    print("P5 Linux acceptance:", result["status"], result.get("reason", ""))
    return return_code

if __name__ == "__main__":
    raise SystemExit(main())
