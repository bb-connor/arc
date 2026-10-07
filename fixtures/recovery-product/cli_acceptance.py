"""Exercise the actual CLI across a private tunnel to the native Linux fixture."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import time
from qualification_runtime import require


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh-config", type=Path, required=True)
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--operator-key", required=True,
                        help="independently pinned current operator Ed25519 public key, as lowercase hex")
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{64}",args.operator_key) is not None,"cli_operator_key")
    args.evidence.mkdir(parents=True, exist_ok=True)
    config = str(args.ssh_config.resolve())
    ssh = ["ssh", "-F", config, "recovery-qualification"]
    guest = "/tmp/recovery-cli-acceptance-" + str(int(time.time()))
    checkout = PurePosixPath(args.checkout)
    require(checkout.is_absolute() and str(checkout) == args.checkout and str(checkout) != "/"
            and ".." not in checkout.parts and all(ord(character) >= 32 and ord(character) != 127
                                                  for character in args.checkout),"cli_native_checkout")
    subprocess.run(ssh + [f"mkdir -m 700 {guest}"], check=True, timeout=30)
    environment = (
        'env -i PATH="$PATH" HOME="$HOME" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" '
        'RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" TMPDIR="${TMPDIR:-/tmp}" '
        "RUSTUP_TOOLCHAIN=1.94.1-x86_64-unknown-linux-gnu "
        "CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=8 "
        "CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 "
        "CARGO_TARGET_DIR=target/recovery-linux/host "
        f"CHIO_RECOVERY_CLI_EXCHANGE={guest}"
    )
    log = (args.evidence / "native-host.log").open("wb")
    host = subprocess.Popen(ssh + [
        f"cd {shlex.quote(args.checkout)} && exec {environment} "
        "cargo test --offline --locked -p chio-control-plane --lib "
        "setup_cli_qualification_host -- --ignored "
        "--nocapture --test-threads=1"
    ], stdout=log, stderr=subprocess.STDOUT)
    tunnel = None

    def wait_file(name: str) -> None:
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            if host.poll() is not None:
                raise RuntimeError("native CLI host terminated")
            if subprocess.run(ssh + [f"test -s {guest}/{name}"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
                return
            time.sleep(0.25)
        raise TimeoutError("native CLI host phase deadline")

    def copy(name: str) -> Path:
        path = args.evidence / name
        subprocess.run(["scp", "-F", config, f"recovery-qualification:{guest}/{name}", str(path)],
                       check=True, timeout=30, stdout=subprocess.DEVNULL)
        os.chmod(path, 0o600)
        return path

    def invoke(action: str, extra: list[str]) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run([
            str(args.cli.resolve()), "recovery", "setup", action,
            "--endpoint", "http://127.0.0.1:20266", "--capability",
            str(args.evidence / "capability.json"), *extra, "--operator-key", args.operator_key,
        ], capture_output=True, timeout=130)
        (args.evidence / (action + "-" + str(len(events)) + ".stderr")).write_bytes(result.stderr)
        events.append({"action": action, "exit_code": result.returncode})
        return result

    events: list[dict[str, object]] = []
    try:
        wait_file("first-ready")
        copy("capability.json")
        workflow = json.loads(copy("workflow.json").read_bytes())
        tunnel = subprocess.Popen([
            "ssh", "-F", config, "-o", "ExitOnForwardFailure=yes", "-N",
            "-L", "127.0.0.1:20266:127.0.0.1:20095", "recovery-qualification",
        ], stdout=subprocess.DEVNULL, stderr=log)
        time.sleep(0.5)
        if tunnel.poll() is not None:
            raise RuntimeError("private CLI tunnel failed")
        probe = invoke("probe", ["--workflow-id", workflow])
        if probe.returncode:
            raise RuntimeError("native CLI probe refused; retained stderr")
        proof = args.evidence / "probe.json"
        proof.write_bytes(probe.stdout)
        os.chmod(proof, 0o600)
        same_writer = invoke("qualify", ["--probe", str(proof)])
        if same_writer.returncode == 0 or b"recovery.restart_required" not in same_writer.stderr:
            raise AssertionError("same-writer qualification did not refuse visibly")
        subprocess.run(ssh + [f"touch {guest}/restart"], check=True, timeout=10)
        events.append({"action": "operator_writer_restart", "exit_code": 0})
        wait_file("second-ready")
        copy("capability.json")
        report = invoke("qualify", ["--probe", str(proof)])
        if report.returncode:
            raise RuntimeError("fresh-writer CLI qualification refused; retained stderr")
        (args.evidence / "report.json").write_bytes(report.stdout)
        subprocess.run(ssh + [f"touch {guest}/finish"], check=True, timeout=10)
        if host.wait(timeout=90):
            raise RuntimeError("native host evidence assertions failed")
        native = json.loads(copy("native-evidence.json").read_bytes())
        require(type(native.get("effects")) is int and native["effects"] == 1,
                "cli_native_effect_count")
        require(native.get("report") == json.loads(report.stdout), "cli_native_report")
        (args.evidence / "result.json").write_text(json.dumps({
            "passed": True, "operator_actions": events, "effects": native["effects"],
            "tree_calls": native["tree_calls"], "host": "native fixture through configured private SSH",
        }, indent=2) + "\n")
        print("CLI native Linux acceptance passed: one effect, identical custody, fresh writer")
    finally:
        if tunnel is not None:
            tunnel.terminate()
            tunnel.wait(timeout=10)
        if host.poll() is None:
            host.terminate()
            host.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
