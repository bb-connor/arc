"""Exercise an existing Python source repository through the installed native tool."""

import argparse
import contextlib
import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_mini_swe.repository_archive import git
from chio_mini_swe.repository_store import Workspace
from chio_process import ProcessClient
from chio_process.launch import provision_native_demo
from qualify_repository import command


@contextlib.contextmanager
def serving(binary, root):
    with (root / "host.log").open("a") as log:
        process = subprocess.Popen(
            [
                str(binary),
                "process",
                "serve",
                "--state",
                str(root / "host"),
                "--socket",
                str(root / "worker.sock"),
            ],
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
        try:
            assert select.select([process.stdout], [], [], 60)[0]
            assert json.loads(process.stdout.readline())["ready"]
            yield
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise
            process.stdout.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="chio-public-repository-"))
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.repository.resolve(strict=True)
    assert (source / "src").is_dir() and (source / "README.md").is_file()
    source_state = git("status", "--porcelain=v1", cwd=source)
    source_hash = hashlib.sha256(
        git("archive", "--format=tar", args.revision, cwd=source)
    ).hexdigest()
    binary = root / "chio"
    shutil.copyfile(args.chio.resolve(strict=True), binary)
    binary.chmod(0o700)
    entrypoint = Path(sys.executable).parent / "chio-mini-swe-repository"
    image = json.loads(args.worker_image_file.read_text())
    helper = command(
        "/usr/bin/docker",
        "--host",
        "unix:///var/run/docker.sock",
        "image",
        "inspect",
        image["base"],
        "--format",
        "{{.Id}}",
    ).strip()
    initialized = json.loads(
        command(
            entrypoint,
            "init",
            "--repository",
            source,
            "--revision",
            args.revision,
            "--state",
            root / "repository",
            "--image",
            image["execution_image"],
            "--helper-image",
            helper,
            "--timeout-seconds",
            "90",
            cwd=root,
        )
    )
    server = provision_native_demo(
        binary,
        "sandbox",
        [str(entrypoint), "serve", "--state", str(root / "repository")],
        root / "launch",
        root,
    )
    server["request_timeout_seconds"] = initialized["timeout_seconds"] + 120
    (root / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: sandbox
        tool: execute
        operations: [invoke, delegate]
        ttl: 3600
""")
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(root / "policy.yaml"),
        "servers": [server],
        "limits": {"max_processes": 2, "max_depth": 1, "max_calls": 8},
        "children": [
            {
                "id": "coder",
                "parent": "root",
                "budget_share_bps": 9000,
                "tools": [{"server_id": "sandbox", "tool_name": "execute"}],
            }
        ],
    }
    (root / "config.json").write_text(json.dumps(config))
    host = json.loads(
        command(
            binary,
            "process",
            "init",
            "--config",
            root / "config.json",
            "--state",
            root / "host",
            cwd=root,
        )
    )
    command(
        binary,
        "process",
        "credential",
        "--state",
        root / "host",
        "--process",
        "coder",
        "--socket",
        root / "worker.sock",
        "--out",
        root / "connection.json",
        cwd=root,
    )
    connection = json.loads((root / "connection.json").read_text())
    client = ProcessClient(connection["socket_path"], connection["credential"], timeout=240)
    compile_arguments = {
        "command": "sleep 65; python -m compileall -q src && git diff --exit-code "
        "&& python -c \"print('x'*500000)\""
    }
    patch_arguments = {
        "command": "printf '\\nChio repository execution qualification.\\n' >> README.md; "
        'git diff --check && python -c "print(chr(0)*79000)"'
    }
    print("Private public-repository qualification state: " + str(root), flush=True)
    try:
        with serving(binary, root):
            first = client.invoke("compile-source", "sandbox", "execute", compile_arguments)
            assert first["verdict"] == "allow" and first["terminal_state"]["state"] == "completed"
            assert first["output"]["value"]["structuredContent"]["returncode"] == 0
            assert first["output"]["value"]["structuredContent"]["output"] == "x" * 500000 + "\n"
        with serving(binary, root):
            replay = client.invoke("compile-source", "sandbox", "execute", compile_arguments)
            assert replay == first
            second = client.invoke("edit-readme", "sandbox", "execute", patch_arguments)
            assert second["verdict"] == "allow" and second["terminal_state"]["state"] == "completed"
            assert second["output"]["value"]["structuredContent"]["returncode"] == 0
            assert second["output"]["value"]["structuredContent"]["output"] == "\0" * 79000 + "\n"
        (root / "receipts.ndjson").write_text(
            first["receipt_json"] + "\n" + second["receipt_json"] + "\n"
        )
        (root / "kernel.pub").write_text(host["kernel_key"])
        verified = json.loads(
            command(
                entrypoint,
                "verify",
                "--state",
                root / "repository",
                "--chio",
                binary,
                "--receipts",
                root / "receipts.ndjson",
                "--kernel-key",
                root / "kernel.pub",
                "--server-id",
                "sandbox",
                "--out",
                args.output / "repository",
                cwd=root,
            )
        )
        assert verified["verified_transitions"] == 2 and not verified["interrupted"]
        run = subprocess.run(
            [
                "/usr/bin/git",
                "apply",
                "--check",
                str((args.output / "repository/changes.patch").resolve()),
            ],
            cwd=source,
            capture_output=True,
            timeout=30,
        )
        assert run.returncode == 0
        assert git("status", "--porcelain=v1", cwd=source) == source_state
        assert (
            hashlib.sha256(git("archive", "--format=tar", args.revision, cwd=source)).hexdigest()
            == source_hash
        )
        report = {
            "private_state": str(root),
            "source_commit": initialized["source_commit"],
            "source_archive_sha256": source_hash,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "execution_image": image["execution_image"],
            "source_compiles": True,
            "command_exceeds_default_host_timeout": True,
            "large_ascii_and_escaped_output_verified": True,
            "host_restart_replay": True,
            "verified_transitions": 2,
            "patch_applies_to_source": True,
            "source_unchanged": True,
            "provider": "none; explicit qualification commands",
        }
        (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    finally:
        with Workspace(root / "repository") as workspace:
            workspace.recover()


if __name__ == "__main__":
    main()
