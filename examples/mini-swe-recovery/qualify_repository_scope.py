"""Run Chio's committed Python SDK tests in a scoped native repository workspace."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE_PATHS = ["sdks/python/chio-process"]


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-repository-scope-"))
    bundle = root / "bundle"
    print("Private scoped repository state: " + str(root), file=sys.stderr, flush=True)
    os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = str(root / "mini-config")
    os.environ["MSWEA_SILENT_STARTUP"] = "1"
    from chio_mini_swe.repository import export
    from chio_mini_swe.repository_archive import entries, git, import_revision
    from chio_mini_swe.repository_proof import verified_receipts, verify
    from chio_mini_swe.repository_review import verify_export
    from chio_mini_swe.repository_store import Workspace, initialize
    from chio_mini_swe.repository_transport import docker
    from chio_process import ProcessClient
    from chio_process.launch import provision_native_demo
    from qualify import command, serving

    binary = args.chio.resolve(strict=True)
    images = json.loads(args.worker_image_file.read_text())
    assert "@sha256:" in images["base"]
    helper = docker("image", "inspect", images["base"], "--format", "{{.Id}}").decode().strip()
    source = HERE.parent.parent
    revision = git("rev-parse", "HEAD", cwd=source).decode().strip()
    source_status = git("status", "--porcelain", cwd=source)
    scope_commit, imported = import_revision(source, revision, source_paths=SOURCE_PATHS)
    assert scope_commit == revision
    expected = entries(imported)
    selected_files = {name for name, (kind, _, _) in expected.items() if kind == "file"}
    assert selected_files and all(name.startswith(SOURCE_PATHS[0] + "/") for name in selected_files)
    os.chdir(root)
    started = time.monotonic()
    config = initialize(
        source,
        revision,
        images["execution_image"],
        helper,
        root / "repository",
        30,
        source_paths=SOURCE_PATHS,
    )
    assert config["schema"] == "chio.repository.workspace.v3"
    initialization_seconds = time.monotonic() - started
    entrypoint = Path(sys.executable).parent / "chio-mini-swe-repository"
    # Explicit fixture authority, with no model gateway or provider credential.
    server = provision_native_demo(
        binary,
        "sandbox",
        [str(entrypoint), "serve", "--state", str(root / "repository")],
        root / "launch",
        root,
    )
    server["request_timeout_seconds"] = 150
    (root / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 1
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: sandbox
        tool: execute
        operations: [invoke, delegate]
        ttl: 3600
""")
    write(
        root / "config.json",
        {
            "schema": "chio.process.host.v1",
            "policy": str(root / "policy.yaml"),
            "servers": [server],
            "limits": {"max_calls": 8, "max_processes": 2, "max_depth": 1},
            "children": [
                {
                    "id": "coder",
                    "parent": "root",
                    "budget_share_bps": 10000,
                    "tools": [{"server_id": "sandbox", "tool_name": "execute"}],
                }
            ],
        },
    )
    initialized = json.loads(
        command(
            binary, "process", "init", "--config", root / "config.json", "--state", root / "host"
        )
    )
    (root / "kernel.pub").write_text(initialized["kernel_key"])
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
    )
    connection = json.loads((root / "connection.json").read_text())
    client = ProcessClient(connection["socket_path"], connection["credential"], timeout=180)
    commands = [
        "test ! -e crates && test ! -e sdks/python/chio-mini-swe && git status --porcelain",
        "cd sdks/python/chio-process && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "
        "python -m unittest discover -s tests -v",
    ]
    receipts, outputs, elapsed = [], [], []
    with serving(binary, root):
        for index, text in enumerate(commands):
            started = time.monotonic()
            result = client.invoke(
                f"sdk-command-{index}",
                "sandbox",
                "execute",
                {"command": text},
                known_outcome_only=True,
            )
            elapsed.append(time.monotonic() - started)
            assert result["verdict"] == "allow"
            assert result["terminal_state"]["state"] == "completed"
            envelope = result["output"]["value"]
            assert envelope.get("isError", False) is False
            output = envelope["structuredContent"]
            assert output["returncode"] == 0 and output["exception_info"] == ""
            receipts.append(result["receipt_json"])
            outputs.append(output)
        assert outputs[0]["output"] == ""
        count = re.search(r"Ran (\d+) tests? in", outputs[1]["output"])
        assert count and int(count[1]) >= 18 and "\nOK\n" in outputs[1]["output"]
        assert client.inspect()["tree_calls"] == 2
    (root / "worker.sock").unlink(missing_ok=True)
    with serving(binary, root):
        replayed = client.invoke(
            "sdk-command-0", "sandbox", "execute", {"command": commands[0]}, known_outcome_only=True
        )
        assert replayed["receipt_json"] == receipts[0]
        assert client.inspect()["tree_calls"] == 2
    (root / "receipts.ndjson").write_text("\n".join(receipts) + "\n")
    with Workspace(root / "repository") as workspace:
        before_violation = workspace.status()
        assert before_violation["revision"] == 2 and not before_violation["interrupted"]
        proof, raw, key = verify(
            workspace,
            binary=binary,
            receipts_path=root / "receipts.ndjson",
            key_path=root / "kernel.pub",
            server_id="sandbox",
        )
        export(workspace, bundle)
    (bundle / "receipts.ndjson").write_bytes(raw)
    (bundle / "kernel.pub").write_bytes(key)
    write(bundle / "receipt-binding.json", proof)
    review_arguments = {
        "binary": binary,
        "repository": source,
        "revision": revision,
        "key_path": root / "kernel.pub",
        "server_id": "sandbox",
    }
    reviewed = verify_export(bundle, **review_arguments, source_paths=SOURCE_PATHS)
    assert reviewed["verified_transitions"] == reviewed["verification"]["receipts_verified"] == 2
    assert (bundle / "changes.patch").read_bytes() == b""
    for scope in (None, ["sdks/python/chio-mini-swe"]):
        try:
            verify_export(bundle, **review_arguments, source_paths=scope)
        except ValueError:
            pass
        else:
            raise AssertionError("Recipient accepted an unexpected source scope")
    # Test refusal separately from the already exported successful prefix.
    (root / "worker.sock").unlink(missing_ok=True)
    with serving(binary, root):
        refused = client.invoke(
            "scope-violation",
            "sandbox",
            "execute",
            {"command": "printf outside > scope-violation.txt"},
        )
        assert refused["output"]["value"]["isError"] is True
        assert client.inspect()["tree_calls"] == 3
    refusal = (refused["receipt_json"] + "\n").encode()
    _, refusal_verification = verified_receipts(binary, refusal, key)
    (args.output / "scope-refusal-receipt.ndjson").write_bytes(refusal)
    with Workspace(root / "repository") as workspace:
        final = workspace.status()
        assert final["interrupted"] and final["revision"] == 2
        assert final["snapshot"] == before_violation["snapshot"]
        for row in workspace.db.execute("SELECT * FROM commands").fetchall():
            label = "chio.repository.lease=" + row["lease"]
            assert not docker("ps", "-aq", "--filter", "label=" + label).strip()
            assert not docker("volume", "ls", "-q", "--filter", "label=" + label).strip()
    assert git("status", "--porcelain", cwd=source) == source_status
    assert import_revision(source, revision, source_paths=SOURCE_PATHS)[1] == imported
    report = {
        "schema": "chio.repository.scope-qualification.v1",
        "private_state": str(root),
        "source_commit": revision,
        "source_paths": SOURCE_PATHS,
        "source_file_count": len(selected_files),
        "source_file_bytes": sum(len(expected[name][2]) for name in selected_files),
        "imported_archive_bytes": len(imported),
        "sdk_tests_passed": int(count[1]),
        "initialization_seconds": initialization_seconds,
        "command_seconds": elapsed,
        "review": reviewed,
        "fresh_host_replay_returned_original_receipt": True,
        "unexpected_scope_refused_by_recipient": True,
        "outside_output_refused_without_revision_promotion": True,
        "scope_refusal_verification": refusal_verification,
        "owned_containers_and_volumes_remaining": 0,
        "source_unchanged": True,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "installed_sources_sha256": {
            name: hashlib.sha256(
                Path(importlib.util.find_spec("chio_mini_swe." + name).origin).read_bytes()
            ).hexdigest()
            for name in (
                "repository_scope",
                "repository_archive",
                "repository_store",
                "repository_review",
                "repository",
            )
        },
        "limits": [
            "Real committed SDK test suite; no model or coding-quality qualification",
            "Explicit fixture launch authority; no production-containment claim",
            "Successful two-command prefix exported before deliberate third-command refusal",
        ],
    }
    shutil.copytree(bundle, args.output / "bundle")
    write(args.output / "qualification.json", report)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sdk_tests_passed": int(count[1]),
                "verified_transitions": reviewed["verified_transitions"],
            }
        )
    )


if __name__ == "__main__":
    main()
