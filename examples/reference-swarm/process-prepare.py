"""Provision an Enforced repository-reader fan-out for the process supervisor."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["chio", "cage-init", "reader", "input-dir", "output"]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--file", action="append", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("the Enforced native-tool profile requires Linux x86_64")
    if os.getuid() == 0 or os.getgid() == 0:
        parser.error("run as the non-root operator whose identity the tool will retain")
    if not 2 <= len(args.file) <= 32 or len(set(args.file)) != len(args.file):
        parser.error("select 2-32 distinct UTF-8 files")
    os.umask(0o077)
    chio = args.chio.resolve(strict=True)
    helper = args.cage_init.resolve(strict=True)
    reader = args.reader.resolve(strict=True)
    source = args.input_dir.resolve(strict=True)
    if not source.is_dir():
        parser.error("input-dir must be a directory")
    inputs = []
    for index, name in enumerate(args.file):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            parser.error("each file must be a relative path inside input-dir")
        path = (source / relative).resolve(strict=True)
        if not path.is_relative_to(source) or not path.is_file():
            parser.error("each file must resolve to a regular file inside input-dir")
        data = path.read_bytes()
        data.decode("utf-8")
        if len(data) > 256 * 1024:
            parser.error("each selected file must fit the reader's 256 KiB limit")
        inputs.append(
            {
                "process": f"reader-{index + 1}",
                "path": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    if sum(item["bytes"] for item in inputs) > 4 * 1024 * 1024:
        parser.error("the selection exceeds the reader's 4 MiB session limit")
    output = args.output.absolute()
    # Tool access must never include the operator's newly created state or keys.
    if output.resolve().is_relative_to(source):
        parser.error("output must be outside input-dir")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve(strict=True)
    launch = output / "reader-launch"
    command = [
        str(chio),
        "security",
        "provision-reference-runtime",
        "--output-dir",
        str(launch),
        "--cage-init",
        str(helper),
        "--target",
        str(reader),
        "--target-arg=--root",
        "--target-arg",
        str(source),
        "--working-directory",
        str(source),
        "--read-path",
        str(source),
        "--discover-tools",
        "--execution-uid",
        str(os.getuid()),
        "--execution-gid",
        str(os.getgid()),
        "--server-id",
        "reference-reader",
    ]
    for gid in sorted(set(os.getgroups()) - {os.getgid()}):
        command.extend(["--execution-supplementary-gid", str(gid)])
    provision = subprocess.run(command, text=True, capture_output=True, check=False)
    (output / "provision.stdout").write_text(provision.stdout)
    (output / "provision.stderr").write_text(provision.stderr)
    if provision.returncode:
        raise RuntimeError(
            f"provisioning refused; inspect {output / 'provision.stderr'}"
        )
    report = json.loads((launch / "provision-report.json").read_text())
    if report["securityMode"] != "enforced_cage":
        raise ValueError("provisioner did not select Enforced cage launch")
    policy = output / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
  require_swarm_admission: true
capabilities:
  default:
    tools:
      - server: reference-reader
        tool: read_file
        operations: [invoke, delegate]
        ttl: 3600
""")
    share, remainder = divmod(10000, len(inputs))
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "servers": [
            {
                "id": "reference-reader",
                "command": [str(reader), "--root", str(source)],
                "launch_policy": str(launch / "cage-launch-policy.json"),
                "launch_policy_signer": report["cagePolicyPublicKey"],
            }
        ],
        "limits": {
            "max_calls": len(inputs) * 4,
            "max_processes": len(inputs) + 1,
            "max_depth": 1,
        },
        "children": [
            {
                "id": item["process"],
                "parent": "root",
                "tools": [{"server_id": "reference-reader", "tool_name": "read_file"}],
                "budget_share_bps": share + (index < remainder),
            }
            for index, item in enumerate(inputs)
        ],
    }
    plan = {
        "schema": "chio.process.swarm-plan.v1",
        "graph_id": "repository-review",
        "calls": [
            {
                "process": item["process"],
                "operation_key": "read-source",
                "server_id": "reference-reader",
                "tool_name": "read_file",
                "arguments": {"path": item["path"]},
            }
            for item in inputs
        ],
    }
    write(output / "host.json", config)
    write(output / "tasks.json", plan)
    initialize = subprocess.run(
        [
            str(chio),
            "process",
            "init",
            "--config",
            str(output / "host.json"),
            "--state",
            str(output / "state"),
            "--aggregate-invocations",
            str(len(inputs)),
            "--swarm-plan",
            str(output / "tasks.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    (output / "initialize.stdout").write_text(initialize.stdout)
    (output / "initialize.stderr").write_text(initialize.stderr)
    if initialize.returncode:
        raise RuntimeError(
            f"Enforced host initialization refused; inspect {output / 'initialize.stderr'}"
        )
    calls = json.loads((output / "state/swarm-calls.json").read_text())
    bootstrap = json.loads((output / "state/swarm-bootstrap.json").read_text())
    capabilities = bootstrap["action"]["parameters"]["capabilities"]
    for item, call in zip(inputs, calls["calls"], strict=True):
        if item["process"] != call["process"]:
            raise ValueError("initialized task order differs from the requested plan")
        item["capability_id"] = capabilities[item["process"]]["id"]
        item["request_id"] = call["request_id"]
    write(
        output / "inputs.json",
        {
            "schema": "chio.reference-swarm.inputs.v1",
            "runtime_id": calls["runtime_id"],
            "files": inputs,
        },
    )
    print(
        json.dumps(
            {
                "state": str(output / "state"),
                "inputs": str(output / "inputs.json"),
                "workers": len(inputs),
            }
        )
    )


if __name__ == "__main__":
    main()
