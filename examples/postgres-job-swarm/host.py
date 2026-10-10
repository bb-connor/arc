"""Native host configuration for the existing PostgreSQL job resource."""

import contextlib
import json
import os
import select
import subprocess

from chio_process.launch import NativeDemoProvisionError, provision_native_demo

ROLES = ("superseded", "replacement")


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def command(arguments, directory, *, env=None, input=None):
    result = subprocess.run(
        [str(value) for value in arguments],
        capture_output=True,
        timeout=90,
        env=env,
        input=input,
    )
    if result.returncode:
        with (directory / "host-errors.log").open("ab") as log:
            log.write(result.stderr)
        raise RuntimeError("command failed; inspect private host-errors.log")
    return result.stdout


def review_tool_surface(arguments, directory, environment, mode):
    """Review metadata with the fixture's explicit database environment only."""
    requests = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "chio-postgres-job-review", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    output = command(
        arguments,
        directory,
        env=environment,
        input="".join(json.dumps(request) + "\n" for request in requests).encode(),
    )
    if len(output) > 4 * 1024 * 1024:
        raise ValueError("gateway metadata exceeded its review bound")
    replies = {}
    for line in output.splitlines():
        reply = json.loads(line)
        if (
            not isinstance(reply, dict)
            or reply.get("jsonrpc") != "2.0"
            or reply.get("id") not in (1, 2)
            or reply["id"] in replies
            or "error" in reply
            or not isinstance(reply.get("result"), dict)
        ):
            raise ValueError("gateway metadata response was not an expected review reply")
        replies[reply["id"]] = reply["result"]
    if set(replies) != {1, 2} or not isinstance(replies[2].get("tools"), list):
        raise ValueError("gateway did not supply its reviewed tool surface")
    fixture = directory / ("reviewed-" + mode + "-tools.json")
    write(fixture, {"tools": replies[2]["tools"]})
    return fixture


def prepare(chio, gateway, tenant, directory, environment, *, operator_command=None):
    chio = chio.resolve(strict=True)
    gateway = gateway.resolve(strict=True)
    (directory / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: jobs
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: jobs-admin
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    servers = []
    for server, mode in (("jobs", "worker"), ("jobs-admin", "operator")):
        native_command = (
            operator_command
            if mode == "operator" and operator_command is not None
            else [str(gateway), mode, tenant]
        )
        stage = "gateway_metadata_review"
        try:
            fixture = review_tool_surface(native_command, directory, environment, mode)
            stage = "native_demo_provision"
            servers.append(
                provision_native_demo(
                    chio,
                    server,
                    native_command,
                    directory / ("launch-" + mode),
                    directory,
                    environment=environment,
                    tools_fixture=fixture,
                )
            )
        except Exception as error:
            # Only fixed phrases and an exit status may leave the private fixture.
            # Child stdout, argv, database URLs and environment stay private.
            write(
                directory / "launch-diagnostics.json",
                {
                    "schema": "chio.postgres-job-swarm.launch-diagnostic.v1",
                    "stage": stage,
                    "exit_status": (
                        error.returncode if isinstance(error, NativeDemoProvisionError) else None
                    ),
                    "diagnostic": (
                        error.diagnostic
                        if isinstance(error, NativeDemoProvisionError)
                        else "gateway metadata review failed"
                    ),
                },
            )
            raise
    write(
        directory / "host-config.json",
        {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "servers": servers,
            "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 100},
            "children": [
                {
                    "id": name,
                    "parent": "root",
                    "budget_share_bps": 4000,
                    "tools": [
                        {"server_id": "jobs", "tool_name": tool}
                        for tool in ("task", "complete", "renew")
                    ],
                }
                for name in ROLES
            ],
        },
    )
    initialized = json.loads(
        command(
            [
                chio,
                "process",
                "init",
                "--config",
                directory / "host-config.json",
                "--state",
                directory / "host",
            ],
            directory,
            env=environment,
        )
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"] + "\n")
    connections = {}
    for name in ("root", *ROLES):
        (directory / name).mkdir(mode=0o700)
        path = directory / name / "connection.json"
        command(
            [
                chio,
                "process",
                "credential",
                "--state",
                directory / "host",
                "--process",
                name,
                "--socket",
                directory / "worker.sock",
                "--out",
                path,
            ],
            directory,
        )
        connections[name] = json.loads(path.read_text())
    return initialized["kernel_key"], connections


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


@contextlib.contextmanager
def serve(chio, directory, key, environment, *, socket_path=None):
    with (directory / "host.log").open("ab") as log:
        process = subprocess.Popen(
            [
                str(chio),
                "process",
                "serve",
                "--state",
                str(directory / "host"),
                "--socket",
                str(socket_path or directory / "worker.sock"),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=log,
        )
        try:
            if not select.select([process.stdout], [], [], 90)[0]:
                raise TimeoutError("host readiness timed out")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError(
                    "host exited before readiness; inspect private host.log"
                )
            ready = json.loads(line)
            if ready.get("ready") is not True or ready.get("kernel_key") != key:
                raise RuntimeError("host readiness or signer changed")
            yield process
        finally:
            stop(process)
            process.stdout.close()


def verify(chio, directory, receipts):
    path = directory / "receipts.ndjson"
    with path.open("x") as stream:
        stream.write("\n".join(dict.fromkeys(receipts)) + "\n")
    command(
        [
            chio,
            "receipt",
            "verify",
            "--input",
            path,
            "--trusted-kernel-pubkey",
            directory / "kernel.pub",
        ],
        directory,
    )
