"""Native host configuration for the existing PostgreSQL job resource."""

import contextlib
import json
import os
import select
import subprocess

from chio_process import ProcessClient

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
        env=host_environment() if env is None else env,
        input=input,
    )
    if result.returncode:
        with (directory / "host-errors.log").open("ab") as log:
            log.write(result.stderr)
        raise RuntimeError("command failed; inspect private host-errors.log")
    return result.stdout


def host_environment():
    """No database or model credentials enter the kernel or broker fixture."""
    return {
        name: os.environ[name]
        for name in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT")
        if name in os.environ
    }


def route(tool, *, operator=False):
    return ("jobs-admin-" if operator else "jobs-") + tool


def prepared_request(connection, operation, tool, arguments, *, known=True):
    server = route(tool, operator=True)
    prepared = ProcessClient(
        connection["socket_path"], connection["credential"]
    ).prepare_invocation(operation, server, tool, arguments)
    if (
        not isinstance(prepared, dict)
        or prepared.get("schema") != "chio.broker-execute.v1"
    ):
        raise ValueError("host returned an invalid preparation")
    return {
        "operation_key": operation,
        "server_id": server,
        "tool_name": tool,
        "arguments": prepared,
        "known_outcome_only": known,
    }


@contextlib.contextmanager
def prepare(chio, gateway, tenant, directory, environment, *, fault=None):
    from services import Services

    with Services(
        chio, gateway, tenant, directory, environment, fault=fault
    ) as services:
        key, connections = initialize(chio, gateway, directory, services.config_path)
        yield key, connections, services


def initialize(chio, gateway, directory, config_path):
    initialized = json.loads(
        command(
            [
                chio,
                "process",
                "init",
                "--config",
                config_path,
                "--state",
                directory / "host",
            ],
            directory,
            env=host_environment(),
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
        if name in ROLES:
            # These are the resource argument schemas, before trusted host
            # preparation. The native manifest accepts only the prepared envelope.
            definitions = json.loads(
                command(
                    [gateway, "definitions", "worker"],
                    directory,
                    env=host_environment(),
                )
            )
            connections[name]["tools"] = [
                {
                    "name": "jobs__" + tool["name"],
                    "server_id": route(tool["name"]),
                    "tool_name": tool["name"],
                    "description": tool["description"],
                    "input_schema": tool["inputSchema"],
                }
                for tool in definitions
            ]
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
def serve(chio, directory, key, services, *, socket_path=None):
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
            env=host_environment(),
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
            services.start()
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
