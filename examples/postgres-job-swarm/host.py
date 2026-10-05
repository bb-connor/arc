"""Native host configuration for the existing PostgreSQL job resource."""

import contextlib
import json
import os
import select
import subprocess


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


def prepare(chio, gateway, tenant, directory, environment, *, resources=None):
    from resources import OPERATIONS, WORKER_OPERATIONS, server

    chio = chio.resolve(strict=True)
    if resources is None:
        configured = environment.get("CHIO_JOB_BROKER_CONFIG")
        if not configured:
            raise ValueError("PostgreSQL native execution requires a provisioned broker config")
        with open(configured) as stream:
            config = json.load(stream)
    else:
        config = json.loads(json.dumps(resources.config))
    routes = config["native_broker"]["routes"]
    if len(routes) != len(OPERATIONS):
        raise ValueError("expected six fixed PostgreSQL broker routes")
    observed = set()
    for route in routes:
        operation = route["quota"]["tool_name"]
        if operation not in OPERATIONS or operation in observed:
            raise ValueError("unexpected or repeated PostgreSQL route")
        observed.add(operation)
        if (route["quota"]["server_id"] != server(operation)
                or route["preparation"]["payload"] != {
                    "kind": "caller_bound_resource", "route": {
                        "resource": "postgres-jobs", "tenant": tenant, "operation": operation}}):
            raise ValueError("PostgreSQL route differs from the fixed host mapping")
    config["limits"] = {"max_processes": 3, "max_depth": 1, "max_calls": 100}
    config["children"] = [
        {"id": name, "parent": "root", "budget_share_bps": 4000,
         "tools": [{"server_id": server(tool), "tool_name": tool}
                   for tool in WORKER_OPERATIONS]}
        for name in ROLES
    ]
    write(directory / "host-config.json", config)
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
    if resources is not None:
        resources.start(initialized["kernel_key"])
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
            env={name: value for name, value in environment.items()
                 if not name.startswith("CHIO_JOB_DATABASE_")},
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
