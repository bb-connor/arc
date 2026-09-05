"""Prepare or resume a local repository review through the public Chio CLI."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import select
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

import native
from snapshot import capture, digest, encoded, load

HERE = Path(__file__).resolve().parent
ROLES = ("changes", "tests", "publisher")


def application_hash():
    return digest(
        {
            p: hashlib.sha256((HERE / p).read_bytes()).hexdigest()
            for p in (
                "review.py",
                "snapshot.py",
                "tools.py",
                "worker.py",
                "handoffs.py",
                "native.py",
            )
        }
    )


def write(path, value):
    with path.open("xb") as output:
        output.write(encoded(value))
        output.flush()
        os.fsync(output.fileno())


def cli(config, directory, *args):
    result = subprocess.run(
        [config["chio"], "process", *map(str, args)], capture_output=True, timeout=90
    )
    if result.returncode:
        with (directory / "host-error.log").open("ab") as output:
            output.write(result.stderr)
        raise RuntimeError("Chio command failed; inspect private host-error.log")
    return json.loads(result.stdout)


def prepare(args):
    directory = args.run_dir.resolve()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    snapshot = capture(args.repo, args.base, args.head)
    snapshot_hash = digest(snapshot)
    write(directory / "snapshot.json", snapshot)
    for child in ("sockets", "connections", *ROLES):
        (directory / child).mkdir(mode=0o700)
    binary = args.chio.resolve(strict=True)
    config = {
        "schema": "chio.repository.review.v1",
        "chio": str(binary),
        "snapshot_hash": snapshot_hash,
        "base": snapshot["base"],
        "head": snapshot["head"],
        "model_factory": args.model_factory,
        "max_rounds": args.max_rounds,
        "application_hash": application_hash(),
    }
    (directory / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 4
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: repo
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")

    def child(name, parent, share, tools, mailbox_tools):
        return {
            "id": name,
            "parent": parent,
            "budget_share_bps": share,
            "tools": (
                [{"server_id": "repo", "tool_name": tool} for tool in tools]
                + [
                    {"server_id": "chio-ipc", "tool_name": tool}
                    for tool in mailbox_tools
                ]
            ),
        }

    write(
        directory / "host-config.json",
        {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "servers": [
                {
                    "id": "repo",
                    "command": [
                        sys.executable,
                        str(HERE / "tools.py"),
                        "--snapshot",
                        str(directory / "snapshot.json"),
                        "--snapshot-hash",
                        snapshot_hash,
                        "--database",
                        str(directory / "publications.db"),
                    ],
                }
            ],
            "limits": {"max_processes": 5, "max_depth": 2, "max_calls": args.max_calls},
            "mailboxes": [{"id": role} for role in ("changes", "tests")],
            "children": [
                child(
                    "changes", "root", 2500, ["changes", "read_file"], ["send_changes"]
                ),
                child(
                    "tests",
                    "root",
                    2500,
                    ["test_inventory", "read_file"],
                    ["send_tests"],
                ),
                child(
                    "editor",
                    "root",
                    4000,
                    ["publish_report"],
                    ["receive_changes", "receive_tests", "ack_changes", "ack_tests"],
                ),
                child(
                    "publisher",
                    "editor",
                    1000,
                    ["publish_report"],
                    ["receive_changes", "receive_tests", "ack_changes", "ack_tests"],
                ),
            ],
        },
    )
    started = time.monotonic()
    initialized = cli(
        config,
        directory,
        "init",
        "--config",
        directory / "host-config.json",
        "--state",
        directory / "host",
    )
    config["kernel_key"] = initialized["kernel_key"]
    config["host_init_seconds"] = time.monotonic() - started
    write(directory / "worker-plan.json", native.plan(config, directory))
    write(directory / "run.json", config)
    print(
        json.dumps(
            {
                "prepared": True,
                "run_dir": str(directory),
                "snapshot_hash": snapshot_hash,
                "changed_paths": len(snapshot["files"]),
                "mode": args.model_factory,
            }
        )
    )


@contextlib.contextmanager
def host(config, directory, socket_path):
    with (directory / "host.log").open("ab") as log:
        process = subprocess.Popen(
            [
                config["chio"],
                "process",
                "serve",
                "--state",
                str(directory / "host"),
                "--socket",
                str(socket_path),
            ],
            stdout=subprocess.PIPE,
            stderr=log,
        )
        try:
            if not select.select([process.stdout], [], [], 90)[0]:
                raise RuntimeError("host startup timed out; inspect private host.log")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("host failed; inspect private host.log")
            ready = json.loads(line)
            if not ready.get("ready") or ready["kernel_key"] != config["kernel_key"]:
                raise RuntimeError("host identity mismatch")
            yield process
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                raise RuntimeError(
                    "host drain timed out; preserve state for recovery"
                ) from None
            process.stdout.close()


def workers(config, directory, connections, roles, *, crash=False, crash_handoff=None):
    processes = []
    with contextlib.ExitStack() as stack:
        try:
            for role in roles:
                log = stack.enter_context((directory / role / "worker.log").open("ab"))
                worker_config = {
                    **config,
                    "role": role,
                    "directory": str(directory / role),
                    "connection": connections[role],
                    "crash_after_publication": crash,
                    "crash_after_handoff": role == crash_handoff,
                }
                process = subprocess.Popen(
                    [sys.executable, str(HERE / "worker.py")],
                    stdin=subprocess.PIPE,
                    stdout=log,
                    stderr=log,
                )
                processes.append((role, process))
                process.stdin.write(encoded(worker_config))
                process.stdin.close()
            deadline = time.monotonic() + 600
            while any(p.poll() is None for _, p in processes):
                if any(p.poll() not in (None, 0) for _, p in processes):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "worker deadline reached; resume the same run directory"
                    )
                time.sleep(0.05)
            failures = [(role, p.returncode) for role, p in processes if p.poll() != 0]
            if failures:
                raise RuntimeError(
                    "workers stopped: " + str(failures) + "; inspect private worker.log"
                )
        finally:
            for _, process in processes:
                if process.poll() is None:
                    process.terminate()
            for _, process in processes:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    results = {}
    for role in roles:
        result = json.loads((directory / role / "result.json").read_text())
        if result["snapshot_hash"] != config["snapshot_hash"] or result["role"] != role:
            raise RuntimeError("worker handoff identity mismatch")
        results[role] = result
    return results


def run(args):
    directory = args.run_dir.resolve(strict=True)
    if directory.stat().st_mode & 0o077:
        raise ValueError("run directory must have mode 0700")
    with (directory / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = json.loads((directory / "run.json").read_text())
        if (
            config["schema"] != "chio.repository.review.v1"
            or config["application_hash"] != application_hash()
        ):
            raise ValueError(
                "application changed; resume with the original application version"
            )
        load(directory / "snapshot.json", config["snapshot_hash"])
        started = time.monotonic()
        runner = None
        if args.command == "run-native":
            runner = native.run(config, directory)
            results = {
                role: json.loads((directory / role / "result.json").read_text())
                for role in ROLES
            }
        else:
            attempt = uuid.uuid4().hex[:12]
            socket_path = directory / "sockets" / (attempt + ".sock")
            if len(os.fsencode(socket_path)) >= 104:
                raise ValueError(
                    "run directory is too long for a portable Unix socket path"
                )
            connections = {}
            for role in ROLES:
                cli(
                    config,
                    directory,
                    "revoke",
                    "--state",
                    directory / "host",
                    "--process",
                    role,
                )
                path = directory / "connections" / f"{attempt}-{role}.json"
                cli(
                    config,
                    directory,
                    "credential",
                    "--state",
                    directory / "host",
                    "--process",
                    role,
                    "--socket",
                    socket_path,
                    "--out",
                    path,
                )
                connections[role] = json.loads(path.read_text())
            results = {}
            with host(config, directory, socket_path) as process:
                results.update(
                    workers(
                        config,
                        directory,
                        connections,
                        ("changes", "tests"),
                        crash_handoff=args.crash_after_handoff,
                    )
                )
                try:
                    results.update(
                        workers(
                            config,
                            directory,
                            connections,
                            ("publisher",),
                            crash=args.crash_after_publication,
                        )
                    )
                except RuntimeError:
                    if args.crash_after_publication:
                        process.kill()
                    raise
        if any(
            result["snapshot_hash"] != config["snapshot_hash"] or result["role"] != role
            for role, result in results.items()
        ):
            raise RuntimeError("worker completion identity mismatch")
        published = json.loads(results["publisher"]["text"])["structuredContent"]
        with sqlite3.connect(
            f"file:{directory / 'publications.db'}?mode=ro", uri=True
        ) as db:
            stored = db.execute(
                "SELECT report FROM reports WHERE id=?", (published["report_id"],)
            ).fetchone()
            publication_count = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        if not stored:
            raise RuntimeError("published report is missing from local history")
        receipts = [
            entry["chio"]["receipt_json"]
            for result in results.values()
            for entry in result["receipts"]
        ]
        if not receipts:
            raise RuntimeError("completed review has no receipt evidence")
        receipt_path = directory / "receipts.ndjson"
        receipt_path.write_text("".join(receipt + "\n" for receipt in receipts))
        key_path = directory / "kernel.pub"
        key_path.write_text(config["kernel_key"])
        verification = subprocess.run(
            [
                config["chio"],
                "--json",
                "receipt",
                "verify",
                "--input",
                str(receipt_path),
                "--trusted-kernel-pubkey",
                str(key_path),
            ],
            capture_output=True,
            timeout=30,
        )
        if verification.returncode:
            raise RuntimeError(
                "offline receipt verification failed; preserve the run directory"
            )
        publication_receipts = [
            receipt
            for entry in results["publisher"]["receipts"]
            if (receipt := json.loads(entry["chio"]["receipt_json"]))["tool_server"]
            == "repo"
            and receipt["tool_name"] == "publish_report"
        ]
        if len(publication_receipts) != 1:
            raise RuntimeError("expected one verified publication receipt")
        publisher_receipt = publication_receipts[0]
        if publisher_receipt["action"]["parameters"] != {
            "report": stored[0],
            "snapshot_hash": config["snapshot_hash"],
        }:
            raise RuntimeError("published report does not match its signed invocation")
        # Exports can be regenerated; the publication and graph journals own recovery.
        (directory / "report.md").write_text(stored[0])
        evidence = {
            "schema": "chio.repository.review.evidence.v1",
            "base": config["base"],
            "head": config["head"],
            "snapshot_hash": config["snapshot_hash"],
            "kernel_key": config["kernel_key"],
            "model_factory": config["model_factory"],
            "host_init_seconds": config["host_init_seconds"],
            "attempt_seconds": time.monotonic() - started,
            "runner": runner,
            "publications": publication_count,
            "publication": published,
            "report_hash": hashlib.sha256(stored[0].encode()).hexdigest(),
            "receipt_verification": json.loads(verification.stdout),
            "workers": {
                role: {"pid": result["worker_pid"], "receipts": result["receipts"]}
                for role, result in results.items()
            },
        }
        (directory / "evidence.json").write_bytes(encoded(evidence))
        print(
            json.dumps(
                {
                    "complete": True,
                    "report": str(directory / "report.md"),
                    "evidence": str(directory / "evidence.json"),
                    "publications": publication_count,
                }
            )
        )


def main():
    os.umask(0o077)

    def stop(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("prepare")
    init.add_argument("--repo", type=Path, required=True)
    init.add_argument("--base", required=True)
    init.add_argument("--head", default="HEAD")
    init.add_argument("--run-dir", type=Path, required=True)
    init.add_argument("--chio", type=Path, required=True)
    init.add_argument(
        "--model-factory",
        default="inventory",
        help="inventory or importable module:factory(role)",
    )
    init.add_argument("--max-rounds", type=int, choices=range(1, 33), default=8)
    init.add_argument("--max-calls", type=int, choices=range(1, 1001), default=100)
    managed = commands.add_parser(
        "run-native", help="run and restart workers with the native Linux host"
    )
    managed.add_argument("--run-dir", type=Path, required=True)
    resume = commands.add_parser("run")
    resume.add_argument("--run-dir", type=Path, required=True)
    resume.add_argument(
        "--crash-after-handoff",
        choices=("changes", "tests"),
        help="qualification only: exit one reader after send, before graph checkpoint",
    )
    resume.add_argument(
        "--crash-after-publication",
        action="store_true",
        help="qualification only: exit publisher before checkpoint, then kill host",
    )
    args = parser.parse_args()
    if args.command == "prepare":
        if args.model_factory != "inventory" and args.model_factory.count(":") != 1:
            parser.error("model factory must be module:factory")
        prepare(args)
    else:
        run(args)


if __name__ == "__main__":
    main()
