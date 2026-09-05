"""Prepare and recover an adaptive repository review through the native host."""

import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from snapshot import capture, digest, load

from . import configuration, verification
from .common import SCHEMA, persist


def binary_hash(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def prepare(args):
    if sys.platform != "linux":
        raise ValueError("the adaptive runner requires Linux")
    directory = args.run_dir.resolve()
    directory.mkdir(mode=0o700, exist_ok=False)
    (directory / "workers").mkdir(mode=0o700)
    snapshot = capture(args.repo, args.base, args.head)
    persist(directory / "snapshot.json", snapshot)
    binary = args.chio.resolve(strict=True)
    config = {
        "schema": SCHEMA,
        "chio": str(binary),
        "native_binary_sha256": binary_hash(binary),
        "base": snapshot["base"],
        "head": snapshot["head"],
        "snapshot_hash": digest(snapshot),
        "model_factory": args.model_factory,
        "max_rounds": args.max_rounds,
        "max_reviews": args.max_reviews,
        "max_parallel": args.max_parallel,
        "max_calls": args.max_calls,
        "application_hash": configuration.application_hash(),
    }
    (directory / "policy.yaml").write_text(configuration.POLICY)
    persist(directory / "host-config.json", configuration.host(config, directory))
    started = time.monotonic()
    result = subprocess.run(
        [
            str(binary),
            "process",
            "init",
            "--config",
            str(directory / "host-config.json"),
            "--state",
            str(directory / "host"),
        ],
        capture_output=True,
        timeout=90,
    )
    if result.returncode:
        (directory / "host-error.log").write_bytes(result.stderr)
        raise RuntimeError("host initialization failed; inspect private host-error.log")
    initialized = json.loads(result.stdout)
    config["kernel_key"] = initialized["kernel_key"]
    config["host_init_seconds"] = time.monotonic() - started
    (directory / "kernel.pub").write_text(config["kernel_key"] + "\n")
    persist(directory / "worker-plan.json", configuration.plan(config, directory))
    persist(directory / "run.json", config)
    return {
        "prepared": True,
        "run_dir": str(directory),
        "changed_paths": len(snapshot["files"]),
        "initial_workers": ["coordinator", "publisher"],
        "max_reviews": config["max_reviews"],
    }


def validate_run(directory):
    if directory.stat().st_mode & 0o077:
        raise ValueError("run directory must have mode 0700")
    config = json.loads((directory / "run.json").read_text())
    if (
        config["schema"] != SCHEMA
        or config["application_hash"] != configuration.application_hash()
    ):
        raise ValueError(
            "application changed; restore the prepared application version"
        )
    if config["native_binary_sha256"] != binary_hash(config["chio"]):
        raise ValueError("native binary changed; restore the prepared host")
    if (directory / "kernel.pub").read_text().strip() != config["kernel_key"]:
        raise ValueError("initialization key changed")
    load(directory / "snapshot.json", config["snapshot_hash"])
    if json.loads((directory / "worker-plan.json").read_text()) != configuration.plan(
        config, directory
    ):
        raise ValueError("run metadata does not match its executable plan")
    expected_host = configuration.host(config, directory)
    expected_host["policy"] = str(directory / "policy.yaml")
    if (
        json.loads((directory / "host/host.json").read_text())["config"]
        != expected_host
    ):
        raise ValueError(
            "run metadata does not match its initialized authority templates"
        )
    return config


def run(args):
    directory = args.run_dir.resolve(strict=True)
    with (directory / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = validate_run(directory)
        with (directory / "host-error.log").open("ab") as errors:
            process = subprocess.Popen(
                [
                    config["chio"],
                    "process",
                    "run",
                    "--state",
                    str(directory / "host"),
                    "--plan",
                    str(directory / "worker-plan.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=errors,
            )
            try:
                output, _ = process.communicate(timeout=3660)
                if process.returncode:
                    raise RuntimeError(
                        "native run stopped; inspect chio process status and retained logs"
                    )
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=10)
        return verification.verify(config, directory, json.loads(output))


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
        help="inventory or module:factory(coordinator|reviewer)",
    )
    init.add_argument("--max-reviews", type=int, choices=range(1, 17), default=8)
    init.add_argument("--max-parallel", type=int, choices=range(1, 17), default=2)
    init.add_argument("--max-rounds", type=int, choices=range(1, 33), default=8)
    init.add_argument("--max-calls", type=int, choices=range(1, 1001), default=300)
    resume = commands.add_parser("run")
    resume.add_argument("--run-dir", type=Path, required=True)
    commands.add_parser("worker", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.command == "worker":
        from .worker import main as worker

        worker()
        return
    if args.command == "prepare":
        if args.model_factory != "inventory" and args.model_factory.count(":") != 1:
            parser.error("model factory must be module:factory")
        result = prepare(args)
    else:
        result = run(args)
    print(json.dumps(result))
