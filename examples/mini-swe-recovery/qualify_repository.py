"""Installed repository service: patch export, isolation, interruption and owned cleanup."""

import argparse
import ctypes
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from chio_mini_swe.repository_archive import contents, entries, git, materialize
from chio_mini_swe.repository_store import Workspace
from chio_mini_swe.repository_transport import docker, run

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.pidfd_open.argtypes = [ctypes.c_int, ctypes.c_uint]
LIBC.pidfd_open.restype = ctypes.c_int
LIBC.pidfd_send_signal.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
LIBC.pidfd_send_signal.restype = ctypes.c_int


def command(*arguments, **kwargs):
    return subprocess.run(
        [str(argument) for argument in arguments],
        text=True,
        capture_output=True,
        check=True,
        timeout=120,
        **kwargs,
    ).stdout


def pidfd_open(pid):
    descriptor = LIBC.pidfd_open(pid, 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "Could not pin repository service process")
    return descriptor


def kill_gateway(descriptor):
    if LIBC.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0) < 0:
        raise OSError(ctypes.get_errno(), "Could not stop repository service process")


class RepositoryFixture:
    def __init__(self, root, image, timeout=20):
        self.root = root
        self.source = root / "source"
        self.source.mkdir(mode=0o700)
        git("init", "--quiet", cwd=self.source)
        (self.source / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
        (self.source / "test_calculator.py").write_text(
            "import unittest\nfrom calculator import add\n"
            "class Addition(unittest.TestCase):\n"
            "    def test_positive(self):\n        self.assertEqual(add(2, 3), 5)\n"
            "    def test_negative(self):\n        self.assertEqual(add(-2, -3), -5)\n"
        )
        (self.source / "binary.dat").write_bytes(bytes(range(256)))
        (self.source / "calculator-link").symlink_to("calculator.py")
        git("add", "--all", cwd=self.source)
        git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@localhost",
            "commit",
            "--quiet",
            "-m",
            "repository fixture",
            cwd=self.source,
        )
        self.entrypoint = Path(sys.executable).parent / "chio-mini-swe-repository"
        self.state = root / "repository"
        base = docker("image", "inspect", image["base"], "--format", "{{.Id}}").decode().strip()
        self.initialized = json.loads(
            command(
                self.entrypoint,
                "init",
                "--repository",
                self.source,
                "--revision",
                "HEAD",
                "--image",
                image.get("execution_image", base),
                "--helper-image",
                base,
                "--timeout-seconds",
                timeout,
                "--state",
                self.state,
                cwd=root,
            )
        )
        self.server_command = [str(self.entrypoint), "serve", "--state", str(self.state)]
        # Neither dirty files nor untracked data belong to the selected commit.
        (self.source / "calculator.py").write_text("operator working tree remains untouched\n")
        (self.source / "private-untracked.txt").write_text("fixture-only untracked data\n")
        self.source_hashes = self.hashes()

    def hashes(self):
        return {
            str(path.relative_to(self.source)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.source.rglob("*")
            if path.is_file() and ".git" not in path.parts and not path.is_symlink()
        }

    def read(self, name):
        with Workspace(self.state) as workspace:
            return entries(contents(workspace.snapshot(workspace.status()["snapshot"])))[name][
                2
            ].decode()

    def verify(self, output):
        summary = json.loads(
            command(
                self.entrypoint,
                "verify",
                "--state",
                self.state,
                "--out",
                output,
                "--chio",
                self.root / "chio",
                "--server-id",
                "sandbox",
                "--receipts",
                self.root / "result/receipts.ndjson",
                "--kernel-key",
                self.root / "result/kernel.pub",
                cwd=self.root,
            )
        )
        manifest = json.loads((output / "manifest.json").read_text())
        assert not summary["interrupted"] and summary["revision"] == 5
        assert summary["verified_transitions"] == 5
        assert manifest["source_commit"] == self.initialized["source_commit"]
        commands = json.loads((output / "commands.json").read_text())
        previous = manifest["baseline"]
        for index, record in enumerate(commands, 1):
            binding = record["result"]["workspace"]
            assert binding["id"] == manifest["id"] and binding["revision"] == index
            assert binding["before_sha256"] == record["before_sha256"] == previous
            assert binding["after_sha256"] == record["after_sha256"]
            previous = record["after_sha256"]
        assert previous == manifest["snapshot"]
        assert commands[-1]["result"]["workspace"]["contents_sha256"] == manifest["contents_sha256"]
        files = entries((output / "workspace.tar").read_bytes())
        assert files["calculator.py"][2] == b"def add(a, b):\n    return a + b\n"
        assert files["binary.dat"][2] == bytes(range(256))
        assert files["calculator-link"] == ("symlink", 0o777, b"calculator.py")
        assert "private-untracked.txt" not in files
        assert self.hashes() == self.source_hashes
        target = self.root / "patch-check"
        target.mkdir()
        materialize((output / "baseline.tar").read_bytes(), target)
        git("init", "--quiet", cwd=target)
        run(
            ["/usr/bin/git", "apply", "--check", "-"],
            cwd=target,
            data=(output / "changes.patch").read_bytes(),
        )
        forged = self.root / "forged-receipts.ndjson"
        receipt_rows = [
            json.loads(line) for line in (output / "receipts.ndjson").read_text().splitlines()
        ]
        receipt_rows[-1]["content_hash"] = "0" * 64
        forged.write_text("".join(json.dumps(row) + "\n" for row in receipt_rows))
        invalid_output = self.root / "forged-export"
        rejected = subprocess.run(
            [
                str(self.entrypoint),
                "verify",
                "--state",
                str(self.state),
                "--chio",
                str(self.root / "chio"),
                "--receipts",
                str(forged),
                "--kernel-key",
                str(output / "kernel.pub"),
                "--server-id",
                "sandbox",
                "--out",
                str(invalid_output),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert rejected.returncode and not invalid_output.exists()
        reviewed = json.loads(
            command(
                self.entrypoint,
                "verify-export",
                "--bundle",
                output,
                "--repository",
                self.source,
                "--revision",
                self.initialized["source_commit"],
                "--chio",
                self.root / "chio",
                "--kernel-key",
                self.root / "result/kernel.pub",
                "--server-id",
                "sandbox",
                cwd=self.root,
            )
        )
        assert reviewed["patch_sha256"] == summary["patch_sha256"]
        assert reviewed["verified_transitions"] == 5
        assert self.hashes() == self.source_hashes
        return {
            "source_commit": manifest["source_commit"],
            "workspace": manifest["id"],
            "revision": summary["revision"],
            "patch_sha256": summary["patch_sha256"],
            "source_untouched": True,
            "dirty_and_untracked_excluded": True,
            "binary_and_symlink_preserved": True,
            "patch_applies": True,
            "verified_workspace_transitions": 5,
            "forged_receipt_refused_before_export": True,
            "recipient_verified_export": reviewed,
        }

    def cleanup(self):
        with Workspace(self.state) as workspace:
            workspace.recover()


def stopped(fixture, expression):
    with Workspace(fixture.state) as workspace:
        original = workspace.status()["snapshot"]
        try:
            workspace.execute(expression)
        except (ValueError, RuntimeError, TimeoutError):
            pass
        else:
            raise AssertionError("Expected repository execution to stop")
        report = workspace.status()
        assert report["interrupted"] and report["revision"] == 0
        assert report["snapshot"] == original
        try:
            workspace.execute("printf unexpected")
        except ValueError:
            pass
        else:
            raise AssertionError("Interrupted workspace redispatched a command")
    return {"interrupted": True, "last_snapshot_retained": True, "redispatch_refused": True}


def killed(fixture):
    process = subprocess.Popen(
        fixture.server_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=fixture.root,
    )
    descriptor = pidfd_open(process.pid)
    try:
        request = {
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"command": "printf partial > partial.txt; sleep 20"},
            },
        }
        process.stdin.write(json.dumps(request).encode() + b"\n")
        process.stdin.flush()
        deadline = time.monotonic() + 30
        while True:
            assert process.poll() is None, "Repository service stopped before injected crash"
            with sqlite3.connect(fixture.state / "journal.db") as db:
                row = db.execute(
                    "SELECT holder,worker FROM commands WHERE status='pending'"
                ).fetchone()
            if row and all(row):
                observed = run(
                    [
                        "/usr/bin/docker",
                        "--host",
                        "unix:///var/run/docker.sock",
                        "exec",
                        row[0],
                        "cat",
                        "/workspace/partial.txt",
                    ],
                    allow_failure=True,
                )
                if observed[0] == 0 and observed[1] == b"partial":
                    break
            assert time.monotonic() < deadline, (
                "Repository command never reached its partial effect"
            )
            time.sleep(0.1)
        kill_gateway(descriptor)
        assert process.wait(timeout=5) == -9
        recovered = json.loads(
            command(fixture.entrypoint, "recover", "--state", fixture.state, cwd=fixture.root)
        )
        assert recovered["interrupted"] and recovered["revision"] == 0
        with Workspace(fixture.state) as workspace:
            assert "partial.txt" not in entries(contents(workspace.snapshot(recovered["snapshot"])))
            try:
                workspace.execute("printf replay")
            except ValueError:
                pass
            else:
                raise AssertionError("Killed service replayed an unknown command")
        return {
            "killed_after_partial_effect": True,
            "owned_containers_recovered": True,
            "last_snapshot_retained": True,
            "redispatch_refused": True,
        }
    finally:
        os.close(descriptor)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        fixture.cleanup()


def isolation(fixture):
    os.environ["CHIO_REPOSITORY_FIXTURE_SECRET"] = "operator-only-fixture"
    probe = """import json, os
from pathlib import Path
status = Path('/proc/self/status').read_text()
print(json.dumps({
    'uid': os.getuid(), 'nnp': 'NoNewPrivs:\\t1' in status,
    'caps': 'CapEff:\\t0000000000000000' in status,
    'memory': Path('/sys/fs/cgroup/memory.max').read_text().strip(),
    'swap': Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),
    'pids': Path('/sys/fs/cgroup/pids.max').read_text().strip(),
    'cpu': Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
    'workspace_bytes': os.statvfs('/workspace').f_blocks * os.statvfs('/workspace').f_frsize,
    'host_secret': 'CHIO_REPOSITORY_FIXTURE_SECRET' in os.environ,
    'docker_socket': Path('/var/run/docker.sock').exists(),
    'worker_credential': Path('/run/chio/connection.json').exists(),
}))
"""
    expression = "python - <<'PY'\n" + probe + "PY\n"
    expression += "git ls-files --error-unmatch calculator.py >/dev/null; "
    expression += "printf first > background.txt; (sleep 2; printf late >> background.txt) &"
    with Workspace(fixture.state) as workspace:
        result = workspace.execute(expression)
        assert result["returncode"] == 0
        measured = json.loads(result["output"].splitlines()[0])
        assert measured == {
            "uid": 65534,
            "nnp": True,
            "caps": True,
            "memory": "536870912",
            "swap": "0",
            "pids": "64",
            "cpu": "100000 100000",
            "workspace_bytes": 67108864,
            "host_secret": False,
            "docker_socket": False,
            "worker_credential": False,
        }
    assert fixture.read("background.txt") == "first"
    with Workspace(fixture.state) as workspace:
        for row in workspace.db.execute("SELECT * FROM commands").fetchall():
            owned = workspace.containers(row)
            assert owned.record("worker") is None and owned.record("holder") is None
            assert owned.volume_record() is None
    return {
        "measured_limits": measured,
        "git_index_available": True,
        "background_process_removed": True,
    }


def foreign(fixture, image):
    import uuid

    identifier = (
        docker(
            "create",
            "--name",
            "chio-repository-foreign-" + uuid.uuid4().hex,
            "--label",
            "chio.qualification.foreign=repository",
            "--network=none",
            "--read-only",
            "--entrypoint=/bin/true",
            image["execution_image"],
        )
        .decode()
        .strip()
    )
    try:
        with Workspace(fixture.state) as workspace:
            lease = uuid.uuid4().hex
            with workspace.db:
                workspace.db.execute(
                    "INSERT INTO commands(lease,command,status,before_sha256,worker) "
                    "VALUES (?,'fixture','pending',?,?)",
                    [lease, workspace.status()["snapshot"], identifier],
                )
            try:
                workspace.recover()
            except ValueError:
                pass
            else:
                raise AssertionError("Recovery accepted an unowned container")
            observed = json.loads(docker("inspect", identifier))[0]
            assert (
                observed["Id"] == identifier
                and observed["Config"]["Labels"]["chio.qualification.foreign"] == "repository"
            )
            with workspace.db:
                workspace.db.execute("UPDATE commands SET worker=NULL WHERE lease=?", [lease])
            workspace.recover()
        return {"unowned_container_preserved": True, "ownership_mismatch_refused": True}
    finally:
        observed = json.loads(docker("inspect", identifier))[0]
        assert (
            observed["Id"] == identifier
            and observed["Config"]["Labels"]["chio.qualification.foreign"] == "repository"
        )
        docker("rm", identifier)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="chio-repository-qualification-"))
    args.output.mkdir(parents=True, exist_ok=False)
    image = json.loads(args.worker_image_file.read_text())
    evidence = {"private_state": str(root), "profiles": {}}
    print("Private repository qualification state: " + str(root), flush=True)
    for name, expression in [
        ("isolation_and_git", None),
        ("foreign_ownership", None),
        ("timeout", "printf partial > partial.txt; sleep 10"),
        ("output_bound", "python -c \"print('x'*600000)\""),
        ("serialized_output_bound", 'python -c "print(chr(0)*81000)"'),
        ("escaping_link", "ln -s /etc/passwd outside"),
        ("special_file", "mkfifo unsupported-fifo"),
        ("service_kill", None),
    ]:
        directory = root / name
        directory.mkdir(mode=0o700)
        fixture = RepositoryFixture(directory, image, timeout=30 if expression is None else 1)
        try:
            if name == "isolation_and_git":
                evidence["profiles"][name] = isolation(fixture)
            elif name == "foreign_ownership":
                evidence["profiles"][name] = foreign(fixture, image)
            else:
                evidence["profiles"][name] = (
                    killed(fixture) if expression is None else stopped(fixture, expression)
                )
            print("Passed repository profile: " + name, flush=True)
        finally:
            fixture.cleanup()
    (args.output / "qualification.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
