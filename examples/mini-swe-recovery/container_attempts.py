"""Operator-side qualification; worker data never selects a host output path."""

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from chio_process import container as container_support
from chio_process.container import ContainerWorkerError, run_container_worker

HERE = Path(__file__).resolve().parent


class ContainerAttempts:
    def __init__(self, image, directory):
        self.image = image
        self.directory = directory
        self.connection = json.loads((directory / "connection.json").read_text())
        self.evidence = {}

    def invoke(self, program, **kwargs):
        return run_container_worker(
            image=self.image,
            connection=self.connection,
            program=program,
            **kwargs,
        )

    def probe(self):
        canary = self.directory / "operator-only-canary"
        canary.write_text("worker must not read this host file")
        result = self.invoke(
            (HERE / "probe_worker.py").read_bytes(),
            arguments=[str(canary), str(self.directory / "host/authority.db")],
        )
        assert result.exit_code == 0, result.output.decode()
        profile = result.profile
        assert profile["network"] == "none" and profile["readonly_rootfs"]
        assert profile["cap_drop"] == ["ALL"]
        assert profile["memory_bytes"] == 512 * 1024 * 1024 and profile["pids_limit"] == 64
        assert {mount["destination"] for mount in profile["mounts"] if mount["type"] == "bind"} == {
            "/run/chio/process.sock",
            "/run/chio/connection.json",
            "/app/worker.py",
        }
        assert all(not mount["writable"] for mount in profile["mounts"] if mount["type"] == "bind")
        self.evidence = {"probe": json.loads(result.output), "profile": profile}
        assert (
            self.evidence["probe"]["launcher_sha256"]
            == hashlib.sha256(Path(container_support.__file__).read_bytes()).hexdigest()
        )
        assert canary.read_text() == "worker must not read this host file"
        # These programs need no Chio operations. Failures must remove the
        # container itself, not just its docker start --attach client.
        before = self._workers()
        for program, options, message in [
            (b"import time\nwhile True: time.sleep(1)\n", {"timeout": 2}, "wall-clock"),
            (
                b"import os\nwhile True: os.write(1, b'x'*8192)\n",
                {"max_output_bytes": 65536},
                "output limit",
            ),
        ]:
            try:
                self.invoke(program, **options)
            except ContainerWorkerError as error:
                assert message in str(error)
            else:
                raise AssertionError("Unbounded worker completed without enforcement")
            assert self._workers() == before
        self.evidence["timeout_and_output_cleanup"] = True
        self._reject_image_volume()

    def _reject_image_volume(self):
        def docker(*args):
            return subprocess.run(
                ["docker", "--host", "unix:///var/run/docker.sock", *args],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            ).stdout.strip()

        fixture = docker("create", "--pull=never", self.image)
        altered = None
        try:
            altered = docker("commit", "--change", "VOLUME /unbounded-storage", fixture)
            try:
                run_container_worker(
                    image=altered,
                    connection=self.connection,
                    program=b"print('must not start')",
                )
            except ValueError as error:
                assert "writable volumes" in str(error)
            else:
                raise AssertionError("Image supplied an undeclared writable mount")
            self.evidence["image_volume_refused"] = True
        finally:
            docker("rm", "--force", fixture)
            if altered is not None:
                docker("image", "rm", "--no-prune", altered)

    @staticmethod
    def _workers():
        return subprocess.run(
            [
                "docker",
                "--host",
                "unix:///var/run/docker.sock",
                "ps",
                "--all",
                "--quiet",
                "--filter",
                "label=chio.worker.owner",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.splitlines()

    def run(self, crash=False):
        result = self.invoke(
            (HERE / "worker.py").read_bytes(),
            arguments=["/work", "--container", *(["--crash"] if crash else [])],
        )
        output = result.output.decode()
        events = [json.loads(line) for line in output.splitlines() if line.startswith('{"event":')]
        if result.exit_code == 0:
            assert sum(event["event"] == "complete" for event in events) == 1, output
        elif crash and result.exit_code == 137:
            assert sum(event["event"] == "before_crash" for event in events) == 1, output
            assert all(event["event"] != "complete" for event in events), output
        for event in events:
            if event["event"] == "model_query":
                with (self.directory / "provider-calls.jsonl").open("a") as stream:
                    stream.write(json.dumps(event) + "\n")
            elif event["event"] == "before_crash":
                (self.directory / "before-crash.receipt.json").write_text(event["receipt"])
            elif event["event"] == "complete":
                (self.directory / "result.json").write_text(json.dumps(event["result"]))
                (self.directory / "trajectory.json").write_text(json.dumps(event["trajectory"]))
                (self.directory / "receipts.ndjson").write_text("\n".join(event["receipts"]) + "\n")
        self.evidence.setdefault("attempts", []).append(
            {
                "exit_code": result.exit_code,
                "container_id": result.container_id,
                "image": result.profile["image"],
            }
        )
        return SimpleNamespace(returncode=result.exit_code, stdout=output, stderr="")
