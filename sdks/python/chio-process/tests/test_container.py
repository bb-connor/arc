"""Reject paths that could expand a worker's mount boundary."""

import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chio_process.container import (
    ContainerWorkerError,
    _collect,
    _private_socket,
    _remove_owned,
    run_container_worker,
)


class ContainerLifecycle(unittest.TestCase):
    def test_observed_worker_state_and_cleanup(self):
        cases = [
            ("created", False, "0001-01-01T00:00:00Z", 1, False, False),
            ("running", True, "2026-01-01T00:00:00Z", 1, False, False),
            ("mystery", False, "2026-01-01T00:00:00Z", 0, False, False),
            ("exited", True, "2026-01-01T00:00:00Z", 0, False, False),
            ("exited", False, "0001-01-01T00:00:00Z", 0, False, False),
            ("exited", False, "not-a-timestamp", 0, False, False),
            ("exited", False, "2026-01-01T00:00:00Z", 1, False, True),
            ("exited", False, "2026-01-01T00:00:00Z", 0, True, True),
        ]
        for status, running, started, attach_code, cleanup_failure, completed in cases:
            with self.subTest(
                status=status,
                running=running,
                started=started,
                attach_code=attach_code,
                cleanup_failure=cleanup_failure,
            ):
                self.run_boundary(status, running, started, attach_code, cleanup_failure, completed)

    def test_collection_failure_preserves_completion_and_limit_diagnostic(self):
        for status, running, completed in [("exited", False, True), ("running", True, False)]:
            with self.subTest(status=status):
                self.run_boundary(
                    status, running, "2026-01-01T00:00:00Z", 0, False, completed, output_limit=True
                )

    def test_attachment_cleanup_failure_preserves_completion(self):
        self.run_boundary(
            "exited", False, "2026-01-01T00:00:00Z", 0, False, True, wait_failure=True
        )

    def run_boundary(
        self,
        status,
        running,
        started,
        attach_code,
        cleanup_failure,
        completed,
        output_limit=False,
        wait_failure=False,
    ):
        image = "sha256:" + "1" * 64
        identity = "2" * 64
        nonce = "3" * 32
        record = {
            "Id": identity,
            "Name": f"/chio-worker-{nonce}",
            "Image": image,
            "Config": {"Labels": {"chio.worker.owner": nonce}, "User": "1000:1000"},
            "State": {
                "Status": status,
                "Running": running,
                "StartedAt": started,
                "ExitCode": 0,
                "OOMKilled": False,
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 64,
            },
            "Mounts": [],
        }
        engine = {
            "CgroupVersion": "2",
            "MemoryLimit": True,
            "SwapLimit": True,
            "CpuCfsQuota": True,
            "PidsLimit": True,
            "SecurityOptions": ["name=seccomp,profile=builtin"],
        }

        def docker(*args, **kwargs):
            if args[0] == "info":
                value = engine
            elif args[:2] == ("image", "inspect"):
                value = [{"Id": image, "Config": {}}]
            elif args[0] == "create":
                return SimpleNamespace(stdout=identity.encode(), returncode=0, stderr=b"")
            elif args[0] == "inspect":
                value = [record]
            elif args[0] == "rm":
                self.assertEqual(args, ("rm", "--force", "--volumes", identity))
                if cleanup_failure:
                    raise ContainerWorkerError("cleanup unavailable")
                return SimpleNamespace(stdout=b"", returncode=0, stderr=b"")
            else:
                self.fail(args)
            return SimpleNamespace(stdout=json.dumps(value).encode(), returncode=0, stderr=b"")

        # Only the external engine and its attachment are doubled. Collection,
        # ownership validation, classification and cleanup use production code.
        attachment = subprocess.Popen(
            [
                sys.executable,
                "-c",
                f"print('x' * {8192 if output_limit else 4}); raise SystemExit({attach_code})",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        wait = attachment.wait
        waits = 0

        def wait_for_attachment(*args, **kwargs):
            nonlocal waits
            waits += 1
            if wait_failure and waits > 1:
                raise subprocess.TimeoutExpired("docker start", 10)
            return wait(*args, **kwargs)

        with (
            patch("chio_process.container._docker", side_effect=docker),
            patch("chio_process.container.subprocess.Popen", return_value=attachment),
            patch.object(attachment, "wait", side_effect=wait_for_attachment),
            patch("chio_process.container.os.getuid", return_value=1000),
            patch("chio_process.container._private_socket", return_value=Path("/tmp/worker.sock")),
            patch("chio_process.container.uuid.uuid4", return_value=SimpleNamespace(hex=nonce)),
        ):
            try:
                result = run_container_worker(
                    image=image,
                    connection={"socket_path": "/tmp/worker.sock", "credential": "test-only"},
                    program=b"pass",
                    max_output_bytes=32 if output_limit else 65536,
                )
            except ContainerWorkerError as failure:
                result = getattr(failure, "result", None)
                if output_limit:
                    self.assertIn("output limit", str(failure))
                if not completed:
                    self.assertIsNone(result)
                    return
                self.assertTrue(cleanup_failure or output_limit or wait_failure, str(failure))
            else:
                self.assertTrue(completed, "never-started or unknown worker was reported completed")
                self.assertFalse(cleanup_failure)
            self.assertIsNotNone(result, "known completion was discarded by cleanup")
            self.assertEqual(result.exit_code, 0)

    def test_collect_timeout_and_output_bound(self):
        for code, timeout, maximum, message in [
            ("import time; time.sleep(10)", 0.05, 1024, "wall-clock"),
            ("print('x' * 8192)", 2, 32, "output"),
        ]:
            with self.subTest(message=message):
                process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
                try:
                    with self.assertRaisesRegex(ContainerWorkerError, message):
                        _collect(process, timeout, maximum)
                finally:
                    process.kill()
                    process.wait()
                    process.stdout.close()

    def test_remove_owned_boundary_replies(self):
        identity = "2" * 64
        for reply, refused in [
            (SimpleNamespace(returncode=1, stderr=b"No such object: worker"), False),
            (SimpleNamespace(returncode=1, stderr=b"daemon unavailable"), True),
            (
                SimpleNamespace(
                    returncode=1, stderr=b"daemon proxy error: No such container upstream"
                ),
                True,
            ),
            (
                SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"Id": "--all", "Config": {"Labels": {"chio.worker.owner": "ours"}}}]
                    ).encode(),
                ),
                True,
            ),
            (
                SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"Id": identity, "Config": {"Labels": {"chio.worker.owner": "foreign"}}}]
                    ).encode(),
                ),
                True,
            ),
            (
                SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"Id": identity, "Config": {"Labels": {"chio.worker.owner": "ours"}}}]
                    ).encode(),
                ),
                False,
            ),
        ]:
            with (
                self.subTest(reply=reply),
                patch("chio_process.container._docker", return_value=reply) as control,
            ):
                if refused:
                    with self.assertRaises(ContainerWorkerError):
                        _remove_owned("worker", "ours")
                    self.assertEqual(control.call_count, 1)
                else:
                    _remove_owned("worker", "ours")
                    if not reply.returncode:
                        self.assertEqual(
                            control.call_args.args, ("rm", "--force", "--volumes", identity)
                        )


@unittest.skipUnless(platform.system() == "Linux", "Linux Docker worker profile")
class ContainerBoundaryInputs(unittest.TestCase):
    @unittest.skipIf(os.getuid() == 0, "non-root operator profile")
    def test_unenforceable_resource_limits_stop_before_image_or_worker_creation(self):
        engine = {
            "CgroupVersion": "2",
            "MemoryLimit": True,
            "SwapLimit": True,
            "CpuCfsQuota": True,
            "PidsLimit": True,
            "SecurityOptions": ["name=seccomp,profile=builtin"],
        }
        with tempfile.TemporaryDirectory(prefix="chio-container-cgroups-") as temporary:
            path = Path(temporary) / "worker.sock"
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                path.chmod(0o600)
                for feature in (
                    "MemoryLimit",
                    "SwapLimit",
                    "CpuCfsQuota",
                    "PidsLimit",
                    "CgroupVersion",
                ):
                    for value in (False, None):
                        with self.subTest(feature=feature, value=value):
                            response = SimpleNamespace(
                                stdout=json.dumps({**engine, feature: value}).encode()
                            )
                            with patch(
                                "chio_process.container._docker", return_value=response
                            ) as control:
                                with self.assertRaisesRegex(ValueError, "cgroup"):
                                    run_container_worker(
                                        image="sha256:" + "1" * 64,
                                        connection={
                                            "socket_path": str(path),
                                            "credential": "test-only",
                                        },
                                        program=b"raise SystemExit(0)",
                                    )
                                control.assert_called_once_with("info", "--format", "{{json .}}")

    def test_socket_must_be_private_and_cannot_be_replaced_by_a_symlink(self):
        with tempfile.TemporaryDirectory(prefix="chio-container-input-") as temporary:
            root = Path(temporary)
            path = root / "worker.sock"
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                path.chmod(0o600)
                self.assertEqual(_private_socket(str(path)), path)
                linked = root / "other.sock"
                linked.symlink_to(path)
                with self.assertRaises(ValueError):
                    _private_socket(str(linked))
                path.chmod(0o660)
                with self.assertRaises(ValueError):
                    _private_socket(str(path))
                path.chmod(0o600)
                root.chmod(0o777)
                with self.assertRaises(ValueError):
                    _private_socket(str(path))
                root.chmod(0o700)
                self.assertEqual(_private_socket(str(path)), path)

    def test_mount_option_injection_and_mutable_images_are_refused(self):
        for path in ("/tmp/private.sock,dst=/var/run/docker.sock", "/tmp/private.sock\n"):
            with self.assertRaises(ValueError):
                _private_socket(path)
        if os.getuid() == 0:
            return
        with self.assertRaisesRegex(ValueError, "immutable"):
            run_container_worker(image="python:3.11-slim", connection={}, program=b"pass")


if __name__ == "__main__":
    unittest.main()
