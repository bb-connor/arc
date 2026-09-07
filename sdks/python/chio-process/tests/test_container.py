"""Reject paths that could expand a worker's mount boundary."""

import os
import platform
import socket
import tempfile
import unittest
from pathlib import Path

from chio_process.container import _private_socket, run_container_worker


@unittest.skipUnless(platform.system() == "Linux", "Linux Docker worker profile")
class ContainerBoundaryInputs(unittest.TestCase):
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
