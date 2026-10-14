"""Exercise remote-I/O refusal, loopback mediation and ready publication."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from qualification_runtime import disable_telemetry, model_free_network_guard, native_environment, wait_endpoint


class QualificationRuntimeTest(unittest.TestCase):
    def test_supported_host_import_controls_disable_telemetry_and_remote_cost_lookup(self):
        with patch.dict(os.environ, {}, clear=True):
            disable_telemetry()
            self.assertEqual(os.environ.get("OTEL_SDK_DISABLED"), "true")
            self.assertEqual(os.environ.get("CREWAI_TELEMETRY_DISABLED"), "true")
            self.assertEqual(os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP"), "True")

    def test_model_free_guard_counts_and_refuses_remote_resolution_and_connect(self):
        with model_free_network_guard() as attempts:
            with self.assertRaisesRegex(RuntimeError, "qualification.model_free_remote_io"):
                socket.getaddrinfo("remote.invalid", 443)
            with socket.socket() as connection:
                with self.assertRaisesRegex(RuntimeError, "qualification.model_free_remote_io"):
                    connection.connect_ex(("203.0.113.1", 443))
        self.assertEqual(attempts, [{"operation":"resolve", "destination":"non_loopback"},
                                    {"operation":"connect_ex", "destination":"non_loopback"}])

    def test_native_loopback_remains_usable_without_a_provider_attempt(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(2)
            with model_free_network_guard() as attempts:
                with socket.create_connection(listener.getsockname(), timeout=2) as client:
                    connection, _ = listener.accept()
                    with connection:
                        client.sendall(b"owned-native-call")
                        self.assertEqual(connection.recv(64), b"owned-native-call")
            self.assertEqual(attempts, [])

    def test_created_empty_ready_file_is_not_an_endpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ready"
            path.write_text("")
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
            def publish():
                time.sleep(0.1)
                path.write_text("http://127.0.0.1:20096\n")
            publisher = threading.Thread(target=publish)
            publisher.start()
            try:
                self.assertEqual(wait_endpoint(path, process, 1), "http://127.0.0.1:20096")
            finally:
                publisher.join()
                process.terminate()
                process.wait(timeout=2)

    def test_fixed_native_host_ready_port_cannot_select_another_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ready"
            path.write_text("20096\n")
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
            try:
                self.assertEqual(wait_endpoint(path, process, 1, fixed_port=20096), "http://127.0.0.1:20096")
                path.write_text("20097\n")
                with self.assertRaises(TimeoutError):
                    wait_endpoint(path, process, 0.1, fixed_port=20096)
                path.write_text("http://127.0.0.1:20097\n")
                with self.assertRaises(TimeoutError):
                    wait_endpoint(path, process, 0.1, fixed_port=20096)
            finally:
                process.terminate()
                process.wait(timeout=2)

    def test_valid_but_unframed_endpoint_prefix_is_not_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ready"
            path.write_text("http://127.0.0.1:2")
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
            def publish():
                time.sleep(0.1)
                path.write_text("http://127.0.0.1:20096\n")
            publisher = threading.Thread(target=publish)
            publisher.start()
            try:
                self.assertEqual(wait_endpoint(path, process, 1), "http://127.0.0.1:20096")
            finally:
                publisher.join()
                process.terminate()
                process.wait(timeout=2)

    def test_native_environment_is_closed_not_a_credential_denylist(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"PATH":"/usr/bin:/bin", "NEW_PROVIDER_SECRET":"synthetic",
                                         "OPENAI_API_KEY":"synthetic", "PYTHONPATH":"foreign",
                                         "HTTP_PROXY":"http://foreign.invalid"}, clear=True):
                observed = native_environment("CHIO_RECOVERY_CAMPAIGN_EXCHANGE", Path(temporary))
            self.assertEqual(observed, {"PATH":"/usr/bin:/bin", "CARGO_NET_OFFLINE":"true",
                                       "CHIO_RECOVERY_CAMPAIGN_EXCHANGE":str(Path(temporary).resolve())})


if __name__ == "__main__":
    unittest.main()
