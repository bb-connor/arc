import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from chio_process import MAX_RESPONSE_BYTES, PROTOCOL, ProcessClient, WorkerError


class ClientTests(unittest.TestCase):
    def exchange(self, payload, operation):
        requests = []
        with tempfile.TemporaryDirectory(prefix="chio-py-") as directory:
            path = str(Path(directory) / "s")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(3)

                def serve():
                    with listener.accept()[0] as stream:
                        data = bytearray()
                        while b"\n" not in data:
                            chunk = stream.recv(8192)
                            if not chunk:
                                return
                            data.extend(chunk)
                        requests.append(json.loads(data))
                        try:
                            stream.sendall(payload)
                        except BrokenPipeError:
                            pass

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    operation(ProcessClient(path, "test-secret", timeout=1))
                finally:
                    thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
        self.assertEqual(len(requests), 1)
        return requests[0]

    def test_preserves_signed_json_and_large_decimal_revision(self):
        receipt = '{"counter":18446744073709551615,"text":"λ"}'
        payload = (json.dumps({"protocol": PROTOCOL, "ok": True, "result": {
            "receipt_json": receipt, "revision": "9007199254740994",
        }}, ensure_ascii=False) + "\n").encode()

        def run(client):
            self.assertNotIn("test-secret", repr(client))
            result = client.checkpoint("9007199254740993", {})
            self.assertEqual(result["receipt_json"], receipt)
            self.assertEqual(result["revision"], "9007199254740994")

        request = self.exchange(payload, run)
        self.assertEqual(request["operation"]["expected_revision"], "9007199254740993")

    def test_invalid_response_and_oversized_response_fail_without_retry(self):
        for payload, code in [
            (b'{"protocol":"other","ok":true,"result":{}}\n', "invalid_response"),
            (b'{"protocol":"chio.process.v1","ok":true}\n', "invalid_response"),
            (b'\xff\n', "invalid_response"),
            (b'{"protocol":', "truncated_response"),
            (b'x' * (MAX_RESPONSE_BYTES + 1), "response_too_large"),
            (b'{"protocol":"chio.process.v1","ok":false,"error":{"code":"unauthenticated"}}\n',
             "unauthenticated"),
        ]:
            with self.subTest(code=code):
                def run(client, expected_code=code):
                    with self.assertRaises(WorkerError) as caught:
                        client.invoke("publish", "tools", "append", {})
                    self.assertEqual(caught.exception.code, expected_code)
                self.exchange(payload, run)

    def test_nonfinite_input_fails_before_connecting(self):
        client = ProcessClient("/absent", "test-secret")
        for number in [float("nan"), float("inf")]:
            with self.assertRaises(ValueError):
                client.invoke("one", "tools", "read", {"value": number})


if __name__ == "__main__":
    unittest.main()
