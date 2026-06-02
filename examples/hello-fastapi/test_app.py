from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import build_chio_config, create_app


class FastAPIAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app(enable_chio=False))

    def test_healthz(self) -> None:
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_hello(self) -> None:
        response = self.client.get("/hello")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "hello from fastapi"})

    def test_echo_defaults_count(self) -> None:
        response = self.client.post("/echo", json={"message": "hello"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "hello", "count": 1})

    def test_echo_requires_nonempty_message(self) -> None:
        response = self.client.post("/echo", json={"message": "", "count": 1})

        self.assertEqual(response.status_code, 422)

    def test_echo_rejects_coerced_count(self) -> None:
        response = self.client.post("/echo", json={"message": "hello", "count": "2"})

        self.assertEqual(response.status_code, 422)

    def test_echo_rejects_boolean_count(self) -> None:
        response = self.client.post("/echo", json={"message": "hello", "count": True})

        self.assertEqual(response.status_code, 422)

    def test_echo_rejects_extra_fields(self) -> None:
        response = self.client.post(
            "/echo",
            json={"message": "hello", "count": 1, "admin": True},
        )

        self.assertEqual(response.status_code, 422)

    def test_builtin_docs_are_disabled(self) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)


class ChioConfigTests(unittest.TestCase):
    def test_explicit_sidecar_config_is_fail_closed(self) -> None:
        config = build_chio_config("http://127.0.0.1:9555")

        self.assertEqual(config.sidecar_url, "http://127.0.0.1:9555")
        self.assertEqual(config.exclude_paths, frozenset({"/healthz"}))
        self.assertFalse(config.fail_open)
        self.assertEqual(config.receipt_header, "X-Chio-Receipt")

    def test_sidecar_config_reads_environment(self) -> None:
        with patch.dict(os.environ, {"CHIO_SIDECAR_URL": "http://127.0.0.1:9444"}):
            config = build_chio_config()

        self.assertEqual(config.sidecar_url, "http://127.0.0.1:9444")


if __name__ == "__main__":
    unittest.main()
