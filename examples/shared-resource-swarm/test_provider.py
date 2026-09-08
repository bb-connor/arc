"""Provider wire and recovery controls with an intercepted HTTP transport."""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from provider import SavedChat, UnknownModelOutcome


class ProviderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "model.db"

    def test_openrouter_request_is_retained_without_credentials_and_reused(self):
        response = {"id": "intercepted-response", "choices": [], "usage": {"cost": 0}}
        calls = []

        def http(request, timeout):
            self.assertEqual(
                request.full_url, "https://openrouter.ai/api/v1/chat/completions"
            )
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture-only")
            self.assertEqual(timeout, 90)
            calls.append(json.loads(request.data))
            with closing(sqlite3.connect(self.database)) as db:
                row = db.execute(
                    "SELECT request, response, kind FROM model_calls"
                ).fetchone()
            self.assertEqual(json.loads(row[0]), calls[0])
            self.assertIsNone(row[1])
            self.assertEqual(row[2], "live_openrouter")
            return io.BytesIO(json.dumps(response).encode())

        with (
            patch.dict(
                "os.environ", {"OPENROUTER_API_KEY": "fixture-only"}, clear=True
            ),
            patch("urllib.request.urlopen", side_effect=http),
        ):
            model = SavedChat(
                self.database, "vendor/model", evidence_kind="live_openrouter"
            )
            self.assertEqual(model.invoke(0, [], []), response)
            recovered = SavedChat(
                self.database, "vendor/model", evidence_kind="live_openrouter"
            )
            self.assertEqual(recovered.invoke(0, [], []), response)
            with self.assertRaisesRegex(ValueError, "provider identity changed"):
                SavedChat(self.database, "vendor/model").invoke(0, [], [])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["max_tokens"], 2048)
        self.assertNotIn("max_completion_tokens", calls[0])
        self.assertEqual(
            calls[0]["provider"], {"allow_fallbacks": False, "require_parameters": True}
        )
        self.assertNotIn(b"fixture-only", self.database.read_bytes())

    def test_openrouter_interrupted_request_is_not_sent_again(self):
        with (
            patch.dict(
                "os.environ", {"OPENROUTER_API_KEY": "fixture-only"}, clear=True
            ),
            patch(
                "urllib.request.urlopen", side_effect=OSError("lost response")
            ) as http,
        ):
            model = SavedChat(
                self.database, "vendor/model", evidence_kind="live_openrouter"
            )
            with self.assertRaises(OSError):
                model.invoke(0, [], [])
            with self.assertRaises(UnknownModelOutcome):
                SavedChat(
                    self.database, "vendor/model", evidence_kind="live_openrouter"
                ).invoke(0, [], [])
            self.assertEqual(http.call_count, 1)

    def test_substitution_cannot_acquire_either_live_provider_label(self):
        for kind in ("live_openai", "live_openrouter"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, "substituted provider"):
                    SavedChat(
                        self.database,
                        "fixture",
                        evidence_kind=kind,
                        transport=lambda _: {},
                    )


if __name__ == "__main__":
    unittest.main()
