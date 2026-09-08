"""Retain complete provider responses before LangGraph can dispatch tools."""

import json
import os
import sqlite3
import time
import urllib.request
from contextlib import closing

from store import encoded


class UnknownModelOutcome(RuntimeError):
    """An earlier request started without a retained complete response."""


def openai_chat(request):
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is required for a new provider request")
    query = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=encoded(request).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    # No automatic retry. A failure may occur after provider acceptance.
    with urllib.request.urlopen(query, timeout=90) as response:
        body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        raise ValueError("provider response exceeds 1 MiB")
    return json.loads(body)


class SavedChat:
    """Application model journal; it owns no tool authority or effect recovery."""

    def __init__(
        self, path, model, *, transport=openai_chat, evidence_kind="live_openai"
    ):
        self.path, self.model = path, model
        self.transport, self.evidence_kind = transport, evidence_kind
        if evidence_kind not in ("live_openai", "scripted_test"):
            raise ValueError("unknown provider evidence kind")
        if transport is not openai_chat and evidence_kind == "live_openai":
            raise ValueError("a substituted provider cannot be labeled live OpenAI")
        with closing(self.connection()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS model_calls (
                turn INTEGER PRIMARY KEY, request TEXT NOT NULL, response TEXT,
                kind TEXT NOT NULL, elapsed_seconds REAL)""")

    def connection(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def invoke(self, turn, messages, tools):
        request = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "max_completion_tokens": 2048,
            "parallel_tool_calls": False,
        }
        body = encoded(request)
        with closing(self.connection()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            saved = db.execute(
                "SELECT request, response, kind FROM model_calls WHERE turn=?", (turn,)
            ).fetchone()
            if saved:
                if saved[0] != body or saved[2] != self.evidence_kind:
                    raise ValueError("saved model request or provider identity changed")
                if saved[1] is None:
                    raise UnknownModelOutcome(
                        "model outcome is unknown; automatic retry refused"
                    )
                return json.loads(saved[1])
            db.execute(
                "INSERT INTO model_calls VALUES(?, ?, NULL, ?, NULL)",
                (turn, body, self.evidence_kind),
            )
        started = time.monotonic()
        result = self.transport(request)
        # Persist the original complete response, including provider and tool IDs,
        # before returning anything that can become an executable graph message.
        response = encoded(result)
        with closing(self.connection()) as db, db:
            changed = db.execute(
                "UPDATE model_calls SET response=?, elapsed_seconds=? "
                "WHERE turn=? AND request=? AND response IS NULL",
                (response, time.monotonic() - started, turn, body),
            ).rowcount
            if changed != 1:
                raise RuntimeError("model journal transition conflict")
        return result

    def evidence(self):
        with closing(self.connection()) as db:
            return [
                {
                    "turn": turn,
                    "kind": kind,
                    "elapsed_seconds": elapsed,
                    "complete": response is not None,
                    "response": None if response is None else json.loads(response),
                }
                for turn, kind, elapsed, response in db.execute(
                    "SELECT turn, kind, elapsed_seconds, response FROM model_calls ORDER BY turn"
                )
            ]
