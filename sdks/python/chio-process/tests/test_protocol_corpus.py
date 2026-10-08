"""Check the client and the published schemas against the shared corpus.

spec/fixtures/chio-process-v1.json is the conformance corpus for the
chio.process.v1 worker protocol. The Rust worker and the Node client consume
the same file.
"""

import base64
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

import chio_process
from chio_process import ProcessClient, WorkerError

CORPUS_FILE = "spec/fixtures/chio-process-v1.json"


def locate_corpus():
    """Use CHIO_PROCESS_PROTOCOL_CORPUS, else the source tree holding these tests."""
    configured = os.environ.get("CHIO_PROCESS_PROTOCOL_CORPUS")
    if configured:
        return Path(configured)
    for parent in Path(__file__).resolve().parents:
        if (parent / CORPUS_FILE).is_file():
            return parent / CORPUS_FILE
    return None


CORPUS_PATH = locate_corpus()
CORPUS = None if CORPUS_PATH is None else json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
ROOT = None if CORPUS_PATH is None else CORPUS_PATH.parents[2]
MARKER = None if CORPUS is None else CORPUS["fill_marker"]
CREDENTIAL = None if CORPUS is None else CORPUS["fixture_credential"]
NO_CORPUS = "the shared corpus is outside this copy of the tests"


def filled(value, fill):
    """Expand the corpus fill marker inside every string of value."""
    if fill is None:
        return value
    if isinstance(value, str):
        return value.replace(MARKER, fill["char"] * fill["count"])
    if isinstance(value, list):
        return [filled(item, fill) for item in value]
    if isinstance(value, dict):
        return {key: filled(item, fill) for key, item in value.items()}
    return value


def call(client, spec):
    op = spec["op"]
    if op == "inspect":
        return client.inspect()
    if op == "invoke":
        options = {
            name: spec[name] for name in ("known_outcome_only", "governed_intent") if name in spec
        }
        key, server, tool = spec["operation_key"], spec["server_id"], spec["tool_name"]
        return client.invoke(key, server, tool, spec["arguments"], **options)
    if op == "prepare_invocation":
        return client.prepare_invocation(
            spec["operation_key"], spec["server_id"], spec["tool_name"], spec["arguments"]
        )
    if op == "checkpoint":
        return client.checkpoint(spec["expected_revision"], spec["value"])
    if op == "blob_put":
        return client.put_blob(bytes.fromhex(spec["data_hex"]))
    if op == "blob_read":
        return {"data_hex": client.read_blob(spec["sha256"]).hex()}
    if op == "cancel":
        return client.cancel()
    raise AssertionError(f"unknown corpus operation {op}")


def response_bytes(case):
    if "response_base64" in case:
        return base64.b64decode(case["response_base64"])
    return filled(case["response"], case.get("fill")).encode("utf-8")


class StubHost:
    """Accept one connection, record its request line and reply with fixed bytes."""

    def __init__(self, directory, response):
        self.path = str(Path(directory) / "s")
        self.response = response
        self.requests = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        with self.listener, self.listener.accept()[0] as stream:
            data = bytearray()
            while b"\n" not in data:
                chunk = stream.recv(65536)
                if not chunk:
                    return
                data.extend(chunk)
            self.requests.append(bytes(data))
            try:
                stream.sendall(self.response)
            except OSError:
                # The client may stop reading once a response exceeds its limit.
                pass


@unittest.skipIf(CORPUS is None, NO_CORPUS)
class ClientCorpusTests(unittest.TestCase):
    def test_limits_and_identifiers_match_the_corpus(self):
        limits = CORPUS["limits"]
        self.assertEqual(chio_process.PROTOCOL, CORPUS["protocol"])
        self.assertEqual(chio_process.MAX_REQUEST_BYTES, limits["max_request_bytes"])
        self.assertEqual(chio_process.MAX_RESPONSE_BYTES, limits["max_response_bytes"])
        self.assertEqual(chio_process.MAX_STATE_BLOB_BYTES, limits["max_state_blob_bytes"])

    def test_client_cases(self):
        for case in CORPUS["client"]["cases"]:
            with self.subTest(case=case["name"]):
                self.run_case(case)

    def run_case(self, case):
        fill = case.get("fill")
        spec = filled(case["call"], fill)
        if case.get("sent") is False:
            # A client that tried to connect would report transport_error instead.
            self.check_outcome(case, lambda: call(ProcessClient("/absent", CREDENTIAL), spec))
            return
        with tempfile.TemporaryDirectory(prefix="chio-py-") as directory:
            host = StubHost(directory, response_bytes(case))
            client = ProcessClient(host.path, CREDENTIAL, timeout=10)
            self.check_outcome(case, lambda: call(client, spec))
            host.thread.join(timeout=10)
            self.assertFalse(host.thread.is_alive())
        self.assertEqual(len(host.requests), 1)
        sent = host.requests[0]
        if "request" in case:
            self.assertEqual(sent, filled(case["request"], fill).encode("utf-8"))
        self.assertTrue(sent.endswith(b"\n"))
        self.assertEqual(sent.count(b"\n"), 1)
        self.assertLessEqual(len(sent), CORPUS["limits"]["max_request_bytes"])

    def check_outcome(self, case, operation):
        if case.get("error") == "invalid_argument":
            with self.assertRaises((ValueError, TypeError)):
                operation()
        elif "error" in case:
            with self.assertRaises(WorkerError) as caught:
                operation()
            self.assertEqual(caught.exception.code, case["error"])
        elif "result" in case:
            self.assertEqual(operation(), case["result"])
        else:
            self.assertTrue(case["accepted"])
            self.assertIsInstance(operation(), dict)

    def test_deeply_nested_response_is_an_invalid_response(self):
        nested = b'{"protocol":"chio.process.v1","ok":true,"result":{"n":' + b"[" * 100_000
        with tempfile.TemporaryDirectory(prefix="chio-py-") as directory:
            host = StubHost(directory, nested + b"]" * 100_000 + b"}}\n")
            client = ProcessClient(host.path, CREDENTIAL, timeout=10)
            with self.assertRaises(WorkerError) as caught:
                client.inspect()
            host.thread.join(timeout=10)
        self.assertEqual(caught.exception.code, "invalid_response")


try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None


@unittest.skipIf(CORPUS is None, NO_CORPUS)
@unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
class SchemaCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        resources = []
        for directory in ("chio-process/v1", "chio-wire/v1/agent"):
            for path in sorted((ROOT / "spec/schemas" / directory).glob("*.schema.json")):
                schema = json.loads(path.read_text(encoding="utf-8"))
                if "$id" in schema:
                    resources.append((schema["$id"], Resource.from_contents(schema)))
        cls.registry = Registry().with_resources(resources)
        cls.request = json.loads((ROOT / CORPUS["schemas"]["request"]).read_text(encoding="utf-8"))
        cls.response = json.loads(
            (ROOT / CORPUS["schemas"]["response"]).read_text(encoding="utf-8")
        )
        for schema in (cls.request, cls.response):
            Draft202012Validator.check_schema(schema)

    def validator(self, schema):
        return Draft202012Validator(schema, registry=self.registry)

    def result_validator(self, name):
        self.assertIn(name, self.response["$defs"])
        return self.validator({"$ref": f"{self.response['$id']}#/$defs/{name}"})

    def test_request_frames_match_their_schema_verdicts(self):
        validator = self.validator(self.request)
        for case in CORPUS["server"]["cases"]:
            if case["schema_valid"] is None:
                continue
            with self.subTest(case=case["name"]):
                frame = json.loads(filled(case["frame"], case.get("fill")))
                self.assertEqual(validator.is_valid(frame), case["schema_valid"])

    def test_server_results_match_the_result_schemas(self):
        for case in CORPUS["server"]["cases"]:
            expect = case["expect"]
            with self.subTest(case=case["name"]):
                if "error" in expect:
                    self.assertIn(expect["error"], self.response["$defs"]["ErrorCode"]["enum"])
                    continue
                definition = self.response["$defs"][expect["result_schema"]]
                if "result_keys" in expect:
                    keys = set(expect["result_keys"])
                    self.assertLessEqual(set(definition["required"]), keys)
                    self.assertLessEqual(keys, set(definition["properties"]))
                if "result" in expect:
                    validator = self.result_validator(expect["result_schema"])
                    self.assertTrue(validator.is_valid(expect["result"]))

    def test_client_responses_a_host_may_send_match_the_schema(self):
        envelope = self.validator(self.response)
        for case in CORPUS["client"]["cases"]:
            if not case.get("server_response"):
                continue
            with self.subTest(case=case["name"]):
                response = json.loads(response_bytes(case))
                self.assertTrue(envelope.is_valid(response))
                if "result_schema" in case:
                    validator = self.result_validator(case["result_schema"])
                    self.assertTrue(validator.is_valid(response["result"]))

    def test_client_request_frames_match_the_request_schema(self):
        validator = self.validator(self.request)
        for case in CORPUS["client"]["cases"]:
            if "request" not in case:
                continue
            with self.subTest(case=case["name"]):
                frame = json.loads(filled(case["request"], case.get("fill")))
                self.assertTrue(validator.is_valid(frame))

    def test_error_vocabulary_matches_the_schema(self):
        self.assertEqual(CORPUS["server_error_codes"], self.response["$defs"]["ErrorCode"]["enum"])


if __name__ == "__main__":
    unittest.main()
