"""Exercise the real schema bundler without downloading or mocking codegen."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("regen-types.sh")
ROOT = SCRIPT.resolve().parents[4]


def bundler_source():
    # Execute the embedded Python used by the shell pipeline, with independent
    # fixture inputs. The assertions inspect its output and refusal behavior.
    start = 'python3 - "${SCHEMAS_DIR}" "${OPENAPI_PATH}" <<\'PY\'\n'
    script = SCRIPT.read_text(encoding="utf-8")
    offset = script.index(start) + len(start)
    return script[offset : script.index("\nPY\n", offset)]


class SchemaPointerBundlerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "schemas"
        self.root.mkdir()
        self.output = Path(self.directory.name) / "bundle.json"

    def write(self, name, schema):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(schema), encoding="utf-8")
        return path

    def bundle(self, root=None):
        return subprocess.run(
            [sys.executable, "-", str(root or self.root), str(self.output)],
            input=bundler_source(),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def components(self):
        return json.loads(self.output.read_text())['components']['schemas']

    def test_unknown_remote_reference_refuses_before_codegen(self):
        for ref in [
            "https://untrusted.invalid/schema.json#/payload",
            "https:untrusted.invalid/schema.json#/payload",
            "urn:untrusted:schema#/payload",
        ]:
            with self.subTest(ref=ref):
                self.output.unlink(missing_ok=True)
                self.write("caller/request.schema.json", {
                    "type": "object", "properties": {"input": {"$ref": ref}},
                })
                result = self.bundle()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("remote", result.stderr)
                self.assertFalse(self.output.exists())

    def resolve(self, components, schema):
        visited = set()
        while isinstance(schema, dict) and "$ref" in schema:
            ref = schema["$ref"]
            self.assertTrue(ref.startswith("#/components/schemas/"), ref)
            self.assertNotIn(ref, visited, "unexpected alias cycle")
            visited.add(ref)
            schema = components[ref.removeprefix("#/components/schemas/")]
        return schema

    def test_cross_file_property_keeps_target_document_reference_context(self):
        self.write("common/count.schema.json", {"type": "integer", "minimum": 1})
        self.write("target/record.schema.json", {
            "type": "object",
            "properties": {"body": {
                "type": "object",
                "required": ["status", "count"],
                "properties": {
                    "status": {"$ref": "#/$defs/state"},
                    "count": {"$ref": "../common/count.schema.json"},
                },
            }},
            "$defs": {"state": {"type": "string", "enum": ["closed", "pending"]}},
        })
        self.write("caller/request.schema.json", {
            "type": "object",
            "properties": {"claim": {"$ref": "../target/record.schema.json#/properties/body"}},
            "$defs": {"state": {"type": "boolean"}},
        })
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        body = self.resolve(components, components["CallerRequest"]["properties"]["claim"])
        self.assertEqual(body["required"], ["status", "count"])
        state = self.resolve(components, body["properties"]["status"])
        self.assertEqual(state, {"type": "string", "enum": ["closed", "pending"]})
        count = self.resolve(components, body["properties"]["count"])
        self.assertEqual(count, {"type": "integer", "format": "int64", "minimum": 1})

    def test_existing_definition_component_names_and_local_refs_are_preserved(self):
        self.write("target/record.schema.json", {
            "type": "object",
            "properties": {"state": {"$ref": "#/$defs/state"}},
            "$defs": {"state": {"type": "string"}},
        })
        self.write("caller/request.schema.json", {"$ref": "../target/record.schema.json#/$defs/state"})
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        expected = {"$ref": "#/components/schemas/TargetRecordState"}
        self.assertEqual(components["CallerRequest"], expected)
        self.assertEqual(components["TargetRecord"]["properties"]["state"], expected)
        self.assertEqual(components["TargetRecordState"], {"type": "string"})

    def test_declared_schema_ids_resolve_to_local_components_without_network_input(self):
        self.write("target/record.schema.json", {
            "$id": "https://schema.invalid/retained-record/v1",
            "type": "object",
            "properties": {"body": {"$ref": "#/$defs/state"}},
            "$defs": {"state": {"type": "string", "enum": ["closed"]}},
        })
        self.write("caller/request.schema.json", {
            "type": "object",
            "properties": {
                "record": {"$ref": "https://schema.invalid/retained-record/v1"},
                "body": {"$ref": "https://schema.invalid/retained-record/v1#/properties/body"},
            },
        })
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        refs = components["CallerRequest"]["properties"]
        self.assertEqual(refs["record"], {"$ref": "#/components/schemas/TargetRecord"})
        self.assertEqual(self.resolve(components, refs["body"]), {
            "type": "string", "enum": ["closed"],
        })

    def test_pointer_escapes_and_percent_encoding_select_the_exact_property(self):
        self.write("target/record.schema.json", {
            "type": "object",
            "properties": {"reported/title~raw": {"type": "string", "maxLength": 17}},
        })
        self.write("caller/request.schema.json", {
            "$ref": "../target/record.schema.json#%2Fproperties%2Freported~1title~0raw",
        })
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        self.assertEqual(self.resolve(components, components["CallerRequest"]), {
            "type": "string", "maxLength": 17,
        })

    def test_lifted_property_can_refer_to_another_local_property(self):
        self.write("target/record.schema.json", {
            "type": "object",
            "properties": {
                "body": {"type": "object", "properties": {"status": {"$ref": "#/properties/status"}}},
                "status": {"type": "string", "enum": ["closed"]},
            },
        })
        self.write("caller/request.schema.json", {"$ref": "../target/record.schema.json#/properties/body"})
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        body = self.resolve(components, components["CallerRequest"])
        self.assertEqual(self.resolve(components, body["properties"]["status"]), {
            "type": "string", "enum": ["closed"],
        })

    def test_recursive_property_lifting_is_finite(self):
        self.write("target/record.schema.json", {
            "properties": {"body": {
                "type": "object",
                "properties": {"next": {"$ref": "#/properties/body"}},
            }},
        })
        self.write("caller/request.schema.json", {"$ref": "../target/record.schema.json#/properties/body"})
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        body = self.resolve(components, components["CallerRequest"])
        self.assertEqual(self.resolve(components, body["properties"]["next"]), body)
        self.assertLess(len(components), 8)

    def test_missing_or_non_schema_targets_refuse_without_an_output(self):
        for ref, document in [
            ("../target/record.schema.json#/properties/missing", {"properties": {}}),
            ("../target/record.schema.json#/$defs/missing", {"$defs": {}}),
            ("../target/record.schema.json#/title", {"title": "not a schema"}),
            ("../target/absent.schema.json", {}),
            ("../target/record.schema.json#/properties/invalid~2escape", {"properties": {}}),
            ("../target/record.schema.json#%GG", {}),
        ]:
            with self.subTest(ref=ref):
                self.output.unlink(missing_ok=True)
                self.write("target/record.schema.json", document)
                self.write("caller/request.schema.json", {"$ref": ref})
                result = self.bundle()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())

    def test_target_cannot_escape_the_schema_root(self):
        outside = Path(self.directory.name) / "outside.schema.json"
        outside.write_text('{"type":"string"}')
        self.write("caller/request.schema.json", {"$ref": "../../outside.schema.json"})
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escapes the schema root", result.stderr)
        self.assertFalse(self.output.exists())

    def test_current_recovery_origins_and_all_local_components_resolve(self):
        result = self.bundle(ROOT / "spec/schemas/chio-wire/v1")
        self.assertEqual(result.returncode, 0, result.stderr)
        components = self.components()
        action = components["RecoveryActionIntent"]
        self.assertNotIn("origin", action["required"])
        origin = action["properties"]["origin"]
        self.assertEqual(origin["required"], ["operation", "request_id", "closure"])
        operation_ref = origin["properties"]["operation"]
        self.assertEqual(operation_ref, {"$ref": "#/components/schemas/RecoveryObservationOperation"})
        operation = self.resolve(components, operation_ref)
        self.assertEqual(operation["required"], [
            "operation_id", "native_admission_digest", "operation_version",
        ])

        def check_refs(node):
            if isinstance(node, dict):
                ref = node.get("$ref", "")
                if ref.startswith("#/components/schemas/"):
                    self.assertIn(ref.removeprefix("#/components/schemas/"), components, ref)
                self.assertNotIn("://", ref, "current wire schemas must use their bundled identity")
                for value in node.values():
                    check_refs(value)
            elif isinstance(node, list):
                for value in node:
                    check_refs(value)

        check_refs(components)


class StagedCodegenTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "workspace"
        self.schemas = self.root / "spec/schemas/chio-wire/v1"
        shutil.copytree(ROOT / "spec/schemas/chio-wire/v1", self.schemas)
        self.scripts = self.root / "sdks/go/chio-go-http/scripts"
        shutil.copytree(SCRIPT.parent, self.scripts)
        self.tracked = self.scripts.parent / "types.go"
        self.original = b"retained dirty checkout bytes\n"
        self.tracked.write_bytes(self.original)
        self.output = Path(self.directory.name) / "staged types.go"

    def generate(self, **environment):
        env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")
        env.update(environment)
        return subprocess.run(
            ["bash", str(self.scripts / "regen-types.sh"), "--output", str(self.output)],
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )

    def test_offline_regeneration_stages_output_and_preserves_dirty_tracked_bytes(self):
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists(), "explicit output path must receive generated bytes")
        self.assertEqual(self.tracked.read_bytes(), self.original)
        first = self.output.read_bytes()
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), first, "offline codegen must be deterministic")
        self.assertEqual(self.tracked.read_bytes(), self.original)

    def test_missing_tool_cache_refuses_without_mutating_either_output(self):
        self.output.write_bytes(self.original)
        result = self.generate(GOMODCACHE=str(Path(self.directory.name) / "empty-cache"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.tracked.read_bytes(), self.original)
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_failed_hardening_preserves_both_existing_outputs(self):
        shutil.rmtree(self.schemas)
        schema = self.schemas / "caller/request.schema.json"
        schema.parent.mkdir(parents=True)
        schema.write_text('{"type":"object","properties":{"body":{"type":"string"}}}')
        self.output.write_bytes(self.original)
        cache = subprocess.check_output(["go", "env", "GOMODCACHE"], text=True).strip()
        # A local file proxy allows the old @version invocation to reach its
        # postprocessing failure, with no network input in this regression.
        result = self.generate(GOPROXY="file://" + cache + "/cache/download")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hardening pattern missing", result.stderr)
        self.assertEqual(self.tracked.read_bytes(), self.original)
        self.assertEqual(self.output.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
