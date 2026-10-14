"""UTF-8 schema facets preserve generated types and fail closed on drift."""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[4]
HELPER = ROOT / "xtask/src/codegen/python_utf8_bounds.py"
SPEC = importlib.util.spec_from_file_location("chio_python_utf8_bounds", HELPER)
utf8 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(utf8)


class GeneratedUtf8BoundsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.schema = self.directory / "schema"
        self.raw = self.directory / "raw"
        self.oracle = self.directory / "oracle"
        self.models = self.directory / "models"
        for path in (self.schema, self.raw, self.oracle, self.models):
            path.mkdir()
        text = {"type": "string", "minLength": 1, "maxLength": 256, "x-maxUtf8Bytes": 256}
        schema = {"$id": "urn:chio:utf8-test", "title": "Envelope", "type": "object",
                  "properties": {"provider": text, "flow": {"$ref": "#/$defs/flowIdentifier"},
                                 "label": {"$ref": "#/$defs/known"}},
                  "$defs": {"flowIdentifier": text,
                            "known": {"type": "object", "properties": {
                                "owners": {"type": "object", "propertyNames": {"$ref": "#/$defs/flowIdentifier"},
                                           "additionalProperties": {"type": "array", "items": {"$ref": "#/$defs/flowIdentifier"}}}}}}}
        utf8.dump_json(self.schema / "probe.schema.json", schema)
        source = '''# DO NOT EDIT - generation header retained.
# Schema sha256: test-header
from __future__ import annotations
from pydantic import BaseModel, Field, RootModel, constr
class FlowIdentifier(RootModel[constr(min_length=1, max_length=256)]):
    root: constr(min_length=1, max_length=256)
class Known(BaseModel):
    owners: dict[str, list[FlowIdentifier]]
class InheritedFlow(FlowIdentifier):
    pass
class InheritedKnown(Known):
    pass
class Envelope(BaseModel):
    provider_id: constr(min_length=1, max_length=256) = Field(alias="provider")
    flow: FlowIdentifier
    label: Known
PublicFlow = FlowIdentifier
'''
        (self.raw / "probe_schema.py").write_text(source)
        (self.raw / "unchanged_schema.py").write_text("# untouched bytes\nclass Unchanged:\n    value: int\n")
        (self.oracle / "probe_schema.py").write_text(source.replace("Known", "ProbeDefinitionsKnown"))
        (self.oracle / "unchanged_schema.py").write_text((self.raw / "unchanged_schema.py").read_text())
        for path in self.raw.glob("*.py"):
            shutil.copyfile(path, self.models / path.name)
        api = utf8.api_helper()
        plan = api.discover_plan(self.raw, self.oracle, {"format": api.FORMAT, "sdk_version": "0.1.1", "exports": {}})
        utf8.dump_json(self.directory / "plan.json", plan)
        self.report = self.directory / "report.json"

    def command(self):
        return [sys.executable, str(HELPER), "--schema-dir", str(self.schema), "--models-dir", str(self.models),
                "--raw-dir", str(self.raw), "--oracle-dir", str(self.oracle),
                "--name-plan", str(self.directory / "plan.json"), "--report", str(self.report)]

    def execute(self):
        return subprocess.run(self.command(), text=True, capture_output=True, check=False)

    def sources(self):
        return {path.relative_to(self.models).as_posix(): path.read_bytes() for path in self.models.rglob("*.py")}

    def load_model(self):
        sdk_name = "_utf8_bounds_test_sdk"
        sdk = types.ModuleType(sdk_name)
        sdk.__path__ = [str(ROOT / "sdks/python/chio-sdk-python/src/chio_sdk")]
        generated = types.ModuleType(sdk_name + "._generated")
        generated.__path__ = [str(self.models)]
        sys.modules[sdk_name] = sdk
        sys.modules[generated.__name__] = generated
        name = generated.__name__ + ".probe_schema"
        spec = importlib.util.spec_from_file_location(name, self.models / "probe_schema.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        self.addCleanup(lambda: [sys.modules.pop(key, None) for key in list(sys.modules) if key.startswith(sdk_name)])
        spec.loader.exec_module(module)
        return module

    def test_cli_discovers_facets_preserves_types_headers_and_untouched_modules(self):
        before = self.sources()
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.sources()
        self.assertEqual(set(before), set(after))
        self.assertEqual(before["unchanged_schema.py"], after["unchanged_schema.py"])
        self.assertTrue(after["probe_schema.py"].startswith(b"# DO NOT EDIT - generation header retained.\n# Schema sha256: test-header\n"))
        report = utf8.read_json(self.report)
        self.assertEqual(report["source_facet_count"], report["covered_facet_count"])
        self.assertEqual(report["field_annotations_changed"], 0)
        self.assertEqual(report["class_declarations_added_or_removed"], 0)
        module = self.load_model()
        exact, oversize = "\U0001f984" * 64, "\U0001f984" * 65
        valid = {"provider": exact, "flow": exact, "label": {"owners": {exact: [exact]}}}
        parsed = module.Envelope.model_validate(valid)
        self.assertEqual(parsed.model_dump(mode="json", by_alias=True), valid)
        self.assertIs(module.PublicFlow, module.FlowIdentifier)
        self.assertIsInstance(parsed.flow, module.FlowIdentifier)
        self.assertIsInstance(parsed.label.owners[exact][0], module.FlowIdentifier)
        for invalid in ({**valid, "provider": oversize}, {**valid, "flow": oversize},
                        {**valid, "label": {"owners": {oversize: [exact]}}},
                        {**valid, "label": {"owners": {exact: [oversize]}}}):
            with self.assertRaises(ValidationError):
                module.Envelope.model_validate(invalid)
        with self.assertRaises(ValidationError):
            module.InheritedFlow.model_validate(oversize)
        with self.assertRaises(ValidationError):
            module.InheritedKnown.model_validate({"owners": {oversize: [exact]}})

    def test_unmapped_facet_cli_refuses_without_partial_source_writes(self):
        path = self.schema / "probe.schema.json"
        value = utf8.read_json(path)
        value["$defs"]["unmapped"] = {"type": "string", "x-maxUtf8Bytes": 8}
        utf8.dump_json(path, value)
        before = self.sources()
        result = self.execute()
        self.assertEqual(result.returncode, 2)
        self.assertIn("unmapped UTF-8 facets", result.stderr)
        self.assertEqual(before, self.sources())

    def test_drifted_ordinary_plan_cli_refuses_without_writes(self):
        plan = utf8.read_json(self.directory / "plan.json")
        del plan["modules"]["probe_schema.py"]["FlowIdentifier"]
        utf8.dump_json(self.directory / "plan.json", plan)
        before = self.sources()
        result = self.execute()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(before, self.sources())

    def test_invalid_facet_cli_refuses_without_writes(self):
        path = self.schema / "probe.schema.json"
        value = utf8.read_json(path)
        value["$defs"]["flowIdentifier"]["x-maxUtf8Bytes"] = True
        utf8.dump_json(path, value)
        before = self.sources()
        result = self.execute()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(before, self.sources())

    def test_unwritable_report_cli_refuses_without_model_writes(self):
        self.report = self.schema
        before = self.sources()
        result = self.execute()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(before, self.sources())

    def test_report_cannot_overwrite_a_model_or_schema_input(self):
        original = self.sources()
        original_schema = (self.schema / "probe.schema.json").read_bytes()
        for path in (self.models / "probe_schema.py", self.schema / "probe.schema.json"):
            with self.subTest(path=path.name):
                for relative, source in original.items():
                    (self.models / relative).write_bytes(source)
                (self.schema / "probe.schema.json").write_bytes(original_schema)
                self.report = path
                before = self.sources()
                schema = (self.schema / "probe.schema.json").read_bytes()
                result = self.execute()
                self.assertEqual(result.returncode, 2)
                self.assertEqual(before, self.sources())
                self.assertEqual(schema, (self.schema / "probe.schema.json").read_bytes())

    def test_existing_class_binding_cannot_shadow_appended_validator(self):
        path = self.models / "probe_schema.py"
        path.write_text(path.read_text().replace("class Envelope(BaseModel):", "class Envelope(BaseModel):\n    _facet_field_validator = None"))
        before = self.sources()
        result = self.execute()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(before, self.sources())


if __name__ == "__main__":
    unittest.main()
