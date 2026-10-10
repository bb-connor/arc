"""Public generated bindings retain actual model identity, including dependencies."""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[4]
SDK = Path(__file__).resolve().parents[1]
HELPER = ROOT / "xtask/src/codegen/python_api_stability.py"
SPEC = importlib.util.spec_from_file_location("chio_python_api_stability", HELPER)
stability = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stability)


class GeneratedApiStabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.models = Path(self.temporary.name)
        self.output_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.output_temporary.cleanup)
        self.outputs = Path(self.output_temporary.name)

    def write(self, relative, source):
        path = self.models / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def baseline(self):
        tree = stability.ApiTree(self.models)
        return {"format": stability.FORMAT, "sdk_version": "0.1.1",
                "exports": tree.inventory(), "enforcement_dependencies": tree.enforcement_inventory()}

    def empty_baseline(self):
        return {"format": stability.FORMAT, "sdk_version": "0.1.1", "exports": {},
                "enforcement_dependencies": {"format": stability.enforcement.FORMAT,
                                              "exports": {}, "graphs_by_contract": {},
                                              "external_source_provenance": {}}}

    def compatibility(self, changes=(), to_version="0.1.1"):
        return {"format": stability.COMPATIBILITY_FORMAT,
                "approved_transitions": [
                    {"export": change["export"], "before": change["before"], "after": change["after"],
                     "version_scope": {"from": "0.1.1", "to": to_version},
                     "reason": "Explicit fixture contract transition."}
                    for change in changes]}

    def cli(self, command, baseline, compatibility=None, report=None, version="0.1.1"):
        inputs = self.models / "inputs"
        inputs.mkdir(exist_ok=True)
        plan = {"format": stability.PLAN_FORMAT, "modules": {
            str(path.relative_to(self.models)): {node.name: node.name for node in ast.parse(path.read_text()).body
                                               if isinstance(node, ast.ClassDef)}
            for path in self.models.rglob("*.py") if path.name != "__init__.py"}}
        for name, value in (("baseline", baseline), ("compatibility", compatibility or self.compatibility()), ("plan", plan)):
            (inputs / (name + ".json")).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        argv = [sys.executable, str(HELPER), command, "--models-dir", str(self.models),
                "--plan", str(inputs / "plan.json"), "--baseline", str(inputs / "baseline.json"),
                "--compatibility", str(inputs / "compatibility.json"), "--sdk-version", version]
        if report is not None:
            argv += ["--inventory-output", str(report)]
        before = {p.relative_to(self.models).as_posix(): p.read_bytes() for p in self.models.rglob("*") if p.is_file()}
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
        return result, before

    def assert_sources_equal(self, before):
        self.assertEqual(before, {p.relative_to(self.models).as_posix(): p.read_bytes()
                                  for p in self.models.rglob("*") if p.is_file()})

    def test_regex_dependency_mutation_cli_refuses_and_preserves_report_and_inputs(self):
        source = "import re\n_NAME_RE = re.compile('^[a-z]+$')\nclass Model:\n    def accepts(self, value):\n        return bool(_NAME_RE.fullmatch(value))\n"
        path = self.write("model_schema.py", source)
        baseline = self.baseline()
        mutant = source.replace("'^[a-z]+$'", "'.*'")
        path.write_text(mutant)
        self.assertEqual(stability.ApiTree(self.models).inventory(), baseline["exports"])
        before_runtime, mutant_runtime = {}, {}
        exec(source, before_runtime)
        exec(mutant, mutant_runtime)
        self.assertTrue(before_runtime["Model"]().accepts("valid"))
        self.assertTrue(mutant_runtime["Model"]().accepts("valid"))
        self.assertFalse(before_runtime["Model"]().accepts("bad/name"))
        self.assertTrue(mutant_runtime["Model"]().accepts("bad/name"))
        report = self.outputs / "inventory.json"
        report.write_bytes(b"existing report\n")
        result, before = self.cli("apply", baseline, report=report)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("unapproved generated API or enforcement dependency", result.stderr)
        self.assertEqual(report.read_bytes(), b"existing report\n")
        self.assert_sources_equal(before)
        path.write_text("class Model:\n    value: str\n")
        baseline = self.baseline()
        path.write_text("class Model:\n    value: int\n")
        result, before = self.cli("apply", baseline, report=report)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("unapproved generated API or enforcement dependency", result.stderr)
        self.assertEqual(report.read_bytes(), b"existing report\n")
        self.assert_sources_equal(before)

    def test_trusted_imports_in_helpers_and_classes_are_dependency_bindings(self):
        for helper in (False, True):
            with self.subTest(helper=helper):
                source = ("from math import isfinite as predicate\n" +
                          ("def accepts_value(value):\n    return predicate(value)\n" if helper else "") +
                          "class Model:\n    def accepts(self, value):\n        return " +
                          ("accepts_value(value)\n" if helper else "predicate(value)\n"))
                path = self.write("model_schema.py", source)
                baseline = self.baseline()
                mutant = source.replace("isfinite", "isnan")
                path.write_text(mutant)
                tree = stability.ApiTree(self.models)
                if helper:
                    self.assertEqual(tree.inventory(), baseline["exports"])
                    self.assertNotEqual(tree.enforcement_inventory()["exports"], baseline["enforcement_dependencies"]["exports"])
                else:
                    self.assertNotEqual(tree.inventory(), baseline["exports"])
                    self.assertEqual(tree.enforcement_inventory()["exports"], baseline["enforcement_dependencies"]["exports"])
                left, right = {}, {}
                exec(source, left)
                exec(mutant, right)
                self.assertTrue(left["Model"]().accepts(1))
                self.assertFalse(right["Model"]().accepts(1))
                result, before = self.cli("apply", baseline)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assert_sources_equal(before)

    def test_dependency_transition_binds_exact_classes_dependencies_and_versions(self):
        source = "import re\n_NAME_RE = re.compile('^[a-z]+$')\nclass Model:\n    def accepts(self, value):\n        return bool(_NAME_RE.fullmatch(value))\n"
        path = self.write("model_schema.py", source)
        baseline = self.baseline()
        path.write_text(source.replace("'^[a-z]+$'", "'.*'"))
        inspection, before = self.cli("inspect", baseline, version="0.1.2")
        self.assertEqual(inspection.returncode, 0, inspection.stderr)
        self.assert_sources_equal(before)
        report = json.loads(inspection.stdout)
        self.assertFalse(report["violations"])
        changes = report["enforcement_dependency_violations"]
        self.assertEqual(len(changes), 1)
        transition = {**changes[0], "version_scope": {"from": "0.1.1", "to": "0.1.2"},
                      "reason": "Reviewed fixture-only predicate replacement."}
        for mutation in ("version", "before_class", "after_class", "before_dependency", "after_dependency", "reason"):
            with self.subTest(mutation=mutation):
                invalid = json.loads(json.dumps(transition))
                if mutation == "version":
                    invalid["version_scope"]["to"] = "0.1.3"
                elif mutation == "reason":
                    invalid["reason"] = " "
                elif mutation.endswith("class"):
                    invalid[mutation.split("_")[0]]["class"] = "OtherModel"
                else:
                    invalid[mutation.split("_")[0] + "_enforcement_dependencies"]["fingerprint"] = "0" * 64
                compatibility = {**self.compatibility(), "enforcement_dependencies_transitions": [invalid]}
                result, inputs = self.cli("apply", baseline, compatibility, version="0.1.2")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assert_sources_equal(inputs)
        compatibility = {**self.compatibility(), "enforcement_dependencies_transitions": [transition]}
        result, _ = self.cli("apply", baseline, compatibility, report=self.outputs / "inventory.json", version="0.1.2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dependency_source_and_graph_bounds_run_before_legacy_fingerprints(self):
        path = self.write("model_schema.py", "class Model:\n    value: str\n")
        for source in ("LIMIT = 1\nCaptured = LIMIT\nLIMIT = 2\nclass Model:\n    def accepts(self, value):\n        return value < Captured\n",
                       "class Model:\n    value: str\n" + "LARGE = '" + "x" * (512 * 1024) + "'\n",
                       "class C0:\n    value: str\n" + "".join(f"class C{i}:\n    value: C{i - 1}\n" for i in range(1, 64)),
                       "class Model:\n    def accepts(self):\n        return eval('True')\n"):
            with self.subTest(source_prefix=source[:30]):
                path.write_text(source)
                with patch.object(stability.ModelModule, "signature", side_effect=AssertionError("legacy fingerprint ran")):
                    with self.assertRaises(stability.enforcement.Refusal):
                        stability.ApiTree(self.models).inventory()

    def test_cli_report_cannot_overwrite_lock_or_source(self):
        self.write("model_schema.py", "class Model:\n    value: str\n")
        baseline = self.baseline()
        for report in (self.models / "inputs/baseline.json", self.models / "inputs/compatibility.json",
                       self.models / "inputs/plan.json", self.models / "model_schema.py"):
            with self.subTest(report=report):
                result, before = self.cli("apply", baseline, report=report)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("report must be outside", result.stderr)
                self.assert_sources_equal(before)

    def test_normal_baseline_cli_passes_and_failed_publication_rolls_back(self):
        self.write("model_schema.py", "class Model:\n    value: str\n")
        baseline = self.baseline()
        plan = {"format": stability.PLAN_FORMAT, "modules": {"model_schema.py": {"Model": "Model"}}}
        report = self.outputs / "inventory.json"
        report.write_bytes(b"existing report\n")
        before = {p.relative_to(self.models).as_posix(): p.read_bytes() for p in self.models.rglob("*") if p.is_file()}
        original_replace, calls = stability.os.replace, []
        def fail_report_once(source, target):
            calls.append(Path(target))
            if Path(target) == report:
                raise OSError("injected report publication failure")
            return original_replace(source, target)
        with patch.object(stability.os, "replace", side_effect=fail_report_once):
            with self.assertRaisesRegex(OSError, "injected report"):
                stability.apply(self.models, plan, baseline, self.compatibility(), "0.1.1", report)
        self.assertIn(report, calls)
        self.assert_sources_equal(before)
        self.assertEqual(report.read_bytes(), b"existing report\n")
        result, _ = self.cli("apply", baseline, report=report)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = json.loads(report.read_text())
        self.assertFalse(actual["violations"])
        self.assertFalse(actual["enforcement_dependency_violations"])

    def test_missing_dependency_ledger_refuses_publication(self):
        self.write("model_schema.py", "class Model:\n    value: str\n")
        baseline = self.baseline()
        baseline.pop("enforcement_dependencies")
        result, before = self.cli("apply", baseline)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("absent protected enforcement", result.stderr)
        self.assert_sources_equal(before)

    def test_unused_import_and_declaration_execution_refuse_public_cli_without_writes(self):
        original = "import math\nfrom unittest import mock\nclass Model:\n    def measure(self):\n        return math.isfinite(1)\n"
        path = self.write("model_schema.py", original)
        baseline = self.baseline()
        additions = {
            "unused_unowned_import": "import unowned_namespace_fixture\n",
            "unused_unowned_from": "from unowned_namespace_fixture import unused\n",
            "private_assignment_call": "class _Private:\n    patcher = mock.patch('math.isfinite', return_value=False).start()\n",
            "function_annotation_call": "def _Unused(value: mock.patch('math.isfinite', return_value=False).start()):\n    pass\n",
            "method_annotation_call": "class _Private:\n    def unused(self, value: mock.patch('math.isfinite', return_value=False).start()):\n        pass\n",
            "method_default_call": "class _Private:\n    def unused(self, value=mock.patch('math.isfinite', return_value=False).start()):\n        pass\n",
            "bare_method_helper": "def _change(method):\n    math.isfinite = lambda _: False\n    return method\nclass _Private:\n    @_change\n    def unused(self):\n        pass\n",
            "class_decorator": "def _change(model):\n    return 42\n@_change\nclass _Private:\n    value: str\n",
            "metaclass_keyword": "class _Private(metaclass=type):\n    value: str\n",
            "private_class_expression": "class _Private:\n    mock.patch('math.isfinite', return_value=False).start()\n",
            "private_class_attribute_assignment": "class _Private:\n    math.isfinite = False\n",
        }
        report = self.outputs / "report.json"
        report.write_bytes(b"existing report\n")
        for case, addition in additions.items():
            with self.subTest(case=case):
                path.write_text(original + addition)
                result, before = self.cli("apply", baseline, report=report)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("unapproved generated API", result.stderr)
                self.assert_sources_equal(before)
                self.assertEqual(report.read_bytes(), b"existing report\n")

    def test_foundation_reader_dependencies_bind_the_complete_owned_module(self):
        sdk_root = self.outputs / "sdk"
        sdk_root.mkdir()
        support = sdk_root / "recovery_wire.py"
        original = (SDK / "src/chio_sdk/recovery_wire.py").read_text()
        support.write_text(original)
        self.write("model_schema.py", "from chio_sdk.recovery_wire import MAX_WIRE_BYTES, assert_foundation_wire\nclass Model:\n    def validate_wire(self, source):\n        return MAX_WIRE_BYTES, assert_foundation_wire(source)\n")
        tree = stability.ApiTree(self.models, sdk_root=sdk_root)
        baseline = tree.inventory()
        dependencies = tree.enforcement_inventory()
        for before, after in (("if not isinstance(key, str) or key in value:", "if not isinstance(key, str):"),
                              ("MAX_WIRE_BYTES = 65536", "MAX_WIRE_BYTES = 65537")):
            with self.subTest(mutation=before):
                self.assertEqual(original.count(before), 1)
                support.write_text(original.replace(before, after, 1))
                mutant = stability.ApiTree(self.models, sdk_root=sdk_root)
                self.assertEqual(mutant.inventory(), baseline)
                self.assertNotEqual(mutant.enforcement_inventory()["exports"], dependencies["exports"])
        support.write_text(original.replace("MAX_WIRE_BYTES = 65536", "MAX_WIRE_BYTES = True", 1))
        with patch.object(stability.ModelModule, "signature", side_effect=AssertionError("legacy fingerprint ran")):
            with self.assertRaisesRegex(stability.enforcement.Refusal, "literal integer"):
                stability.ApiTree(self.models, sdk_root=sdk_root).inventory()

    def test_owned_support_unused_import_and_shadowed_decorator_are_rejected(self):
        sdk_root = self.outputs / "sdk"
        sdk_root.mkdir()
        support = sdk_root / "recovery_wire.py"
        original = "def require_utf8_bound(value: str, maximum: int) -> str:\n    if len(value.encode('utf-8')) > maximum:\n        raise ValueError('UTF-8 bound')\n    return value\n"
        support.write_text(original)
        self.write("model_schema.py", "from chio_sdk.recovery_wire import require_utf8_bound\nclass Model:\n    value: str\n")
        stability.ApiTree(self.models, sdk_root=sdk_root).inventory()
        for mutation in ("import unowned_namespace_fixture\n" + original,
                         "from unowned_namespace_fixture import unused\n" + original,
                         "property = 42\n" + original + "class Unrelated:\n    @property\n    def value(self):\n        return True\n"):
            with self.subTest(mutation=mutation[:40]):
                support.write_text(mutation)
                with patch.object(stability.ModelModule, "signature", side_effect=AssertionError("legacy fingerprint ran")):
                    with self.assertRaises(stability.enforcement.Refusal):
                        stability.ApiTree(self.models, sdk_root=sdk_root).inventory()

    def test_module_assignment_annotations_refuse_public_cli_without_writes(self):
        original = "import math\nfrom unittest import mock\nclass Model:\n    def measure(self):\n        return math.isfinite(1)\n"
        path = self.write("model_schema.py", original)
        baseline = self.baseline()
        report = self.outputs / "report.json"
        report.write_bytes(b"existing report\n")
        for value in (" = 0", ""):
            with self.subTest(value=value):
                path.write_text(original + "_UNUSED: mock.patch('math.isfinite', return_value=False).start()" + value + "\n")
                result, before = self.cli("apply", baseline, report=report)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("unapproved generated API", result.stderr)
                self.assert_sources_equal(before)
                self.assertEqual(report.read_bytes(), b"existing report\n")
        path.write_text(original + "_UNUSED: bool = True\n_DECLARED: str\n")
        candidate = stability.ApiTree(self.models).inventory()
        self.assertEqual({name: candidate[name] for name in baseline["exports"]}, baseline["exports"])

    def test_owned_assignment_annotations_refuse_before_legacy_fingerprints(self):
        sdk_root = self.outputs / "sdk"
        sdk_root.mkdir()
        support = sdk_root / "recovery_wire.py"
        original = "from unittest import mock\ndef require_utf8_bound(value: str, maximum: int) -> str:\n    if len(value.encode('utf-8')) > maximum:\n        raise ValueError('UTF-8 bound')\n    return value\n"
        support.write_text(original)
        self.write("model_schema.py", "from chio_sdk.recovery_wire import require_utf8_bound\nclass Model:\n    value: str\n")
        baseline = stability.ApiTree(self.models, sdk_root=sdk_root).inventory()
        annotation = "mock.patch('math.isfinite', return_value=False).start()"
        for owner in ("module", "class"):
            for value in (" = 0", ""):
                with self.subTest(owner=owner, value=value):
                    addition = "_UNUSED: " + annotation + value + "\n"
                    if owner == "class":
                        addition = "class Unrelated:\n    " + addition
                    support.write_text(original + addition)
                    with patch.object(stability.ModelModule, "signature", side_effect=AssertionError("legacy fingerprint ran")):
                        with self.assertRaises(stability.enforcement.Refusal):
                            stability.ApiTree(self.models, sdk_root=sdk_root).inventory()
        support.write_text(original + "_UNUSED: bool = True\n_DECLARED: str\nclass Unrelated:\n    value: str = ''\n    declared: int\n")
        self.assertEqual(stability.ApiTree(self.models, sdk_root=sdk_root).inventory(), baseline)

    def test_pydantic_evaluated_quoted_annotation_refuses_before_inventory(self):
        original = ("from __future__ import annotations\nfrom pydantic import BaseModel\n"
                    "from typing import Literal\nevents = []\nclass Model(BaseModel):\n"
                    "    version: Literal[1] = 1\n")
        path = self.write("model_schema.py", original)
        baseline = self.baseline()
        mutant = original.replace("version: Literal[1]",
                                  'version: "(events.append(\'annotation-evaluated\'), Literal[1])[1]"')
        runtime = types.ModuleType("quoted_annotation_fixture")
        sys.modules[runtime.__name__] = runtime
        try:
            exec(mutant, runtime.__dict__)
            self.assertEqual(runtime.events, ["annotation-evaluated"])
            self.assertEqual(runtime.Model.model_validate_json('{"version":1}', strict=True).version, 1)
        finally:
            sys.modules.pop(runtime.__name__, None)
        path.write_text(mutant)
        result, before = self.cli("inspect", baseline)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assert_sources_equal(before)
        with patch.object(stability.ModelModule, "signature", side_effect=AssertionError("legacy fingerprint ran")):
            with self.assertRaises(stability.enforcement.Refusal):
                stability.ApiTree(self.models).inventory()

    def test_quoted_annotation_bounds_preserve_literal_metadata_and_wire_strings(self):
        positive = '''\
from typing import Annotated, ForwardRef, Literal
WireKind = Literal
WireMetadata = Annotated
WireReference = ForwardRef
class Reference:
    value: str
class Model:
    reference: "list[Reference]"
    explicit: ForwardRef("Reference")
    kind: Literal["call('wire')"] = "call('wire')"
    metadata: Annotated["Reference", "call('metadata')", {"wire": "Reference()"}]
    quoted_kind: "Literal[\\"call('wire')\\"]"
    quoted_metadata: "Annotated[str, \\"call('metadata')\\"]"
    aliased_kind: WireKind["call('wire')"]
    aliased_metadata: WireMetadata["Reference", "call('metadata')"]
    aliased_reference: WireReference("Reference")
    description: str = "ordinary JSONObject data is not a type ???)"
    def wire(self):
        return '{"JSONObject":"Reference()"}'
'''
        path = self.write("model_schema.py", positive)
        baseline = self.baseline()
        self.assertEqual(stability.ApiTree(self.models).inventory(), baseline["exports"])
        for annotation in ("str()", "list['str()']", "A" * 4097, "list[" * 90 + "str" + "]" * 90, "\ud800"):
            with self.subTest(annotation=annotation[:40]):
                path.write_text("class Model:\n    value: " + repr(annotation) + "\n")
                with patch.object(stability.ModelModule, "signature", side_effect=AssertionError("legacy fingerprint ran")):
                    with self.assertRaises(stability.enforcement.Refusal):
                        stability.ApiTree(self.models).inventory()
        path.write_text("from typing import ForwardRef\nclass Model:\n    value: ForwardRef('str()')\n")
        with self.assertRaises(stability.enforcement.Refusal):
            stability.ApiTree(self.models).inventory()
        path.write_text("from typing import ForwardRef\nWireReference = ForwardRef\nclass Model:\n    value: WireReference('str()')\n")
        with self.assertRaises(stability.enforcement.Refusal):
            stability.ApiTree(self.models).inventory()
        path.write_text("from typing import ForwardRef, Literal\nWireReference = ForwardRef\nclass Model:\n"
                        "    value: WireReference('str()')\nWireReference = Literal\n")
        with patch.object(stability.ModelModule, "__init__", side_effect=AssertionError("class normalization began")):
            with self.assertRaises(stability.enforcement.Refusal):
                stability.ApiTree(self.models)

    def test_forwardref_alias_call_refuses_automatic_pydantic_type_evaluation(self):
        original = ("from __future__ import annotations\nfrom pydantic import BaseModel\n"
                    "from typing import Literal, ForwardRef\nReferenceType = ForwardRef\nevents = []\n"
                    "class Model(BaseModel):\n    version: ReferenceType('Literal[1]') = 1\n")
        path = self.write("model_schema.py", original)
        baseline = self.baseline()
        mutant = original.replace("ReferenceType('Literal[1]')",
                                  'ReferenceType("(events.append(\'annotation-evaluated\'), Literal[1])[1]")')
        runtime = types.ModuleType("quoted_forwardref_alias_fixture")
        sys.modules[runtime.__name__] = runtime
        try:
            exec(mutant, runtime.__dict__)
            self.assertEqual(runtime.events, ["annotation-evaluated"])
            self.assertEqual(runtime.Model.model_validate_json('{"version":1}', strict=True).version, 1)
        finally:
            sys.modules.pop(runtime.__name__, None)
        path.write_text(mutant)
        result, before = self.cli("inspect", baseline)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assert_sources_equal(before)

    def test_method_decorators_bind_exact_symbols_and_literal_arguments(self):
        originals = (
            "from pydantic import BaseModel, field_validator\nclass Model(BaseModel):\n    value: str\n    @field_validator('value', mode='after')\n    @classmethod\n    def validate(cls, value):\n        return value\n",
            "class Model:\n    @property\n    def value(self):\n        return True\n")
        for original in originals:
            path = self.write("model_schema.py", original)
            stability.ApiTree(self.models).inventory()
            mutations = ([original.replace("mode='after'", "mode=MODE").replace("class Model", "MODE = 'after'\nclass Model"),
                          original.replace("mode='after'", "mode=str('after')"),
                          original.replace("mode='after'", "**{'mode': 'after'}"),
                          original.replace("class Model", "classmethod = 42\nclass Model")]
                         if "field_validator" in original else
                         ["property = 42\n" + original, original.replace("class Model:", "class Model:\n    property = 42")])
            for mutation in mutations:
                with self.subTest(mutation=mutation[:55]):
                    path.write_text(mutation)
                    with self.assertRaises(stability.enforcement.Refusal):
                        stability.ApiTree(self.models).inventory()

    def test_identity_oracle_preserves_authored_order_and_only_adds_titles(self):
        original = {
            "title": "OrderedRoot", "type": "object",
            "properties": {
                "z_field": {"type": "string", "x-maxUtf8Bytes": 256},
                "a_field": {"type": "object", "properties": {"z_child": {"type": "string"}, "a_child": {"type": "integer"}}},
                "title": {"type": "string"}},
            "$defs": {
                "z_record": {"type": "object", "properties": {"z_child": {"type": "string"}, "a_child": {"type": "integer"}}},
                "a_record": {"enum": ["second", "first"]}},
            "required": ["z_field", "a_field"], "additionalProperties": False,
            "default": {"title": "wire value", "z_field": 1, "a_field": 2}}
        source = self.models / "schemas/example.schema.json"
        source.parent.mkdir()
        source.write_text(json.dumps(original))
        before = source.read_bytes()
        output = self.models / "oracle"
        result = subprocess.run([sys.executable, str(HELPER), "annotate", "--input-dir", str(source.parent),
                                 "--output-dir", str(output)], text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = json.loads((output / "example.schema.json").read_text())
        self.assertEqual(actual["properties"]["a_field"].pop("title"), "ExampleAField")
        self.assertEqual(actual["$defs"]["z_record"].pop("title"), "ExampleDefinitionsZRecord")
        self.assertEqual(actual["$defs"]["a_record"].pop("title"), "ExampleDefinitionsARecord")
        self.assertEqual(actual, original)

        def assert_ordered(expected, candidate):
            if isinstance(expected, dict):
                self.assertEqual(list(candidate), list(expected))
                for key in expected:
                    assert_ordered(expected[key], candidate[key])
            elif isinstance(expected, list):
                self.assertEqual(len(candidate), len(expected))
                for left, right in zip(expected, candidate):
                    assert_ordered(left, right)
            else:
                self.assertEqual(candidate, expected)
        assert_ordered(original, actual)
        self.assertEqual(source.read_bytes(), before)

    def test_nested_same_shape_reference_rebinding_is_a_contract_change(self):
        path = self.write("tool_manifest_schema.py", """\
class ReadPath:
    root: str
class WritePath:
    root: str
class ToolDefinition:
    read_paths: list[ReadPath]
""")
        baseline = self.baseline()
        path.write_text(path.read_text().replace("list[ReadPath]", "list[WritePath]"))
        candidate = stability.ApiTree(self.models).inventory()
        rejected = stability.compatibility_violations(baseline, candidate, self.compatibility(), "0.1.1")
        self.assertEqual([row["export"] for row in rejected], ["tool_manifest_schema.py:ToolDefinition"])

    def test_approved_label_transition_does_not_approve_same_shape_body_rebinding(self):
        path = self.write("declassification_grant_schema.py", """\
class TargetLabel:
    level: int
class Body:
    target_label: TargetLabel
class Body2:
    target_label: TargetLabel
class SignedDeclassificationGrant:
    body: Body2
SecurityBody = Body2
""")
        baseline = self.baseline()
        path.write_text(path.read_text().replace("level: int", "level: int | None"))
        candidate = stability.ApiTree(self.models).inventory()
        required = stability.compatibility_violations(baseline, candidate, self.compatibility(), "0.1.1")
        approved = self.compatibility(required)
        self.assertFalse(stability.compatibility_violations(baseline, candidate, approved, "0.1.1"))
        self.assertEqual(candidate["declassification_grant_schema.py:Body"]["fingerprint"],
                         candidate["declassification_grant_schema.py:Body2"]["fingerprint"])
        path.write_text(path.read_text().replace("SecurityBody = Body2", "SecurityBody = Body"))
        mutated = stability.ApiTree(self.models).inventory()
        rejected = stability.compatibility_violations(baseline, mutated, approved, "0.1.1")
        self.assertEqual([row["export"] for row in rejected], ["declassification_grant_schema.py:SecurityBody"])
        self.assertTrue(stability.compatibility_violations(baseline, candidate, approved, "0.2.0"))

    def test_quoted_annotations_are_normalized_by_resolved_identity(self):
        self.write("paths_schema.py", """\
from typing import ForwardRef, Literal
class ReadPath:
    root: str
class WritePath:
    root: str
class ToolDefinition:
    read_paths: "list[ReadPath]"
    other: ForwardRef("ReadPath")
    kind: Literal["ReadPath"]
""")
        baseline = self.baseline()
        path = self.models / "paths_schema.py"
        path.write_text(path.read_text().replace('"list[ReadPath]"', '"list[WritePath]"'))
        candidate = stability.ApiTree(self.models).inventory()
        self.assertNotEqual(baseline["exports"]["paths_schema.py:ToolDefinition"]["fingerprint"],
                            candidate["paths_schema.py:ToolDefinition"]["fingerprint"])
        plans = {"paths_schema.py": {"ReadPath": "ScopedReadPath", "WritePath": "ScopedWritePath", "ToolDefinition": "ToolDefinition"}}
        original = stability.ModelModule("paths_schema.py", path.read_text())
        rewritten = stability.ModelModule("paths_schema.py", stability.rewrite_module(original, plans))
        self.assertEqual(original.signature("ToolDefinition"), rewritten.signature("ToolDefinition"))

    def test_renaming_preserves_wire_keys_metadata_and_shadowed_runtime_bindings(self):
        source = """\
from typing import Annotated, ForwardRef, Literal
class Header:
    root: str
class Envelope:
    Header: Annotated["Header", "Header", {"wire": "Header"}]
    other: ForwardRef("Header")
    kind: Literal["Header"] = "Header"
    def global_type(self):
        return Header
    def local_type(self, Header):
        return Header
    def nested_type(self, Header):
        def inner():
            return Header
        return inner()
    def comprehension(self):
        return [Header for Header in (Header,)]
"""
        original = stability.ModelModule("envelope_schema.py", source)
        rewritten = stability.rewrite_module(original, {"envelope_schema.py": {"Header": "ScopedHeader", "Envelope": "Envelope"}})
        tree = ast.parse(rewritten)
        envelope = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Envelope")
        field = envelope.body[0]
        self.assertEqual(field.target.id, "Header")
        self.assertEqual(ast.literal_eval(field.annotation.slice.elts[0]), "ScopedHeader")
        self.assertEqual(ast.literal_eval(field.annotation.slice.elts[1]), "Header")
        self.assertEqual(ast.literal_eval(field.annotation.slice.elts[2]), {"wire": "Header"})
        namespace = {}
        exec(compile(tree, "envelope_schema.py", "exec"), namespace)
        obj = namespace["Envelope"]()
        self.assertIs(obj.global_type(), namespace["ScopedHeader"])
        self.assertEqual(obj.local_type("wire"), "wire")
        self.assertEqual(obj.nested_type("wire"), "wire")
        self.assertEqual(obj.comprehension(), [namespace["ScopedHeader"]])

    def test_unresolved_generated_reference_is_rejected(self):
        self.write("model_schema.py", "from .missing_schema import Missing\nclass Model:\n    field: Missing\n")
        with self.assertRaises(stability.StabilityError):
            stability.ApiTree(self.models).inventory()

    def test_duplicate_actual_class_bindings_are_rejected(self):
        self.write("model_schema.py", "class Model:\n    field: str\nclass Model:\n    field: int\n")
        with self.assertRaises(stability.StabilityError):
            stability.ApiTree(self.models).inventory()

    def test_unsupported_class_namespace_rebinding_is_rejected(self):
        source = "class Header:\n    root: str\nclass Model:\n    Header = 'wire'\n    def parse(self, default=Header):\n        return default\n"
        with self.assertRaises(stability.StabilityError):
            module = stability.ModelModule("model_schema.py", source)
            stability.rewrite_module(module, {"model_schema.py": {"Header": "ScopedHeader", "Model": "Model"}})

    def test_unsupported_forward_reference_and_nested_classes_are_rejected(self):
        for source in ('from typing import ForwardRef\nclass Header:\n    root: str\nclass Model:\n    field: ForwardRef("Header", module="x")\n',
                       'class Header:\n    class Nested:\n        field: str\n'):
            with self.assertRaises(stability.StabilityError):
                module = stability.ModelModule("model_schema.py", source)
                plan = {"model_schema.py": {name: name for name in module.classes}}
                stability.rewrite_module(module, plan)

    def test_ambiguous_oracle_without_reference_evidence_is_rejected(self):
        raw = self.models / "raw"
        oracle = self.models / "oracle"
        raw.mkdir()
        oracle.mkdir()
        (raw / "model_schema.py").write_text("class Value:\n    root: str\n")
        (oracle / "model_schema.py").write_text("class ModelLeft:\n    root: str\nclass ModelRight:\n    root: str\n")
        baseline = self.empty_baseline()
        with self.assertRaises(stability.StabilityError):
            stability.discover_plan(raw, oracle, baseline)

    def test_top_level_canonical_namespace_mutations_cli_refuse_without_writes(self):
        historical = "class ScopedModel:\n    value: str\nModel = ScopedModel\n"
        self.write("model_schema.py", historical)
        baseline = self.baseline()
        transitions = {"format": stability.COMPATIBILITY_FORMAT, "approved_transitions": []}
        plan = {"format": stability.PLAN_FORMAT, "modules": {"model_schema.py": {"Model": "ScopedModel"}}}
        for name, value in (("baseline", baseline), ("compatibility", transitions), ("plan", plan)):
            (self.models / (name + ".json")).write_text(json.dumps(value))
        mutations = {
            "constant": "ScopedModel = 42\n",
            "function": "def ScopedModel():\n    return 42\n",
            "annotated": "ScopedModel: int = 42\n",
            "import": "from builtins import int as ScopedModel\n",
            "module_import": "import builtins as ScopedModel\n",
            "delete": "del ScopedModel\n",
            "wildcard": "from builtins import *\n",
            "exec": "exec('ScopedModel = 42')\n",
            "eval_assignment": "ignored = eval('globals().__setitem__(\"ScopedModel\", 42)')\n",
            "dynamic_target": "globals()['ScopedModel'] = 42\n",
            "conditional": "if True:\n    ScopedModel = 42\n",
        }
        command = [sys.executable, str(HELPER), "apply", "--models-dir", str(self.models),
                   "--plan", str(self.models / "plan.json"), "--baseline", str(self.models / "baseline.json"),
                   "--compatibility", str(self.models / "compatibility.json"), "--sdk-version", "0.1.1"]
        for case, mutation in mutations.items():
            with self.subTest(case=case):
                for path in self.models.glob("*.py"):
                    path.unlink()
                self.write("model_schema.py", "class Model:\n    value: str\n" + mutation)
                before = {p.name: p.read_bytes() for p in self.models.glob("*.py")}
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.models.glob("*.py")})

    def test_schema_digest_remains_a_star_export_after_api_apply(self):
        self.write("model_schema.py", "class Model:\n    value: str\n")
        self.write("__init__.py", "SCHEMA_SHA256 = 'fixed-test-digest'\nfrom .model_schema import Model\n__all__ = ['Model', 'SCHEMA_SHA256']\n")
        plan = {"format": stability.PLAN_FORMAT, "modules": {"model_schema.py": {"Model": "Model"}}}
        stability.apply(self.models, plan, self.baseline(), self.compatibility(), "0.1.1")
        spec = importlib.util.spec_from_file_location("_digest_probe", self.models / "__init__.py",
                                                    submodule_search_locations=[str(self.models)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[package.__name__] = package
        self.addCleanup(lambda: [sys.modules.pop(name, None) for name in list(sys.modules)
                                 if name == "_digest_probe" or name.startswith("_digest_probe.")])
        spec.loader.exec_module(package)
        self.assertEqual(package.SCHEMA_SHA256, "fixed-test-digest")
        exported = {}
        exec("from _digest_probe import *", exported)
        self.assertEqual(exported["SCHEMA_SHA256"], "fixed-test-digest")

    def test_alias_captures_the_binding_before_a_later_alias_rebind(self):
        source = "class First:\n    value: str\nclass Second:\n    value: int\nCurrent = First\nCaptured = Current\nCurrent = Second\n"
        self.write("model_schema.py", source)
        tree = stability.ApiTree(self.models)
        namespace = {}
        exec(source, namespace)
        self.assertIs(namespace["Captured"], namespace["First"])
        self.assertIs(namespace["Current"], namespace["Second"])
        self.assertEqual(tree.resolve("model_schema.py", "Captured"), ("model_schema.py", "First"))
        self.assertEqual(tree.resolve("model_schema.py", "Current"), ("model_schema.py", "Second"))
        with self.assertRaises(stability.enforcement.Refusal):
            tree.inventory()

    def test_consumed_model_alias_rebinding_cli_refuses_without_writes(self):
        consumers = ("class Derived(Choice):\n    count: int\n",
                     "class Derived:\n    value: Choice\n",
                     'class Derived:\n    value: "Choice"\n',
                     'class Derived:\n    value: ForwardRef("Choice")\n')
        plan = {"format": stability.PLAN_FORMAT,
                "modules": {"model_schema.py": {name: name for name in ("First", "Second", "Derived")}}}
        baseline = self.empty_baseline()
        for name, value in (("baseline", baseline), ("compatibility", self.compatibility()), ("plan", plan)):
            (self.models / (name + ".json")).write_text(json.dumps(value))
        command = [sys.executable, str(HELPER), "apply", "--models-dir", str(self.models),
                   "--plan", str(self.models / "plan.json"), "--baseline", str(self.models / "baseline.json"),
                   "--compatibility", str(self.models / "compatibility.json"), "--sdk-version", "0.1.1"]
        for consumer in consumers:
            with self.subTest(consumer=consumer):
                for path in self.models.glob("*.py"):
                    path.unlink()
                self.write("model_schema.py", "from typing import ForwardRef\nclass First:\n    value: str\nclass Second:\n    value: str\nChoice = First\n" + consumer + "Choice = Second\n")
                before = {path.name: path.read_bytes() for path in self.models.glob("*.py")}
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(before, {path.name: path.read_bytes() for path in self.models.glob("*.py")})

    def test_literal_wire_string_does_not_consume_a_model_alias(self):
        self.write("model_schema.py", 'from typing import Literal\nclass First:\n    value: str\nclass Second:\n    value: str\nChoice = First\nclass Derived:\n    kind: Literal["Choice"]\nChoice = Second\n')
        tree = stability.ApiTree(self.models)
        self.assertNotIn("Choice", tree.modules["model_schema.py"].class_references("Derived"))
        with self.assertRaises(stability.enforcement.Refusal):
            tree.inventory()

    def test_model_declaration_cannot_shadow_its_predeclaration_import(self):
        self.write("other_schema.py", "class ForeignA:\n    value: str\nclass ForeignB:\n    value: str\n")
        plan = {"format": stability.PLAN_FORMAT, "modules": {
            "other_schema.py": {"ForeignA": "ForeignA", "ForeignB": "ForeignB"}, "model_schema.py": {"A": "A"}}}
        baseline = self.empty_baseline()
        for name, value in (("baseline", baseline), ("compatibility", self.compatibility()), ("plan", plan)):
            (self.models / (name + ".json")).write_text(json.dumps(value))
        command = [sys.executable, str(HELPER), "apply", "--models-dir", str(self.models),
                   "--plan", str(self.models / "plan.json"), "--baseline", str(self.models / "baseline.json"),
                   "--compatibility", str(self.models / "compatibility.json"), "--sdk-version", "0.1.1"]
        for declaration in ("class A(A):\n    count: int\n", "class A:\n    field: A\n"):
            with self.subTest(declaration=declaration):
                (self.models / "__init__.py").unlink(missing_ok=True)
                self.write("model_schema.py", "from .other_schema import ForeignA as A\n" + declaration)
                before = {p.name: p.read_bytes() for p in self.models.glob("*.py")}
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.models.glob("*.py")})

    def test_initializer_cannot_capture_a_partially_initialized_namespace(self):
        self.write("pkg/other_schema.py", "class First:\n    value: str\nclass Second:\n    value: str\n")
        self.write("pkg/__init__.py", "from .other_schema import First as Current\nfrom ..pkg import Current as Captured\nfrom .other_schema import Second as Current\n__all__ = ['Captured', 'Current']\n")
        plan = {"format": stability.PLAN_FORMAT, "modules": {
            "pkg/other_schema.py": {"First": "First", "Second": "Second"}}}
        baseline = self.empty_baseline()
        for name, value in (("baseline", baseline), ("compatibility", self.compatibility()), ("plan", plan)):
            (self.models / (name + ".json")).write_text(json.dumps(value))
        command = [sys.executable, str(HELPER), "apply", "--models-dir", str(self.models),
                   "--plan", str(self.models / "plan.json"), "--baseline", str(self.models / "baseline.json"),
                   "--compatibility", str(self.models / "compatibility.json"), "--sdk-version", "0.1.1"]
        before = {p.relative_to(self.models).as_posix(): p.read_bytes() for p in self.models.rglob("*.py")}
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(before, {p.relative_to(self.models).as_posix(): p.read_bytes() for p in self.models.rglob("*.py")})

    def test_model_cannot_import_an_ancestor_initializer_namespace(self):
        self.write("pkg/other_schema.py", "class First:\n    value: str\nclass Second:\n    value: str\n")
        self.write("pkg/__init__.py", "from .other_schema import First as Current\nfrom . import model_schema\nfrom .other_schema import Second as Current\n")
        self.write("pkg/model_schema.py", "from . import Current as Captured\nclass Model:\n    value: Captured\n")
        before = {p.relative_to(self.models).as_posix(): p.read_bytes() for p in self.models.rglob("*.py")}
        with self.assertRaises(stability.StabilityError):
            stability.ApiTree(self.models)
        self.assertEqual(before, {p.relative_to(self.models).as_posix(): p.read_bytes() for p in self.models.rglob("*.py")})

    def test_generated_import_cycles_refuse_before_namespace_resolution(self):
        self.write("first_schema.py", "class First:\n    value: str\nfrom .second_schema import Second\n")
        self.write("second_schema.py", "class Second:\n    value: str\nfrom .first_schema import First\n")
        with self.assertRaises(stability.StabilityError):
            stability.ApiTree(self.models)

    def test_maintained_generated_exports_match_protected_contracts(self):
        baseline = stability.read_json(SDK / "generated-api.lock.json")
        compatibility = stability.read_json(SDK / "generated-api-compatibility.json")
        candidate = stability.ApiTree(SDK / "src/chio_sdk/_generated").inventory()
        version = tomllib.loads((SDK / "pyproject.toml").read_text())["project"]["version"]
        problems = stability.compatibility_violations(baseline, candidate, compatibility, version)
        if problems:
            self.fail(f"{len(problems)} protected generated bindings changed: " +
                      ", ".join(row["export"] for row in problems[:12]))


if __name__ == "__main__":
    unittest.main()
