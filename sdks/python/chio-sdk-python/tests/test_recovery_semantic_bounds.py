"""Semantic authored channels and text retain the native closed byte profile."""
from copy import deepcopy
import importlib
import json
from pathlib import Path

import pytest

from .recovery_schema_validation import RecoverySchemaValidator
from .test_recovery_semantic_contracts import REGISTRY, VECTORS

ROOT = Path(__file__).resolve().parents[4]


def _validator_and_value(name):
    schema = json.loads((ROOT / "spec/schemas/chio-wire/v1/recovery" / name).read_bytes())
    value = json.loads(next(row["wire"] for row in VECTORS if row["name"] == name))
    return RecoverySchemaValidator(schema, registry=REGISTRY), value


def test_authored_withheld_status_accepts_only_one_closed_audience_object():
    validator, value = _validator_and_value("semantic-package.schema.json")
    assert validator.is_valid(value)
    operation = value["operations"][0]
    operation["withheld_status"] = {"audience": {"kind": "known", "owners": {}, "compartments": []}}
    assert validator.is_valid(value)
    for refused in [None, {}, {"audience": None}, {"audience": {"kind": "top"}, "authority": True}]:
        operation["withheld_status"] = refused
        assert not validator.is_valid(value)


def test_generated_withheld_status_preserves_absence_and_refuses_explicit_null():
    _, legacy = _validator_and_value("semantic-package.schema.json")
    model = importlib.import_module("chio_sdk._generated.recovery.semantic_package_schema").SemanticPackageV1
    parsed = model.model_validate_json(json.dumps(legacy), strict=True)
    assert json.loads(parsed.model_dump_json(by_alias=True)) == legacy
    value = deepcopy(legacy)
    value["operations"][0]["withheld_status"] = {"audience": {"kind": "top"}}
    parsed = model.model_validate_json(json.dumps(value), strict=True)
    assert json.loads(parsed.model_dump_json(by_alias=True)) == value
    value["operations"][0]["withheld_status"] = None
    with pytest.raises(ValueError):
        model.model_validate_json(json.dumps(value), strict=True)


@pytest.mark.parametrize("role,limit", [("text", 4096), ("endpoint", 2048), ("reason", 512)])
def test_semantic_text_roles_apply_decoded_utf8_bounds(role, limit):
    name = "semantic-payload.schema.json" if role == "text" else "semantic-deployment.schema.json"
    validator, baseline = _validator_and_value(name)
    assert validator.is_valid(baseline)
    for size, valid in [(limit, True), (limit + 2, False)]:
        value = deepcopy(baseline)
        text = "é" * (size // 2)
        if role == "text":
            value["fields"][0]["value"]["value"] = text
        elif role == "endpoint":
            value["routes"][0]["destinations"][0][role] = text
        else:
            value["routes"][0]["reviewed_overrides"] = [{
                "selector_index": 0, "reason": text, "fixture_digests": [[1] * 32],
            }]
        assert validator.is_valid(value) == valid
