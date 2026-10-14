"""Unicode flow roles obey the native identifier byte ceiling."""
from copy import deepcopy
import importlib
import json
from pathlib import Path

import pytest

from .recovery_schema_validation import RecoverySchemaValidator
from .test_recovery_authority_contracts import FILE_MODELS, REGISTRY

ROOT = Path(__file__).resolve().parents[4]
POSITIVE = json.loads((ROOT / "spec/vectors/recovery/v1/authority-positive.json").read_text())


def _case(role, value):
    if role in {"provider", "account"}:
        body = deepcopy(POSITIVE["provider_finality"]["body"])
        body[role] = value
        return "provider_body", body
    if role == "capability":
        body = deepcopy(POSITIVE["action"])
        body["capability_id"] = value
        return "action", body
    body = deepcopy(POSITIVE["requirements"])
    if role in {"recipient", "purpose"}:
        body[role] = value
    elif role == "owner":
        body["source_label"] = {"kind": "known", "owners": {value: [value]}, "compartments": []}
    elif role == "reader":
        body["source_label"] = {"kind": "known", "owners": {"owner": ["owner", value]}, "compartments": []}
    else:
        body["source_label"] = {"kind": "known", "owners": {}, "compartments": [value]}
    return "requirements", body


@pytest.mark.parametrize("role", ["provider", "account", "capability", "recipient", "purpose", "owner", "reader", "compartment"])
def test_schema_flow_roles_measure_utf8_bytes(role):
    contract, exact = _case(role, "é" * 128)
    name, _ = FILE_MODELS[contract]
    schema = json.loads((ROOT / "spec/schemas/chio-wire/v1/recovery" / f"{name}.schema.json").read_text())
    validate = RecoverySchemaValidator(schema, registry=REGISTRY)
    assert validate.is_valid(exact)
    _, oversized = _case(role, "é" * 129)
    assert not validate.is_valid(oversized)


@pytest.mark.parametrize("role", ["provider", "account", "capability", "recipient", "purpose", "owner", "reader", "compartment"])
def test_generated_flow_roles_measure_utf8_bytes(role):
    contract, exact = _case(role, "é" * 128)
    name, class_name = FILE_MODELS[contract]
    module = importlib.import_module("chio_sdk._generated.recovery." + name.replace("-", "_") + "_schema")
    model = getattr(module, class_name)
    model.model_validate_json(json.dumps(exact, ensure_ascii=False), strict=True)
    _, oversized = _case(role, "é" * 129)
    with pytest.raises(ValueError):
        model.model_validate_json(json.dumps(oversized, ensure_ascii=False), strict=True)
