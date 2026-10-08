"""The same structural bytes use maintained model, schema and wire readers."""
import importlib
import json
from pathlib import Path

import pytest
from referencing import Registry, Resource

from chio_sdk.recovery_wire import assert_foundation_wire
from .recovery_schema_validation import RecoverySchemaRegistry, RecoverySchemaValidator


ROOT = Path(__file__).resolve().parents[4]
SCHEMA_ROOT = ROOT / "spec/schemas/chio-wire/v1"
FILE_MODELS = {
    "approval_submission": ("approval-submission", "RecoveryApprovalSubmissionV1"),
    "approval_intent": ("approval-intent", "RecoveryApprovalIntentV1"),
    "command": ("command", "RecoveryCommandV1"),
    "grant_binding": ("grant-binding", "RecoveryMandatoryGrantBindingV1"),
    "action": ("action-intent", "RecoveryExactActionIntentV1"),
}
RESOURCES = []
for path in SCHEMA_ROOT.rglob("*.schema.json"):
    schema = json.loads(path.read_bytes())
    if "$id" not in schema:
        continue
    resource = Resource.from_contents(schema)
    RESOURCES.append((schema["$id"], resource))
    for domain in ["chio.computer", "chio.world"]:
        alias = f"https://{domain}/schemas/chio-wire/v1/{path.relative_to(SCHEMA_ROOT).as_posix()}"
        if alias != schema["$id"]:
            RESOURCES.append((alias, resource))
REGISTRY = RecoverySchemaRegistry(Registry().with_resources(RESOURCES))
CORPUS = json.loads((ROOT / "spec/vectors/recovery/v1/byte-boundaries.json").read_bytes())
assert CORPUS["format_version"] == 1
VECTORS = CORPUS["vectors"]
assert VECTORS


def model_for(contract):
    name, class_name = FILE_MODELS[contract]
    module = importlib.import_module(f"chio_sdk._generated.recovery.{name.replace('-', '_')}_schema")
    return getattr(module, class_name)


def model_accepts(contract, wire):
    try:
        model = model_for(contract).model_validate_json(wire, strict=True)
    except ValueError:
        return False
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(wire)
    return True


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_approval_and_epoch_boundaries_use_maintained_readers(vector):
    name, _ = FILE_MODELS[vector["contract"]]
    schema = json.loads((SCHEMA_ROOT / "recovery" / f"{name}.schema.json").read_bytes())
    shape = RecoverySchemaValidator(schema, registry=REGISTRY).is_valid(json.loads(vector["wire"]))
    assert shape == vector["schema_valid"]
    try:
        assert_foundation_wire(vector["wire"])
        profile = True
    except ValueError:
        profile = False
    assert profile == vector["wire_profile_valid"]
    raw_model = model_accepts(vector["contract"], vector["wire"])
    assert raw_model == vector["python_model_valid"]
    assert (shape and profile) == vector["rust_typed_valid"]
    assert (raw_model and profile) == vector["rust_typed_valid"]
    if "nested_approval_valid" in vector:
        approval = json.loads(vector["wire"])["command"]["approval"]
        assert model_accepts("approval_submission", approval) == vector["nested_approval_valid"]
        assert_foundation_wire(approval)
