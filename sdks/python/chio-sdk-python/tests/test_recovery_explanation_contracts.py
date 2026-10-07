"""Shared explanation structural vectors. Rust owns signature and context verification."""
import importlib
import json
from pathlib import Path
import pytest
from .recovery_schema_validation import RecoverySchemaRegistry, RecoverySchemaValidator as Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[4]
FILE_MODELS = {
 "snapshot":("explanation-snapshot","RecoveryExplanationSnapshotV1"),
 "registry":("remedy-registry","RecoveryRemedyRegistryV1"),
 "evaluation":("explanation-evaluation","RecoveryExplanationEvaluationV1"),
 "report":("explanation-report","RecoveryExplanationReportV1"),
 "view":("explanation-view","RecoveryExplanationViewV1"),
 "signed_report":("signed-explanation-report","RecoverySignedExplanationReportV1"),
 "signed_view":("signed-explanation-view","RecoverySignedExplanationViewV1"),
}
SCHEMA_ROOT = ROOT / "spec/schemas/chio-wire/v1"
RESOURCES = []
for path in SCHEMA_ROOT.rglob("*.schema.json"):
    schema = json.loads(path.read_text())
    if "$id" in schema:
        resource = Resource.from_contents(schema)
        RESOURCES.append((schema["$id"], resource))
        # The established receipt ID uses a different namespace. File-relative
        # references still resolve through the authoritative local schema tree.
        for domain in ["chio.computer", "chio.world"]:
            alias = "https://" + domain + "/schemas/chio-wire/v1/" + path.relative_to(SCHEMA_ROOT).as_posix()
            if alias != schema["$id"]:
                RESOURCES.append((alias, resource))
REGISTRY = RecoverySchemaRegistry(Registry().with_resources(RESOURCES))
VECTORS = json.loads((ROOT / "spec/vectors/recovery/v1/explanation-contracts.json").read_text())["vectors"]


def test_unversioned_facts_use_a_closed_freshness_qualified_state():
    snapshot = json.loads((ROOT / "spec/vectors/recovery/v1/explanation-positive.json").read_bytes())["snapshot"]
    observation = snapshot["observations"][0]
    evidence = observation["state"]["evidence"]
    observation["state"] = {"kind": "freshness_qualified", "evidence": evidence, "satisfied": True}
    schema = json.loads((SCHEMA_ROOT / "recovery/explanation-snapshot.schema.json").read_bytes())
    validator = Draft202012Validator(schema, registry=REGISTRY)
    assert validator.is_valid(snapshot)
    observation["state"]["version"] = 1
    assert not validator.is_valid(snapshot)
    observation["state"].pop("version")
    observation["state"].pop("evidence")
    assert not validator.is_valid(snapshot)

@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_closed_wire_shape(vector):
    name, _ = FILE_MODELS[vector["contract"]]
    schema = json.loads((ROOT / "spec/schemas/chio-wire/v1/recovery" / f"{name}.schema.json").read_text())
    assert Draft202012Validator(schema, registry=REGISTRY).is_valid(json.loads(vector["wire"])) == vector["schema_valid"]

@pytest.mark.parametrize("vector", [v for v in VECTORS if v["valid"]], ids=lambda vector: vector["name"])
def test_generated_types_preserve_native_positive_bytes(vector):
    name, cls = FILE_MODELS[vector["contract"]]
    module = importlib.import_module("chio_sdk._generated.recovery." + name.replace("-", "_") + "_schema")
    model = getattr(module, cls).model_validate_json(vector["wire"], strict=True)
    # Optional absent fields are omitted, matching the Rust wire projection.
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(vector["wire"])
