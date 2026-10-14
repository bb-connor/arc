"""Shared recovery shapes and generated data models do not establish authority."""

import json
from pathlib import Path

import pytest
from .recovery_schema_validation import RecoverySchemaRegistry, RecoverySchemaValidator as Draft202012Validator
from referencing import Registry, Resource
from chio_sdk import _generated as generated
from chio_sdk._generated import security

from chio_sdk._generated.recovery.dependency_graph_schema import RecoveryDependencyGraphV1
from chio_sdk._generated.recovery.effect_contract_schema import SemanticEffectContractV1
from chio_sdk._generated.recovery.observation_schema import RecoveryObservationV1
from chio_sdk._generated.recovery.profile_requirements_schema import (
    RecoveryProfileRequirementsV1,
)
from chio_sdk._generated.recovery.trajectory_schema import RecoveryTrajectoryV1

ROOT = Path(__file__).resolve().parents[4]
FILES = {
    "observation": "observation",
    "profile": "profile-requirements",
    "effect_contract": "effect-contract",
    "graph": "dependency-graph",
    "trajectory": "trajectory",
}
SCHEMAS = {
    contract: json.loads(
        (ROOT / "spec/schemas/chio-wire/v1/recovery" / f"{filename}.schema.json").read_text()
    )
    for contract, filename in FILES.items()
}
REGISTRY = RecoverySchemaRegistry(Registry().with_resources(
    (schema["$id"], Resource.from_contents(schema)) for schema in SCHEMAS.values()
))
MODELS = {
    "observation": RecoveryObservationV1,
    "profile": RecoveryProfileRequirementsV1,
    "effect_contract": SemanticEffectContractV1,
    "graph": RecoveryDependencyGraphV1,
    "trajectory": RecoveryTrajectoryV1,
}
VECTORS = json.loads((ROOT / "spec/vectors/recovery/v1/contracts.json").read_text())["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_recovery_shape(vector):
    # JSON shape cannot preserve raw duplicate keys or enforce trusted host
    # context. The Rust intake corpus checks those separate acceptance conditions.
    validator = Draft202012Validator(SCHEMAS[vector["contract"]], registry=REGISTRY)
    assert validator.is_valid(json.loads(vector["wire"])) == vector["schema_valid"]


@pytest.mark.parametrize(
    "vector", [vector for vector in VECTORS if vector["valid"]], ids=lambda vector: vector["name"]
)
def test_generated_recovery_model_preserves_every_positive_field(vector):
    model = MODELS[vector["contract"]].model_validate_json(vector["wire"], strict=True)
    assert model.model_dump(mode="json", by_alias=True) == json.loads(vector["wire"])


def test_recovery_does_not_rename_existing_security_exports():
    assert generated.Digest32 is security.Digest32
    assert generated.Digest32Item is security.Digest32Item
    assert generated.Effect is security.Effect
