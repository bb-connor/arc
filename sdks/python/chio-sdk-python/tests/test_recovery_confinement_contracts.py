"""confinement finite local contracts and generated closed SDK models."""
import importlib
import json
from pathlib import Path

import pytest
from .recovery_schema_validation import RecoverySchemaRegistry, RecoverySchemaValidator as Draft202012Validator
from pydantic import ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[4]
SCHEMA_ROOT = ROOT / "spec/schemas/chio-wire/v1"
RESOURCES = []
for path in SCHEMA_ROOT.rglob("*.schema.json"):
    schema = json.loads(path.read_text())
    if "$id" in schema:
        resource = Resource.from_contents(schema)
        RESOURCES.append((schema["$id"], resource))
        alias = "https://chio.computer/schemas/chio-wire/v1/" + path.relative_to(SCHEMA_ROOT).as_posix()
        if alias != schema["$id"]:
            RESOURCES.append((alias, resource))
REGISTRY = RecoverySchemaRegistry(Registry().with_resources(RESOURCES))
CORPUS = json.loads((ROOT / "spec/vectors/recovery/v1/confinement-contracts.json").read_text())
VECTORS = CORPUS["cases"]


def model_for(schema_name):
    name = schema_name.removesuffix(".schema.json")
    module = importlib.import_module("chio_sdk._generated.recovery." + name.replace("-", "_") + "_schema")
    return getattr(module, "".join(part.capitalize() for part in name.split("-")) + "V1")


def test_versioned_corpus():
    assert CORPUS["schema"] == "chio.recovery-confinement-contract-vectors.v1"


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_closed_wire_shape(vector):
    schema = json.loads((SCHEMA_ROOT / "recovery" / vector["schema"]).read_text())
    assert Draft202012Validator(schema, registry=REGISTRY).is_valid(vector["body"]) == vector["schema_valid"]


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["schema_valid"]], ids=lambda vector: vector["name"])
def test_generated_types_preserve_exact_structural_bytes(vector):
    model = model_for(vector["schema"]).model_validate_json(json.dumps(vector["body"]), strict=True)
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == vector["body"]


@pytest.mark.parametrize("vector", [v for v in VECTORS if not v["schema_valid"]], ids=lambda vector: vector["name"])
def test_generated_types_refuse_unknown_and_missing_fields(vector):
    with pytest.raises(ValidationError):
        model_for(vector["schema"]).model_validate_json(json.dumps(vector["body"]), strict=True)
