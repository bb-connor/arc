"""semantic local closed wire corpus. Rust owns signatures and native authority."""
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
        # Compatibility aliases resolve locally. They never fetch these domains.
        for domain in ("chio.computer", "chio.world", "chio-protocol.dev"):
            RESOURCES.append((f"https://{domain}/schemas/chio-wire/v1/" + path.relative_to(SCHEMA_ROOT).as_posix(), resource))
REGISTRY = RecoverySchemaRegistry(Registry().with_resources(RESOURCES))
VECTORS = json.loads((ROOT / "spec/vectors/recovery/v1/semantic-contracts.json").read_text())["vectors"]


def model_for(schema_name):
    name = schema_name.removesuffix(".schema.json")
    module = importlib.import_module("chio_sdk._generated.recovery." + name.replace("-", "_") + "_schema")
    cls = "".join(part.capitalize() for part in name.split("-")) + "V1"
    return getattr(module, cls)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_shared_closed_wire_shape(vector):
    schema = json.loads((SCHEMA_ROOT / "recovery" / vector["schema"]).read_text())
    assert Draft202012Validator(schema, registry=REGISTRY).is_valid(json.loads(vector["wire"])) == vector["schema_valid"]


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["schema_valid"]], ids=lambda vector: vector["name"])
def test_generated_types_preserve_exact_structural_bytes(vector):
    model = model_for(vector["schema"]).model_validate_json(vector["wire"], strict=True)
    assert model.model_dump(mode="json", by_alias=True, exclude_unset=True) == json.loads(vector["wire"])


@pytest.mark.parametrize("vector", [v for v in VECTORS if not v["schema_valid"]], ids=lambda vector: vector["name"])
def test_generated_types_refuse_unknown_fields_and_missing_nullable(vector):
    with pytest.raises(ValidationError):
        model_for(vector["schema"]).model_validate_json(vector["wire"], strict=True)
