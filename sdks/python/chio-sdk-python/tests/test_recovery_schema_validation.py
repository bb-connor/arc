"""The byte profile persists through local references and validates its facets."""
from copy import deepcopy
import json
from pathlib import Path

from jsonschema import SchemaError
import pytest
from referencing import Registry, Resource

from .recovery_schema_validation import RecoverySchemaValidator

DIALECT = "https://json-schema.org/draft/2020-12/schema"


def test_local_references_keep_the_published_utf8_byte_keyword():
    resource = {
        "$schema": DIALECT,
        "$id": "https://chio.computer/schemas/example/identifier.schema.json",
        "type": "string", "x-maxUtf8Bytes": 256,
    }
    registry = Registry().with_resource(resource["$id"], Resource.from_contents(resource))
    schema = {"$schema": DIALECT, "$ref": resource["$id"]}
    validator = RecoverySchemaValidator(schema, registry=registry)
    assert validator.is_valid("é" * 128)
    assert not validator.is_valid("é" * 129)
    assert resource["$schema"] == DIALECT


@pytest.mark.parametrize("ceiling", [0, -1, True, 1.5, "256", 9007199254740992])
def test_nested_utf8_facets_refuse_invalid_declared_ceilings(ceiling):
    schema = {"$schema": DIALECT, "type": "object", "properties": {
        "identifier": {"type": "string", "x-maxUtf8Bytes": ceiling},
    }}
    before = deepcopy(schema)
    with pytest.raises(SchemaError):
        RecoverySchemaValidator(schema)
    assert schema == before


@pytest.mark.parametrize("position", ["owner", "reader", "compartment"])
def test_shared_flow_identifiers_refuse_final_newlines(position):
    root = Path(__file__).resolve().parents[4]
    schema = json.loads((root / "spec/schemas/chio-wire/v1/security/information-label.schema.json").read_text())
    value = {"kind": "known", "owners": {"owner": ["owner"]}, "compartments": ["restricted"]}
    if position == "owner":
        value["owners"] = {"owner\n": ["owner\n"]}
    elif position == "reader":
        value["owners"]["owner"].append("reader\n")
    else:
        value["compartments"] = ["restricted\n"]
    assert not RecoverySchemaValidator(schema).is_valid(value)


@pytest.mark.parametrize(("pattern", "value", "valid"), [
    (r"^token$", "token", True),
    (r"^token$", "token\n", False),
    (r"^token$", "token\u2028", False),
    (r"^token$", "token\u2029", False),
    (r"token", "prefix token\n suffix", True),
    (r"cost\$", "cost$\n", True),
    (r"^[a$]+$", "a$", True),
    (r"^[a$]+$", "a$\n", False),
])
def test_ecmascript_end_anchors_preserve_unanchored_and_literal_dollar_meaning(pattern, value, valid):
    schema = {"$schema": DIALECT, "type": "string", "pattern": pattern}
    before = deepcopy(schema)
    assert RecoverySchemaValidator(schema).is_valid(value) == valid
    assert schema == before


def test_flow_identifiers_preserve_interior_unicode_line_separators():
    root = Path(__file__).resolve().parents[4]
    schema = json.loads((root / "spec/schemas/chio-wire/v1/security/information-label.schema.json").read_text())
    principal = "owner\u2028interior"
    value = {"kind": "known", "owners": {principal: [principal]}, "compartments": ["restricted\u2029interior"]}
    assert RecoverySchemaValidator(schema).is_valid(value)
