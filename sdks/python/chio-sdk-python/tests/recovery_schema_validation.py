"""Structural recovery conformance with the published UTF-8 byte facet."""
from copy import deepcopy
from dataclasses import dataclass, field
from functools import lru_cache
import re

from jsonschema import Draft202012Validator, SchemaError, ValidationError, validators
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

MAX_SAFE_INTEGER = 9007199254740991
DIALECT = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_MAPS = {"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
_SCHEMA_LISTS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_SCHEMA_VALUES = {"additionalProperties", "unevaluatedProperties", "items", "contains",
                  "unevaluatedItems", "propertyNames", "not", "if", "then", "else", "contentSchema"}


def _utf8_bytes(validator, maximum, instance, schema):
    if not isinstance(instance, str):
        return
    try:
        valid = len(instance.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    if not valid:
        yield ValidationError("string exceeds its decoded UTF-8 byte bound")


@lru_cache(maxsize=512)
def _absolute_end_pattern(pattern):
    """Preserve the unflagged ECMAScript end anchors used by this catalog.

    Python's dollar anchor also matches before a final LF. JSON Schema's
    unflagged ECMAScript pattern requires the actual end. Leave literal dollars
    and substring searches intact; this is not a general regex translator.
    """
    parts = []
    escaped = in_class = False
    for character in pattern:
        if escaped:
            parts.append(character)
            escaped = False
        elif character == "\\":
            parts.append(character)
            escaped = True
        elif character == "[" and not in_class:
            parts.append(character)
            in_class = True
        elif character == "]" and in_class:
            parts.append(character)
            in_class = False
        elif character == "$" and not in_class:
            parts.append(r"\Z")
        else:
            parts.append(character)
    return re.compile("".join(parts))


def _pattern(validator, pattern, instance, schema):
    if isinstance(instance, str) and _absolute_end_pattern(pattern).search(instance) is None:
        yield ValidationError("string does not match its schema pattern")


_Validator = validators.extend(Draft202012Validator, {
    "x-maxUtf8Bytes": _utf8_bytes,
    "pattern": _pattern,
})


def _profile_schema(schema):
    """Keep the extension on dialect-bearing resources without global registration."""
    value = deepcopy(schema)

    def visit(node):
        if not isinstance(node, dict):
            return
        dialect = node.pop("$schema", DIALECT)
        if dialect != DIALECT:
            raise SchemaError("recovery conformance requires the draft 2020-12 byte profile")
        if "x-maxUtf8Bytes" in node:
            maximum = node["x-maxUtf8Bytes"]
            if type(maximum) is not int or not 1 <= maximum <= MAX_SAFE_INTEGER:
                raise SchemaError("x-maxUtf8Bytes must be a positive safe integer")
        for key, child in node.items():
            if key in _SCHEMA_MAPS and isinstance(child, dict):
                for nested in child.values():
                    visit(nested)
            elif key in _SCHEMA_LISTS and isinstance(child, list):
                for nested in child:
                    visit(nested)
            elif key in _SCHEMA_VALUES:
                visit(child)

    visit(value)
    _Validator.check_schema(value)
    return value


@dataclass(frozen=True, init=False)
class RecoverySchemaRegistry:
    """A prepared immutable catalog avoids recompiling every local document per vector."""
    _profiled: Registry = field(repr=False)

    def __init__(self, registry):
        profiled = Registry().with_resources(
            (uri, Resource.from_contents(_profile_schema(registry[uri].contents),
                                         default_specification=DRAFT202012))
            for uri in registry
        )
        object.__setattr__(self, "_profiled", profiled)


def RecoverySchemaValidator(schema, **options):
    """Compile trusted schemas and reject malformed byte-bound declarations."""
    registry = options.pop("registry", Registry())
    if not isinstance(registry, RecoverySchemaRegistry):
        registry = RecoverySchemaRegistry(registry)
    return _Validator(_profile_schema(schema), registry=registry._profiled, **options)
