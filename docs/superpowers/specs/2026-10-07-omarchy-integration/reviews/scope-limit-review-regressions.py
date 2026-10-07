#!/usr/bin/env python3
"""Check the proposed wire limit contract; never qualifies native enforcement."""
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
registry = Registry()
for path in (ROOT / 'contracts').glob('*.schema.json'):
    schema = json.loads(path.read_text())
    schema['$id'] = path.as_uri()
    registry = registry.with_resource(path.as_uri(), Resource.from_contents(schema))
path = ROOT / 'contracts/operator-response.schema.json'
schema = json.loads(path.read_text())
schema['$id'] = path.as_uri()
validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
base = json.loads((ROOT / 'examples/response-scope-get.json').read_text())
count = 0
for dimension in ['wall_ms', 'calls', 'input_bytes', 'output_bytes', 'tokens',
                  'cost_microunits', 'memory_bytes']:
    for enforcement in ['enforced', 'measured_only', 'unavailable']:
        for value in [None, -1, 0, 1, 9007199254740991, 9007199254740992, 0.5, True, '1']:
            response = copy.deepcopy(base)
            response['result']['value']['limits'] = [
                {'dimension': dimension, 'enforcement': enforcement, 'value': value}]
            expected = ((type(value) is int and 0 <= value <= 9007199254740991)
                        or (value is None and enforcement != 'enforced'))
            if validator.is_valid(response) != expected:
                raise AssertionError((dimension, enforcement, value, expected))
            count += 1
print(f'{count} independently enumerated wire limit cases passed; no runtime qualification')
