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
duplicate_cases = 0
for dimension in ['wall_ms', 'calls', 'input_bytes', 'output_bytes', 'tokens',
                  'cost_microunits', 'memory_bytes']:
    for first in ['enforced', 'measured_only', 'unavailable']:
        for second in ['enforced', 'measured_only', 'unavailable']:
            response = copy.deepcopy(base)
            response['result']['value']['limits'] = [
                {'dimension': dimension, 'enforcement': first, 'value': 1},
                {'dimension': dimension, 'enforcement': second, 'value': 2}]
            if validator.is_valid(response):
                raise AssertionError(('duplicate dimension', dimension, first, second))
            response['result']['value']['limits'].pop()
            if not validator.is_valid(response):
                raise AssertionError(('duplicate repair control', dimension, first))
            duplicate_cases += 1
error_base = json.loads((ROOT / 'examples/response-error.json').read_text())
reference = error_base['error']['operation_ref']
expected_errors = {
    'invalid_request': ('never', 'null'),
    'unsupported_version': ('after_operator_repair', 'null'),
    'prerequisite_unavailable': ('after_operator_repair', 'optional'),
    'revision_conflict': ('refresh', 'optional'),
    'idempotency_conflict': ('never', 'optional'),
    'capacity': ('after_operator_repair', 'null'),
    'authority_denied': ('never', 'optional'),
    'outcome_unknown': ('reconcile_original', 'required'),
    'cursor_expired': ('refresh', 'null'),
    'storage_unavailable': ('after_operator_repair', 'null'),
    'response_too_large': ('never', 'optional'),
}
error_cases = 0
for code, (expected_retry, reference_mode) in expected_errors.items():
    for retry in ['never', 'refresh', 'after_operator_repair', 'reconcile_original']:
        for operation_ref in [None, reference]:
            response = copy.deepcopy(error_base)
            response['error'].update(code=code, retry=retry, operation_ref=operation_ref)
            valid_ref = (reference_mode == 'optional'
                         or (reference_mode == 'null' and operation_ref is None)
                         or (reference_mode == 'required' and operation_ref is not None))
            expected = retry == expected_retry and valid_ref
            if validator.is_valid(response) != expected:
                raise AssertionError(('error recovery', code, retry, operation_ref))
            error_cases += 1
print(f'{duplicate_cases} duplicate-limit cases and {error_cases} error-recovery combinations passed')
