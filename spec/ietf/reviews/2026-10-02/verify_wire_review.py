#!/usr/bin/env python3
"""Independent schema and signing-input checks for the release-draft review.

Run with the pinned security source worktree as the sole argument.
Requires jsonschema, referencing, and cryptography. Does not execute Rust or
claim runtime acceptance. JSON output records each assertion and input hashes.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

EXPECTED = '122414b48ef1bc7999a9e32c7ae303d561fcd429'
source = Path(sys.argv[1]).resolve()
head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
if head != EXPECTED:
    raise SystemExit(f'Expected security source {EXPECTED}, found {head}')
schema_dir = source / 'spec/schemas/chio-wire/v1'
registry = Registry()
schemas = {}
for path in schema_dir.rglob('*.schema.json'):
    schema = json.loads(path.read_text())
    relative = path.relative_to(schema_dir).as_posix()
    location = 'https://chio-protocol.dev/schemas/chio-wire/v1/' + relative
    schema.setdefault('$id', location)
    schemas[relative] = schema
    resource = Resource.from_contents(schema)
    registry = registry.with_resource(location, resource)
    registry = registry.with_resource(schema['$id'], resource)
fixture_path = source / 'tests/bindings/fixtures/protocol-primitives-v1.json'
fixtures = json.loads(fixture_path.read_text())['cases']
checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append({'name': name, 'passed': True})
def accepts(name, instance):
    return Draft202012Validator(schemas[name], registry=registry).is_valid(instance)
for case in fixtures:
    schema_name = case['schema_file'].split('chio-wire/v1/')[-1]
    check('source-fixture/' + case['name'], accepts(schema_name, case['instance']) == case['valid'])

renderer = Path(__file__).resolve().parents[2] / 'tools/render_vectors.py'
spec = importlib.util.spec_from_file_location('ietf_vectors', renderer)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
# The document's independently implemented canonicalizer covers integer ranges,
# ordering, and string escaping; preserve actual numbers instead of binary64.
canonical = module.canonical_bytes
args = {'amount': 1250, 'destination': 'merchant-a'}
args_hash = '0x' + hashlib.sha256(canonical(args)).hexdigest()
intent = {
    'id': 'intent-review-1', 'server_id': 'payments', 'tool_name': 'charge',
    'purpose': 'Pay the approved merchant',
    'body': {'kind': 'bound_tool_invocation', 'value': {
        'capability_id': 'cap-review-1', 'parameters_hash': args_hash,
    }},
}
intent_schema = 'agent/governed-transaction-intent.schema.json'
check('bound-intent/valid', accepts(intent_schema, intent))
for mutation in ('missing-capability', 'missing-hash', 'unknown-binding', 'uppercase-hash', 'no-prefix'):
    bad = copy.deepcopy(intent)
    body = bad['body']['value']
    if mutation == 'missing-capability': del body['capability_id']
    elif mutation == 'missing-hash': del body['parameters_hash']
    elif mutation == 'unknown-binding': body['execution_allowed'] = True
    elif mutation == 'uppercase-hash': body['parameters_hash'] = args_hash.upper()
    else: body['parameters_hash'] = args_hash[2:]
    check('bound-intent/' + mutation, not accepts(intent_schema, bad))
check('bound-intent/parameter-substitution-changes-digest',
      args_hash != '0x' + hashlib.sha256(canonical({**args, 'amount': 1251})).hexdigest())

nonce = copy.deepcopy(next(c['instance']['nonce'] for c in fixtures if c['name'] == 'operation-execution-nonce'))
wrapper = {'schema': 'chio.admission-execution-nonce-signature.v1',
           'operation_id': 'operation-review-1', 'nonce': nonce}
key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
signature = key.sign(canonical(wrapper))
def verifies(value):
    try:
        key.public_key().verify(signature, canonical(value))
        return True
    except InvalidSignature:
        return False
check('operation-nonce/exact-wrapper', verifies(wrapper))
check('operation-nonce/reject-body-only-v1-preimage', not verifies(nonce))
check('operation-nonce/reject-other-operation', not verifies({**wrapper, 'operation_id': 'operation-review-2'}))
relabeled = copy.deepcopy(wrapper)
relabeled['nonce']['schema'] = 'chio.execution_nonce.v1'
check('operation-nonce/reject-schema-substitution', not verifies(relabeled))

pending = copy.deepcopy(next(c['instance'] for c in fixtures if c['name'] == 'pending-approval-result'))
# This frame case checks syntax and nonce exclusion, not signed outcome semantics.
receipt = next(c['instance'] for c in fixtures if c['name'] == 'receipt-internal-origin')
frame = {'type': 'tool_call_response', 'id': 'request-1', 'result': pending, 'receipt': receipt}
check('pending/frame-shape', accepts('kernel/tool_call_response.schema.json', frame))
frame['execution_nonce'] = next(c['instance'] for c in fixtures if c['name'] == 'operation-execution-nonce')
check('pending/no-execution-nonce', not accepts('kernel/tool_call_response.schema.json', frame))

print(json.dumps({
    'scope': 'Independent JSON Schema validation and Ed25519 preimage separation; no runtime tests',
    'source_commit': head,
    'fixture_sha256': hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
    'source_fixture_count': len(fixtures), 'checks': checks,
    'passed': len(checks),
    'bound_arguments_canonical_utf8': canonical(args).decode(),
    'bound_arguments_sha256': args_hash,
    'operation_nonce_signing_input_utf8': canonical(wrapper).decode(),
}, indent=2))
