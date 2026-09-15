#!/usr/bin/env python3
"""Offline wire-shape regressions. Synthetic signatures grant no authority."""
import copy
import json
import os
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'spec/schemas/chio-work'
H = 'a' * 64
SIG = 'b' * 128
ADDRESS = '0x' + 'c' * 40
HASH = '0x' + H
MAX = 9007199254740991


def load(path):
    return json.loads(path.read_text())


registry = Registry()
for path in [*WORK.rglob('*.schema.json'),
             ROOT / 'spec/schemas/chio-finding/v1/finding.schema.json',
             ROOT / 'spec/schemas/chio-finding/v1/verifier-report.schema.json']:
    schema = load(path)
    Draft202012Validator.check_schema(schema)
    registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))

families = {
    'agreement': 'v2/agreement.schema.json',
    'submission': 'v1/submission.schema.json',
    'dependency': 'v1/dependency.schema.json',
    'decision': 'v2/decision.schema.json',
}
validators = {name: Draft202012Validator(load(WORK / rel), registry=registry)
              for name, rel in families.items()}
rows = load(ROOT / 'spec/schemas/registry.json')['artifacts']
for name, rel in families.items():
    schema_id = validators[name].schema['properties']['body']['properties']['schema']['const']
    matches = [row for row in rows if row['schema'] == schema_id]
    assert len(matches) == 1 and matches[0]['schemaFile'] == 'spec/schemas/chio-work/' + rel
assert not any(row['schema'] in {
    'chio.experimental.native-funded-w0-agreement.v1',
    'chio.experimental.native-funded-decision.v1',
} for row in rows)

binding = dict(allocationId=HASH, agreementSha256=H, authorityUuid='authority',
               operationId='operation', holdId='hold', authorizationId='authorization',
               requestSha256=H, outcomeId='outcome', rawOutcomeSha256=H, expiresAt=MAX)
floor = ['artifact_integrity', 'guarantee_consistency']
facet_kinds = validators['decision'].schema['$defs']['facetKinds']['items']['enum']
waiver = {'body': dict(schema='chio.contractual-capture-waiver.v1', policyDigest=H,
                      contractContextDigest=H, capabilityDigest=H, requestId='request',
                      issuedAtUnixMs=1, expiresAtUnixMs=MAX),
          'receiverSignature': SIG, 'counterpartySignature': SIG}
finding = dict(schema='chio.finding.v1', finding_id=H,
               descriptor=dict(topic='security:test', context_sha256=H, outcome_class='positive_result'),
               guarantee_class='asserted', payload_sha256=H, payload_media_type='application/json',
               evidence_receipt_ids=[], evidence_checkpoint_ref='unavailable:pre-settlement',
               evidence_cost=dict(units=100, currency='USD'), evidence_class='asserted',
               bond_ref='unbacked:experimental', status_feed_ref='unavailable:experimental',
               issuer=H, issued_at=1, expires_at=MAX, signature=SIG)
bodies = {
    'agreement': dict(policySha256=H, authorityUuid='authority', buyerKey=H, providerKey=H,
                      requestId='request', requestSha256=H,
                      domain=dict(profile='chio.experimental.local-confirmed-funding.v1', chainId='31337',
                                  genesisHash=HASH, escrow=ADDRESS, escrowCodeHash=HASH,
                                  token=ADDRESS, tokenCodeHash=HASH),
                      work=dict(payer=ADDRESS, beneficiary=ADDRESS, verifier=ADDRESS, amount='100',
                                submitBy=1, challengeUntil=2, resolveBy=3, refundAfter=MAX),
                      findingContextSha256=H, requiredFindingFacets=floor),
    'submission': dict(binding=binding, inputSha256=H, outputSha256=H, finding=finding),
    'dependency': dict(parentAgreement=H, childAgreement=H, parentRequest=H, childRequest=H,
                       parentAuthority='parent', childAuthority='child', inputSha256=H),
    'decision': dict(binding=binding, commitment=HASH, findingId=H, checkerSha256=H,
                    claimTransactionHash=HASH, claimBlockHash=HASH, accepted=True,
                    findingAssessment=dict(schema='chio.experimental.funded-finding-assessment.v1',
                                           contextSha256=H, findingArtifactSha256=H,
                                           resolvedEvidenceBundleSha256=H, evaluatedAt=MAX,
                                           requiredFacets=floor,
                                           facets=[dict(facet=f, outcome='verified', reason='shape fixture')
                                                   for f in facet_kinds], outcome='accepted')),
}
count = 0
shape_cases = []


def check(name, value, valid):
    global count
    errors = list(validators[name].iter_errors(value))
    assert bool(errors) != valid, (name, valid, [e.message for e in errors])
    count += 1
    shape_cases.append(dict(name=name, value=copy.deepcopy(value), valid=valid))


for name, body in bodies.items():
    body['schema'] = validators[name].schema['properties']['body']['properties']['schema']['const']
    envelope = {'body': body, **({'buyerSignature': SIG, 'providerSignature': SIG}
                               if name == 'agreement' else {'signature': SIG})}
    check(name, envelope, True)
    for key in body:
        changed = copy.deepcopy(envelope)
        changed['body'].pop(key)
        check(name, changed, False)
        changed = copy.deepcopy(envelope)
        changed['body'][key] = None
        check(name, changed, False)
    changed = copy.deepcopy(envelope)
    changed['extra'] = True
    check(name, changed, False)
    changed = copy.deepcopy(envelope)
    changed['body']['extra'] = True
    check(name, changed, False)
    for value in ['', SIG.upper(), SIG[:-1], SIG + '0', '0x' + SIG]:
        changed = copy.deepcopy(envelope)
        changed['buyerSignature' if name == 'agreement' else 'signature'] = value
        check(name, changed, False)
    changed = copy.deepcopy(envelope)
    changed['body']['schema'] = body['schema'] + '.future'
    check(name, changed, False)
    if name == 'agreement':
        changed = copy.deepcopy(envelope)
        changed['body']['captureWaiverTerms'] = waiver
        check(name, changed, True)
        for value in [None, {}, {**waiver, 'extra': True},
                      {**waiver, 'body': {**waiver['body'], 'schema': 'unknown'}}]:
            changed['body']['captureWaiverTerms'] = value
            check(name, changed, False)
        for value in [[], floor[:1], floor * 2, ['unknown', *floor]]:
            changed = copy.deepcopy(envelope)
            changed['body']['requiredFindingFacets'] = value
            check(name, changed, False)
        for value in ['00', '+1', '-1', '1.0', '1e2', '1' * 79]:
            changed = copy.deepcopy(envelope)
            changed['body']['work']['amount'] = value
            check(name, changed, False)
    if name == 'submission':
        for value in [None, {}, {**finding, 'extra': True}]:
            changed = copy.deepcopy(envelope)
            changed['body']['finding'] = value
            check(name, changed, False)
    if name == 'decision':
        for key, value in [('evaluatedAt', MAX + 1), ('evaluatedAt', -1),
                           ('facets', []), ('facets', list(reversed(body['findingAssessment']['facets']))),
                           ('requiredFacets', floor[:1]), ('schema', 'unknown')]:
            changed = copy.deepcopy(envelope)
            changed['body']['findingAssessment'][key] = value
            check(name, changed, False)
print(f'OK registered work schemas: 4 registrations, 4 meta-schemas, {count} shape cases')

# Optional cross-check using the existing pinned buyer environment, without
# installing jsonschema into it or weakening its dependency lock.
if independent_python := os.environ.get('CHIO_WORK_PYTHON'):
    program = """
import json, sys
sys.path.insert(0, sys.argv[1])
from funded_wire import Shapes
shapes = Shapes()
for case in json.load(sys.stdin):
    family = 'chio.experimental.native-funded-' + ('w0-agreement.v2' if case['name'] == 'agreement' else case['name'] + ('.v2' if case['name'] == 'decision' else '.v1'))
    uri = shapes.families[family]
    actual = shapes.matches(case['value'], shapes.documents[uri], uri)
    if actual != case['valid']:
        raise SystemExit('independent shape disagreement: ' + case['name'])
print('OK independent schema interpreter agrees on every shape case')
"""
    subprocess.run([independent_python, '-c', program, str(ROOT / 'examples/federated-work')],
                   input=json.dumps(shape_cases), text=True, check=True)
