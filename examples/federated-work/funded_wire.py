#!/usr/bin/env python3
"""Independent bounded wire parser. Shape and content hashes grant no authority."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urldefrag, urljoin

import rfc8785

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 262144
MAX_INT = 9007199254740991
FAMILIES = {
    'chio.experimental.native-funded-w0-agreement.v2': 'v2/agreement.schema.json',
    'chio.experimental.native-funded-submission.v1': 'v1/submission.schema.json',
    'chio.experimental.native-funded-dependency.v1': 'v1/dependency.schema.json',
    'chio.experimental.native-funded-decision.v2': 'v2/decision.schema.json',
}
KEYWORDS = {'$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'const',
            'enum', 'required', 'properties', 'additionalProperties', 'allOf', 'anyOf',
            'if', 'then', 'else', 'not', 'minimum', 'maximum', 'minLength', 'maxLength',
            'pattern', 'minItems', 'maxItems', 'uniqueItems', 'items', 'prefixItems', 'contains'}


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def forbidden_number(_):
    raise Invalid('non-integer JSON number')


def bounded(value):
    require(value is not None, 'null is not an omitted optional value')
    if type(value) is int:
        require(0 <= value <= MAX_INT, 'integer outside safe unsigned range')
    elif isinstance(value, dict):
        for child in value.values():
            bounded(child)
    elif isinstance(value, list):
        for child in value:
            bounded(child)


class Shapes:
    """Closed subset needed by the six pinned local schemas; never fetches URLs."""
    def __init__(self):
        self.documents = {}
        self.families = {}
        paths = [ROOT / 'spec/schemas/chio-work' / rel for rel in FAMILIES.values()]
        paths += [ROOT / 'spec/schemas/chio-finding/v1' / name
                  for name in ['finding.schema.json', 'verifier-report.schema.json']]
        for path in paths:
            document = json.loads(path.read_text(), object_pairs_hook=pairs)
            require(document['$id'] not in self.documents, 'duplicate local schema id')
            self.audit(document)
            self.documents[document['$id']] = document
        for family, rel in FAMILIES.items():
            self.families[family] = 'https://chio.world/schemas/chio-work/' + rel

    @staticmethod
    def audit(schema):
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict) or set(schema) - KEYWORDS:
            raise RuntimeError('unsupported local schema vocabulary')
        for key in ['properties', '$defs']:
            for child in schema.get(key, {}).values():
                Shapes.audit(child)
        for key in ['allOf', 'anyOf', 'prefixItems']:
            for child in schema.get(key, []):
                Shapes.audit(child)
        for key in ['if', 'then', 'else', 'not', 'items', 'contains', 'additionalProperties']:
            if key in schema:
                Shapes.audit(schema[key])

    def matches(self, value, schema, base):
        try:
            self.check(value, schema, base)
            return True
        except Invalid:
            return False

    def check(self, value, schema, base):
        if isinstance(schema, bool):
            require(schema, 'schema denies value')
            return
        unknown = set(schema) - KEYWORDS
        # Unsupported schema instructions are configuration failures, never an anyOf mismatch.
        if unknown:
            raise RuntimeError(f'unsupported schema keywords: {sorted(unknown)}')
        base = schema.get('$id', base)
        if '$ref' in schema:
            uri, pointer = urldefrag(urljoin(base, schema['$ref']))
            if uri not in self.documents:
                raise RuntimeError('schema reference outside pinned local inventory')
            target = self.documents[uri]
            if pointer:
                if not pointer.startswith('/'):
                    raise RuntimeError('unsupported schema fragment')
                for key in pointer[1:].split('/'):
                    target = target[key.replace('~1', '/').replace('~0', '~')]
            self.check(value, target, uri)
        types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool}
        if 'type' in schema:
            if schema['type'] not in types:
                raise RuntimeError('unsupported schema type')
            require(type(value) is types[schema['type']], 'wrong JSON type')
        if 'const' in schema:
            require(type(value) is type(schema['const']) and value == schema['const'], 'wrong constant')
        if 'enum' in schema:
            require(any(type(value) is type(v) and value == v for v in schema['enum']), 'unknown enum')
        for child in schema.get('allOf', []):
            self.check(value, child, base)
        if 'anyOf' in schema:
            require(any(self.matches(value, child, base) for child in schema['anyOf']), 'no allowed shape')
        if 'not' in schema:
            require(not self.matches(value, schema['not'], base), 'forbidden shape')
        if 'if' in schema:
            branch = 'then' if self.matches(value, schema['if'], base) else 'else'
            self.check(value, schema.get(branch, True), base)
        if isinstance(value, dict):
            require(set(schema.get('required', [])) <= set(value), 'missing required field')
            properties = schema.get('properties', {})
            for key, child in value.items():
                if key in properties:
                    self.check(child, properties[key], base)
                elif 'additionalProperties' in schema:
                    self.check(child, schema['additionalProperties'], base)
        if isinstance(value, str):
            require(schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', MAX_BYTES), 'string length')
            if 'pattern' in schema:
                pattern = schema['pattern']
                if pattern.endswith('$'):
                    pattern = pattern[:-1] + r'\Z'
                require(re.search(pattern, value) is not None, 'string pattern')
        if type(value) is int:
            require(schema.get('minimum', 0) <= value <= schema.get('maximum', MAX_INT), 'integer bound')
        if isinstance(value, list):
            require(schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', MAX_BYTES), 'array length')
            if schema.get('uniqueItems', False):
                require(len({rfc8785.dumps(v) for v in value}) == len(value), 'duplicate array item')
            prefix = schema.get('prefixItems', [])
            for index, child in enumerate(value):
                self.check(child, prefix[index] if index < len(prefix) else schema.get('items', True), base)
            if 'contains' in schema:
                require(any(self.matches(child, schema['contains'], base) for child in value), 'missing array member')


def identifier(value):
    require(0 < len(value.encode()) <= 512 and not any(c.isspace() or ord(c) < 32 or 127 <= ord(c) <= 159 for c in value), 'identifier bound')


def nonzero(value):
    require(int(value[2:], 16) != 0, 'zero chain hash or address')


def requirements(value, kinds):
    require(value == [kind for kind in kinds if kind in value], 'noncanonical facet order')


def ed25519_key(value, weak=False):
    # Decode Edwards25519 and reject non-points, matching typed Ed25519 keys.
    p = 2**255 - 19
    encoded = int.from_bytes(bytes.fromhex(value), 'little')
    y = (encoded & (2**255 - 1)) % p
    sign = encoded >> 255
    d = (-121665 * pow(121666, p - 2, p)) % p
    x2 = ((y*y - 1) * pow(d*y*y + 1, p - 2, p)) % p
    x = pow(x2, (p + 3) // 8, p)
    if (x*x - x2) % p:
        x = x * pow(2, (p - 1) // 4, p) % p
    require((x*x - x2) % p == 0, 'invalid Ed25519 point')
    if x & 1 != sign:
        x = (-x) % p
    if weak:
        for _ in range(3):
            product = d*x*x*y*y % p
            x, y = (2*x*y * pow(1 + product, p - 2, p)) % p, ((y*y + x*x) * pow(1 - product, p - 2, p)) % p
        require((x, y) != (0, 1), 'weak Ed25519 issuer')


def semantic(body, shapes):
    kind = body['schema']
    schema = shapes.documents[shapes.families[kind]]
    kinds = schema.get('$defs', {}).get('facetKinds', {}).get('items', {}).get('enum', [])
    if kind.endswith('agreement.v2'):
        for key in ['authorityUuid', 'requestId']:
            identifier(body[key])
        for key in ['buyerKey', 'providerKey']:
            ed25519_key(body[key])
        requirements(body['requiredFindingFacets'], kinds)
        domain, work = body['domain'], body['work']
        require(domain['chainId'] == '31337', 'unsupported chain')
        for key in ['genesisHash', 'escrowCodeHash', 'tokenCodeHash', 'escrow', 'token']:
            nonzero(domain[key])
        require(domain['escrow'] != domain['token'], 'escrow/token collision')
        actors = [work[key] for key in ['payer', 'beneficiary', 'verifier']] + [domain['escrow']]
        for actor in actors:
            nonzero(actor)
        require(len(set(actors)) == 4, 'funding actor collision')
        require(0 < int(work['amount']) <= MAX_INT, 'amount bound')
        deadlines = [work[key] for key in ['submitBy', 'challengeUntil', 'resolveBy', 'refundAfter']]
        require(0 < deadlines[0] and all(a < b for a, b in zip(deadlines, deadlines[1:])), 'deadline order')
        if 'captureWaiverTerms' in body:
            waiver = body['captureWaiverTerms']['body']
            identifier(waiver['requestId'])
            require(0 < waiver['issuedAtUnixMs'] < waiver['expiresAtUnixMs'] <= waiver['issuedAtUnixMs'] + 86400000, 'waiver lifetime')
    elif kind.endswith('dependency.v1'):
        identifier(body['parentAuthority'])
        identifier(body['childAuthority'])
        require(body['parentAuthority'] != body['childAuthority'], 'dependency authority collision')
    else:
        binding = body['binding']
        nonzero(binding['allocationId'])
        for key in ['authorityUuid', 'operationId', 'holdId', 'authorizationId', 'outcomeId']:
            identifier(binding[key])
        if kind.endswith('submission.v1'):
            finding = body['finding']
            ed25519_key(finding['issuer'], weak=True)
            require(finding['expires_at'] > finding['issued_at'], 'Finding validity window')
            def finding_text(value):
                if isinstance(value, str):
                    require(len(value.encode()) <= 512 and bool(value.strip()), 'Finding text byte bound')
                elif isinstance(value, dict):
                    for v in value.values(): finding_text(v)
                elif isinstance(value, list):
                    for v in value: finding_text(v)
            finding_text(finding)
            unsigned = {**finding, 'finding_id': '', 'signature': ''}
            require(hashlib.sha256(rfc8785.dumps(unsigned)).hexdigest() == finding['finding_id'], 'Finding content id mismatch')
        else:
            for key in ['commitment', 'claimTransactionHash', 'claimBlockHash']:
                nonzero(body[key])
            assessment = body['findingAssessment']
            requirements(assessment['requiredFacets'], kinds)
            for facet in assessment['facets']:
                require(0 < len(facet['reason'].encode()) <= 512, 'facet reason byte bound')
                for reference in facet.get('evidence_refs', []):
                    identifier(reference)


def parse(raw, shapes=None):
    require(len(raw) <= MAX_BYTES, 'artifact byte bound')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_float=forbidden_number, parse_constant=forbidden_number)
    bounded(value)
    require(rfc8785.dumps(value) == raw, 'artifact is not exact canonical JSON')
    require(isinstance(value, dict) and isinstance(value.get('body'), dict), 'signed body missing')
    schema = value['body'].get('schema')
    require(isinstance(schema, str) and schema in FAMILIES, 'unsupported work schema')
    shapes = shapes or Shapes()
    uri = shapes.families[schema]
    shapes.check(value, shapes.documents[uri], uri)
    semantic(value['body'], shapes)
    return dict(schema=schema, sha256=hashlib.sha256(raw).hexdigest(), authorityVerified=False)


def vectors(manifest):
    suite = json.loads(manifest.read_text(), object_pairs_hook=pairs)
    require(suite['schema'] == 'chio.experimental.work-wire-vectors.v1', 'unknown vector manifest')
    shapes = Shapes()
    for case in suite['cases']:
        path = (manifest.parent / case['file']).resolve()
        require(path.is_relative_to(manifest.parent.resolve()), 'vector path escapes manifest')
        try:
            parse(path.read_bytes(), shapes)
            accepted = True
        except (ValueError, UnicodeError, OverflowError, RecursionError):
            accepted = False
        require(accepted == case['accepted'], f'vector disagreement: {case["name"]}')
    return dict(cases=len(suite['cases']), passed=True, authorityVerified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--vectors', action='store_true')
    args = parser.parse_args()
    try:
        if args.vectors:
            result = vectors(args.artifact)
        else:
            with args.artifact.open('rb') as source:
                result = parse(source.read(MAX_BYTES + 1))
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    except (ValueError, UnicodeError, OverflowError, RecursionError, RuntimeError, OSError) as error:
        print(f'work wire rejected: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
