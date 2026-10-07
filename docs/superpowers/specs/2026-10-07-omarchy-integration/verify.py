#!/usr/bin/env python3
"""Validate this specification package. Never executes or qualifies a runtime."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent
PHASES = {
    'PRD': 'P0', 'UX': 'P1', 'UI': 'P1', 'ARC': 'P1', 'API': 'P1',
    'AUT': 'P3', 'HST': 'P2', 'LNX': 'P2', 'RES': 'P2', 'DSK': 'P4',
    'FIX': 'P5', 'OPS': 'P7', 'DLG': 'P6', 'DAT': 'P2', 'VER': 'P7',
    'PLN': 'P0', 'OBS': 'P7',
}
ROW = re.compile(r'^\| (OM-([A-Z]+)-\d{3}) \| (.*?) \| (AT-[A-Z]+-\d{3}) \|$', re.M)
ACCEPTANCE = re.compile(r'^### (AT-[A-Z]+-\d{3}):', re.M)
LINK = re.compile(r'(?<!!)\[[^\]\n]+\]\(([^\s)]+)(?:\s+"[^"\n]*")?\)')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read(path, overrides):
    return overrides[path] if path in overrides else path.read_text(encoding='utf-8')


def reject_constant(value):
    raise ValueError(f'non-JSON constant: {value}')


def decode(path, overrides):
    return json.loads(read(path, overrides), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def package_files(root):
    plans = root.parent.parent / 'plans' / root.name
    files = set(root.rglob('*')) | set(plans.rglob('*'))
    design = root.parent / (root.name + '-design.md')
    if design.exists():
        files.add(design)
    return sorted(p for p in files if p.is_file() and p.suffix in {'.md', '.json', '.py', '.txt'})


def source_digest(root, overrides):
    digest = hashlib.sha256()
    for path in package_files(root):
        if path == root / 'reviews/document-validation.json':
            continue
        name = path.relative_to(root.parent.parent).as_posix().encode('utf-8')
        content = read(path, overrides).encode('utf-8')
        for value in (name, content):
            digest.update(len(value).to_bytes(8, 'big'))
            digest.update(value)
    return digest.hexdigest()


def validation_record(root, overrides, stats):
    return {'scope': 'documents and synthetic schemas only', 'passed': True,
            'source_digest_sha256': source_digest(root, overrides),
            'counts': stats, 'errors': []}


def markdown_body(text):
    return re.sub(r'^```[^\n]*\n.*?^```\s*$', '', text, flags=re.M | re.S)


def anchors(text):
    result = set()
    counts = {}
    for title in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', text, flags=re.M):
        slug = re.sub(r'[^\w\- ]', '', title.lower()).replace(' ', '-')
        number = counts.get(slug, 0)
        counts[slug] = number + 1
        result.add(slug if not number else f'{slug}-{number}')
    return result


def traceability(root, overrides):
    rows = []
    for path in sorted(root.glob('[0-9][0-9]-*.md')):
        for rid, prefix, requirement, acceptance in ROW.findall(read(path, overrides)):
            rows.append({
                'requirement_id': rid,
                'requirement': requirement,
                'spec': path.name,
                'planning_phase': PHASES.get(prefix, 'UNMAPPED'),
                'proposed_acceptance_test': acceptance,
                'evidence_status': 'proposed',
            })
    return {
        'schema_version': 1,
        'status': 'proposed specifications, no runtime acceptance performed',
        'profile_applicability_gate': 'P0-PROFILE-MATRIX',
        'planning_phase_is_not_release_applicability': True,
        'requirements': rows,
    }


def validate(root=ROOT, overrides=None, check_record=True):
    overrides = overrides or {}
    errors = []
    stats = {}
    json_files = [p for p in package_files(root) if p.suffix == '.json']
    for path in json_files:
        try:
            decode(path, overrides)
        except (OSError, ValueError) as exc:
            label = path.relative_to(root if path.is_relative_to(root) else root.parent.parent)
            errors.append(f'{label}: invalid JSON: {exc}')
    stats['json_files'] = len(json_files)
    plans = root.parent.parent / 'plans' / root.name
    markdown = sorted(root.rglob('*.md')) + sorted(plans.glob('*.md'))
    design = root.parent / (root.name + '-design.md')
    if design.exists():
        markdown.append(design)
    numbered = sorted(root.glob('[0-9][0-9]-*.md'))
    if [p.name[:2] for p in numbered] != [f'{i:02}' for i in range(1, 18)]:
        errors.append('expected exactly numbered specs 01 through 17')
    all_reqs, all_cases = [], []
    for path in numbered:
        content = read(path, overrides)
        rows = ROW.findall(content)
        cases = ACCEPTANCE.findall(content)
        if not rows:
            errors.append(f'{path.name}: no requirements')
        for rid, prefix, _, aid in rows:
            if prefix not in PHASES:
                errors.append(f'{rid}: unmapped prefix')
            if aid not in cases:
                errors.append(f'{rid}: missing acceptance definition {aid}')
        if set(cases) != {row[3] for row in rows}:
            errors.append(f'{path.name}: acceptance definitions do not match requirements')
        all_reqs += [row[0] for row in rows]
        all_cases += cases
    for label, values in [('requirements', all_reqs), ('acceptance cases', all_cases)]:
        if len(set(values)) != len(values):
            errors.append(f'duplicate {label}')
    for path in markdown:
        content = read(path, overrides)
        if '\u2014' in content:
            errors.append(f'{path.name}: forbidden em dash')
        if re.search(r'https://github\.com/(?:bb-connor/arc|backbay-labs/arc)(?:/|\b)', content):
            errors.append(f'{path.name}: working-repository URL in public proposal')
        for target in LINK.findall(markdown_body(content)):
            target = target.strip('<>')
            parts = urlsplit(target)
            if parts.scheme or target.startswith('//'):
                continue
            destination = (path.parent / unquote(parts.path)).resolve() if parts.path else path
            if not destination.exists():
                errors.append(f'{path.name}: broken local link {target}')
            elif parts.fragment and destination.suffix == '.md':
                if unquote(parts.fragment) not in anchors(read(destination, overrides)):
                    errors.append(f'{path.name}: missing anchor {target}')
    generated = traceability(root, overrides)
    try:
        if decode(root / 'requirements.json', overrides) != generated:
            errors.append('requirements.json is stale; run --write-traceability')
    except (OSError, ValueError) as exc:
        errors.append(f'requirements.json: {exc}')
    schemas = {}
    registry = Registry()
    try:
        checker = FormatChecker()
        if ('date-time' not in checker.checkers
                or checker.conforms('not-a-date', 'date-time')
                or checker.conforms('2026-02-30T12:00:00Z', 'date-time')
                or not checker.conforms('2026-10-07T12:00:00Z', 'date-time')):
            errors.append('date-time format validation unavailable; install requirements-validation.txt')
        for path in sorted((root / 'contracts').glob('*.schema.json')):
            value = decode(path, overrides)
            Draft202012Validator.check_schema(value)
            value = {**value, '$id': path.as_uri()}
            schemas[path.name] = value
            registry = registry.with_resource(path.as_uri(), Resource.from_contents(value))
        validators = {
            name: Draft202012Validator(value, registry=registry, format_checker=checker)
            for name, value in schemas.items()
        }
        catalog = decode(root / 'contracts/fixture-catalog.json', overrides)
        method_catalog = decode(root / 'contracts/method-catalog.json', overrides)
        fixtures = catalog['fixtures']
        paths = set()
        response_examples = []
        request_coverage = {True: set(), False: set()}
        for fixture in fixtures:
            path = root / fixture['file']
            if path in paths:
                errors.append(f'duplicate fixture {fixture["file"]}')
            paths.add(path)
            value = decode(path, overrides)
            valid = validators[Path(fixture['schema']).name].is_valid(value)
            if valid != fixture['valid']:
                errors.append(f'{fixture["file"]}: expected valid={fixture["valid"]}, got {valid}')
            if Path(fixture['schema']).name == 'operator-request.schema.json':
                request_coverage[fixture['valid']].add(value.get('method'))
                if fixture['valid'] and value.get('method') == 'hello':
                    outcome = ('invalid_request' if value['protocol'] != value['params']['protocol']
                               else 'selected' if value['protocol'] == method_catalog['protocol']
                               else 'unsupported_version')
                    if fixture.get('hello_outcome') != outcome:
                        errors.append(f'{fixture["file"]}: incorrect hello_outcome; expected {outcome}')
            if fixture['valid'] and path.name.startswith('response-') and value.get('ok') is True:
                response_examples.append(value)
        if paths != set((root / 'examples').glob('*.json')):
            errors.append('fixture catalog does not cover every example exactly once')
        methods = method_catalog['methods']
        names = [item['method'] for item in methods]
        if len(names) != len(set(names)):
            errors.append('duplicate method catalog entry')
        for valid, covered in request_coverage.items():
            missing = set(names) - covered
            if missing:
                errors.append(f'missing valid={valid} request fixtures: {sorted(missing)}')
        requests = schemas['operator-request.schema.json']['oneOf']
        response_shapes = schemas['operator-response.schema.json']['oneOf']
        if set(names) != {item['properties']['method']['const'] for item in requests}:
            errors.append('request schema method set differs from catalog')
        successes = [item for item in response_shapes if item['properties']['ok']['const']]
        actual = {item['properties']['method']['const']: item['properties']['result']['properties']['kind']['const'] for item in successes}
        expected = {item['method']: item['result_kind'] for item in methods}
        if actual != expected or {v['method'] for v in response_examples} != set(names):
            errors.append('response schema/examples differ from method catalog')
        swaps = 0
        for value in response_examples:
            for method in names:
                if method == value['method']:
                    continue
                changed = copy.deepcopy(value)
                changed['method'] = method
                if validators['operator-response.schema.json'].is_valid(changed):
                    errors.append(f'cross-method response accepted: {value["method"]} as {method}')
                swaps += 1
        stats.update(schemas=len(schemas), fixtures=len(fixtures), response_substitutions=swaps)
    except Exception as exc:
        errors.append(f'contract validation failed: {type(exc).__name__}: {exc}')
    stats.update(specs=len(numbered), requirements=len(all_reqs), acceptance_cases=len(all_cases), markdown_files=len(markdown))
    if check_record:
        try:
            if decode(root / 'reviews/document-validation.json', overrides) != validation_record(root, overrides, stats):
                errors.append('document-validation.json is stale; run --self-test --write-validation')
        except (OSError, ValueError) as exc:
            errors.append(f'document-validation.json: {exc}')
    return errors, stats


def self_test():
    """Independent input mutants ensure the validator does not accept its own omissions."""
    first = ROOT / '01-product-scope.md'
    text = first.read_text()
    heading = ACCEPTANCE.search(text).group(0)
    row = ROW.search(text).group(0)
    example = ROOT / 'examples/request-task-get.json'
    bad = json.loads(example.read_text())
    bad['params']['task_id'] = '/untrusted/path'
    pins = ROOT / 'research/source-pins.json'
    record = ROOT / 'reviews/document-validation.json'
    old_record = decode(record, {})
    stale_record = copy.deepcopy(old_record)
    stale_record['counts']['fixtures'] = -1
    changed_pins = decode(pins, {})
    changed_pins['_freshness_probe'] = True
    response_schema = ROOT / 'contracts/operator-response.schema.json'
    weakened_response = decode(response_schema, {})
    scope_shape = next(shape for shape in weakened_response['oneOf']
                       if shape['properties']['method'].get('const') == 'scope.get'
                       and shape['properties']['ok'].get('const') is True)
    scope_shape['properties']['result']['properties']['value']['properties']['limits']['items'].pop('allOf', None)
    mutants = {
        'missing acceptance': ({first: text.replace(heading, '### removed:', 1)}, 'missing acceptance definition'),
        'duplicate requirement': ({first: text + '\n' + row + '\n'}, 'duplicate requirements'),
        'broken local link': ({first: text + '\n[missing](definitely-absent.md)\n'}, 'broken local link'),
        'invalid positive fixture': ({example: json.dumps(bad)}, 'expected valid=True, got False'),
        'malformed source pins': ({pins: '{'}, 'research/source-pins.json: invalid JSON'),
        'duplicate source keys': ({pins: '{"source":1,"source":2}'}, 'duplicate JSON key'),
        'non-JSON constant': ({pins: '{"source":NaN}'}, 'non-JSON constant'),
        'malformed validation record': ({record: '{'}, 'reviews/document-validation.json: invalid JSON'),
        'stale record counts': ({record: json.dumps(stale_record)}, 'document-validation.json is stale'),
        'stale source digest': ({pins: json.dumps(changed_pins)}, 'document-validation.json is stale'),
        'missing enforced ceiling check': ({response_schema: json.dumps(weakened_response)},
                                           'invalid-response-scope-enforced-null.json: expected valid=False, got True'),
    }
    failures = []
    for name, (overrides, expected) in mutants.items():
        errors, _ = validate(overrides=overrides)
        if not any(expected in error for error in errors):
            failures.append(f'self-test accepted mutant: {name}')
    catalog_path = ROOT / 'contracts/fixture-catalog.json'
    catalog = decode(catalog_path, {})
    methods = decode(ROOT / 'contracts/method-catalog.json', {})['methods']
    hello_count = 0
    for index, fixture in enumerate(catalog['fixtures']):
        if 'hello_outcome' not in fixture:
            continue
        modified = copy.deepcopy(catalog)
        modified['fixtures'][index]['hello_outcome'] = 'incorrect'
        errors, _ = validate(overrides={catalog_path: json.dumps(modified)})
        if not any('incorrect hello_outcome' in e for e in errors):
            failures.append(f'self-test accepted invalid hello outcome: {fixture["file"]}')
        hello_count += 1
    for method in methods:
        name = method['method']
        modified = copy.deepcopy(catalog)
        modified['fixtures'] = [f for f in modified['fixtures'] if not (
            f['schema'].endswith('operator-request.schema.json') and not f['valid']
            and decode(ROOT / f['file'], {}).get('method') == name)]
        errors, _ = validate(overrides={catalog_path: json.dumps(modified)})
        if not any('missing valid=False request fixtures' in e and name in e for e in errors):
            failures.append(f'self-test accepted missing negative coverage: {name}')
    missing_checker = FormatChecker()
    missing_checker.checkers.pop('date-time', None)
    with patch(__name__ + '.FormatChecker', return_value=missing_checker):
        errors, _ = validate()
    if not any('date-time format validation unavailable' in e for e in errors):
        failures.append('self-test accepted missing date-time checker')
    return failures, len(mutants) + len(methods) + hello_count + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-traceability', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--write-validation', action='store_true',
                        help='refresh structural record after successful self-tests')
    args = parser.parse_args()
    if args.write_validation and not args.self_test:
        parser.error('--write-validation requires --self-test')
    if args.write_traceability:
        (ROOT / 'requirements.json').write_text(json.dumps(traceability(ROOT, {}), indent=2) + '\n')
    errors, stats = validate(check_record=not args.write_validation)
    count = None
    if args.self_test:
        extra, count = self_test()
        errors += extra
    if args.write_validation and not errors:
        (ROOT / 'reviews/document-validation.json').write_text(
            json.dumps(validation_record(ROOT, {}, stats), indent=2) + '\n', encoding='utf-8')
        errors, stats = validate()
    report = {**validation_record(ROOT, {}, stats), 'passed': not errors, 'errors': errors}
    if count is not None:
        report['validator_mutants'] = count
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
