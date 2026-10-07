#!/usr/bin/env python3
"""Validate this specification package. Never executes or qualifies a runtime."""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

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
    return overrides.get(path, path.read_text(encoding='utf-8'))


def decode(path, overrides):
    return json.loads(read(path, overrides), object_pairs_hook=unique_object)


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


def validate(root=ROOT, overrides=None):
    overrides = overrides or {}
    errors = []
    stats = {}
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
        for path in sorted((root / 'contracts').glob('*.schema.json')):
            value = decode(path, overrides)
            Draft202012Validator.check_schema(value)
            value = {**value, '$id': path.as_uri()}
            schemas[path.name] = value
            registry = registry.with_resource(path.as_uri(), Resource.from_contents(value))
        validators = {
            name: Draft202012Validator(value, registry=registry, format_checker=FormatChecker())
            for name, value in schemas.items()
        }
        catalog = decode(root / 'contracts/fixture-catalog.json', overrides)
        fixtures = catalog['fixtures']
        paths = set()
        response_examples = []
        for fixture in fixtures:
            path = root / fixture['file']
            if path in paths:
                errors.append(f'duplicate fixture {fixture["file"]}')
            paths.add(path)
            value = decode(path, overrides)
            valid = validators[Path(fixture['schema']).name].is_valid(value)
            if valid != fixture['valid']:
                errors.append(f'{fixture["file"]}: expected valid={fixture["valid"]}, got {valid}')
            if fixture['valid'] and path.name.startswith('response-') and value.get('ok') is True:
                response_examples.append(value)
        if paths != set((root / 'examples').glob('*.json')):
            errors.append('fixture catalog does not cover every example exactly once')
        methods = decode(root / 'contracts/method-catalog.json', overrides)['methods']
        names = [item['method'] for item in methods]
        if len(names) != len(set(names)):
            errors.append('duplicate method catalog entry')
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
    mutants = {
        'missing acceptance': ({first: text.replace(heading, '### removed:', 1)}, 'missing acceptance definition'),
        'duplicate requirement': ({first: text + '\n' + row + '\n'}, 'duplicate requirements'),
        'broken local link': ({first: text + '\n[missing](definitely-absent.md)\n'}, 'broken local link'),
        'invalid positive fixture': ({example: json.dumps(bad)}, 'expected valid=True, got False'),
    }
    failures = []
    for name, (overrides, expected) in mutants.items():
        errors, _ = validate(overrides=overrides)
        if not any(expected in error for error in errors):
            failures.append(f'self-test accepted mutant: {name}')
    return failures, len(mutants)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-traceability', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.write_traceability:
        (ROOT / 'requirements.json').write_text(json.dumps(traceability(ROOT, {}), indent=2) + '\n')
    errors, stats = validate()
    if args.self_test:
        extra, count = self_test()
        errors += extra
        stats['validator_mutants'] = count
    print(json.dumps({'scope': 'documents and synthetic schemas only', 'passed': not errors, 'counts': stats, 'errors': errors}, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
