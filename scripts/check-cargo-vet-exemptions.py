#!/usr/bin/env python3
"""Reject added exemptions and weakened Cargo Vet policy requirements.

The AWS-LC upstream-review criterion is the sole explicit composite exception:
its exact policy is coupled to the source, feature and fork-audit checks in
check-supply-chain.sh. It does not imply that published AWS-LC is deployable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib


AWS_LC_DEPENDENCIES = {name: 'safe-to-deploy' for name in
                       ('aws-lc-sys', 'aws-lc-fips-sys', 'untrusted', 'zeroize')}


def load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding='utf-8'))


def criteria_set(value) -> set[str]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError('criteria must be a string or list of strings')
    return set(values)


def exemption_entries(path: Path) -> set[str]:
    return {f'{name}@{row["version"]}#{",".join(sorted(criteria_set(row["criteria"])))}'
            for name, rows in load(path).get('exemptions', {}).items() for row in rows}


def implies(value, required: str, definitions: dict) -> bool:
    pending = list(criteria_set(value))
    seen = set()
    while pending:
        criterion = pending.pop()
        if criterion == required or (criterion == 'safe-to-deploy' and required == 'safe-to-run'):
            return True
        if criterion not in seen:
            seen.add(criterion)
            pending.extend(criteria_set(definitions.get(criterion, {}).get('implies', [])))
    return False


def weak_policies(config: dict, audits: dict) -> set[str]:
    result = set()
    definitions = audits.get('criteria', {})
    for package, policy in config.get('policy', {}).items():
        composite = (package == 'aws-lc-rs'
                     and policy.get('audit-as-crates-io') is True
                     and policy.get('criteria') == 'aws-lc-upstream-reviewed'
                     and policy.get('dependency-criteria') == AWS_LC_DEPENDENCIES)
        for field, required in [('criteria', 'safe-to-deploy'), ('dev-criteria', 'safe-to-run')]:
            if field not in policy or (composite and field == 'criteria'):
                continue
            if not implies(policy[field], required, definitions):
                result.add(f'{package}.{field}={json.dumps(policy[field], sort_keys=True)}')
        for dependency, criteria in policy.get('dependency-criteria', {}).items():
            if not implies(criteria, 'safe-to-deploy', definitions):
                result.add(f'{package}.dependency-criteria.{dependency}={json.dumps(criteria)}')
    return result


def audit_definitions(path: Path | None, config: Path) -> dict:
    if path is not None:
        return load(path)
    adjacent = config.parent / 'audits.toml'
    return load(adjacent) if adjacent.exists() else {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--head', required=True, type=Path)
    parser.add_argument('--base-audits', type=Path)
    parser.add_argument('--head-audits', type=Path)
    parser.add_argument('--policy-only', action='store_true',
                        help='Check policy weakening without the separately justified exemption gate')
    args = parser.parse_args()
    try:
        base_exemptions = exemption_entries(args.base)
        head_exemptions = exemption_entries(args.head)
        added = sorted(head_exemptions - base_exemptions)
        if args.policy_only:
            added = []
        weak = sorted(weak_policies(load(args.head), audit_definitions(args.head_audits, args.head))
                      - weak_policies(load(args.base), audit_definitions(args.base_audits, args.base)))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'invalid cargo-vet policy: {error}', file=sys.stderr)
        return 1
    print(f'cargo-vet exemption count: base={len(base_exemptions)} head={len(head_exemptions)}')
    if added:
        print('net-new cargo-vet exemptions are blocked: ' + ', '.join(added), file=sys.stderr)
    if weak:
        print('weakened cargo-vet policy is blocked: ' + ', '.join(weak), file=sys.stderr)
    return int(bool(added or weak))


if __name__ == '__main__':
    raise SystemExit(main())
