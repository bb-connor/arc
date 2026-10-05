"""Qualify the corrected claim replay and its mutation under one source inventory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / 'docs/papers/verifiable-work/evidence/claim-replay-20261005'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    files = [* (ROOT / 'contracts/src').rglob('*.sol'),
             * (ROOT / 'contracts/scripts').rglob('*.mjs'),
             * (ROOT / 'contracts/scripts/fixtures').rglob('*.sol'),
             * (ROOT / 'examples/funded-work-model').glob('*.py'),
             ROOT / 'examples/funded-work-model/claim-traces.json',
             ROOT / 'contracts/package.json', ROOT / 'contracts/pnpm-lock.yaml',
             Path(__file__), Path(__file__).with_name('compare.py')]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(files))}


def validate(record):
    if not record.get('complete') or record.get('source_files') != sources():
        raise ValueError('claim replay source qualification missing or stale')
    if set(record.get('commands', {})) != {'explore', 'compare', 'bytecode', 'mutation'}:
        raise ValueError('claim replay command inventory mismatch')
    for name, command in record['commands'].items():
        if command['exit_code'] != (1 if name == 'mutation' else 0):
            raise ValueError('unexpected claim replay exit: ' + name)
        for stream in ('stdout', 'stderr'):
            if sha(OUT / (name + '.' + stream)) != command[stream + '_sha256']:
                raise ValueError('claim replay output hash mismatch')
    corpus = json.loads((OUT / 'traces.json').read_text())
    comparison = json.loads((OUT / 'comparison.json').read_text())
    if (sha(OUT / 'traces.json') != sha(ROOT / 'examples/funded-work-model/claim-traces.json')
            or comparison['mismatches'] or corpus['counterexample'] is not None):
        raise ValueError('claim replay model or comparator disagrees')
    if len(corpus['traces']) != comparison['traces']:
        raise ValueError('claim replay trace count mismatch')
    positive = (OUT / 'bytecode.stdout').read_text()
    mutation = (OUT / 'mutation.stdout').read_text()
    passed = re.search(r'(?:#|ℹ) pass (\d+)', positive)
    failed = re.search(r'(?:#|ℹ) fail (\d+)', mutation)
    if (not passed or int(passed[1]) != len(corpus['traces']) + 1
            or not re.search(r'(?:#|ℹ) fail 0\b', positive)
            or not failed or int(failed[1]) == 0
            or 'WrongState' not in mutation or 'RefundNotDue' not in mutation
            or 'Missing expected rejection' not in mutation):
        raise ValueError('claim replay positive or negative calibration incomplete')
    return dict(CurrentClaimTraces=len(corpus['traces']), CurrentClaimSteps=comparison['checked_steps'],
                CurrentClaimTests=int(passed[1]), CurrentClaimMutationFailures=int(failed[1]))


def record():
    if (OUT / 'qualification.json').exists():
        raise ValueError('claim replay record already exists; preserve it before a replacement run')
    OUT.mkdir(parents=True, exist_ok=True)
    before = sources()
    result = dict(schema='chio.claim-replay.qualification.v1', source_files=before,
                  commands={}, complete=False)
    commands = {
        'explore': ['python3', '-B', 'examples/funded-work-model/claim_explorer.py', '--output', str(OUT / 'traces.json')],
        'compare': ['python3', '-B', 'docs/papers/verifiable-work/tools/compare.py', '--corpus', str(OUT / 'traces.json'), '--output', str(OUT / 'comparison.json')],
        'bytecode': ['node', '--test', 'contracts/scripts/work-claim-model.test.mjs'],
        'mutation': ['node', '--test', 'contracts/scripts/work-claim-model.test.mjs'],
    }
    for name, argv in commands.items():
        env = dict(os.environ)
        env.pop('CHIO_CLAIM_MUTATION', None)
        if name == 'mutation':
            env['CHIO_CLAIM_MUTATION'] = 'expire-payable'
        with (OUT / (name + '.stdout')).open('w') as stdout, (OUT / (name + '.stderr')).open('w') as stderr:
            run = subprocess.run(argv, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
        result['commands'][name] = dict(argv=argv, exit_code=run.returncode,
                                       mutation=env.get('CHIO_CLAIM_MUTATION'),
                                       stdout_sha256=sha(OUT / (name + '.stdout')),
                                       stderr_sha256=sha(OUT / (name + '.stderr')))
        (OUT / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
        print(f'{name}: exit {run.returncode}', flush=True)
        if run.returncode != (1 if name == 'mutation' else 0):
            raise ValueError('unexpected command failure: ' + name)
    result['complete'] = before == sources()
    (OUT / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(validate(result)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', action='store_true')
    args = parser.parse_args()
    if args.record:
        record()
    else:
        print(json.dumps(validate(json.loads((OUT / 'qualification.json').read_text()))))
