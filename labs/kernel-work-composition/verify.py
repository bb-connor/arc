#!/usr/bin/env python3
"""Reproduce the bounded experiment or verify the exact retained artifact bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LAB = Path('labs/kernel-work-composition')
OUT = Path('docs/research/kernel-work/results/model')

def digest(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()

def sources():
    files = [p.relative_to(ROOT) for p in (ROOT / LAB / 'src').rglob('*.rs')]
    files += [p.relative_to(ROOT) for p in (ROOT / LAB / 'tests').rglob('*.rs')]
    files += [LAB / name for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'README.md', 'verify.py']]
    files += [Path('docs/research/kernel-work') / name for name in ['MODEL.md', 'fixtures.json', 'WITNESS.md', 'G1-DECISION.md', 'task3-sources.json', 'recovery-baseline.json']]
    return {str(p): digest(p) for p in sorted(files)}

def check():
    manifest = json.loads((ROOT / OUT / 'verification.json').read_text())
    if manifest.get('complete') is not True or len(manifest['commands']) != 5:
        raise ValueError('incomplete verification run')
    expected_streams = [str(OUT / f'{name}.stdout') for name in ['tests', 'format', 'clippy', 'explorer', 'provenance']]
    if [item['stdout'] for item in manifest['commands']] != expected_streams:
        raise ValueError('verification command sequence mismatch')
    if manifest['sources'] != sources():
        raise ValueError('source hash mismatch; rerun --record for changed inputs')
    for item in manifest['commands']:
        if item['exit_code'] != 0:
            raise ValueError(f"failed recorded command: {item['argv']}")
        for stream in ['stdout', 'stderr']:
            if digest(item[stream]) != item[stream + '_sha256']:
                raise ValueError(f'{stream} evidence hash mismatch')
    report = json.loads((ROOT / OUT / 'explorer.stdout').read_text())
    if report['violations'] or report['divergences']:
        raise ValueError('recorded exploration failure')
    print(json.dumps({'result': 'pass', 'source_files': len(manifest['sources']), 'commands': len(manifest['commands']), 'variants': len(report['scenarios']), 'transitions': report['transitions'], 'scope': 'retained source and artifact verification'}, indent=2))

def record():
    before = sources()
    manifest = {'schema': 'chio.kernel-work.verification.v1', 'repository_head_at_run': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'sources': before, 'commands': [], 'complete': False}
    cargo = ['--locked', '--manifest-path', str(LAB / 'Cargo.toml')]
    commands = [
        ('tests', ['cargo', 'test', *cargo]),
        ('format', ['cargo', 'fmt', '--manifest-path', str(LAB / 'Cargo.toml'), '--', '--check']),
        ('clippy', ['cargo', 'clippy', *cargo, '--all-targets', '--', '-D', 'warnings']),
        ('explorer', ['cargo', 'run', *cargo, '--bin', 'explore']),
        ('provenance', ['python3', 'docs/research/kernel-work/verify_task1.py']),
    ]
    for name, argv in commands:
        start = time.monotonic()
        stdout = OUT / f'{name}.stdout'
        stderr = OUT / f'{name}.stderr'
        with (ROOT / stdout).open('w') as out, (ROOT / stderr).open('w') as err:
            result = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, check=False)
        item = {'argv': argv, 'exit_code': result.returncode, 'elapsed_seconds_diagnostic_only': round(time.monotonic() - start, 3), 'stdout': str(stdout), 'stderr': str(stderr), 'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}
        manifest['commands'].append(item)
        (ROOT / OUT / 'verification.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(f'{name}: exit {result.returncode}', flush=True)
        if result.returncode:
            raise RuntimeError(f'{name} failed; inspect retained logs')
    if before != sources():
        raise ValueError('inputs changed during verification')
    manifest['complete'] = True
    (ROOT / OUT / 'verification.json').write_text(json.dumps(manifest, indent=2) + '\n')
    check()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--record', action='store_true')
    choice.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        record() if args.record else check()
    except (ValueError, RuntimeError, KeyError, OSError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
