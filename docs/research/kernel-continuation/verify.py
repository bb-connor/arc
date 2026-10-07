#!/usr/bin/env python3
"""Record and check this continuation's local, source-bound qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RESULTS = HERE / 'results'
RECORD = RESULTS / 'verification.json'
PREFIX = str(HERE.relative_to(ROOT))
FROZEN_TREE = 'b8c5b771ca04903e219f9b42a50a050d326ba0ac'
NATIVE = 'crates/kernel/chio-kernel/tests/three_owner_composition.rs'
CHECKS = [
    ('python-tests', [sys.executable,'-B','-m','unittest','discover','-s',PREFIX,'-p','test_*.py'],0),
    ('capital', [sys.executable,'-B',f'{PREFIX}/capital.py'],0),
    ('synthetic-intake', [sys.executable,'-B',f'{PREFIX}/trial_intake.py',f'{PREFIX}/synthetic-demo/manifest.json'],0),
    ('empty-intake', [sys.executable,'-B',f'{PREFIX}/trial_intake.py',f'{PREFIX}/operator-template/manifest.json'],2),
    ('native-tests', ['cargo','test','--locked','-p','chio-kernel','--features','admission-test-support','--test','three_owner_composition'],0),
    ('native-clippy', ['cargo','clippy','--locked','-p','chio-kernel','--features','admission-test-support','--test','three_owner_composition','--','-D','warnings'],0),
    ('native-format', ['rustfmt','--edition','2021','--check',NATIVE],0),
]


def digest(path):
    data = ('symlink:' + os.readlink(path)).encode() if path.is_symlink() else path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def sources():
    roots = ['crates','third_party','spec','.cargo','Cargo.toml','Cargo.lock',
             'rust-toolchain.toml',PREFIX,'docs/research/kernel-work/results/integration-records.csv',
             'docs/superpowers/plans/2026-10-02-kernel-capital-and-composition.md']
    listing = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z','--',*roots],cwd=ROOT)
    paths = sorted(set(p for p in listing.decode().split('\0') if p and not p.startswith(f'{PREFIX}/results/')))
    return {p:digest(ROOT/p) for p in paths}


def outputs():
    return {str(p.relative_to(ROOT)):digest(p) for p in sorted(RESULTS.rglob('*'))
            if p.is_file() and p != RECORD}


def assert_record(record, actual_sources, actual_outputs):
    if record.get('schema') != 'chio.kernel-continuation.qualification.v1' or record.get('complete') is not True:
        raise ValueError('qualification is not complete')
    if record.get('sources') != actual_sources:
        raise ValueError('qualification source closure changed')
    if record.get('outputs') != actual_outputs:
        raise ValueError('qualification output closure changed')
    expected = [(name,command,code) for name,command,code in CHECKS]
    actual = [(r.get('name'),r.get('command'),r.get('exit_code')) for r in record.get('checks',[])]
    if actual != expected:
        raise ValueError('missing or nonterminal qualification check')
    for name,_,_ in CHECKS:
        for extension in ('stdout','stderr'):
            if f'{PREFIX}/results/qualified-{name}.{extension}' not in actual_outputs:
                raise ValueError('command output is not retained')


def frozen_paper():
    path = 'docs/papers/verifiable-work'
    tree = subprocess.check_output(['git','rev-parse',f'HEAD:{path}'],cwd=ROOT,text=True).strip()
    dirty = subprocess.check_output(['git','diff','HEAD','--',path],cwd=ROOT)
    untracked = subprocess.check_output(['git','ls-files','--others','--exclude-standard','--',path],cwd=ROOT)
    if tree != FROZEN_TREE or dirty or untracked:
        raise ValueError('frozen manuscript changed')


def check():
    frozen_paper()
    record = json.loads(RECORD.read_text())
    assert_record(record,sources(),outputs())
    print(f'PASS: {len(CHECKS)} terminal checks, {len(record["sources"])} source files, {len(record["outputs"])} output files; manuscript frozen')


def run():
    frozen_paper()
    RESULTS.mkdir(exist_ok=True)
    initial = sources()
    record = {'schema':'chio.kernel-continuation.qualification.v1','complete':False,
              'source_base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'scope':'Local research and native profile only; no hosted, independent or publication acceptance.',
              'sources':initial,'checks':[]}
    RECORD.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR='/tmp/chio-paper-target',CARGO_BUILD_JOBS='4',
               CHIO_CHECKOUT_ROOT=str(ROOT),CHIO_COMPOSITION_EVIDENCE=str(RESULTS/'native'))
    # A new successful command must produce its own trajectories. Archive the
    # old bytes before starting, including when the new run later fails.
    native = RESULTS/'native'
    if native.exists():
        archive = RESULTS/'native-history'/uuid.uuid4().hex
        archive.parent.mkdir(exist_ok=True)
        shutil.move(native,archive)
    native.mkdir()
    for name,command,expected in CHECKS:
        print(f'RUN {name}',flush=True)
        with (RESULTS/f'qualified-{name}.stdout').open('wb') as stdout, (RESULTS/f'qualified-{name}.stderr').open('wb') as stderr:
            result = subprocess.run(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=900)
        record['checks'].append({'name':name,'command':command,'exit_code':result.returncode})
        RECORD.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
        if result.returncode != expected:
            raise ValueError(f'{name}: exit {result.returncode}, expected {expected}; see retained output')
    if sources() != initial:
        raise ValueError('sources changed during qualification')
    native_files = {p.name for p in (RESULTS/'native').glob('*.json')}
    expected_files = {f'{name}-true.json' for name in ('none','tool-return-recorded','post-return-evaluation-begun',
        'post-return-resolved','security-release-acknowledged','security-release-checkpointed','terminal-projected')}
    expected_files.add('none-false.json')
    if native_files != expected_files:
        raise ValueError('native trajectory evidence is incomplete')
    record['outputs'] = outputs()
    record['complete'] = True
    RECORD.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    check()


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--record',action='store_true');modes.add_argument('--check',action='store_true')
    args=parser.parse_args()
    try:
        run() if args.record else check()
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        print(f'FAIL: {error}',file=sys.stderr)
        raise SystemExit(1)
