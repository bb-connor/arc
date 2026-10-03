"""Run the focused profile once and bind terminal evidence to its source inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from provenance import COMMANDS, EVIDENCE, native_sources, verify_qualification

ROOT = Path(__file__).resolve().parents[4]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--record', action='store_true')
    args = parser.parse_args()
    directory = ROOT/EVIDENCE
    path = directory/'qualification.json'
    if not args.record:
        errors = verify_qualification(ROOT, json.loads(path.read_text()))
        if errors:
            raise SystemExit('\n'.join(errors))
        print('PASS: current native source and terminal evidence agree')
        return
    previous = [*directory.glob('qualified-*')]
    if path.exists():
        previous.append(path)
    if previous:
        archive = directory/'history'/str(uuid.uuid4())
        archive.mkdir(parents=True)
        for old in previous:
            shutil.move(old, archive/old.name)
    before = native_sources(ROOT)
    env = os.environ.copy()
    env.setdefault('CARGO_TARGET_DIR', '/tmp/chio-paper-target')
    env.setdefault('CARGO_BUILD_JOBS', '4')
    env['CHIO_CHECKOUT_ROOT'] = str(ROOT)
    env['CHIO_DYNAMIC_RECOVERY_EVIDENCE'] = str(directory/'qualified-native-recovery.json')
    commands = {}
    for name, command in COMMANDS.items():
        stdout = directory/f'qualified-{name}.stdout'
        stderr = directory/f'qualified-{name}.stderr'
        start = time.monotonic()
        with stdout.open('w') as out, stderr.open('w') as err:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err)
        commands[name] = dict(command=command, exit_code=result.returncode,
                              seconds=round(time.monotonic()-start, 3),
                              stdout=str(stdout.relative_to(ROOT)), stderr=str(stderr.relative_to(ROOT)))
        print(f'{name}: exit {result.returncode}', flush=True)
        if result.returncode:
            break
    after = native_sources(ROOT)
    outputs = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(directory.glob('qualified-*')) if p.is_file()}
    record = dict(schema='chio.dynamic-delegation.qualification.v1', source_files=before,
                  commands=commands, outputs=outputs)
    path.write_text(json.dumps(record, indent=2)+'\n')
    errors = verify_qualification(ROOT, record)
    if before != after:
        errors.append('source changed during qualification')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'PASS: {len(commands)} terminal checks, {len(before)} source files, {len(outputs)} outputs')


if __name__ == '__main__':
    main()
