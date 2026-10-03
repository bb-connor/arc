"""Separate historical source evidence from the currently qualified native profile."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

HISTORICAL_SOURCE = '71e5cbc3bf7b08f477ed0e0361f2cca0c36eaea3'
EVIDENCE = Path('docs/research/dynamic-delegation/evidence')
TOOLS = 'docs/papers/verifiable-work/tools/'
COMMANDS = {
    'workflow-tests': ['cargo', 'test', '--locked', '-p', 'chio-workflow'],
    'native-tests': ['cargo', 'test', '--locked', '-p', 'chio-kernel', '--features',
                     'admission-test-support', '--test', 'dynamic_delegation'],
    'native-regression': ['cargo', 'test', '--locked', '-p', 'chio-kernel', '--features',
                          'admission-test-support', '--test', 'three_owner_composition'],
    'evolution-tests': ['cargo', 'test', '--locked', '--no-fail-fast', '-p', 'chio-swarm-authority',
                        '-p', 'chio-runtime-core'],
    'workflow-clippy': ['cargo', 'clippy', '--locked', '-p', 'chio-workflow', '--all-targets', '--', '-D', 'warnings'],
    'native-clippy': ['cargo', 'clippy', '--locked', '-p', 'chio-kernel', '--features',
                     'admission-test-support', '--lib', '--test', 'dynamic_delegation',
                     '--example', 'dynamic_delegation', '--', '-D', 'warnings'],
    'evolution-clippy': ['cargo', 'clippy', '--locked', '-p', 'chio-swarm-authority',
                         '-p', 'chio-runtime-core', '--all-targets', '--', '-D', 'warnings'],
    'evolution-format': ['cargo', 'fmt', '-p', 'chio-swarm-authority',
                         '-p', 'chio-runtime-core', '--', '--check'],
    'format': ['rustfmt', '--edition', '2021', '--check',
               'crates/platform/chio-workflow/src/delegation/mod.rs',
               'crates/platform/chio-workflow/tests/delegation.rs',
               'crates/kernel/chio-kernel/src/delegated_work.rs',
               'crates/kernel/chio-kernel/tests/dynamic_delegation.rs',
               'crates/kernel/chio-kernel/examples/dynamic_delegation.rs'],
    'example': ['cargo', 'run', '--locked', '-p', 'chio-kernel', '--example', 'dynamic_delegation'],
    'artifact-tests': ['python3', '-B', '-m', 'unittest', 'discover', '-s', TOOLS.rstrip('/'), '-p', 'test_*.py'],
}


def safe_path(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and '..' not in path.parts


def verify_revision_files(root, revision, hashes):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        return ['invalid historical revision']
    if any(not safe_path(n) for n in hashes):
        return ['outside historical source root']
    remaining = set(hashes)
    errors = []
    with tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(['git', '-C', str(root), 'archive', '--format=tar', revision],
                                stdout=subprocess.PIPE, stderr=stderr)
        try:
            with tarfile.open(fileobj=proc.stdout, mode='r|') as archive:
                for member in archive:
                    if member.name not in remaining:
                        continue
                    remaining.remove(member.name)
                    if not member.isfile():
                        errors.append('non-file historical source: '+member.name)
                        continue
                    source = archive.extractfile(member)
                    digest = hashlib.file_digest(source, 'sha256').hexdigest()
                    if digest != hashes[member.name]:
                        errors.append('historical hash mismatch: '+member.name)
        except (tarfile.TarError, OSError) as error:
            errors.append('historical source archive failed: '+str(error))
        finally:
            proc.stdout.close()
            if proc.wait() != 0:
                errors.append('historical source revision unavailable')
    errors.extend('missing historical source: '+n for n in sorted(remaining))
    return errors


def native_sources(root):
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--cached',
                                     '--others', '--exclude-standard']).decode().split('\0')
    # Retain the broad repository context, including indirect test fixtures.
    # Only this change's publication/evidence files are qualified separately.
    excluded = ('docs/papers/verifiable-work/', 'docs/research/dynamic-delegation/',
                'docs/research/swarm-evolution/',
                'docs/superpowers/plans/2026-10-02-dynamic-delegation.md',
                'docs/superpowers/specs/2026-10-02-dynamic-delegation-design.md',
                'docs/superpowers/plans/2026-10-02-sovereign-swarm-evolution.md',
                'docs/superpowers/specs/2026-10-02-sovereign-swarm-evolution-design.md')
    selected = sorted({n for n in names if n and (n.startswith(TOOLS) or not n.startswith(excluded))})
    result = {}
    for name in selected:
        path = root/name
        if path.is_symlink():
            target = path.resolve(strict=True)
            if not target.is_relative_to(root.resolve()):
                raise ValueError('native input link escapes repository: '+name)
            relative = str(target.relative_to(root.resolve()))
            if not any(n == relative or n.startswith(relative+'/') for n in selected):
                raise ValueError('native input link target absent from inventory: '+name)
            data = b'symlink\0'+os.fsencode(os.readlink(path))
        else:
            data = path.read_bytes()
        result[name] = hashlib.sha256(data).hexdigest()
    return result


def verify_qualification(root, record):
    errors = []
    if record.get('schema') != 'chio.dynamic-delegation.qualification.v1':
        errors.append('invalid dynamic qualification schema')
    if record.get('source_files') != native_sources(root):
        errors.append('dynamic native source inventory drift')
    commands = record.get('commands', {})
    if set(commands) != set(COMMANDS):
        errors.append('missing or unexpected dynamic qualification commands')
    outputs = record.get('outputs', {})
    for name, command in COMMANDS.items():
        result = commands.get(name, {})
        if result.get('command') != command or result.get('exit_code') != 0:
            errors.append('dynamic qualification not terminal and passing: '+name)
        for stream in ('stdout', 'stderr'):
            path = result.get(stream)
            if path != str(EVIDENCE/f'qualified-{name}.{stream}') or path not in outputs:
                errors.append('missing dynamic command stream: '+name+'/'+stream)
    required = str(EVIDENCE/'qualified-native-recovery.json')
    if required not in outputs:
        errors.append('missing fresh native recovery trajectory')
    else:
        try:
            recovery = json.loads((root/required).read_text())
            expected = dict(cut='ToolReturnRecorded', signal=9, recovery_dispatches=0,
                            blind_replacement_rejected=True,
                            sibling_completed_before_recovery=True,
                            original_request='original-uncertain')
            if any(type(recovery.get(k)) is not type(v) or recovery.get(k) != v
                   for k, v in expected.items()):
                errors.append('native recovery trajectory does not establish the claimed cut')
            for name in ('recovered_receipt', 'sibling_receipt'):
                if not isinstance(recovery.get(name), dict) or not recovery[name].get('signature'):
                    errors.append('missing native recovery receipt: '+name)
        except (OSError, ValueError, TypeError, AttributeError):
            errors.append('invalid native recovery trajectory')
    for name, digest in outputs.items():
        file = (root/name).resolve()
        if (not safe_path(name) or not file.is_relative_to(root.resolve())
                or PurePosixPath(name).parent != PurePosixPath(EVIDENCE)
                or not PurePosixPath(name).name.startswith('qualified-')):
            errors.append('outside dynamic evidence root: '+name)
        elif not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            errors.append('dynamic evidence mismatch: '+name)
    return errors
