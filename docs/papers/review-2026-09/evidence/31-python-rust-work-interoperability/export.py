import hashlib
import json
from pathlib import Path
import shutil
import subprocess

repo = Path('/home/connor/backbay/arc')
run = Path('/tmp/chio-python31-qualified')
out = repo / 'docs/papers/review-2026-09/evidence/31-python-rust-work-interoperability'
out.mkdir(parents=True, exist_ok=False)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


previous_path = repo / 'docs/papers/review-2026-09/evidence/30-recoverable-checked-output-rejections/manifest.json'
previous = json.loads(previous_path.read_text())
for relative, expected in previous['artifact_sha256'].items():
    assert sha(previous_path.parent / relative) == expected, relative
changed = [relative for relative, expected in previous['source_sha256'].items()
           if sha(repo / relative) != expected]
assert set(changed) == {
    'docs/papers/evidence-crosses/paper.pdf',
    'docs/papers/evidence-crosses/sections/01-rule.tex',
    'docs/papers/review-2026-09/README.md',
    'examples/federated-work/README.md',
}, changed
(out / 'prior-source-comparison.json').write_text(json.dumps({
    'manifest': str(previous_path.relative_to(repo)), 'manifestSha256': sha(previous_path),
    'previousSourceFiles': len(previous['source_sha256']),
    'changedExistingSources': changed,
    'nativeRustSourcesChangedSincePriorQualification': False,
    'previousArtifactsVerified': len(previous['artifact_sha256']),
}, indent=2) + '\n')

summary = json.loads((run / 'summary.json').read_text())
assert summary['passed'] == len(summary['scenarios']) == 16
for case in summary['scenarios']:
    root = run / case['scenario']
    token = json.loads((root / 'buyer/session.json').read_text())
    seeds = [(root / role / 'key.seed').read_text().strip() for role in ('buyer', 'provider')]
    token_strings = [json.dumps(token), json.dumps(token, separators=(',', ':'))]

    def check(value):
        assert value != token, 'negotiation bearer credential in export'
        if isinstance(value, str):
            assert not any(seed in value for seed in seeds), 'private seed in export'
            assert not any(encoded in value for encoded in token_strings), 'encoded bearer token in export'
        elif isinstance(value, dict):
            for name, child in value.items():
                check(name)
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)

    files = {name: root / name for name in ('public.json', 'verification.json', 'cross-verification.json', 'isolation.json')}
    files['peers.json'] = root / 'buyer/peers.json'
    for name, path in files.items():
        if path.exists():
            check(json.loads(path.read_text()))
            shutil.copyfile(path, out / f'{case["scenario"]}-{name}')
shutil.copyfile(run / 'summary.json', out / 'summary.json')

logs = {
    'process-scenarios.log': '/tmp/chio-python31-qualified.log',
    'unit.log': '/tmp/chio-python31-unit-final.log',
    'dependency-install.log': '/tmp/chio-python31-install.log',
    'environment.log': '/tmp/chio-python31-environment.log',
    'source-check.log': '/tmp/chio-python31-source-check.log',
    'paper.log': '/tmp/chio-paper31.log',
    'diff-check.log': '/tmp/chio-diff31.log',
}
for name, source in logs.items():
    shutil.copyfile(source, out / name)
assert 'Ran 10 tests' in (out / 'unit.log').read_text() and '\nOK\n' in (out / 'unit.log').read_text()
assert 'body words: 4995' in (out / 'paper.log').read_text()
assert 'pages: 12' in (out / 'paper.log').read_text()
assert not (out / 'diff-check.log').read_bytes()
assert 'PASS:' in (out / 'source-check.log').read_text()
assert 'Installed 4 packages' in (out / 'dependency-install.log').read_text()

# The prior inventory covers all local native path dependencies and sources.
# No native source changed; augment it with the new participant and report.
paths = {repo / relative for relative in previous['source_sha256']}
example = repo / 'examples/federated-work'
example_files = {path for path in example.rglob('*') if path.is_file()
                 and '__pycache__' not in path.parts and 'target' not in path.parts and path.suffix != '.pyc'}
paths.update(example_files)
paths.add(repo / 'docs/papers/review-2026-09/31-python-rust-work-interoperability.md')
for name in ('paid-normal-public.json', 'paid-corrupt-report-public.json'):
    paths.add(previous_path.parent / name)
    shutil.copyfile(previous_path.parent / name, out / ('unit-fixture-' + name))
for path in sorted(example_files):
    target = out / 'source' / path.relative_to(repo)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
shutil.copyfile(Path(__file__), out / 'export.py')
(out / 'public-artifact-check.log').write_text(
    'PASS: all selected public artifacts omit both participant signing seeds and the private negotiation bearer capability.\n'
    'Paid work capabilities are proof-of-possession bound; public work packages intentionally disclose public test inputs.\n')
binary = repo / 'target/debug/chio-federated-work'
manifest = {
    'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
    'tree': 'uncommitted local checkout',
    'boundary': 'Separate Python buyer and verifier against the Rust provider; one host, project author and operator. Native market artifact signing, checked work, local credit accounting, retained terminal recovery and receipt inclusion. No Chio library or verifier subprocess in the Python participant. No external funds transfer, independent company operation, release, remote CI qualification or breakthrough claim.',
    'qualification': {'processScenarios': 16, 'pythonUnitTests': 10, 'paperPages': 12, 'paperBodyWords': 4995,
                      'freshHashRequiredPythonInstall': True, 'nativeRustSourcesUnchanged': True},
    'source_hash_scope': 'Prior complete local native path-dependency source inventory plus current example files, Python dependency lock, report, paper and public unit fixtures. Source inventory, not a reproducible-build attestation.',
    'provider_binary': {'path': str(binary.relative_to(repo)), 'sha256': sha(binary)},
    'source_sha256': {str(path.relative_to(repo)): sha(path) for path in sorted(paths)},
    'artifact_sha256': {str(path.relative_to(out)): sha(path) for path in sorted(out.rglob('*'))
                       if path.is_file() and path.name != 'manifest.json'},
}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
for relative, expected in manifest['source_sha256'].items():
    assert sha(repo / relative) == expected, relative
for relative, expected in manifest['artifact_sha256'].items():
    assert sha(out / relative) == expected, relative
print(json.dumps({'sourceFiles': len(manifest['source_sha256']), 'artifacts': len(manifest['artifact_sha256']),
                  'manifest': str(out / 'manifest.json')}))
