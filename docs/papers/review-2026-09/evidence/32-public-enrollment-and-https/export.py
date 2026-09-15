import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

repo = Path('/home/connor/backbay/arc')
sys.path.insert(0, str(repo / 'examples/federated-work/python_buyer'))
import client
import protocol as p
import review

out = repo / 'docs/papers/review-2026-09/evidence/32-public-enrollment-and-https'
out.mkdir(parents=True, exist_ok=False)
run = Path('/tmp/chio-https32-qualified')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


previous_path = repo / 'docs/papers/review-2026-09/evidence/31-python-rust-work-interoperability/manifest.json'
previous = json.loads(previous_path.read_text())
for relative, expected in previous['artifact_sha256'].items():
    assert sha(previous_path.parent / relative) == expected, relative
changed = [relative for relative, expected in previous['source_sha256'].items()
           if sha(repo / relative) != expected]
assert not any(path.startswith('crates/') for path in changed), changed
(out / 'prior-source-comparison.json').write_text(json.dumps({
    'manifest': str(previous_path.relative_to(repo)), 'manifestSha256': sha(previous_path),
    'previousSourceFiles': len(previous['source_sha256']), 'changedExistingSources': changed,
    'productionCrateSourcesChangedSincePriorQualification': False,
    'previousArtifactsVerified': len(previous['artifact_sha256']),
}, indent=2) + '\n')

summary = json.loads((run / 'summary.json').read_text())
assert summary['passed'] == len(summary['scenarios']) == 17
assert summary['scenarios'][-1]['denials'] == 13
verified_work = 0
verified_enrollments = 0
verified_sender_denials = 0
for case in summary['scenarios']:
    root = run / case['scenario']
    peers = json.loads((root / 'provider/peers.json').read_text())
    secrets = [(root / role / 'key.seed').read_text().strip() for role in ('buyer', 'provider')]
    secrets.append((root / 'provider/tls-key.pem').read_text().strip())
    enrollment = json.loads((root / 'enrollment.json').read_text())
    client.verify_enrollment(enrollment, peers['provider'], peers['buyer'], enrollment['body']['origin'])
    assert all(g['dpop_required'] is True for g in enrollment['body']['session']['scope']['grants'])
    assert not (root / 'buyer/session.json').exists()
    assert not (root / 'buyer/peers.json').exists()
    verified_enrollments += 1

    def check(value):
        global verified_work
        if isinstance(value, str):
            assert not any(secret in value for secret in secrets), 'private key in public export'
            assert '-----BEGIN PRIVATE KEY-----' not in value, 'private PEM in public export'
            assert '-----BEGIN EC PRIVATE KEY-----' not in value, 'private EC PEM in public export'
            assert '-----BEGIN RSA PRIVATE KEY-----' not in value, 'private RSA PEM in public export'
        elif isinstance(value, dict):
            if 'request' in value and 'delivery' in value:
                review.terminal(value['request'], value['delivery'], peers)
                verified_work += 1
            for key, child in value.items():
                check(key)
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)

    files = {name: root / name for name in ('public.json', 'verification.json', 'cross-verification.json',
                                           'isolation.json', 'enrollment.json', 'activation.json')}
    files['peers.json'] = root / 'provider/peers.json'
    for name, path in files.items():
        if path.exists():
            value = json.loads(path.read_text())
            check(value)
            if name == 'public.json' and case['scenario'] == 'transport-denials':
                for denial in value['denials']:
                    if denial['case'].startswith('public-enrollment-'):
                        receipt = denial['response']['task']['metadata']['chio']['receipt']
                        args = receipt['action']['parameters']
                        p.verify_quote(args, peers)
                        p.receipt(receipt, peers['provider'], 'quote', args)
                        assert receipt['decision']['verdict'] == 'deny'
                        verified_sender_denials += 1
            shutil.copyfile(path, out / f'{case["scenario"]}-{name}')
shutil.copyfile(run / 'summary.json', out / 'https-summary.json')
http = Path('/tmp/chio-http32-qualified')
http_summary = json.loads((http / 'summary.json').read_text())
assert http_summary['passed'] == 16
shutil.copyfile(http / 'summary.json', out / 'http-regression-summary.json')
assert verified_work == 14, verified_work
assert verified_sender_denials == 2

logs = {
    'https-scenarios.log': '/tmp/chio-https32-qualified.log',
    'http-regression.log': '/tmp/chio-http32-qualified.log',
    'rust-build.log': '/tmp/chio-https32-build-qualified.log',
    'rust-unit.log': '/tmp/chio-https32-rust-qualified.log',
    'python-unit.log': '/tmp/chio-https32-python-unit.log',
    'clippy.log': '/tmp/chio-https32-clippy-qualified.log',
    'rust-format.log': '/tmp/chio-https32-format-qualified.log',
    'python-environment.log': '/tmp/chio-python31-environment.log',
    'source-check.log': '/tmp/chio-https32-source-check.log',
    'paper.log': '/tmp/chio-paper32.log',
    'diff-check.log': '/tmp/chio-diff32.log',
}
for name, path in logs.items():
    shutil.copyfile(path, out / name)
for name in ('rust-build.log', 'clippy.log'):
    assert 'Finished ' in (out / name).read_text(), name
assert '6 passed; 0 failed' in (out / 'rust-unit.log').read_text()
assert 'Ran 16 tests' in (out / 'python-unit.log').read_text() and '\nOK\n' in (out / 'python-unit.log').read_text()
assert 'pages: 12' in (out / 'paper.log').read_text() and 'body words: 4999' in (out / 'paper.log').read_text()
for name in ('rust-format.log', 'diff-check.log'):
    assert not (out / name).read_bytes(), name

metadata = json.loads(subprocess.check_output([
    'cargo', 'metadata', '--locked', '--offline', '--format-version', '1',
    '--manifest-path', str(repo / 'examples/federated-work/Cargo.toml')], cwd=repo, text=True))
paths = set()
for package in metadata['packages']:
    if package.get('source') is not None:
        continue
    root = Path(package['manifest_path']).parent
    for name in ('Cargo.toml', 'build.rs'):
        if (root / name).is_file():
            paths.add(root / name)
    for name in ('src', 'tests', 'benches'):
        paths.update(path for path in (root / name).rglob('*') if path.is_file())
selected = {'rustls', 'rustls-pemfile', 'tokio-rustls', 'tokio', 'tiny_http'}
(out / 'tls-dependencies.json').write_text(json.dumps([
    {key: package[key] for key in ('name', 'version', 'source')}
    for package in metadata['packages'] if package['name'] in selected
], indent=2) + '\n')
example = repo / 'examples/federated-work'
example_files = {path for path in example.rglob('*') if path.is_file()
                 and '__pycache__' not in path.parts and 'target' not in path.parts and path.suffix != '.pyc'}
paths.update(example_files)
paths.update(repo / name for name in (
    'Cargo.toml', 'Cargo.lock', 'AGENTS.md',
    'docs/papers/evidence-crosses/sections/01-rule.tex', 'docs/papers/evidence-crosses/paper.pdf',
    'docs/papers/review-2026-09/32-public-enrollment-and-https.md',
    'docs/papers/review-2026-09/README.md',
    'docs/papers/review-2026-09/evidence/30-recoverable-checked-output-rejections/paid-normal-public.json',
    'docs/papers/review-2026-09/evidence/30-recoverable-checked-output-rejections/paid-corrupt-report-public.json',
))
for path in sorted(example_files):
    target = out / 'source' / path.relative_to(repo)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
shutil.copyfile(Path(__file__), out / 'export.py')
(out / 'public-artifact-check.json').write_text(json.dumps({
    'verifiedPublicWorkPackages': verified_work, 'verifiedPublicEnrollments': verified_enrollments,
    'verifiedSignedSenderDenials': verified_sender_denials,
    'applicationSeedsOrTlsPrivateKeysExported': False,
    'legacyBearerCredentialsExported': False,
    'boundary': 'Public enrollment capabilities require the buyer key. Public work packages disclose the public test input. Verification uses the configured peer pins copied from provider state, not keys selected by a remote package.',
}, indent=2) + '\n')
binary = repo / 'target/debug/chio-federated-work'
manifest = {
    'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
    'tree': 'uncommitted local checkout',
    'boundary': 'Native TLS 1.3 provider and separately implemented Python buyer. Provider-signed public enrollment, receiver-local trust activation and proof-of-possession-bound negotiation. All runs are on one host under one project author and operator. No independent administration, external funds, release, remote CI qualification, public activation or breakthrough claim.',
    'qualification': {'httpsScenarios': 17, 'enrollmentAndTransportDenials': 13, 'legacyHttpScenarios': 16,
                      'rustUnitTests': 6, 'pythonUnitTests': 16, 'paperPages': 12, 'paperBodyWords': 4999},
    'source_hash_scope': 'Current local path-dependency manifests, build scripts and source/test/bench trees, all example sources and locks, paper/report references and public unit fixtures. Source inventory, not a reproducible-build attestation.',
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
                  'verifiedPublicWorkPackages': verified_work, 'verifiedPublicEnrollments': verified_enrollments,
                  'manifest': str(out / 'manifest.json')}))
