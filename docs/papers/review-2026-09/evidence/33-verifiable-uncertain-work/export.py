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
import incident

out = repo / 'docs/papers/review-2026-09/evidence/33-verifiable-uncertain-work'
run = Path('/tmp/chio-https33-final')
http = Path('/tmp/chio-http33-final')

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

previous_path = repo / 'docs/papers/review-2026-09/evidence/32-public-enrollment-and-https/manifest.json'
previous = json.loads(previous_path.read_text())
for relative, expected in previous['artifact_sha256'].items():
    assert sha(previous_path.parent / relative) == expected, relative
changed = [relative for relative, expected in previous['source_sha256'].items() if sha(repo / relative) != expected]
native = [x for x in changed if x.startswith('crates/')]
assert set(native) == {
    'crates/kernel/chio-kernel/src/admission_operation/remote_projection.rs',
    'crates/kernel/chio-kernel/src/admission_operation_tests/terminal_projection.rs',
    'crates/platform/chio-store-sqlite/src/admission_operation_store.rs',
    'crates/platform/chio-store-sqlite/src/admission_operation_store/projection.rs',
    'crates/platform/chio-store-sqlite/src/admission_operation_store_tests.rs',
    'crates/platform/chio-store-sqlite/src/admission_operation_store_tests/recovery.rs',
}, native
summary = json.loads((run / 'summary.json').read_text())
http_summary = json.loads((http / 'summary.json').read_text())
assert summary['passed'] == len(summary['scenarios']) == 19
assert http_summary['passed'] == len(http_summary['scenarios']) == 18
assert summary['scenarios'][-1]['denials'] == 13
for results in (summary, http_summary):
    uncertain = [x for x in results['scenarios'] if x.get('incidentVerified')]
    assert len(uncertain) == 3
    assert all(x['signedIncidentDenials'] == 10 and x['reserved'] == 100 and not x['paymentResolved']
               and x['immutableOperationJournalAndBudget'] and x['concurrentBuyers'] == 4 for x in uncertain)
logs = {
    'build.log': '/tmp/chio-incident33-build-final.log',
    'kernel-tests.log': '/tmp/chio-incident33-kernel-final.log',
    'store-tests.log': '/tmp/chio-incident33-store-final.log',
    'example-tests.log': '/tmp/chio-incident33-example-tests-final.log',
    'python-tests.log': '/tmp/chio-incident33-python-final.log',
    'native-clippy.log': '/tmp/chio-incident33-native-clippy-final.log',
    'example-clippy.log': '/tmp/chio-incident33-example-clippy.log',
    'format.log': '/tmp/chio-incident33-fmt.log',
    'example-format.log': '/tmp/chio-incident33-example-fmt.log',
    'diff-check.log': '/tmp/chio-incident33-diff.log',
    'paper.log': '/tmp/chio-incident33-paper.log',
    'https-run.log': '/tmp/chio-https33-final.log',
    'http-run.log': '/tmp/chio-http33-final.log',
}
for name, count in (('kernel-tests.log', 72), ('store-tests.log', 85), ('example-tests.log', 6)):
    assert f'test result: ok. {count} passed; 0 failed' in Path(logs[name]).read_text(), name
assert 'Ran 20 tests' in Path(logs['python-tests.log']).read_text()
assert Path(logs['python-tests.log']).read_text().rstrip().endswith('OK')
for name in ('native-clippy.log', 'example-clippy.log', 'build.log'):
    assert 'Finished ' in Path(logs[name]).read_text() and '\nerror' not in Path(logs[name]).read_text(), name
for name in ('format.log', 'example-format.log', 'diff-check.log'):
    assert not Path(logs[name]).read_bytes(), name
assert 'body words: 4997' in Path(logs['paper.log']).read_text()
assert 'pages: 12' in Path(logs['paper.log']).read_text()
out.mkdir(parents=True, exist_ok=False)

def write(name, value):
    (out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

write('prior-source-comparison.json', {'manifest': str(previous_path.relative_to(repo)),
    'manifestSha256': sha(previous_path), 'previousSourceFiles': len(previous['source_sha256']),
    'previousArtifactsVerified': len(previous['artifact_sha256']), 'changedExistingSources': changed})
write('https-summary.json', summary)
write('http-summary.json', http_summary)
for name, path in logs.items():
    shutil.copyfile(path, out / name)
counts = {'work': 0, 'incidents': 0, 'enrollments': 0, 'signedIncidentDenials': 0}
for scenario in summary['scenarios']:
    root = run / scenario['scenario']
    peers = json.loads((root / 'provider/peers.json').read_text())
    seeds = [(root / role / 'key.seed').read_text().strip() for role in ('buyer', 'provider')]
    seeds.append((root / 'provider/tls-key.pem').read_text().strip())
    def public_check(value):
        if isinstance(value, dict):
            if 'request' in value and 'delivery' in value:
                review.terminal(value['request'], value['delivery'], peers)
                counts['work'] += 1
            if 'request' in value and 'incident' in value:
                incident.verify(value['request'], value['incident'], peers)
                counts['incidents'] += 1
            for child in value.values():
                public_check(child)
        elif isinstance(value, list):
            for child in value:
                public_check(child)
    for filename in ('public.json', 'enrollment.json', 'activation.json', 'verification.json', 'cross-verification.json',
                     'isolation.json', 'invariants.json', 'incident-denials.json', 'incident-vectors.json'):
        path = root / filename
        if not path.exists():
            continue
        raw = path.read_text()
        assert not any(secret in raw for secret in seeds), 'private material in public artifact'
        assert '-----BEGIN PRIVATE KEY-----' not in raw
        value = json.loads(raw)
        if filename == 'public.json':
            public_check(value)
        elif filename == 'enrollment.json':
            client.verify_enrollment(value, peers['provider'], peers['buyer'], value['body']['origin'])
            counts['enrollments'] += 1
        elif filename == 'incident-vectors.json':
            assert value['peers'] == peers
            incident.verify(value['valid']['request'], value['valid']['incident'], peers)
            assert len(value['cases']) == 10
            for vector in value['cases']:
                v = vector['public']
                envelope = v['incident']['projection']
                p.Ed25519PublicKey.from_public_bytes(p.hex_bytes(peers['provider'])).verify(
                    p.hex_bytes(envelope['signature'], 64), incident.NATIVE.encode() + b'\0' + p.canonical(envelope['body']))
                try:
                    incident.verify(v['request'], v['incident'], peers)
                except p.ProtocolError:
                    counts['signedIncidentDenials'] += 1
                else:
                    raise AssertionError(vector['case'])
        shutil.copyfile(path, out / (scenario['scenario'] + '-' + filename))
assert counts['incidents'] == 3 and counts['signedIncidentDenials'] == 30 and counts['enrollments'] == 19, counts
write('public-artifact-check.json', {**counts, 'applicationSeedsOrTlsPrivateKeysExported': False,
    'roleDatabasesExported': False, 'legacyBearerCredentialsExported': False,
    'meaning': 'Expected application peers are supplied separately by the fixture operator. Work inputs are public test data. Incidents are historical attestations, not proof of no effect or authority to release payment.'})
paths = {repo / path for path in previous['source_sha256']}
example = repo / 'examples/federated-work'
example_files = {path for path in example.rglob('*') if path.is_file() and 'target' not in path.parts
                 and '__pycache__' not in path.parts and path.suffix != '.pyc'}
paths.update(example_files)
report = repo / 'docs/papers/review-2026-09/33-verifiable-uncertain-work.md'
paths.add(report)
for path in sorted(example_files | {repo / path for path in native} | {report}):
    target = out / 'source' / path.relative_to(repo)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
shutil.copyfile(__file__, out / 'export.py')
write('commands.json', {'build': 'cargo build --manifest-path examples/federated-work/Cargo.toml --locked',
    'kernelTests': 'cargo test -p chio-kernel --lib admission_operation:: --locked',
    'storeTests': 'cargo test -p chio-store-sqlite --lib admission_operation_store:: --locked',
    'exampleTests': 'cargo test --manifest-path examples/federated-work/Cargo.toml --locked',
    'pythonTests': 'PYTHONDONTWRITEBYTECODE=1 /tmp/chio-python31-locked-venv/bin/python -m unittest discover -s examples/federated-work/python_buyer -p test_*.py',
    'https': 'python3 examples/federated-work/https_smoke.py --binary examples/federated-work/target/debug/chio-federated-work --python-env /tmp/chio-python31-locked-venv --output /tmp/chio-https33-final',
    'http': 'python3 examples/federated-work/python_smoke.py --binary examples/federated-work/target/debug/chio-federated-work --python-env /tmp/chio-python31-locked-venv --output /tmp/chio-http33-final',
    'paper': 'make -C docs/papers/evidence-crosses all'})
binary = repo / 'examples/federated-work/target/debug/chio-federated-work'
manifest = {'base_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
    'tree': 'uncommitted local checkout',
    'boundary': 'Qualified retained incident export and Python buyer retention over local HTTPS. One author, host and operator. Historical evidence only; no no-effect proof, payment resolution, external funds, independent-company operation, release, remote CI or breakthrough claim.',
    'qualification': {'httpsScenarios':19,'legacyHttpScenarios':18,'incidentScenariosPerTransport':3,
        'signedIncidentDenialClassesPerScenario':10,'enrollmentAndTransportDenials':13,
        'nativeAdmissionTests':72,'sqliteAdmissionTests':85,'exampleRustTests':6,'pythonTests':20,
        'paperPages':12,'paperBodyWords':4997},
    'provider_binary': {'path':str(binary.relative_to(repo)),'sha256':sha(binary)},
    'source_hash_scope':'Previous complete local dependency source inventory plus current example sources, public unit vectors and report. Source inventory, not a reproducible-build attestation.',
    'source_sha256': {str(path.relative_to(repo)):sha(path) for path in sorted(paths)},
    'artifact_sha256': {str(path.relative_to(out)):sha(path) for path in sorted(out.rglob('*')) if path.is_file() and path.name!='manifest.json'}}
write('manifest.json',manifest)
for relative, expected in manifest['source_sha256'].items():
    assert sha(repo / relative)==expected, relative
for relative, expected in manifest['artifact_sha256'].items():
    assert sha(out / relative)==expected, relative
print(json.dumps({'sourceFiles':len(manifest['source_sha256']),'artifacts':len(manifest['artifact_sha256']),**counts}))
