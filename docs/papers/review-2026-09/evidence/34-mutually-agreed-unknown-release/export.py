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
import resolution

out = repo / 'docs/papers/review-2026-09/evidence/34-mutually-agreed-unknown-release'
prior_path = repo / 'docs/papers/review-2026-09/evidence/33-verifiable-uncertain-work/manifest.json'
prior = json.loads(prior_path.read_text())

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

for path, expected in prior['artifact_sha256'].items():
    assert sha(prior_path.parent / path) == expected, path
changed = [path for path, expected in prior['source_sha256'].items() if sha(repo / path) != expected]
logs = {
    'build.log': 'example-build-final', 'native-clippy.log': 'native-clippy',
    'example-clippy.log': 'example-clippy-final', 'kernel-tests.log': 'kernel-tests',
    'integration-tests.log': 'integration-final', 'store-tests.log': 'store-tests2',
    'budget-tests.log': 'budget-tests', 'global-tests.log': 'global-tests',
    'example-tests.log': 'example-tests-final', 'python-tests.log': 'python-final',
    'format.log': 'format', 'example-format.log': 'example-format',
    'diff-check.log': 'diff', 'paper.log': 'paper',
    'https-run.log': 'https-final', 'http-run.log': 'http-final', 'release-run.log': 'crashes-final',
}
logs = {name: Path('/tmp/chio-release34-' + suffix + '.log') for name, suffix in logs.items()}
for name, count in [('kernel-tests.log',72),('integration-tests.log',13),('store-tests.log',86),
                    ('budget-tests.log',122),('global-tests.log',9),('example-tests.log',7)]:
    assert f'test result: ok. {count} passed; 0 failed' in logs[name].read_text(), name
assert 'Ran 23 tests' in logs['python-tests.log'].read_text()
assert logs['python-tests.log'].read_text().rstrip().endswith('OK')
for name in ['build.log','native-clippy.log','example-clippy.log']:
    assert 'Finished ' in logs[name].read_text() and '\nerror' not in logs[name].read_text(), name
for name in ['format.log','example-format.log','diff-check.log']:
    assert not logs[name].read_bytes(), name
assert 'body words: 4998' in logs['paper.log'].read_text() and 'pages: 12' in logs['paper.log'].read_text()
binary = repo / 'target/debug/chio-federated-work'
assert sha(binary) == Path('/tmp/chio-release34-binary.sha256').read_text().split()[0]
runs = {label:Path('/tmp/chio-release34-' + label + '-final') for label in ['https','http','crashes']}
summaries = {label:json.loads((path/'summary.json').read_text()) for label,path in runs.items()}
for label, count in [('https',19),('http',18),('crashes',7)]:
    assert summaries[label]['passed'] == len(summaries[label]['scenarios']) == count
assert summaries['https']['scenarios'][-1]['denials'] == 13
out.mkdir(parents=True, exist_ok=False)

def write(name,value):
    (out/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

for name,path in logs.items():
    shutil.copyfile(path,out/name)
for label,value in summaries.items():
    write(label+'-summary.json',value)
write('prior-source-comparison.json',{'manifest':str(prior_path.relative_to(repo)), 'manifestSha256':sha(prior_path),
    'previousSourceFiles':len(prior['source_sha256']), 'previousArtifactsVerified':len(prior['artifact_sha256']),
    'changedExistingSources':changed})
counts={'work':0,'incidents':0,'enrollments':0,'releases':0,'signedIncidentDenials':0,'signedReleaseDenials':0}
for label in ['https','crashes']:
    for scenario in summaries[label]['scenarios']:
        root=runs[label]/scenario['scenario']
        peers=json.loads((root/'provider/peers.json').read_text())
        secrets=[(root/role/'key.seed').read_text().strip() for role in ['provider','buyer']]
        secrets.append((root/'provider/tls-key.pem').read_text().strip())
        def check_public(value):
            if isinstance(value,dict):
                if 'request' in value and 'delivery' in value:
                    review.terminal(value['request'],value['delivery'],peers); counts['work']+=1
                if 'request' in value and 'incident' in value:
                    incident.verify(value['request'],value['incident'],peers); counts['incidents']+=1
                for child in value.values(): check_public(child)
            elif isinstance(value,list):
                for child in value: check_public(child)
        for name in ['public.json','unknown.json','enrollment.json','activation.json','verification.json',
                     'cross-verification.json','isolation.json','invariants.json','incident-denials.json','incident-vectors.json']:
            path=root/name
            if not path.exists(): continue
            raw=path.read_text()
            assert not any(secret in raw for secret in secrets), 'private material in public artifact'
            assert '-----BEGIN PRIVATE KEY-----' not in raw
            value=json.loads(raw)
            if name=='public.json':
                if label=='crashes':
                    resolution.verify(value['release'],peers); counts['releases']+=1
                    assert value['paymentResolution']=='released_by_agreement' and value['workExecuted'] is None
                    assert [value[k] for k in ['available','reserved','spent']]==[1000,0,0]
                    assert scenario['originalIncidentUnchanged'] and scenario['originalInvocationCount']==1
                else: check_public(value)
            elif name=='enrollment.json':
                client.verify_enrollment(value,peers['provider'],peers['buyer'],value['body']['origin']); counts['enrollments']+=1
            elif name=='unknown.json':
                incident.verify(value['request'],value['incident'],peers)
                assert not value['localCreditSettled'] and value['reserved']==100
            elif name=='incident-vectors.json':
                incident.verify(value['valid']['request'],value['valid']['incident'],peers)
                for case in value['cases']:
                    v=case['public']; e=v['incident']['projection']
                    p.Ed25519PublicKey.from_public_bytes(p.hex_bytes(peers['provider'])).verify(p.hex_bytes(e['signature'],64),incident.NATIVE.encode()+b'\0'+p.canonical(e['body']))
                    try: incident.verify(v['request'],v['incident'],peers)
                    except p.ProtocolError: counts['signedIncidentDenials']+=1
                    else: raise AssertionError(case['case'])
            shutil.copyfile(path,out/(label+'-'+scenario['scenario']+'-'+name))
vectors=client.read(repo/'examples/federated-work/fixtures/release-vectors.json')
resolution.verify(vectors['valid'],vectors['peers'])
for case in vectors['cases']:
    p.envelope(case['public']['receipt'],vectors['peers']['provider'])
    try: resolution.verify(case['public'],vectors['peers'])
    except p.ProtocolError: counts['signedReleaseDenials']+=1
    else: raise AssertionError(case['case'])
assert counts=={'work':14,'incidents':3,'enrollments':26,'releases':7,'signedIncidentDenials':30,'signedReleaseDenials':11},counts
write('public-artifact-check.json',{**counts,'privateKeysExported':False,'roleDatabasesExported':False,
    'externalFundsTransferred':False,'independentOperators':False,
    'meaning':'Peer keys supplied separately by the fixture operator. Native completion attests to the configured local rail. Consent waives the claim without establishing a known execution result.'})
paths={repo/path for path in prior['source_sha256']}
example={path for path in (repo/'examples/federated-work').rglob('*') if path.is_file() and 'target' not in path.parts and '__pycache__' not in path.parts and path.suffix!='.pyc'}
added={repo/path for path in ['crates/kernel/chio-kernel/src/payment/unknown_release.rs',
    'crates/kernel/chio-kernel/tests/durable_admission_sqlite/unknown_release.rs',
    'crates/platform/chio-store-sqlite/src/admission_operation_store/unknown_release.rs',
    'docs/papers/review-2026-09/34-mutually-agreed-unknown-release.md','docs/papers/review-2026-09/README.md']}
paths |= example | added
for path in sorted(example | added | {repo/path for path in changed}):
    target=out/'source'/path.relative_to(repo); target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,target)
shutil.copyfile(__file__,out/'export.py')
write('commands.json',{'build':'CARGO_TARGET_DIR=target cargo build --manifest-path examples/federated-work/Cargo.toml --locked',
 'kernelTests':'cargo test -p chio-kernel --lib admission_operation:: --locked',
 'integrationTests':'cargo test -p chio-kernel --test durable_admission_sqlite --locked',
 'storeTests':'cargo test -p chio-store-sqlite --lib admission_operation_store:: --locked',
 'budgetTests':'cargo test -p chio-store-sqlite --lib budget_store:: --locked',
 'globalTests':'cargo test -p chio-store-sqlite --lib serving_owner::global_commit_chain:: --locked',
 'exampleTests':'CARGO_TARGET_DIR=target cargo test --manifest-path examples/federated-work/Cargo.toml --locked',
 'pythonTests':"/tmp/chio-python31-locked-venv/bin/python -m unittest discover -s examples/federated-work/python_buyer -p 'test_*.py'",
 'https':'python3 examples/federated-work/https_smoke.py --binary target/debug/chio-federated-work --python-env /tmp/chio-python31-locked-venv --output /tmp/chio-release34-https-final',
 'http':'python3 examples/federated-work/python_smoke.py --binary target/debug/chio-federated-work --python-env /tmp/chio-python31-locked-venv --output /tmp/chio-release34-http-final',
 'release':'python3 examples/federated-work/resolution_smoke.py --binary target/debug/chio-federated-work --python-env /tmp/chio-python31-locked-venv --output /tmp/chio-release34-crashes-final',
 'paper':'make -C docs/papers/evidence-crosses'})
manifest={'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
 'tree':'uncommitted local checkout',
 'boundary':'Mutually agreed release of a historical unknown local-credit hold, independently verified in Python and Rust. One host and operator; no known work result, external funds, independent-company deployment, legal effect, remote CI, release or breakthrough claim.',
 'qualification':{'httpsScenarios':19,'legacyHttpScenarios':18,'releaseHttpsScenarios':7,'concurrentReleaseBuyersPerScenario':4,
    'nativeAdmissionTests':72,'kernelSqliteIntegrationTests':13,'sqliteAdmissionTests':86,'budgetStoreTests':122,'globalChainTests':9,
    'exampleRustTests':7,'pythonTests':23,'signedReleaseDenialClasses':11,'paperPages':12,'paperBodyWords':4998},
 'provider_binary':{'path':str(binary.relative_to(repo)),'sha256':sha(binary)},
 'source_hash_scope':'Prior local dependency inventory plus current example, native release modules, tests and report. Source inventory, not a reproducible-build attestation.',
 'source_sha256':{str(path.relative_to(repo)):sha(path) for path in sorted(paths)},
 'artifact_sha256':{str(path.relative_to(out)):sha(path) for path in sorted(out.rglob('*')) if path.is_file() and path.name!='manifest.json'}}
write('manifest.json',manifest)
for name,expected in manifest['source_sha256'].items(): assert sha(repo/name)==expected,name
for name,expected in manifest['artifact_sha256'].items(): assert sha(out/name)==expected,name
print(json.dumps({'sourceFiles':len(manifest['source_sha256']),'artifacts':len(manifest['artifact_sha256']),**counts}))
