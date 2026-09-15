import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

repo = Path('/home/connor/backbay/arc')
sys.path.insert(0, str(repo / 'examples/federated-work/python_buyer'))
import client
import protocol as p
import review
import incident
import resolution
import subcontract

out = repo / 'docs/papers/review-2026-09/evidence/35-bounded-intercompany-subcontracts'
prior_path = repo / 'docs/papers/review-2026-09/evidence/34-mutually-agreed-unknown-release/manifest.json'
prior = json.loads(prior_path.read_text())

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

for name, expected in prior['artifact_sha256'].items():
    assert sha(prior_path.parent / name) == expected, name
changed = [name for name, expected in prior['source_sha256'].items() if sha(repo / name) != expected]
assert all(name.startswith(('examples/federated-work/', 'docs/papers/')) for name in changed), changed
logs = {name: Path('/tmp/chio-subcontract35-' + suffix + '.log') for name, suffix in {
    'build.log':'build-final', 'clippy.log':'clippy-final', 'rust-tests.log':'rust-final', 'python-tests.log':'python-final',
    'format.log':'format', 'example-format.log':'example-format', 'diff.log':'diff', 'paper.log':'paper',
    'subcontract-run.log':'final', 'https-run.log':'https-final', 'http-run.log':'http-final', 'release-run.log':'release-final',
}.items()}
assert 'test result: ok. 11 passed; 0 failed' in logs['rust-tests.log'].read_text()
assert 'Ran 30 tests' in logs['python-tests.log'].read_text() and logs['python-tests.log'].read_text().rstrip().endswith('OK')
for name in ['build.log','clippy.log']:
    assert 'Finished ' in logs[name].read_text() and '\nerror' not in logs[name].read_text(), name
for name in ['format.log','example-format.log','diff.log']:
    assert not logs[name].read_bytes(), name
assert 'body words: 4937' in logs['paper.log'].read_text() and 'pages: 12' in logs['paper.log'].read_text()
binary = repo / 'target/debug/chio-federated-work'
assert sha(binary) == Path('/tmp/chio-subcontract35-binary.sha256').read_text().split()[0]
runs = {'subcontract':Path('/tmp/chio-subcontract35-final')}
runs.update({name:Path('/tmp/chio-subcontract35-' + name + '-final') for name in ['https','http','release']})
summaries = {name:json.loads((root/'summary.json').read_text()) for name,root in runs.items()}
for name, count in [('subcontract',10),('https',19),('http',18),('release',7)]:
    assert summaries[name]['passed'] == len(summaries[name]['scenarios']) == count, name
out.mkdir(parents=True, exist_ok=False)

def write(name, value):
    (out/name).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')

for name, path in logs.items(): shutil.copyfile(path, out/name)
for name, value in summaries.items(): write(name+'-summary.json', value)
write('prior-source-comparison.json', {'manifest':str(prior_path.relative_to(repo)), 'manifestSha256':sha(prior_path),
    'priorSources':len(prior['source_sha256']), 'priorArtifactsVerified':len(prior['artifact_sha256']),
    'changedExistingSources':changed, 'nativeKernelAndStoreSourcesChanged':False})
counts = {'workPackages':0,'incidentPackages':0,'releases':0,'enrollments':0,'receiverDenials':0,'nestedReportDenials':0}


def package(value, peers):
    if 'delivery' in value:
        review.terminal(value['request'],value['delivery'],peers); counts['workPackages'] += 1
    elif 'incident' in value:
        incident.verify(value['request'],value['incident'],peers); counts['incidentPackages'] += 1
    else: raise AssertionError('not a work or incident package')
    if 'release' in value:
        resolution.verify(value['release'],peers); counts['releases'] += 1


def export(path, name, private):
    raw = path.read_text()
    assert '-----BEGIN PRIVATE KEY-----' not in raw and not any(secret in raw for secret in private), name
    shutil.copyfile(path, out/name)

for scenario in summaries['subcontract']['scenarios']:
    label = scenario.get('scenario','normal')
    root = runs['subcontract']/label
    parent_peers = client.read(root/'parent/provider/peers.json')
    child_peers = client.read(root/'specialist/provider/peers.json')
    private = [path.read_text().strip() for path in root.rglob('key.seed')]
    private += [path.read_text().strip() for path in root.rglob('tls-key.pem')]
    write(label+'-peers.json', {'parent':parent_peers, 'child':child_peers})
    parent = client.read(root/'public.json') if (root/'public.json').exists() else None
    for name in ['public.json','released.json','child-recovered.json','child-released.json']:
        path=root/name
        if not path.exists(): continue
        value=client.read(path)
        is_child=name.startswith('child-')
        peers=child_peers if is_child else parent_peers
        package(value,peers)
        if is_child:
            quote=value['request']['acceptance']['quote']
            subcontract.verify_permit(quote['subcontractPermit'],quote['agreement'],parent_peers['provider'])
            assert p.same(quote['subcontractPermit']['body'],subcontract.permit_terms(parent['request']))
        export(path,label+'-'+name,private)
    for name in ['verification.json','verify-work.json','verify-incident.json','verify-release.json','isolation.json','invariants.json']:
        path=root/name
        if path.exists(): export(path,label+'-'+name,private)
    for role in ['parent','specialist']:
        config_file=root/role/'enrollment.json' if role=='parent' else root/'parent/provider/subcontract.json'
        if not config_file.exists(): continue
        value=client.read(config_file)
        if role=='specialist': value=value['enrollment']
        peers=parent_peers if role=='parent' else child_peers
        client.verify_enrollment(value,peers['provider'],peers['buyer'],value['body']['origin'])
        counts['enrollments']+=1
        write(label+'-'+role+'-enrollment.json',value)
    for name in ['spending-denials.json','sandbox-attack.json','denials.json']:
        path=root/name
        if not path.exists(): continue
        value=client.read(path)
        values=[{'response':value}] if name=='sandbox-attack.json' else value
        pin=parent_peers['provider'] if name=='denials.json' else child_peers['provider']
        for case in values:
            receipt=case['response']['task']['metadata']['chio']['receipt']
            p.receipt(receipt,pin,receipt['tool_name'],receipt['action']['parameters'])
            assert receipt['decision'] != {'verdict':'allow'}
            assert case['response']['task']['status']['state']=='TASK_STATE_FAILED'
            counts['receiverDenials']+=1
        export(path,label+'-'+name,private)
    # Public counters from stopped, owned stores; no database or private row is exported.
    if parent is not None:
        child = parent.get('delivery',{}).get('report',{}).get('body',{}).get('subcontract')
        if child is None: child=client.read(root/'child-recovered.json')
        evidence={}
        for role, value in [('parent',parent),('specialist',child)]:
            token=value['request']['acceptance']['ask']['body']['tokenOffer']
            with sqlite3.connect(root/role/'provider/authority.sqlite') as db:
                row=db.execute('SELECT invocation_count,total_cost_exposed,total_cost_realized_spend FROM capability_grant_budgets WHERE capability_id=?',(token['id'],)).fetchone()
                assert row is not None and row[0]==1 and row[1]==0,(label,role,row)
                expected = 100 if (role=='parent' and label in ('normal','hostile-worker')) or (role=='specialist' and label not in ('child-before-review','child-after-review','both-after-child-write')) else 0
                assert row[2]==expected,(label,role,row)
                evidence[role]={'capabilityId':token['id'],'issuer':token['issuer'],'subject':token['subject'],
                                'invocations':row[0],'exposure':row[1],'realizedSpend':row[2]}
        write(label+'-native-counters.json',evidence)

# Retain selected public evidence from all prior-profile HTTPS and release runs.
for group in ['https','release']:
    for scenario in summaries[group]['scenarios']:
        label=scenario['scenario']; root=runs[group]/label
        peers=client.read(root/'provider/peers.json')
        private=[path.read_text().strip() for path in root.rglob('key.seed')]
        private += [path.read_text().strip() for path in root.rglob('tls-key.pem')]
        for name in ['public.json','verification.json','enrollment.json','activation.json','invariants.json','cross-verification.json','isolation.json']:
            path=root/name
            if not path.exists(): continue
            value=client.read(path)
            if name=='public.json':
                if 'request' in value: package(value,peers)
                elif 'workAfterRepair' in value: package(value['workAfterRepair'],peers)
            elif name=='enrollment.json':
                client.verify_enrollment(value,peers['provider'],peers['buyer'],value['body']['origin']); counts['enrollments']+=1
            export(path,group+'-'+label+'-'+name,private)

vectors=client.read(repo/'examples/federated-work/fixtures/subcontract-vectors.json')
review.verify_report(vectors['request'],vectors['valid'])
for case in vectors['cases']:
    p.envelope(case['report'],vectors['valid']['signerKey'])
    try: review.verify_report(vectors['request'],case['report'])
    except p.ProtocolError: counts['nestedReportDenials']+=1
    else: raise AssertionError(case['case'])
assert counts['nestedReportDenials']==12 and counts['receiverDenials']==19,counts
write('nested-report-verification.json',{'valid':True,'rejectedWithValidParentSignatures':12})

counter_root=Path('/tmp/chio-subcontract35-dev')
counter=client.read(counter_root/'unbounded-delegate-counterexample.json')
peers=client.read(counter_root/'specialist/provider/peers.json')
review.terminal(counter['public']['request'],counter['public']['delivery'],peers)
assert counter['additionalCharge']==100 and counter['heldProviderKernelKey'] is False
write('pre-permit-counterexample.json',counter)
write('pre-permit-counterexample-boundary.json',{'peers':peers,'binarySha256':sha(Path('/tmp/chio-subcontract35-prepermit')),
    'additionalCharge':100,'heldProviderKernelKey':False,'sourceSnapshotPackaged':False,
    'meaning':'Historical pre-permit binary and owned three-party fixture; current receiver denial tests bypass client preflight.'})
write('public-artifact-check.json',{**counts,'privateKeysExported':False,'databasesExported':False,
    'independentOperators':False,'externalFundsTransferred':False})

example={path for path in (repo/'examples/federated-work').rglob('*') if path.is_file() and 'target' not in path.parts and '__pycache__' not in path.parts and path.suffix!='.pyc'}
paper=repo/'docs/papers/evidence-crosses'
paper_sources={path for path in paper.rglob('*') if path.is_file() and path.suffix in ('.tex','.bib','.py')}
paper_sources |= {paper/name for name in ['paper.pdf','Makefile','README.md','proof-model.md']}
added={repo/'docs/papers/review-2026-09/35-bounded-intercompany-subcontracts.md',repo/'docs/papers/review-2026-09/README.md'}
paths={repo/name for name in prior['source_sha256']} | example | paper_sources | added
for path in sorted(example | paper_sources | added | {repo/name for name in changed}):
    destination=out/'source'/path.relative_to(repo); destination.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,destination)
shutil.copyfile(__file__,out/'export.py')
write('commands.json',{'build':'CARGO_TARGET_DIR=target cargo build --manifest-path examples/federated-work/Cargo.toml --locked',
 'rustTests':'CARGO_TARGET_DIR=target cargo test --manifest-path examples/federated-work/Cargo.toml --locked',
 'pythonTests':"/path/to/venv/bin/python -m unittest discover -s examples/federated-work/python_buyer -p 'test_*.py'",
 'clippy':'CARGO_TARGET_DIR=target cargo clippy --manifest-path examples/federated-work/Cargo.toml --locked --all-targets -- -D warnings',
 'subcontract':'/path/to/venv/bin/python examples/federated-work/subcontract_smoke.py --binary target/debug/chio-federated-work --python-env /path/to/venv --output /tmp/fresh-subcontracts',
 'baselineScripts':['https_smoke.py','python_smoke.py','resolution_smoke.py'],
 'paper':'make -C docs/papers/evidence-crosses'})
manifest={'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
 'tree':'uncommitted local checkout',
 'boundary':'Bounded three-party work through separate agent and kernel keys, exact disclosure and receiver-enforced procurement permits. Local TST, one host/operator; no independent company deployment, external settlement, distributed atomicity, release qualification or breakthrough claim.',
 'qualification':{'threePartyScenarios':10,'priorHttpsScenarios':19,'priorHttpScenarios':18,'priorReleaseScenarios':7,
    'totalProcessScenarios':54,'rustExampleTests':11,'pythonTests':30,'receiverDenials':19,'nestedReportDenials':12,
    'concurrentRecoveriesPerParentAndChild':4,'paperPages':12,'paperBodyWords':4937},
 'provider_binary':{'path':str(binary.relative_to(repo)),'sha256':sha(binary)},
 'source_hash_scope':'Prior dependency inventory, complete example and paper sources, plus this report. Includes paper sections omitted by the earlier inventory. Source inventory, not a reproducible-build attestation.',
 'source_sha256':{str(path.relative_to(repo)):sha(path) for path in sorted(paths)},
 'artifact_sha256':{str(path.relative_to(out)):sha(path) for path in sorted(out.rglob('*')) if path.is_file() and path.name!='manifest.json'}}
write('manifest.json',manifest)
for name,expected in manifest['source_sha256'].items(): assert sha(repo/name)==expected,name
for name,expected in manifest['artifact_sha256'].items(): assert sha(out/name)==expected,name
print(json.dumps({'sourceFiles':len(manifest['source_sha256']),'artifacts':len(manifest['artifact_sha256']),**counts}))
