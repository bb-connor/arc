import gzip, hashlib, json, pathlib, shutil, tarfile
root=pathlib.Path('/home/ubuntu/native-multiroute-evidence-20260929')
source=pathlib.Path('/home/ubuntu/arc-native-consumers-20260929')
out=pathlib.Path('/tmp/chio-consumer-public-evidence')
out.mkdir(exist_ok=True)
logs=out/'native'; logs.mkdir(exist_ok=True)
# Explicit diagnostic/campaign families only. Excludes raw syscall traces,
# private databases, credentials, policy configurations and signing material.
prefixes=('history-followup','mini-native-14','session-followup','state-followup','repository-operator-followup','saved-followup','scope-followup','operator-followup','scoped-session','public-repository-followup','comparison-followup','review-native-followup','shared-native-followup','review-full-followup','review-adaptive-followup','shared-ownership-followup','process-packages-followup','offline-review-followup','ai-sdk-native-followup','ai-sdk-benchmark-followup','repository-adapter-final-tests','exact-read-write-tests','sqlite-final-profile-tests','response-budget-tests','large-envelope-replay-diagnostic','mcp-drain-cli-build','classification-cli-build','classifier-chain-cli-build','output-read-cli-build','projection-cli-build','final-installed-schema-tests','final-sdk-install','adapters-final-build','broker-mcp-final-build','cage-final-build','consumer-helper-final-build')
for path in sorted(root.iterdir()):
 if path.is_file() and path.name.startswith(prefixes) and path.suffix in {'.log','.stdout','.stderr'}:
  (logs/(path.name+'.gz')).write_bytes(gzip.compress(path.read_bytes(),mtime=0))

for campaign,state in [('public-repository-followup-1','/tmp/chio-public-repository-sxb0vn8n'),('public-repository-followup-2','/tmp/chio-public-repository-hbkjw0vv'),('public-repository-followup-3','/tmp/chio-public-repository-dvtf9oim'),('public-repository-followup-4','/tmp/chio-public-repository-lsyzamem'),('public-repository-followup-5','/tmp/chio-public-repository-z3z91fu3')]:
 path=pathlib.Path(state)/'host.log'
 if path.exists():(logs/(campaign+'-host.log.gz')).write_bytes(gzip.compress(path.read_bytes(),mtime=0))
reports=out/'reports';reports.mkdir(exist_ok=True)
cases=('mini-native-14','session-followup-7','state-followup-2','repository-operator-followup-1','saved-followup-2','scope-followup-2','operator-followup-2','scoped-session-followup-1','scoped-session-final-2','public-repository-followup-6','comparison-followup-6','review-native-followup-10','shared-native-followup-10','review-full-followup-1','review-adaptive-followup-1','shared-ownership-followup-1','process-packages-followup-2/evidence','offline-review-followup-2/evidence','ai-sdk-native-followup-1','ai-sdk-benchmark-followup-1')
for case in cases:
 folder=root/case
 for name in ('qualification.json','comparison.json','summary.json','benchmark.json','report.json'):
  path=folder/name
  if path.is_file():shutil.copyfile(path,reports/(case.replace('/','-')+'-'+name))
for name in ('worker-image-final.json','repository-images-final.json','worker-image-followup.json','repository-images-followup.json','python-runtime-followup.json','final-sdk-protected.json','source-native-final.json','source-final-differences.json'):
 shutil.copyfile(root/name,out/name)
manifest=json.loads(pathlib.Path('/tmp/chio-local-source-closeout.json').read_text())
files={name:hashlib.sha256((source/name).read_bytes()).hexdigest() if (source/name).is_file() else None for name in manifest['files']}
(out/'native-source.json').write_text(json.dumps(dict(schema=manifest['schema'],common_base=manifest['common_base'],git_head=__import__('subprocess').check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),dirty=True,files=files),indent=2)+'\n')
(out/'source-differences.json').write_text(json.dumps([dict(path=n,local=sha,native=files[n]) for n,sha in manifest['files'].items() if files[n]!=sha],indent=2)+'\n')
binaries={}
paths=list(root.glob('chio-followup-[1-9]'))+[root/'chio-cage-init-final',root/'chio-broker-mcp-final']
target=pathlib.Path('/home/ubuntu/chio-x86-cage-c38ea127ed-target/docker-release')
paths += [target/'chio-docker-adapter',target/'chio-repository-adapter']
for r in map(json.loads,(root/'consumer-helper-final.jsonl').read_text().splitlines()):
 if r.get('reason')=='compiler-artifact' and r.get('executable') and r['target']['name']=='chio_secret_broker':paths.append(pathlib.Path(r['executable']))
paths += list((root/'final-wheels').glob('*.whl'))
for path in paths:
 if path.exists():binaries[str(path)]={'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),'bytes':path.stat().st_size}
(out/'binaries-and-wheels.json').write_text(json.dumps(binaries,indent=2)+'\n')
with tarfile.open('/tmp/chio-consumer-public-evidence.tgz','w:gz') as archive:
 for path in sorted(out.rglob('*')):
  if path.is_file():archive.add(path,arcname=path.relative_to(out))
print(json.dumps({'logs':len(list(logs.iterdir())),'reports':len(list(reports.iterdir())),'source_differences':sum(files[n]!=sha for n,sha in manifest['files'].items()),'archive_bytes':pathlib.Path('/tmp/chio-consumer-public-evidence.tgz').stat().st_size}))
