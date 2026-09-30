import json, os, pathlib, subprocess
root=pathlib.Path('/home/ubuntu/arc-native-consumers-20260929')
evidence=pathlib.Path('/home/ubuntu/native-multiroute-evidence-20260929')
target=pathlib.Path('/home/ubuntu/chio-x86-cage-c38ea127ed-target')
import time
limit=time.monotonic()+900
while not (evidence/'native-build-final.ready').exists():
 assert time.monotonic()<limit
 time.sleep(1)
records=[json.loads(line) for line in (evidence/'consumer-helper-final.jsonl').read_text().splitlines()]
helper=[r['executable'] for r in records if r.get('reason')=='compiler-artifact' and r.get('executable') and r['target']['name']=='chio_secret_broker']
assert len(helper)==1
settings=dict(line.split('=',1) for line in pathlib.Path('/home/ubuntu/native-consumers-evidence-20260929/fixture.env').read_text().splitlines())
settings.update(CHIO_CAGE_INIT=str(evidence/'chio-cage-init-final'),CHIO_BROKER_TEST_BINARY=helper[0],CHIO_BROKER_MCP_TOOL=str(evidence/'chio-broker-mcp-final'),CHIO_REPOSITORY_ADAPTER=str(target/'docker-release/chio-repository-adapter'),CHIO_DOCKER_ADAPTER=str(target/'docker-release/chio-docker-adapter'),MSWEA_SILENT_STARTUP='1',PYTHONDONTWRITEBYTECODE='1')
environment=dict(os.environ,**settings)
import time
limit=time.monotonic()+900
while not (evidence/"chio-followup-9").exists():
 assert time.monotonic()<limit
 time.sleep(1)
python=evidence/'session-install-final/venv/bin/python'
cases = [('qualify_public_repository.py','public-repository-followup-6',['--worker-image-file',str(evidence/'repository-images-final.json'),'--repository','/home/ubuntu/itsdangerous-native','--revision','HEAD'])]

for script,name,extras in cases:
 with (evidence/(name+'.stdout')).open('w') as out,(evidence/(name+'.stderr')).open('w') as err:
  result=subprocess.run([str(python),str(root/'examples/mini-swe-recovery'/script),'--chio',str(evidence/'chio-followup-9'),'--output',str(evidence/name),*extras],env=environment,cwd=root,stdout=out,stderr=err)
 print(name,result.returncode,flush=True)

 if result.returncode:
  raise SystemExit(result.returncode)
