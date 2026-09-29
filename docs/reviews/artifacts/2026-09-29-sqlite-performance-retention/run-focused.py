from pathlib import Path
import subprocess,json,time,re,sys
w=Path(__file__).parent;b=json.loads((w/'binaries-final.json').read_text());results=[]
lib=b['chio_store_sqlite']
groups=[('serving',[lib,'serving_owner::'])]
for name in ['integrity','recovery','schema','connection_recovery','authority_clock','budget_atomicity']:
 groups.append(('admission-'+name,[lib,'admission_operation_store::tests::'+name+'::']))
groups += [('admission-replay',[lib,'--exact','admission_operation_store::tests::begin_replays_exactly_conflicts_before_mutation_and_retains_rows']),('security-connection',[lib,'security_state::participant_source::tests::connection_recovery::']),('retention-ownership',[b['receipt_retention_liveness'],'--skip','retention_workload_commits_are_serialized_on_writer'])]
for name,cmd in groups:
 cmd+=['--test-threads=4'];start=time.monotonic()
 with (w/(name+'-tests.log')).open('w') as f:
  try: result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300);exit_code=result.returncode
  except subprocess.TimeoutExpired: exit_code=124
 log=(w/(name+'-tests.log')).read_text();summaries=re.findall(r'test result:.*',log)
 row=dict(name=name,command=cmd,exit_code=exit_code,seconds=round(time.monotonic()-start,2),summaries=summaries);results.append(row)
 (w/'focused-test-results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(row),flush=True)
 if exit_code: sys.exit(1)
