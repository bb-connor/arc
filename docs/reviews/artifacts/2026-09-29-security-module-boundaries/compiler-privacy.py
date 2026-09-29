#!/usr/bin/env python3
"""Calibrate actual compiler privacy using temporary sibling probes; restore on exit."""
import json, os, pathlib, subprocess, sys
root=pathlib.Path.cwd(); output=pathlib.Path(sys.argv[1]); output.mkdir(parents=True,exist_ok=True)
broker=root/'crates/security/chio-secret-broker/src/service'; control=root/'crates/platform/chio-control-plane/src/security/event_consumer'
old='struct ValidatedBrokerAuthorities' in (broker.with_suffix('.rs')).read_text()
owner='super' if old else 'super::authorization'
probes=[('broker-authorities','chio-secret-broker',broker/'ipc.rs',f'''
#[allow(dead_code)] fn boundary_probe_authority(value: {owner}::ValidatedBrokerAuthorities) {{ let _ = value.revocation_set; }}
#[allow(dead_code)] fn boundary_probe_audit(value: {owner}::ValidatedBrokerAuditAuthorities) {{ let _ = value.validated_at_unix_seconds; }}
#[allow(dead_code)] fn boundary_probe_secret(service: &super::BrokerService) {{ drop(service.retained_prepared_dispatches()); }}
'''),('response-reservation','chio-control-plane',control/'coordinator.rs','''
#[allow(dead_code)] fn boundary_probe_reservation(mut value: super::ReservedAttestedFindingResponsePlan) { value.admission_artifact_digest = None; }
''')]
results=[]
for label,package,path,probe in probes:
 if len(sys.argv)>2 and label!=sys.argv[2]:continue
 original=path.read_bytes()
 try:
  path.write_bytes(original+probe.encode())
  with (output/f'{label}.jsonl').open('w') as out, (output/f'{label}.log').open('w') as err:
   run=subprocess.run(['cargo','check','--locked','-p',package,'--lib','--message-format=json'],stdout=out,stderr=err,env={**os.environ,'CARGO_INCREMENTAL':'0'})
  messages=[]
  for line in (output/f'{label}.jsonl').read_text().splitlines():
   try: item=json.loads(line)
   except ValueError: continue
   if item.get('reason')=='compiler-message' and item['message']['level']=='error':messages.append(item['message'])
  errors=[m for m in messages if m.get('code',{}).get('code') in ('E0451','E0616','E0603','E0624') and any(s['file_name']==str(path.relative_to(root)) for s in m['spans'])]
  ok=run.returncode!=0 and len(errors)>=(3 if package=='chio-secret-broker' else 1) and len(messages)==len(errors)
  results.append({'probe':label,'rejected':ok,'cargo_exit':run.returncode,'privacy_diagnostics':[m['rendered'] for m in errors]})
  print(label,'PASS' if ok else 'FAIL: compiler accepted sibling access or unrelated failure',flush=True)
 finally:path.write_bytes(original)
(output/'result.json').write_text(json.dumps(results,indent=2))
sys.exit(0 if all(r['rejected'] for r in results) else 1)
