from pathlib import Path
import json,subprocess,os,time,hashlib,shutil,signal
w=Path(__file__).parent.resolve();b=json.loads((w/'binaries-before.json').read_text())
original=Path(b['chio_store_sqlite']);binary=w/'retention-candidate';original.rename(binary)
env=os.environ.copy();env.update(CHIO_RETENTION_CASES='256',PROPTEST_CASES='256',PROPTEST_RNG_SEED='20260926',CHIO_DIAGNOSTIC_SYNC_DELAY_MS='3',LD_PRELOAD=str(w/'slow-sync.so'))
cmd=[str(binary),'--exact','receipt_store::tests::retention::state_machine::prop_retention_preserves_append_invariant','--nocapture']
meta={'command':cmd,'cases':256,'seed':'20260926','sync_delay_ms':3,'overall_budget_seconds':900,'no_progress_budget_seconds':45,'source_scope':'Current receipt production owner at a3669c03d1 plus extracted original property with phase diagnostics; historical workload size, not the historical binary/unknown seed.', 'original_executable':str(original),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'interposer_sha256':hashlib.sha256((w/'slow-sync.so').read_bytes()).hexdigest()}
log=w/'retention-original-scale.log';start=time.monotonic()
with log.open('w') as f:
 p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True);meta['pid']=p.pid
 (w/'retention-original-scale-result.json').write_text(json.dumps(meta,indent=2)+'\n')
 size=0;changed=start
 while p.poll() is None:
  time.sleep(1);now=time.monotonic();new_size=log.stat().st_size
  if new_size!=size:size=new_size;changed=now
  if now-start>900 or now-changed>45:
   meta['timeout']='overall' if now-start>900 else 'no progress'
   snapshot={}
   for task in Path(f'/proc/{p.pid}/task').iterdir():
    entry={}
    for name in ['comm','wchan','syscall','stack']:
     try:entry[name]=(task/name).read_text()
     except OSError as e:entry[name]=str(e)
    snapshot[task.name]=entry
   (w/'retention-stalled-threads.json').write_text(json.dumps(snapshot,indent=2)+'\n')
   if shutil.which('gdb'):
    with (w/'retention-stalled-stacks.log').open('w') as stacks:
     try:subprocess.run(['gdb','-batch','-ex','set pagination off','-ex','thread apply all bt','-p',str(p.pid)],stdout=stacks,stderr=subprocess.STDOUT,timeout=20)
     except subprocess.TimeoutExpired:stacks.write('\ngdb observation timed out\n')
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   break
 meta['exit_code']=p.wait();meta['seconds']=round(time.monotonic()-start,2)
meta['completed_cases']=sum('phase=complete' in line for line in log.read_text().splitlines())
(w/'retention-original-scale-result.json').write_text(json.dumps(meta,indent=2)+'\n');print(json.dumps(meta),flush=True)
raise SystemExit(0 if meta['exit_code']==0 else 1)
