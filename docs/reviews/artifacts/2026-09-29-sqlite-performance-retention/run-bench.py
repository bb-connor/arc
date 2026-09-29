from pathlib import Path
import json,subprocess,time,os,sys,hashlib,shutil
w=Path(__file__).parent;phase=sys.argv[1]
b=json.loads((w/('binaries-'+phase+'.json')).read_text())
cmd=[b['store_authorization_path'],'--save-baseline' if phase=='before' else '--baseline','sqlite-batch-before','--sample-size','10','--warm-up-time','0.2','--measurement-time','1','--bench']
env=os.environ.copy();env.update(CHIO_AUTHORIZATION_ROWS='1000',CHIO_AUTHORIZATION_SUSPENSIONS='128')
meta={'command':cmd,'phase':phase,'rows':1000,'capabilities':512,'suspensions':128,'profile':'dev, unoptimized Rust, incremental disabled','executable_sha256':hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest()}
started=time.monotonic()
with (w/('bench-'+phase+'-complete.log')).open('w') as log:
 p=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,env=env);meta['pid']=p.pid
 (w/('bench-'+phase+'-result.json')).write_text(json.dumps(meta,indent=2)+'\n')
 meta['exit_code']=p.wait();meta['seconds']=round(time.monotonic()-started,2)
(w/('bench-'+phase+'-result.json')).write_text(json.dumps(meta,indent=2)+'\n')
for p in Path('target/criterion').glob('*/'+('sqlite-batch-before' if phase=='before' else 'new')+'/estimates.json'):
 if p.parent.parent.name in ['budget_charge_release_pair_populated','budget_charge_reverse_pair_populated','budget_usage_read_populated','admission_operation_record_populated','admission_operation_read_populated','security_state_denial_read_populated','security_state_allow_read_populated','authorization_store_composite_populated']:
  shutil.copyfile(p,w/(phase+'-'+p.parent.parent.name+'.json'))
print(json.dumps(meta),flush=True)
sys.exit(meta['exit_code'])
