from pathlib import Path
import json,subprocess,sys,time
from concurrent.futures import ThreadPoolExecutor
w=Path(__file__).parent;b=json.loads((w/'binaries.json').read_text())
def run(case):
 name,pkg,*args=case;started=time.monotonic()
 with (w/(name+'.log')).open('w') as f:r=subprocess.run([b[pkg],*args],stdout=f,stderr=subprocess.STDOUT)
 result={'name':name,'command':[b[pkg],*args],'exit_code':r.returncode,'seconds':round(time.monotonic()-started,2)}
 (w/(name+'-result.json')).write_text(json.dumps(result,indent=2)+'\n');print(result,flush=True)
 print((w/(name+'.log')).read_text()[-700:],flush=True);return r.returncode
sets={
 'kernel': [('kernel-final-2','chio_kernel','--test-threads=4')],
 'integration': [('durable-integration-final','durable_admission_sqlite','federation_context','--test-threads=4')],
 'identities':[(n,p,'--test-threads=4') for n,p in [('fincred-final','chio_fincred'),('security-types-final','chio_security_types'),('settle-final','chio_settle'),('runtime-core-final','chio_runtime_core'),('proof-parity-final','chio_runtime_proof_parity'),('response-authority-final','chio_active_response_authority')]]+ [('core-canonical-final','chio_core_types','canonical'),('core-identities-final','chio_core_types','shared_identifiers')],
 'native':[('native-flow-final','chio_control_plane','native_flow','--test-threads=12','--nocapture')],
 'runtime-expiry':[('runtime-expiry-final','chio_control_plane','runtime_expiry_after_native_verification_rolls_back_physical_capture','--nocapture')],
 'native-fixes':[('native-fixes-final','chio_control_plane','runtime_expiry_after_native_verification_rolls_back_physical_capture','expiry_at_final_commit','native_output_preparation_cannot_renew_a_lease_that_expires_during_classification','native_broker_connection_prepares_original_and_refuses_misbound_acknowledgement','native_caller_output_refusal_revocation_and_stop_never_release_raw_delivery','native_captured_lifecycle_rechecks_revocation_and_stop_after_output_join','native_caller_abort_after_release_checkpoint','--test-threads=3','--nocapture')],
 'caller':[('caller-ledger-final','caller_execution_ledger','--test-threads=4'),('caller-connection-final','chio_store_sqlite','caller_execution_ledger::','--test-threads=4')],
 'admission':[('sqlite-admission-final','chio_store_sqlite','admission_operation_store::tests::authority_clock::','admission_operation_store::tests::injected_clock::','admission_operation_store::tests::clock_migration::','admission_operation_store::tests::dpop_replay::','admission_operation_store::tests::governed_approval_replay::','admission_operation_store::tests::runtime_replay::','admission_operation_store::tests::factor_assignment::','--test-threads=4')],
}
with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(run,sets[sys.argv[1]]))
sys.exit(any(statuses))
