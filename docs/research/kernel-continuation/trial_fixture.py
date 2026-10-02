"""Explicitly synthetic intake fixture. No human or operator measurements."""
import csv
import hashlib
import json
from pathlib import Path

FIELDS = (Path(__file__).parent.parent / 'kernel-work/results/integration-records.csv').read_text().splitlines()[0].split(',')

def make_package(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    def artifact(name, data):
        data = data.encode()
        sha = hashlib.sha256(data).hexdigest()
        (root / name).write_bytes(data)
        artifacts[sha] = name
        return sha
    source = artifact('synthetic-source.txt','SYNTHETIC source placeholder\n')
    adjudication = artifact('synthetic-adjudication.json',json.dumps({'synthetic':True, 'exercises':{f'I{i}':{'safety_matched':True,'progress_matched':True,'quality_matched':True} for i in range(1,7)}}))
    rows = []
    for number in range(1,7):
        for arm in ('Chio','B1'):
            operator = 'SYNTHETIC-operator'
            attestation = artifact('synthetic-attestation.txt','SYNTHETIC attestation, no person participated\n')
            attempts = [
                {'attempt_id':f'I{number}-{arm}-failed','status':'failed', 'hands_on_hours':'1',
                 'incident_id':None,'recoverable_incident':False,'recovered_without_repair':False,'database_edits':0,'bespoke_repairs':0},
                {'attempt_id':f'I{number}-{arm}-succeeded','status':'succeeded', 'hands_on_hours':'1' if arm=='Chio' else '3',
                 'incident_id':f'I{number}-{arm}-incident','recoverable_incident':True,'recovered_without_repair':True,'database_edits':0,'bespoke_repairs':0}]
            events = artifact(f'I{number}-{arm}.jsonl',''.join(json.dumps(a)+'\n' for a in attempts))
            row = dict.fromkeys(FIELDS,'0')
            row.update(exercise=f'I{number}',arm=arm,order=str(1 if (arm=='Chio')==(number%2==1) else 2),
                operator_id=operator,provider_source_sha=source,verifier_source_sha=source,task_corpus_sha=source,
                model_pin='SYNTHETIC-model',trust_profile='SYNTHETIC-trust',budget_profile='SYNTHETIC-budget',
                repeated_hands_on_hours='2' if arm=='Chio' else '4',quality_adjudication=adjudication,
                failed_attempts='1',recoverable_incidents='1',recovered_without_repair='1',
                adapter_diff_sha=source,event_log_sha=events,operator_attestation=attestation)
            rows.append(row)
    with (root/'records.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS);writer.writeheader();writer.writerows(rows)
    manifest={'schema':'chio.integration-intake.v1','mode':'synthetic','records':'records.csv',
        'scheduled_incidents':{f'I{i}/{arm}':[f'I{i}-{arm}-incident'] for i in range(1,7) for arm in ('Chio','B1')},
        'artifacts':artifacts,'operators':{'SYNTHETIC-operator':{'administration_id':'SYNTHETIC-admin'}},
        'adjudications':{f'I{i}':{'safety_matched':True,'progress_matched':True,'quality_matched':True,
            'artifact_sha':adjudication} for i in range(1,7)}}
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return root/'manifest.json'

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory');args=parser.parse_args()
    if Path(args.directory).exists(): parser.error('fixture output must not already exist')
    print(make_package(args.directory))
