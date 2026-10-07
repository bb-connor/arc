"""Reopen the retained public work and every actor outbox without private keys."""
from pathlib import Path
import json
import sys

sys.path.insert(0,str(Path.cwd()/'examples/funded-work'))
import artifacts as p
from custody import Custody
from rail_journal import Journal

state=Path(sys.argv[1]);report=json.loads(Path(sys.argv[2]).read_bytes())
body=p.verify_agreement(report['agreement'],report['pins'])
submission=report['submission'];allocation=submission['body']['allocationId']
p.verify_submission(submission,body,allocation)
with Custody(state/'custody.sqlite',report['pins']['custodian']) as custody:
    assert custody.get(body['inputSha256'])==report['input'].encode()
    assert custody.get(submission['body']['outputSha256'])==p.canonical(report['output'])
    assert custody.get(p.digest(submission))==p.canonical(submission)
    decision=custody.decision(allocation)
    p.verify_decision(decision,body,submission)
    assert decision==report['certificate']['decision']
seen=set()
for recovery in report['railRecoveries']:
    prepared=recovery['journal']['prepared'];owner=prepared['intent']['actor']
    config=json.loads((state/('rail-'+owner)/'rail-config.json').read_bytes())
    with Journal(config['path'],config['owner'],config['domain']) as journal:
        assert journal.read(recovery['operationId'])==recovery['journal']
    nonce=(owner,prepared['nonce']);assert nonce not in seen;seen.add(nonce)
print('Verified retained work signatures and exact original signed records for '+str(len(seen))+' lifecycle actions. No private keys read. The ended private chain was not re-observed.')
