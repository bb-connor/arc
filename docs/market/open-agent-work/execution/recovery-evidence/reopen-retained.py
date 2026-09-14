"""Reopen local retained artifacts after process exit, without reading private keys."""
from pathlib import Path
import json
import sys

sys.path.insert(0,str(Path.cwd()/'examples/funded-work'))
import artifacts as p
from custody import Custody
from rail_journal import Journal

state=Path(sys.argv[1])
report=json.loads(Path(sys.argv[2]).read_bytes())
body=p.verify_agreement(report['agreement'],report['pins'])
submission=report['submission']
allocation=submission['body']['allocationId']
p.verify_submission(submission,body,allocation)
with Custody(state/'custody.sqlite',report['pins']['custodian']) as store:
    assert store.get(body['inputSha256'])==report['input'].encode()
    assert store.get(submission['body']['outputSha256'])==p.canonical(report['output'])
    assert store.get(p.digest(submission))==p.canonical(submission)
    decision=store.decision(allocation)
    p.verify_decision(decision,body,submission)
    assert decision==report['certificate']['decision']
config=json.loads((state/'rail-config.json').read_bytes())
with Journal(config['path'],config['owner'],config['domain']) as journal:
    assert journal.read(report['recovery']['operationId'])==report['recovery']['journal']
print('Exact input, output, submission, signed decision and original signed transaction survived process exit and reopened from local custody/outbox. This does not re-observe the ended private chain.')
