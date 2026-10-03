import json, os, subprocess, tempfile
from pathlib import Path
binary='/home/connor/chio-security-target-6d-final/debug/chio'
with tempfile.TemporaryDirectory(prefix='chio-transport-cli-') as temporary:
    directory=Path(temporary)
    receipt=directory/'absent'/'receipts.db'
    env=dict(os.environ)
    for key in list(env):
        if key.startswith('CHIO_'):
            del env[key]
    common=[binary, '--receipt-db', str(receipt)]
    cases=[
        ['trust','serve','--listen','0.0.0.0:0','--service-token','transport-control-token'],
        ['api','protect','--listen','0.0.0.0:0','--upstream','http://127.0.0.1:1'],
        ['start','--listen','0.0.0.0:0'],
        ['mcp','serve-http','--listen','0.0.0.0:0','--policy',str(directory/'missing.yaml'),'--server-id','test','--cage-policy',str(directory/'missing-cage.json'),'--cage-policy-signer','test-signer','--','/bin/true'],
    ]
    for args in cases:
        result=subprocess.run(common+args,env=env,text=True,capture_output=True,timeout=15)
        output=result.stdout+result.stderr
        assert result.returncode != 0,(args,output)
        assert 'non-loopback' in output,(args,output)
        assert not receipt.parent.exists(),(args,'startup mutated receipt state')
        print(json.dumps({'command':args,'exit_code':result.returncode,'nonloopback_denied':True,'store_created':False}))
print('4 native startup controls passed')
