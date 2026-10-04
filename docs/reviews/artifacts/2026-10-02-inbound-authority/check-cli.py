import os, pathlib, subprocess, tempfile, json
with tempfile.TemporaryDirectory(prefix='chio-proof-check-') as directory:
    p=pathlib.Path(directory)
    policy=p/'proof.yaml'
    policy.write_text("hushspec: '0.1.0'\nrules:\n  tool_access:\n    default: block\n    allow: ['*']\n    dpop_required: true\n")
    r=subprocess.run(['/home/connor/chio-security-target-6d-final/debug/chio','--format','json','check','--policy',str(policy),'--receipt-db',str(p/'receipts.sqlite3'),'--session-db',str(p/'sessions.sqlite3'),'--server','proof-srv','--tool','read_file','--params','{"path":"README.md"}'],capture_output=True,text=True)
    print(r.stdout); print(r.stderr)
    assert r.returncode == 0
    assert json.loads(r.stdout)['verdict'] == 'ALLOW'
