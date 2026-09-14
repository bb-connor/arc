"""Remove one effect guard in an isolated module and require its real-chain test to fail."""
from pathlib import Path
import subprocess
import sys
import tempfile

root=Path.cwd();scripts=root/'contracts/scripts'
action=sys.argv[1]
guards={'decision':'assert.equal(current.accepted,call.args[2]);',
        'refund':'assert.equal(current.refunded,current.terms.amount);'}
guard=guards[action]
with tempfile.TemporaryDirectory(prefix='chio-action-mutation-') as directory:
    probe=Path(directory)
    (probe/'node_modules').symlink_to(root/'contracts/node_modules',target_is_directory=True)
    source=(scripts/'work-claim-recovery.mjs').read_text()
    assert source.count(guard)==1
    (probe/'work-claim-recovery.mjs').write_text(source.replace(guard,'/* Deliberately removed effect guard. */'))
    tests=(scripts/'work-claim-recovery-actions.test.mjs').read_text()
    tests=tests.replace("'./work-claim-fixture.mjs'",repr((scripts/'work-claim-fixture.mjs').as_uri()))
    test=probe/'mutated.test.mjs';test.write_text(tests)
    result=subprocess.run(['node','--test','--test-name-pattern=^'+action,str(test)])
    raise SystemExit(result.returncode)
