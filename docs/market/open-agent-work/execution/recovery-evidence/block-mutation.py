"""Calibrate the live-chain negative test against one isolated missing guard."""
from pathlib import Path
import subprocess
import tempfile

root=Path.cwd()
scripts=root/'contracts/scripts'
with tempfile.TemporaryDirectory(prefix='chio-block-mutation-') as directory:
    probe=Path(directory)
    (probe/'node_modules').symlink_to(root/'contracts/node_modules',target_is_directory=True)
    source=(scripts/'work-claim-recovery.mjs').read_text()
    guard="assert.equal(block?.hash,receipt.blockHash,'receipt is not on the observed canonical chain');"
    assert source.count(guard)==1
    (probe/'work-claim-recovery.mjs').write_text(source.replace(guard,'// Deliberately omitted canonical block check.'))
    tests=(scripts/'work-claim-recovery-core.test.mjs').read_text()
    tests=tests.replace("'./work-claim-fixture.mjs'",repr((scripts/'work-claim-fixture.mjs').as_uri()))
    test=probe/'mutated.test.mjs'
    test.write_text(tests)
    result=subprocess.run(['node','--test','--test-name-pattern=unavailable or mismatched',str(test)])
    raise SystemExit(result.returncode)
