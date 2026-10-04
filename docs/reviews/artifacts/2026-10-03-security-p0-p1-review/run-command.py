import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path('/tmp/arc-security-launch')
archive = Path('/home/connor/chio-security-evidence/2026-10-03-security-p0-p1-review')
archive.mkdir(parents=True, exist_ok=True)
label, *command = sys.argv[1:]
log = archive / (label + '.log')
if log.exists():
    raise SystemExit('Refusing to overwrite terminal evidence: ' + label)
env = dict(os.environ, CARGO_TARGET_DIR='/home/connor/chio-security-target-6d-final', CARGO_INCREMENTAL='0', CHIO_CHECKOUT_ROOT=str(root), CARGO_BUILD_JOBS='4')
source_diff = subprocess.check_output(['git', 'diff', '--binary', 'HEAD', '--', 'Cargo.toml', 'Cargo.lock', 'crates', 'scripts'], cwd=root)
source_files = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '--', 'crates', 'scripts'], cwd=root, text=True).splitlines()
untracked_sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in source_files}
started = time.monotonic()
with log.open('w') as output:
    result = subprocess.run(command, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT)
metadata = {'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'tracked_source_diff_sha256': hashlib.sha256(source_diff).hexdigest(), 'untracked_sources': untracked_sources, 'command': command, 'exit_code': result.returncode, 'elapsed_seconds': round(time.monotonic()-started, 2), 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
log.with_suffix('.json').write_text(json.dumps(metadata, indent=2)+'\n')
print(json.dumps(metadata))
print('\n'.join(line[:1500] for line in log.read_text().splitlines()[-18:]))
sys.exit(result.returncode)
