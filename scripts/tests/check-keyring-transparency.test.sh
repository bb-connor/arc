#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

# Calibrate the actual checkpoint caller against the five-test hosted fixture.
# The fixture is independent of the inventory extracted from the caller.
python3 - <<'PY'
import re
import subprocess
import tempfile
from pathlib import Path

root = Path.cwd()
source = (root / "scripts/check-keyring-transparency.sh").read_text()
start = source.index("run_tests() {")
function = source[start:source.index("\n}\n", start) + 3]
call = re.search(
    r'run_tests "checkpoint and witness signatures" no "\$\(cat <<\x27EOF\x27\n'
    r'.*?\nEOF\n\)" cargo test -p chio-keyring --test checkpoint',
    source,
    re.S,
)
if call is None:
    raise SystemExit("checkpoint caller no longer owns its exact target")

fixture = [
    "checkpoint_deserialization_rejects_oversized_witness_vectors",
    "checkpoint_operator_signature_and_identity_are_canonical",
    "checkpoint_validation_rejects_root_size_sequence_and_predecessor_mismatch",
    "review_checkpoint_rejects_universal_operator_and_witness_signatures",
    "witness_signatures_bind_checkpoint_hash_and_require_distinct_known_quorum",
]
with tempfile.TemporaryDirectory(prefix="chio-keyring-caller-") as directory:
    work = Path(directory)
    fake = work / "cargo"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"names = {fixture!r}\n"
        "if sys.argv[1:] == ['test', '-p', 'chio-keyring', '--test', 'checkpoint', '--', '--list']:\n"
        "    print('\\n'.join(name + ': test' for name in names))\n"
        "elif sys.argv[1:] == ['test', '-p', 'chio-keyring', '--test', 'checkpoint']:\n"
        "    print('\\n'.join('test ' + name + ' ... ok' for name in names))\n"
        "    print('test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s')\n"
        "else:\n"
        "    raise SystemExit('checkpoint caller changed its Cargo target')\n"
    )
    fake.chmod(0o700)
    probe = work / "probe.sh"
    probe.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        'inventory_checker="$1"\n'
        'export PATH="$2:$PATH"\n'
        + function + "\n" + call[0] + "\n"
    )
    result = subprocess.run(
        ["bash", str(probe), str(root / "scripts/check-exact-cargo-test-inventory.py"), str(work)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(result.stdout + result.stderr)

print("Keyring checkpoint caller contract passed (five exact hosted fixture names)")
PY
