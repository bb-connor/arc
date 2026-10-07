#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cat > "$temporary/cargo" <<'SH'
#!/usr/bin/env bash
test "$*" = 'kani --version' || exit 99
printf '%s\n' "$FAKE_KANI_VERSION"
exit "${FAKE_KANI_EXIT:-0}"
SH
chmod +x "$temporary/cargo"
export PATH="$temporary:$PATH"
export KANI_HOME="$temporary/kani"
python3 - <<'PY'
import importlib.util
import os
from pathlib import Path
spec = importlib.util.spec_from_file_location("kani_toolchain", "scripts/kani-toolchain.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
bundle = Path(os.environ["KANI_HOME"]) / "kani-0.68.0"
(bundle / "bin").mkdir(parents=True)
(bundle / "bin/kani-compiler").write_bytes(b"compiler fixture")
module.record_bundle(bundle)
PY
export FAKE_KANI_VERSION='Kani Rust Verifier 0.68.0 (cargo plugin)'
bash scripts/check-kani-version.sh > "$temporary/output"
grep -Fq '0.68.0' "$temporary/output"

for version in 'Kani Rust Verifier 0.67.0' 'Kani Rust Verifier 0.68.01' '' 'cargo 1.94.1'; do
  if FAKE_KANI_VERSION="$version" bash scripts/check-kani-version.sh > "$temporary/output" 2>&1; then
    echo "Accepted incompatible verifier: $version" >&2
    exit 1
  fi
done
if FAKE_KANI_EXIT=1 bash scripts/check-kani-version.sh > "$temporary/output" 2>&1; then
  echo 'Accepted a failing version probe' >&2
  exit 1
fi
if CHIO_KANI_VERSION=0.67.0 bash scripts/check-kani-version.sh > "$temporary/output" 2>&1; then
  echo 'Accepted an incompatible configured verifier' >&2
  exit 1
fi
echo 'Kani version boundary passed'
