#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani public core check requires cargo-kani" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required to read Kani harness manifest") from exc

manifest = tomllib.loads(
    Path("formal/rust-verification/kani-public-harnesses.toml").read_text(
        encoding="utf-8"
    )
)
if manifest.get("schema") != "chio.kani-public-harnesses.v1":
    raise SystemExit("Kani public harness manifest schema mismatch")

lanes = manifest.get("lanes", {})
pr_lane = lanes.get("pr", {})
expected = pr_lane.get("harnesses", [])
if not expected:
    raise SystemExit("Kani public harness manifest lanes.pr.harnesses is empty")

source = Path("crates/chio-kernel-core/src/kani_public_harnesses.rs")
text = source.read_text(encoding="utf-8")
missing = [name for name in expected if f"fn {name}" not in text]
if missing:
    raise SystemExit(f"missing public Kani harnesses: {missing}")

Path("target/formal").mkdir(parents=True, exist_ok=True)
Path("target/formal/kani-public-harnesses.list").write_text(
    "\n".join(expected) + "\n",
    encoding="utf-8",
)
PY

while IFS= read -r harness; do
  [[ -n "$harness" ]] || continue
  cargo kani -p chio-kernel-core --lib --harness "$harness" --default-unwind 8 --no-unwinding-checks
done < target/formal/kani-public-harnesses.list

echo "Kani public core harnesses passed"
