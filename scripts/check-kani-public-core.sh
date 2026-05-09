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
if manifest.get("evidence_class") != "bounded_no_unwinding":
    raise SystemExit("Kani public harness manifest must declare evidence_class=bounded_no_unwinding")
if manifest.get("full_soundness_evidence") is not False:
    raise SystemExit("Kani public harness manifest must declare full_soundness_evidence=false")
if manifest.get("unwinding_assertions") is not False:
    raise SystemExit("Kani public harness manifest runner expects unwinding_assertions=false")
default_unwind = int(manifest.get("default_unwind", 0))
if default_unwind <= 0:
    raise SystemExit("Kani public harness manifest requires positive default_unwind")

lanes = manifest.get("lanes", {})
pr_lane = lanes.get("pr", {})
description = (pr_lane.get("description") or "").lower()
for forbidden in ("full sweep", "full soundness", "complete soundness"):
    if forbidden in description:
        raise SystemExit(
            f"Kani public harness lanes.pr.description contains release-unsafe wording: {forbidden}"
        )
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
Path("target/formal/kani-public-settings.env").write_text(
    f"DEFAULT_UNWIND={default_unwind}\nUNWINDING_ASSERTIONS=false\n",
    encoding="utf-8",
)
PY

source target/formal/kani-public-settings.env
while IFS= read -r harness; do
  [[ -n "$harness" ]] || continue
  cargo kani -p chio-kernel-core --lib --harness "$harness" --default-unwind "$DEFAULT_UNWIND" --no-unwinding-checks
done < target/formal/kani-public-harnesses.list

echo "Bounded/no-unwinding Kani public core harnesses passed (not full soundness evidence)"
