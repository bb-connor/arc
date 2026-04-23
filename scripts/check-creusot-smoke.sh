#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo creusot version >/dev/null 2>&1; then
  echo "Creusot smoke check requires cargo-creusot" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-creusot-smoke.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

(
  cd "${tmp_dir}"
  cargo creusot new chio-creusot-smoke >/dev/null
  cd chio-creusot-smoke
  python3 - <<'PY'
from pathlib import Path

manifest = Path("Cargo.toml")
text = manifest.read_text(encoding="utf-8")
text = text.replace(
    'creusot-std = "0.11.0"',
    'creusot-std = { git = "https://github.com/creusot-rs/creusot.git", rev = "a12f3ac7f688c7b93cee2c2eb60282004a2bdb30" }',
)
manifest.write_text(text, encoding="utf-8")
PY
  cargo creusot prove
)

echo "Creusot smoke check passed"
