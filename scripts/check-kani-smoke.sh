#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani smoke check requires cargo-kani" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-kani-smoke.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

(
  cd "${tmp_dir}"
  cargo new --lib chio-kani-smoke >/dev/null
  cat > chio-kani-smoke/src/lib.rs <<'EOF'
pub fn bounded_add_one(x: u8) -> u8 {
    if x < u8::MAX {
        x + 1
    } else {
        x
    }
}

#[cfg(kani)]
#[kani::proof]
fn bounded_add_one_never_decreases() {
    let x: u8 = kani::any();
    kani::assume(x < u8::MAX);
    assert!(bounded_add_one(x) > x);
}
EOF
  cd chio-kani-smoke
  cargo kani
)

echo "Kani smoke check passed"
