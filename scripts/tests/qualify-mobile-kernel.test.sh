#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

bin="${tmp_dir}/bin"
mkdir -p "${bin}"
cat >"${bin}/rustup" <<'STUB'
#!/usr/bin/env bash
echo aarch64-apple-ios
echo aarch64-apple-ios-sim
STUB
cat >"${bin}/uname" <<'STUB'
#!/usr/bin/env bash
echo Darwin
STUB
cat >"${bin}/cargo" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *ffi_roundtrip*) exit 1 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${bin}/rustup" "${bin}/uname" "${bin}/cargo"

if PATH="${bin}:${PATH}" ARTIFACT_DIR="${tmp_dir}/artifacts" \
  CARGO_TARGET_DIR="${tmp_dir}/target" \
  bash scripts/qualify-mobile-kernel.sh >"${tmp_dir}/out" 2>&1; then
  echo "mobile qualification passed with a failed host_ffi lane" >&2
  exit 1
fi
grep -Fq 'one or more required lanes failed: host_ffi: ffi_roundtrip failed' \
  "${tmp_dir}/out"
if grep -Fq 'target_mobile_gate:' "${tmp_dir}/out"; then
  echo "passing target_mobile_gate was named as failed" >&2
  exit 1
fi
