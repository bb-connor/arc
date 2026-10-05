#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/release-qualification/mobile-kernel/ios"
SWIFT_OUT="${OUT_DIR}/swift"
HEADERS_OUT="${OUT_DIR}/headers"
FRAMEWORK_OUT="${OUT_DIR}/ChioKernel.xcframework"
UDL="${ROOT}/crates/kernel/chio-kernel-mobile/src/chio_kernel_mobile.udl"

if [[ "${1:-}" == "--test-only" ]]; then
  bash -n "$0"
  test -f "${ROOT}/sdks/swift/Package.swift"
  test -f "${ROOT}/sdks/swift/Sources/Chio/AppAttest.swift"
  test -f "${ROOT}/sdks/swift/Tests/ChioTests/AppAttestTests.swift"
  grep -q "DCAppAttestService" "${ROOT}/sdks/swift/Sources/Chio/AppAttest.swift"
  grep -q "generateAssertion" "${ROOT}/sdks/swift/Sources/Chio/AppAttest.swift"
  grep -q "binaryTarget" "${ROOT}/sdks/swift/Package.swift"
  mkdir -p "${OUT_DIR}"
  cat > "${OUT_DIR}/test-only-summary.json" <<JSON
{"lane":"ios_framework","status":"pass","mode":"test-only"}
JSON
  exit 0
fi

if [[ "${1:-}" != "" && "${1:-}" != "--install" ]]; then
  echo "usage: $0 [--install|--test-only]" >&2
  exit 2
fi

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required tool missing: $1" >&2
    exit 1
  fi
}

require_tool cargo
require_tool lipo
require_tool xcodebuild
require_tool python3
cd "${ROOT}"
export IPHONEOS_DEPLOYMENT_TARGET=15.0
mkdir -p "${OUT_DIR}" "${SWIFT_OUT}" "${HEADERS_OUT}"

TARGET_DIR="${ROOT}/target/mobile-ios"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --locked --release --lib --target aarch64-apple-ios -p chio-kernel-mobile
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --locked --release --lib --target aarch64-apple-ios-sim -p chio-kernel-mobile
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --locked --release --lib --target x86_64-apple-ios -p chio-kernel-mobile

CARGO_TARGET_DIR="${TARGET_DIR}" cargo run --locked -p chio-kernel-mobile --example bindgen -- \
  generate --language swift --no-format --out-dir "${SWIFT_OUT}" "${UDL}"
python3 - "${SWIFT_OUT}/chio_kernel_mobile.swift" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
# Normalize generated comments to the repository's documentation style.
lines = (line.replace('\u2014', '-') if line.lstrip().startswith('//') else line
         for line in path.read_text().splitlines())
path.write_text('\n'.join(line.rstrip() for line in lines) + '\n')
PY
cp "${SWIFT_OUT}/chio_kernel_mobileFFI.h" "${HEADERS_OUT}/"
# XCFramework consumers discover the C module only under this canonical name.
cp "${SWIFT_OUT}/chio_kernel_mobileFFI.modulemap" "${HEADERS_OUT}/module.modulemap"

SIM_UNIVERSAL="${TARGET_DIR}/ios-sim-universal/release"
mkdir -p "${SIM_UNIVERSAL}"
lipo -create \
  "${TARGET_DIR}/aarch64-apple-ios-sim/release/libchio_kernel_mobile.a" \
  "${TARGET_DIR}/x86_64-apple-ios/release/libchio_kernel_mobile.a" \
  -output "${SIM_UNIVERSAL}/libchio_kernel_mobile.a"

rm -rf "${FRAMEWORK_OUT}"
xcodebuild -create-xcframework \
  -library "${TARGET_DIR}/aarch64-apple-ios/release/libchio_kernel_mobile.a" \
  -headers "${HEADERS_OUT}" \
  -library "${SIM_UNIVERSAL}/libchio_kernel_mobile.a" \
  -headers "${HEADERS_OUT}" \
  -output "${FRAMEWORK_OUT}"

python3 - "${ROOT}" "${OUT_DIR}" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root, output = map(Path, sys.argv[1:])
files = sorted(p for p in output.rglob('*') if p.is_file() and p.suffix != '.json')
manifest = {
    'schema': 'chio.mobile.ios-framework-build.v1',
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'cargo_lock_sha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest(),
    'rustc': subprocess.check_output(['rustc', '--version'], cwd=root, text=True).strip(),
    'files': {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
}
(output / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY

if [[ "${1:-}" == "--install" ]]; then
  rm -rf "${ROOT}/sdks/swift/Frameworks/ChioKernel.xcframework"
  cp -R "${FRAMEWORK_OUT}" "${ROOT}/sdks/swift/Frameworks/ChioKernel.xcframework"
  mkdir -p "${ROOT}/sdks/swift/Sources/chio_kernel_mobile"
  cp "${SWIFT_OUT}/chio_kernel_mobile.swift" "${ROOT}/sdks/swift/Sources/chio_kernel_mobile/"
  cp "${OUT_DIR}/build-manifest.json" "${ROOT}/sdks/swift/Frameworks/build-manifest.json"
fi
