#!/usr/bin/env bash
# Build chio-kernel-browser to wasm and bundle for the TS SDK.
#
# Pinned versions are read from .tooling/{wasm-pack,wasm-bindgen}.version
# so the build is reproducible across local dev and CI. The wasm-bindgen
# version is consumed transitively by wasm-pack; we record it here so
# `cargo install wasm-bindgen-cli --version $(cat .tooling/wasm-bindgen.version)`
# can be invoked in environments that need the standalone CLI (for
# example, custom bindgen post-processing).
#
# Usage:
#   build-wasm.sh                 # defaults to --target web
#   build-wasm.sh web|nodejs|bundler|deno|no-modules
#   build-wasm.sh --target web
#   build-wasm.sh --target=web

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

WASM_PACK_VERSION="$(cat "${REPO_ROOT}/.tooling/wasm-pack.version")"
WASM_BINDGEN_VERSION="$(cat "${REPO_ROOT}/.tooling/wasm-bindgen.version")"

TARGET="${1:-web}"
case "${TARGET}" in
  --target)
    TARGET="${2:-web}"
    ;;
  --target=*)
    TARGET="${TARGET#--target=}"
    ;;
  web|nodejs|bundler|deno|no-modules)
    ;;
  *)
    echo "ERROR: unknown target '${TARGET}'." >&2
    echo "  expected one of: web, nodejs, bundler, deno, no-modules" >&2
    exit 1
    ;;
esac

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "WARN: wasm-pack not installed. Install with:" >&2
  echo "  cargo install wasm-pack --version ${WASM_PACK_VERSION}" >&2
  echo "WARN: wasm-bindgen-cli (transitive) pinned at ${WASM_BINDGEN_VERSION}." >&2
  echo "  cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION}" >&2
  echo "Soft-skipping wasm build; CI installs the toolchain via .tooling/ pins." >&2
  exit 0
fi

ACTUAL_WP_VER="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
if [ "${ACTUAL_WP_VER}" != "${WASM_PACK_VERSION}" ]; then
  echo "WARN: wasm-pack version mismatch: expected ${WASM_PACK_VERSION}, got ${ACTUAL_WP_VER}" >&2
  echo "  reinstall with: cargo install wasm-pack --version ${WASM_PACK_VERSION} --force" >&2
fi

if command -v wasm-bindgen >/dev/null 2>&1; then
  ACTUAL_WB_VER="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
  if [ "${ACTUAL_WB_VER}" != "${WASM_BINDGEN_VERSION}" ]; then
    echo "WARN: wasm-bindgen version mismatch: expected ${WASM_BINDGEN_VERSION}, got ${ACTUAL_WB_VER}" >&2
    echo "  reinstall with: cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --force" >&2
  fi
fi

OUT_DIR="${REPO_ROOT}/sdks/typescript/packages/browser/pkg"
CRATE_DIR="${REPO_ROOT}/crates/chio-kernel-browser"

if [ ! -d "${CRATE_DIR}" ]; then
  echo "ERROR: crate directory not found: ${CRATE_DIR}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "INFO: building chio-kernel-browser (target=${TARGET}) -> ${OUT_DIR}"
cd "${CRATE_DIR}"
wasm-pack build \
  --target "${TARGET}" \
  --out-dir "${OUT_DIR}" \
  --release
echo "INFO: wasm build complete."
