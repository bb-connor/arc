#!/usr/bin/env bash
set -euo pipefail

checkout_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$checkout_root"
mkdir -p "${CARGO_TARGET_DIR:-target}"
target_root="$(cd "${CARGO_TARGET_DIR:-target}" && pwd)"
export CARGO_TARGET_DIR="$target_root"
generated_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-kotlin-native.XXXXXX")"
trap 'rm -rf -- "$generated_dir"' EXIT

cargo build --locked -p chio-kernel-mobile --lib --example bindgen
"$target_root/debug/examples/bindgen" generate --language kotlin --no-format \
  --out-dir "$generated_dir/source" \
  "$checkout_root/crates/kernel/chio-kernel-mobile/src/chio_kernel_mobile.udl"
cp "$checkout_root/sdks/jvm/chio-kernel-mobile/src/main/kotlin/dev/chio/kernel/Chio.kt" \
  "$generated_dir/source/Chio.kt"

CHIO_KOTLIN_NATIVE_SOURCE="$generated_dir/source" \
CHIO_KOTLIN_NATIVE_LIB_DIR="$target_root/debug" \
  "$checkout_root/sdks/jvm/gradlew" \
  --project-dir "$checkout_root/tests/bindings/kotlin-mobile" \
  --project-cache-dir "$generated_dir/gradle-cache" \
  -PchioKotlinBuildDir="$generated_dir/build" \
  --no-daemon --max-workers=2 run
