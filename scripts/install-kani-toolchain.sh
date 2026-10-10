#!/usr/bin/env bash
# Kani 0.68 supports the workspace MSRV. Its bundled nightly changed the
# catch_unwind return type; upstream #4819 repairs that signature assertion.
# Reachable catch_unwind remains unsupported and fails verification.
set -euo pipefail

expected_version=0.68.0
source_revision=0d2328a93f0e0ff66132d6bfa1a7d884877cf862
compiler_toolchain=nightly-2026-08-21
patch_sha256=65e329fcccab249c7c9c8b16f7631e4a02ac90e1667e71d70045863afac8406e
if [[ "${CHIO_KANI_VERSION:-$expected_version}" != "$expected_version" ]]; then
  echo "Kani installer requires CHIO_KANI_VERSION=$expected_version" >&2
  exit 1
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
patch="$repo_root/scripts/toolchain-patches/kani-0.68-catch-unwind.patch"
printf '%s  %s\n' "$patch_sha256" "$patch" | sha256sum --check --strict
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/chio-kani-toolchain.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

cargo install kani-verifier --locked --version "$expected_version"
cargo kani setup
git init --quiet "$work/source"
git -C "$work/source" fetch --quiet --depth 1 https://github.com/model-checking/kani.git "$source_revision"
git -C "$work/source" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$work/source" rev-parse HEAD)" = "$source_revision"
git -C "$work/source" submodule update --init --depth 1
git -C "$work/source" apply --check "$patch"
git -C "$work/source" apply "$patch"
rustup toolchain install "$compiler_toolchain" --profile minimal --component rustc-dev --component rust-src --component llvm-tools-preview
(
  cd "$work/source"
  CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 \
    cargo +"$compiler_toolchain" build --locked --release -p kani-compiler --target-dir "$work/target"
)
kani_root="${KANI_HOME:-${HOME}/.kani}/kani-$expected_version"
test -f "$kani_root/bin/kani-compiler"
install -m 0755 "$work/target/release/kani-compiler" "$kani_root/bin/kani-compiler"
printf 'Kani upstream source: %s; upstream repair: https://github.com/model-checking/kani/pull/4819\n' "$source_revision"
sha256sum "$patch" "$kani_root/bin/kani-compiler"
cargo kani --version
