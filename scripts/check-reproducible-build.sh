#!/usr/bin/env bash
# Build the chio binary twice from the same commit in two separate source
# trees and compare the results byte for byte. Each tree is a clean archive
# of the commit, built into its own target directory with its own path
# remapped away, so a match shows the binary does not depend on where the
# tree lived. Prints one JSON line and exits nonzero when the builds differ.
set -euo pipefail

usage() {
  echo "usage: $0 [--rev <git-rev>] [--jobs <n>] [--keep] <work-dir>" >&2
  exit 64
}

rev=HEAD
jobs=
keep=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rev) rev=$2; shift 2 ;;
    --jobs) jobs=$2; shift 2 ;;
    --keep) keep=1; shift ;;
    -h|--help) usage ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[[ $# -eq 1 ]] || usage
work=$(realpath -m "$1")
repo=$(git rev-parse --show-toplevel)
commit=$(git -C "$repo" rev-parse --verify "${rev}^{commit}")
cargo_home=${CARGO_HOME:-$HOME/.cargo}
mkdir -p "$work"

build() {
  local side=$1 tree="$work/$1"
  rm -rf "$tree"
  mkdir -p "$tree"
  git -C "$repo" archive --format=tar "$commit" | tar -x -C "$tree"
  (
    cd "$tree"
    env RUSTFLAGS="--remap-path-prefix=$tree=/chio --remap-path-prefix=$cargo_home=/cargo" \
      CARGO_TARGET_DIR="$tree/target" CARGO_INCREMENTAL=0 \
      ${jobs:+CARGO_BUILD_JOBS="$jobs"} \
      cargo build --release --locked --offline -p chio-cli >"$work/build-$side.log" 2>&1
  )
  sha256sum "$tree/target/release/chio" | cut -d' ' -f1
}

first=$(build a)
second=$(build b)
size=$(stat -c %s "$work/a/target/release/chio")
identical=false
[[ "$first" == "$second" ]] && identical=true
printf '{"schema":"chio.reproducible-build.v1","commit":"%s","host":"%s","target":"%s","binary":"chio","bytes":%s,"sha256":["%s","%s"],"identical":%s}\n' \
  "$commit" "$(uname -m)-$(uname -s)" "$(rustc -vV | awk '/^host:/ {print $2}')" "$size" "$first" "$second" "$identical"
if [[ $keep -eq 0 ]]; then
  rm -rf "$work/a" "$work/b"
fi
[[ $identical == true ]]
