#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: scripts/install-chio.sh [--root DIRECTORY] [--debug] [--force]

Build and install the chio CLI from this source checkout with Cargo.lock.
The default destination is $HOME/.local/bin/chio. No sudo is required.

  --root DIRECTORY  Cargo installation prefix (binary goes in DIRECTORY/bin)
  --debug           Use the development profile for a faster local preview
  --force           Replace a previously installed chio binary
  -h, --help        Show this help

Run from a reviewed checkout with the repository's Rust toolchain installed.
CARGO_BUILD_JOBS and CARGO_TARGET_DIR may be set to control build resources.
HELP
}

die() { printf '%s\n' "$*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_root="${HOME}/.local"
install_args=(install --locked --path "$repo_root/crates/products/chio-cli" --bin chio)
replace=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || die '--root requires a directory'
      install_root="$2"
      shift 2
      ;;
    --debug) install_args+=(--debug); shift ;;
    --force) replace=1; install_args+=(--force); shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

command -v cargo >/dev/null || die 'Install Rust and Cargo before running this script.'
[[ -f "$repo_root/Cargo.lock" ]] || die 'Run the installer from a complete Chio source checkout.'
# Resolve the destination before changing to the source directory.
[[ "$install_root" = /* ]] || install_root="$PWD/$install_root"
if [[ ( -e "$install_root/bin/chio" || -L "$install_root/bin/chio" ) && "$replace" -ne 1 ]]; then
  die 'A chio binary already exists at the destination. Use --force to replace it.'
fi

cd "$repo_root"
printf 'Building Chio from %s\n' "$repo_root"
if command -v git >/dev/null && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'Source revision: %s\n' "$(git rev-parse HEAD)"
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    printf 'This checkout also contains uncommitted changes.\n'
  fi
fi
cargo "${install_args[@]}" --root "$install_root"
"$install_root/bin/chio" --version
printf '\nInstalled: %s/bin/chio\nAdd %s/bin to PATH to use chio from any directory.\n' \
  "$install_root" "$install_root"
