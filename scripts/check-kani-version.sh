#!/usr/bin/env bash
set -euo pipefail

# Kani bundles its own rustc. Workspace MSRV compatibility therefore depends on
# the verifier release, even when the invoking Cargo uses our pinned toolchain.
expected_version='0.68.0'
if [[ "${CHIO_KANI_VERSION:-$expected_version}" != "$expected_version" ]]; then
  echo "Kani check requires CHIO_KANI_VERSION=$expected_version" >&2
  exit 2
fi
if ! version="$(cargo kani --version 2>&1)"; then
  echo 'Kani check requires a working cargo-kani installation' >&2
  exit 2
fi
pattern="${expected_version//./\\.}"
if [[ ! "$version" =~ (^|[^0-9.])${pattern}([^0-9.]|$) ]]; then
  echo "Kani check requires $expected_version, found: $version" >&2
  exit 2
fi
printf '%s\n' "$version"
