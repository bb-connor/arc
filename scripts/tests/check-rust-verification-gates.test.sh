#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

fixture="${tmp_dir}/repo"
mkdir -p "${fixture}/.kani" "${fixture}/formal/rust-verification" \
  "${fixture}/scripts" "${tmp_dir}/bin"
cp "${repo_root}/scripts/check-rust-verification-gates.sh" "${fixture}/scripts/"
cp "${repo_root}/.kani/harnesses.toml" "${fixture}/.kani/"
cp "${repo_root}"/formal/rust-verification/{creusot-contracts,kani-harnesses,kani-public-harnesses}.toml \
  "${fixture}/formal/rust-verification/"

cp "${repo_root}/scripts/check-kani-crypto-scope.py" "${fixture}/scripts/"
cp "${repo_root}/scripts/kani_open_residual.py" "${fixture}/scripts/"
cp "${repo_root}/formal/assumptions.toml" "${fixture}/formal/"
cp "${repo_root}/formal/rust-verification/crypto-proof-scope.toml" "${fixture}/formal/rust-verification/"
for crate in chio-weights chio-attest-verify; do
  crate_path="crates/trust/${crate}"
  mkdir -p "${fixture}/${crate_path}/src"
  cp "${repo_root}/${crate_path}/Cargo.toml" "${fixture}/${crate_path}/"
  cp "${repo_root}/${crate_path}"/src/{lib,kani_public_harnesses,kani_crypto_research}.rs "${fixture}/${crate_path}/src/"
done

log="${tmp_dir}/calls.log"
for script in \
  check-creusot-body-sync.sh \
  check-creusot-smoke.sh \
  check-kani-smoke.sh \
  check-creusot-core.sh \
  check-kani-core.sh \
  check-kani-public-core.sh \
  run-kani-manifest.sh
do
  cat >"${fixture}/scripts/${script}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$(basename "$0")" >>"${FAKE_VERIFICATION_LOG}"
printf ' %s' "$@" >>"${FAKE_VERIFICATION_LOG}"
printf '\n' >>"${FAKE_VERIFICATION_LOG}"
SH
  chmod +x "${fixture}/scripts/${script}"
done

for tool in creusot kani; do
  cat >"${tmp_dir}/bin/${tool}" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "${tmp_dir}/bin/${tool}"
done

export FAKE_VERIFICATION_LOG="${log}"
export PATH="${tmp_dir}/bin:${PATH}"

: >"${log}"
CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "${fixture}/scripts/check-rust-verification-gates.sh"
if [[ "$(cat "${log}")" != "check-creusot-body-sync.sh " ]]; then
  echo "metadata-only Rust verification executed a strict proof command" >&2
  cat "${log}" >&2
  exit 1
fi

: >"${log}"
bash "${fixture}/scripts/check-rust-verification-gates.sh" >"${tmp_dir}/strict.out"
expected_summary="Strict Rust verification tools and executed registered Kani checks passed
OPEN/UNPROVED: chio-attest-verify::public_expect_report_data_determinism_and_binding (KANI-ATTEST-DECOMP); not executed or counted as passed"
if [[ "$(grep -v '^[[:space:]]*$' "${tmp_dir}/strict.out" | tail -n 2)" != "${expected_summary}" ]]; then
  echo "strict Rust verification summary does not end by naming the unexecuted open residual" >&2
  cat "${tmp_dir}/strict.out" >&2
  exit 1
fi
if [[ "$(grep -c '^run-kani-manifest.sh --lane pr --exclude-crate chio-kernel-core$' "${log}")" -ne 1 ]]; then
  echo "strict Rust verification did not execute the non-core manifest runner exactly once" >&2
  cat "${log}" >&2
  exit 1
fi
if [[ "$(grep -c '^check-kani-public-core.sh ' "${log}")" -ne 1 ]]; then
  echo "strict Rust verification did not own exactly one public-core invocation" >&2
  cat "${log}" >&2
  exit 1
fi

cp "${repo_root}/.kani/harnesses.toml" "${fixture}/.kani/harnesses.toml"
printf '\nunknown_entry = true\n' >>"${fixture}/.kani/harnesses.toml"
if CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "${fixture}/scripts/check-rust-verification-gates.sh" >/dev/null 2>&1; then
  echo "Rust verification accepted an unknown multi-crate harness key" >&2
  exit 1
fi

for profile_case in standalone stale-hex no-cover no-unwinding eq memcmp; do
  cp "${repo_root}/.kani/harnesses.toml" "${fixture}/.kani/harnesses.toml"
  python3 - "${fixture}/.kani/harnesses.toml" "$profile_case" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
case = sys.argv[2]
name = 'harness = "public_expect_report_data_determinism_and_binding"'
head, tail = path.read_text().split(name, 1)
body, rest = tail.split("\n[[harness]]", 1)
body = body.replace("\npublic_key_hex_unwind = 0", "")
if case == "stale-hex":
    body += "\npublic_key_hex_unwind = 0\n"
elif case == "no-cover":
    body = body.replace("require_cover = true", "require_cover = false")
elif case == "no-unwinding":
    body = body.replace("unwinding_checks = true", "unwinding_checks = false")
elif case == "eq":
    body += "\npublic_key_eq_unwind = 8\n"
elif case == "memcmp":
    body += "\nmemcmp_unwind = 136\n"
path.write_text(head + name + body + "\n[[harness]]" + rest)
PY
  if [[ "$profile_case" == standalone ]]; then
    CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
      bash "${fixture}/scripts/check-rust-verification-gates.sh"
  elif CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
    bash "${fixture}/scripts/check-rust-verification-gates.sh" >/dev/null 2>&1; then
    echo "Rust verification accepted invalid P256 profile: $profile_case" >&2
    exit 1
  fi
done

echo "Rust verification umbrella contract passed"
