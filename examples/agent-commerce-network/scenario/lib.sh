#!/usr/bin/env bash
set -euo pipefail

SCENARIO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_ROOT="$(cd "${SCENARIO_ROOT}/.." && pwd)"
ARTIFACTS_ROOT="${EXAMPLE_ROOT}/artifacts"
CONTRACTS_ROOT="${EXAMPLE_ROOT}/contracts"

stage_bundle() {
  local scenario_id="$1"
  local scenario_title="$2"
  local summary="$3"

  local ts
  ts="$(date -u +"%Y%m%dT%H%M%SZ")"
  local out_dir="${ARTIFACTS_ROOT}/${scenario_id}/${ts}"

  mkdir -p "${out_dir}/contracts"
  cp "${CONTRACTS_ROOT}"/*.json "${out_dir}/contracts/"

  cat > "${out_dir}/README.md" <<EOF
# ${scenario_title}

${summary}

Generated at: ${ts}

## Contents

- \`contracts/\`: seeded example artifacts for the scenario
- \`steps.md\`: execution checklist
- \`expected-outputs.md\`: ARC outputs to look for once the live services are wired
EOF

  printf '%s\n' "${out_dir}"
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-60}"

  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for HTTP endpoint: ${url}" >&2
  return 1
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "${attempts}"); do
    if python3 - "${host}" "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(0.5)
    sock.connect((host, port))
PY
    then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for TCP port ${host}:${port}" >&2
  return 1
}
