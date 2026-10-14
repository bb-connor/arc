#!/usr/bin/env bash
# The trust image entrypoint refuses public demo or empty tokens unless
# CHIO_DEMO=1, and refuses a plaintext listener without an explicit opt-in.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
entrypoint="${repo_root}/deploy/docker/chio-trust-serve.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mkdir "${work}/bin"
cat > "${work}/bin/chio" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "${CHIO_STUB_ARGS}"
STUB
chmod +x "${work}/bin/chio"

run() {
  rm -f "${work}/args"
  env -i PATH="${work}/bin:/usr/bin:/bin" CHIO_STUB_ARGS="${work}/args" "$@" sh "${entrypoint}"
}

refuse() {
  if run "$@" 2>"${work}/stderr"; then
    echo "entrypoint started with: $*" >&2
    exit 1
  fi
  grep -q '^chio-trust-serve: ' "${work}/stderr"
  test ! -e "${work}/args"
}

has() {
  grep -qx -- "$1" "${work}/args"
}

private=(CHIO_SERVICE_TOKEN=private-a CHIO_AUTHORITY_WORKLOAD_TOKEN=private-b)

refuse CHIO_ALLOW_PLAINTEXT=1
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_SERVICE_TOKEN=private-a
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_SERVICE_TOKEN=demo-control-token CHIO_AUTHORITY_WORKLOAD_TOKEN=private-b
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_SERVICE_TOKEN=private-a CHIO_AUTHORITY_WORKLOAD_TOKEN=demo-workload-token
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_SERVICE_TOKEN=private-a CHIO_AUTHORITY_WORKLOAD_TOKEN=demo-control-token
refuse CHIO_DEMO=yes CHIO_ALLOW_PLAINTEXT=1
refuse "${private[@]}"
refuse "${private[@]}" CHIO_ALLOW_PLAINTEXT=yes
refuse "${private[@]}" CHIO_TLS_CERT=/tls/cert.pem
refuse "${private[@]}" CHIO_TLS_KEY=/tls/key.pem

run "${private[@]}" CHIO_TLS_CERT=/tls/cert.pem CHIO_TLS_KEY=/tls/key.pem
has private-a && has private-b && has /tls/cert.pem && has /tls/key.pem
! has --allow-plaintext

run "${private[@]}" CHIO_ALLOW_PLAINTEXT=1
has --allow-plaintext && has private-a

run CHIO_DEMO=1
has demo-control-token && has demo-workload-token && has --allow-plaintext

run CHIO_DEMO=1 CHIO_SERVICE_TOKEN=private-a
has private-a && has demo-workload-token

echo "chio-trust-serve entrypoint contract passed"
