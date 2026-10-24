#!/usr/bin/env bash
# The trust image entrypoint refuses public demo, empty or shared tokens unless
# CHIO_DEMO=1, refuses a plaintext listener without an explicit opt-in, and
# writes an access configuration through `chio trust config credential --role`
# holding one credential per role and only the tokens' SHA-256 digests.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
entrypoint="${repo_root}/deploy/docker/chio-trust-serve.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mkdir "${work}/bin"
cat > "${work}/bin/chio" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" >> "${CHIO_STUB_ARGS}"
if [ "$1 $2 $3" = "trust config credential" ]; then
  role= secret_env=
  while [ $# -gt 0 ]; do
    case "$1" in
      --role) role="$2"; shift ;;
      --secret-env) secret_env="$2"; shift ;;
    esac
    shift
  done
  secret="$(printenv "$secret_env")"
  printf '[[credentials]]\nrole = "%s"\nsecret_sha256 = "%s"\n' \
    "$role" "$(printf '%s' "$secret" | sha256sum | cut -d ' ' -f 1)"
fi
STUB
chmod +x "${work}/bin/chio"

run() {
  rm -f "${work}/args" "${work}/access.toml"
  env -i PATH="${work}/bin:/usr/bin:/bin" CHIO_STUB_ARGS="${work}/args" \
    CHIO_ACCESS_CONFIG_OUT="${work}/access.toml" "$@" sh "${entrypoint}"
}

refuse() {
  if run "$@" 2>"${work}/stderr"; then
    echo "entrypoint started with: $*" >&2
    exit 1
  fi
  grep -q '^chio-trust-serve: ' "${work}/stderr"
  test ! -e "${work}/args"
  test ! -e "${work}/access.toml"
}

has() {
  grep -qx -- "$1" "${work}/args"
}

digest() {
  printf '%s' "$1" | sha256sum | cut -d ' ' -f 1
}

holds() {
  grep -A1 -x "role = \"$1\"" "${work}/access.toml" \
    | grep -qx "secret_sha256 = \"$(digest "$2")\""
  ! grep -q -- "$2\"" "${work}/access.toml"
}

private=(
  CHIO_KERNEL_HOST_TOKEN=private-a
  CHIO_OPERATOR_TOKEN=private-b
  CHIO_AUTHORITY_WORKLOAD_TOKEN=private-c
)

refuse CHIO_ALLOW_PLAINTEXT=1
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=private-b
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=demo-control-token CHIO_OPERATOR_TOKEN=private-b CHIO_AUTHORITY_WORKLOAD_TOKEN=private-c
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=demo-operator-token CHIO_AUTHORITY_WORKLOAD_TOKEN=private-c
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=private-b CHIO_AUTHORITY_WORKLOAD_TOKEN=demo-workload-token
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=private-b CHIO_AUTHORITY_WORKLOAD_TOKEN=demo-control-token
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=private-a CHIO_AUTHORITY_WORKLOAD_TOKEN=private-c
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=private-b CHIO_AUTHORITY_WORKLOAD_TOKEN=private-a
refuse CHIO_ALLOW_PLAINTEXT=1 CHIO_KERNEL_HOST_TOKEN=private-a CHIO_OPERATOR_TOKEN=private-b CHIO_AUTHORITY_WORKLOAD_TOKEN=private-b
refuse CHIO_DEMO=yes CHIO_ALLOW_PLAINTEXT=1
refuse "${private[@]}"
refuse "${private[@]}" CHIO_ALLOW_PLAINTEXT=yes
refuse "${private[@]}" CHIO_TLS_CERT=/tls/cert.pem
refuse "${private[@]}" CHIO_TLS_KEY=/tls/key.pem

run "${private[@]}" CHIO_TLS_CERT=/tls/cert.pem CHIO_TLS_KEY=/tls/key.pem
has --access-config && has "${work}/access.toml" && has /tls/cert.pem && has /tls/key.pem
has kernel-host && has operator && has authority-workload
holds kernel-host private-a && holds operator private-b && holds authority-workload private-c
! has --allow-plaintext
! has private-a && ! has private-b && ! has private-c

run "${private[@]}" CHIO_ALLOW_PLAINTEXT=1
has --allow-plaintext && holds kernel-host private-a

run CHIO_DEMO=1
holds kernel-host demo-control-token && holds operator demo-operator-token \
  && holds authority-workload demo-workload-token && has --allow-plaintext

run CHIO_DEMO=1 CHIO_KERNEL_HOST_TOKEN=private-a
holds kernel-host private-a && holds operator demo-operator-token \
  && holds authority-workload demo-workload-token

echo "chio-trust-serve entrypoint contract passed"
