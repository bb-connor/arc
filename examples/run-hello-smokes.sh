#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

EXAMPLES=(
  hello-openapi-sidecar
  hello-trust-control
  hello-receipt-verify
  hello-fastapi
  hello-fastify
  hello-chi
  hello-express
  hello-django
  hello-elysia
  hello-spring-boot
  hello-dotnet
  hello-mcp
  hello-a2a
  hello-acp
)

usage() {
  cat <<'EOF'
Usage:
  ./run-hello-smokes.sh [--list] [example-name ...]

Examples:
  ./run-hello-smokes.sh --list
  ./run-hello-smokes.sh hello-fastapi hello-fastify
  ./run-hello-smokes.sh
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--list" ]]; then
  printf '%s\n' "${EXAMPLES[@]}"
  exit 0
fi

TARGETS=()
if [[ "$#" -eq 0 ]]; then
  TARGETS=("${EXAMPLES[@]}")
else
  TARGETS=("$@")
fi

for target in "${TARGETS[@]}"; do
  if [[ ! " ${EXAMPLES[*]} " =~ " ${target} " ]]; then
    echo "unknown hello example: ${target}" >&2
    usage >&2
    exit 1
  fi

  smoke="${ROOT}/${target}/smoke.sh"
  if [[ ! -x "${smoke}" ]]; then
    echo "missing smoke script: ${smoke}" >&2
    exit 1
  fi

  echo
  echo "==> ${target}"
  "${smoke}"
done
