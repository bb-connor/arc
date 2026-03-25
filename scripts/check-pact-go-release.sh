#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
sdk_dir="${repo_root}/packages/sdk/pact-go"

if ! command -v go >/dev/null 2>&1; then
  echo "pact-go release checks require go on PATH" >&2
  exit 1
fi

module_version="$(awk -F'"' '/ModuleVersion/ { print $2; exit }' "${sdk_dir}/version/version.go")"
if [[ -z "${module_version}" ]]; then
  echo "failed to determine pact-go module version" >&2
  exit 1
fi
release_version="${module_version}"
if [[ "${release_version}" != v* ]]; then
  release_version="v${release_version}"
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/pact-go-release.XXXXXX")"
consumer_dir="${work_dir}/consumer"
bin_dir="${work_dir}/bin"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

(
  cd "${sdk_dir}"
  CGO_ENABLED=0 go test ./...
  CGO_ENABLED=0 go vet ./...
  CGO_ENABLED=0 go build ./...
  GOBIN="${bin_dir}" CGO_ENABLED=0 go install ./cmd/conformance-peer
)

if [[ ! -x "${bin_dir}/conformance-peer" ]]; then
  echo "expected conformance-peer binary at ${bin_dir}/conformance-peer" >&2
  exit 1
fi

mkdir -p "${consumer_dir}"
cat > "${consumer_dir}/main.go" <<'EOF'
package main

import (
	"context"
	"fmt"

	"github.com/medica/pact/packages/sdk/pact-go/auth"
	"github.com/medica/pact/packages/sdk/pact-go/client"
	"github.com/medica/pact/packages/sdk/pact-go/version"
)

func main() {
	consumer := client.WithStaticBearer("http://127.0.0.1:8080", "token", nil)
	if consumer == nil {
		panic("nil client")
	}
	fmt.Printf("%s %s\n", version.DefaultClientName, version.ModuleVersion)
	_ = auth.StaticBearerToken("token")
	_, _ = context.WithCancel(context.Background())
}
EOF

(
  cd "${consumer_dir}"
  go mod init example.com/pact-go-release-smoke
  go mod edit -require=github.com/medica/pact/packages/sdk/pact-go@"${release_version}"
  go mod edit -replace=github.com/medica/pact/packages/sdk/pact-go="${sdk_dir}"
  CGO_ENABLED=0 go mod tidy
  CGO_ENABLED=0 go build ./...
)

echo "pact-go release qualification passed for ${release_version}"
