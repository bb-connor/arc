#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="${repo_root}/packages/sdk/pact-ts"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/pact-ts-release.XXXXXX")"
repo_copy_dir="${work_dir}/repo"
sdk_dir="${repo_copy_dir}/packages/sdk/pact-ts"
consumer_dir="${work_dir}/consumer"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

if ! command -v npm >/dev/null 2>&1; then
  echo "pact-ts release checks require npm on PATH" >&2
  exit 1
fi

mkdir -p "${repo_copy_dir}/packages/sdk" "${repo_copy_dir}/tests"
cp -R "${source_dir}" "${sdk_dir}"
rm -rf "${sdk_dir}/node_modules" "${sdk_dir}/dist"
cp -R "${repo_root}/tests/bindings" "${repo_copy_dir}/tests/bindings"

(
  cd "${sdk_dir}"
  if [[ -f package-lock.json ]]; then
    npm ci --no-fund --no-audit
  else
    npm install --no-fund --no-audit
  fi
  npm test
  npm run build
)

pack_file="$(
  cd "${sdk_dir}" &&
    npm pack --json | node --input-type=module -e '
      let data = "";
      process.stdin.on("data", (chunk) => (data += chunk));
      process.stdin.on("end", () => {
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0].filename) {
          throw new Error("npm pack did not return a package filename");
        }
        process.stdout.write(parsed[0].filename);
      });
    '
)"

mkdir -p "${consumer_dir}"
cat > "${consumer_dir}/package.json" <<'EOF'
{
  "name": "pact-ts-release-smoke",
  "private": true,
  "type": "module"
}
EOF

(
  cd "${consumer_dir}"
  npm install --no-fund --no-audit "${sdk_dir}/${pack_file}"
  node --input-type=module <<'EOF'
import { PactClient } from "@pact-protocol/sdk";

if (typeof PactClient?.withStaticBearer !== "function") {
  throw new Error("expected PactClient.withStaticBearer export");
}

const client = PactClient.withStaticBearer("http://127.0.0.1:8080/mcp", "token");
if (!client || typeof client.initialize !== "function") {
  throw new Error("expected initialized PactClient surface");
}

console.log("pact-ts package smoke verified");
EOF
)

echo "pact-ts release qualification passed"
