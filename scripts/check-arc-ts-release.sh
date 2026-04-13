#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="${repo_root}/packages/sdk/arc-ts"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/arc-ts-release.XXXXXX")"
repo_copy_dir="${work_dir}/repo"
sdk_dir="${repo_copy_dir}/packages/sdk/arc-ts"
consumer_dir="${work_dir}/consumer"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

if ! command -v npm >/dev/null 2>&1; then
  echo "ARC TypeScript release checks require npm on PATH" >&2
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
  "name": "arc-ts-release-smoke",
  "private": true,
  "type": "module"
}
EOF

(
  cd "${consumer_dir}"
  npm install --no-fund --no-audit "${sdk_dir}/${pack_file}"
  node --input-type=module <<'EOF'
import { ArcClient, ReceiptQueryClient } from "@arc-protocol/sdk";

if (typeof ArcClient?.withStaticBearer !== "function") {
  throw new Error("expected ArcClient.withStaticBearer export");
}

if (typeof ReceiptQueryClient !== "function") {
  throw new Error("expected ReceiptQueryClient export");
}

const client = ArcClient.withStaticBearer("http://127.0.0.1:8080/mcp", "token");
if (!client || typeof client.initialize !== "function") {
  throw new Error("expected initialized ArcClient surface");
}

const receiptClient = new ReceiptQueryClient("http://127.0.0.1:8940", "token");
if (!receiptClient || typeof receiptClient.query !== "function") {
  throw new Error("expected receipt query surface");
}

console.log("ARC TypeScript package smoke verified");
EOF
)

echo "ARC TypeScript release qualification passed"
