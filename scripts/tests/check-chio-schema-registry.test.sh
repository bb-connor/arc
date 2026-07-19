#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

bash "${repo_root}/scripts/check-chio-schema-registry.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/chio-schema-registry-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

mkdir -p \
  "${tmp}/crates/test/src" \
  "${tmp}/scripts" \
  "${tmp}/spec/schemas/chio-transaction/v1" \
  "${tmp}/spec/schemas/chio-wire/v1/security" \
  "${tmp}/spec/schemas/unused"
cp "${repo_root}/scripts/check-chio-schema-registry.sh" "${tmp}/scripts/check-chio-schema-registry.sh"

cat >"${tmp}/crates/test/src/signed.rs" <<'RS'
pub const SIGNED_MINIMAL_SCHEMA: &str = "chio.security.minimal.v1";
pub struct SignedMinimal;
RS

cat >"${tmp}/spec/schemas/chio-transaction/v1/minimal.schema.json" <<'JSON'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.chio.example/chio-transaction/v1/minimal.schema.json",
  "type": "object",
  "properties": {
    "schema": { "const": "chio.transaction.minimal.v1" }
  },
  "required": ["schema"],
  "additionalProperties": false
}
JSON

write_valid_signed_map() {
  cat >"${tmp}/spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json" <<'JSON'
{
  "schema": "chio.exported-signed-artifact-schema-map.v1",
  "source_roots": [
    "crates/test/src"
  ],
  "artifacts": [
    {
      "rust_type": "SignedMinimal",
      "source": "crates/test/src/signed.rs",
      "schema_constant": "SIGNED_MINIMAL_SCHEMA",
      "schema_value": "chio.security.minimal.v1",
      "schema_file": "spec/schemas/chio-wire/v1/security/minimal-security.schema.json"
    }
  ],
  "exclusions": []
}
JSON
}

write_valid_signed_map

cat >"${tmp}/spec/schemas/chio-wire/v1/security/minimal-security.schema.json" <<'JSON'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.world/schemas/chio-wire/v1/security/minimal-security.schema.json",
  "type": "object",
  "properties": {
    "schema": { "const": "chio.security.minimal.v1" }
  },
  "required": ["schema"],
  "additionalProperties": false
}
JSON

cat >"${tmp}/spec/schemas/chio-wire/v1/security/required-schema-inventory.json" <<'JSON'
{
  "schema": "chio.security-required-schema-inventory.v1",
  "schemas": [
    {
      "file": "minimal-security.schema.json",
      "schema_id": "https://chio.world/schemas/chio-wire/v1/security/minimal-security.schema.json"
    }
  ]
}
JSON

cat >"${tmp}/spec/schemas/registry.json" <<'JSON'
{
  "schema": "chio.schema-registry.v1",
  "artifacts": [
    {
      "schema": "chio.transaction.minimal.v1",
      "artifactKind": "transaction-test",
      "introducedBy": "schema-registry-test",
      "schemaFile": "spec/schemas/chio-transaction/v1/minimal.schema.json",
      "status": "Required"
    },
    {
      "schema": "chio.security.minimal.v1",
      "artifactKind": "security-test",
      "introducedBy": "schema-registry-test",
      "schemaFile": "spec/schemas/chio-wire/v1/security/minimal-security.schema.json",
      "status": "Required"
    }
  ]
}
JSON

printf '1\n' >"${tmp}/spec/schemas/VERSION"
printf '{}\n' >"${tmp}/spec/schemas/unused/stale.extra"

(
  cd "$tmp"
  git init -q
  git config user.email test@example.invalid
  git config user.name test
  git add crates/test/src/signed.rs \
    scripts/check-chio-schema-registry.sh \
    spec/schemas/VERSION \
    spec/schemas/chio-transaction/v1/minimal.schema.json \
    spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json \
    spec/schemas/chio-wire/v1/security/minimal-security.schema.json \
    spec/schemas/chio-wire/v1/security/required-schema-inventory.json \
    spec/schemas/registry.json
  python3 - <<'PY'
import hashlib
from pathlib import Path

paths = [
    "spec/schemas/VERSION",
    "spec/schemas/chio-transaction/v1/minimal.schema.json",
    "spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json",
    "spec/schemas/chio-wire/v1/security/minimal-security.schema.json",
    "spec/schemas/chio-wire/v1/security/required-schema-inventory.json",
    "spec/schemas/registry.json",
    "spec/schemas/unused/stale.extra",
]
lines = [
    f"{hashlib.sha256(Path(path).read_bytes()).hexdigest()}  {path}\n"
    for path in paths
]
without_self = "".join(lines).encode("utf-8")
self_hash = hashlib.sha256(without_self).hexdigest()
Path("spec/schemas/MANIFEST.sha256").write_text(
    f"{self_hash}  spec/schemas/MANIFEST.sha256\n" + "".join(lines),
    encoding="utf-8",
)
PY
)

if (cd "$tmp" && bash scripts/check-chio-schema-registry.sh >/tmp/chio-schema-registry-extra.out 2>&1); then
  echo "check-chio-schema-registry.test.sh: expected extra MANIFEST path to fail" >&2
  cat /tmp/chio-schema-registry-extra.out >&2
  exit 1
fi

if ! grep -Fq "MANIFEST.sha256 path set is not deterministic" /tmp/chio-schema-registry-extra.out; then
  echo "check-chio-schema-registry.test.sh: extra path failed for the wrong reason" >&2
  cat /tmp/chio-schema-registry-extra.out >&2
  exit 1
fi

write_valid_manifest() {
  (
    cd "$tmp"
    python3 - <<'PY'
import hashlib
import subprocess
from pathlib import Path

inventory = subprocess.run(
    [
        "git",
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "spec/schemas",
    ],
    check=True,
    stdout=subprocess.PIPE,
).stdout.decode("utf-8").split("\0")
paths = sorted(
    path
    for path in inventory
    if Path(path).is_file()
    and (
        path.endswith(".schema.json")
        or path
        in {
            "spec/schemas/MANIFEST.sha256",
            "spec/schemas/VERSION",
            "spec/schemas/registry.json",
            "spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json",
            "spec/schemas/chio-wire/v1/security/required-schema-inventory.json",
        }
    )
)
without_self = "".join(
    f"{hashlib.sha256(Path(path).read_bytes()).hexdigest()}  {path}\n"
    for path in paths
    if path != "spec/schemas/MANIFEST.sha256"
)
self_hash = hashlib.sha256(without_self.encode("utf-8")).hexdigest()
Path("spec/schemas/MANIFEST.sha256").write_text(
    "".join(
        f"{self_hash}  {path}\n"
        if path == "spec/schemas/MANIFEST.sha256"
        else f"{hashlib.sha256(Path(path).read_bytes()).hexdigest()}  {path}\n"
        for path in paths
    ),
    encoding="utf-8",
)
PY
  )
}

python3 - "${tmp}/spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["artifacts"] = []
path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
PY
write_valid_manifest

if (cd "$tmp" && bash scripts/check-chio-schema-registry.sh >/tmp/chio-schema-registry-missing-map.out 2>&1); then
  echo "check-chio-schema-registry.test.sh: expected missing signed artifact mapping to fail" >&2
  cat /tmp/chio-schema-registry-missing-map.out >&2
  exit 1
fi
if ! grep -Fq "exported signed artifact SignedMinimal has no schema mapping" /tmp/chio-schema-registry-missing-map.out; then
  echo "check-chio-schema-registry.test.sh: missing signed artifact mapping failed for the wrong reason" >&2
  cat /tmp/chio-schema-registry-missing-map.out >&2
  exit 1
fi

write_valid_signed_map
python3 - "${tmp}/spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["artifacts"][0]["schema_file"] = (
    "spec/schemas/chio-wire/v1/security/missing-security.schema.json"
)
path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
PY
write_valid_manifest

if (cd "$tmp" && bash scripts/check-chio-schema-registry.sh >/tmp/chio-schema-registry-missing-mapped-schema.out 2>&1); then
  echo "check-chio-schema-registry.test.sh: expected missing mapped schema to fail" >&2
  cat /tmp/chio-schema-registry-missing-mapped-schema.out >&2
  exit 1
fi
if ! grep -Fq "exported signed artifact SignedMinimal points at missing schema" /tmp/chio-schema-registry-missing-mapped-schema.out; then
  echo "check-chio-schema-registry.test.sh: missing mapped schema failed for the wrong reason" >&2
  cat /tmp/chio-schema-registry-missing-mapped-schema.out >&2
  exit 1
fi

write_valid_signed_map
write_valid_manifest

python3 - "${tmp}/spec/schemas/chio-wire/v1/security/required-schema-inventory.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["schemas"] = []
path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
PY
write_valid_manifest

if (cd "$tmp" && bash scripts/check-chio-schema-registry.sh >/tmp/chio-schema-registry-zero.out 2>&1); then
  echo "check-chio-schema-registry.test.sh: expected zero-count inventory to fail" >&2
  cat /tmp/chio-schema-registry-zero.out >&2
  exit 1
fi
if ! grep -Fq "required security schema inventory must contain at least one schema" /tmp/chio-schema-registry-zero.out; then
  echo "check-chio-schema-registry.test.sh: zero-count inventory failed for the wrong reason" >&2
  cat /tmp/chio-schema-registry-zero.out >&2
  exit 1
fi

cat >"${tmp}/spec/schemas/chio-wire/v1/security/required-schema-inventory.json" <<'JSON'
{
  "schema": "chio.security-required-schema-inventory.v1",
  "schemas": [
    {
      "file": "minimal-security.schema.json",
      "schema_id": "https://chio.world/schemas/chio-wire/v1/security/minimal-security.schema.json"
    }
  ]
}
JSON
rm "${tmp}/spec/schemas/chio-wire/v1/security/minimal-security.schema.json"
write_valid_manifest

if (cd "$tmp" && bash scripts/check-chio-schema-registry.sh >/tmp/chio-schema-registry-deletion.out 2>&1); then
  echo "check-chio-schema-registry.test.sh: expected deleted required schema to fail" >&2
  cat /tmp/chio-schema-registry-deletion.out >&2
  exit 1
fi
if ! grep -Fq "required security schema inventory points at missing file minimal-security.schema.json" /tmp/chio-schema-registry-deletion.out; then
  echo "check-chio-schema-registry.test.sh: deleted required schema failed for the wrong reason" >&2
  cat /tmp/chio-schema-registry-deletion.out >&2
  exit 1
fi

echo "check-chio-schema-registry.test.sh: schema registry contract passed"
