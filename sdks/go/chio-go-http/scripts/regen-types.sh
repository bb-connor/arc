#!/usr/bin/env bash
#
# regen-types.sh - regenerate sdks/go/chio-go-http/types.go from
# spec/schemas/chio-wire/v1/**/*.schema.json via oapi-codegen v2.4.1.
#
# This is the M01.P3.T4 checked-in regen pattern: Go uses a committed
# generated file rather than a live `cargo xtask codegen --lang go` pipeline.
# `cargo xtask codegen --lang go` shells out to this script (see
# xtask/src/main.rs::run_codegen). With `--check`, the xtask additionally
# runs `git diff --exit-code sdks/go/chio-go-http/types.go` to surface drift.
#
# Toolchain pin: oapi-codegen v2.4.1 (xtask/codegen-tools.lock.toml [go]).
# Bumping the pin requires re-running this script, committing the regenerated
# bytes, and updating the lock file in the same PR.
#
# Inputs:
#   spec/schemas/chio-wire/v1/**/*.schema.json (35 schema files, JSON Schema
#   draft 2020-12). The script walks them deterministically (sorted by path)
#   and bundles them into a single OpenAPI 3.0 document fed to oapi-codegen.
#
# Outputs:
#   sdks/go/chio-go-http/types.go (header-stamped, deterministic).
#
# Hard requirements:
#   - go on PATH (any 1.21+; verified on 1.25 in M01.P3.T4).
#   - python3 on PATH (stdlib only; used to translate JSON Schema 2020-12 ->
#     OpenAPI 3.0 components.schemas, which oapi-codegen accepts).
#   - git on PATH (used to embed the schema git SHA in the file header).
#
# House rules:
#   - No em dashes (U+2014) in this script or in the emitted file.
#   - Fail closed on any error (`set -euo pipefail`).
#   - Deterministic: sorted file walk, no timestamps in the body, schema git
#     SHA pinned to HEAD of the schema subtree at script-run time.

set -euo pipefail

# --- locate the workspace root ----------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# scripts/ -> chio-go-http/ -> go/ -> sdks/ -> WORKSPACE
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
SCHEMAS_DIR="${WORKSPACE_ROOT}/spec/schemas/chio-wire/v1"
OUTPUT_FILE="${WORKSPACE_ROOT}/sdks/go/chio-go-http/types.go"
PACKAGE_NAME="chio"
OAPI_CODEGEN_VERSION="v2.4.1"

# --- preflight --------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "regen-types.sh: 'go' is required on PATH (Go 1.21+); install Go and re-run" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "regen-types.sh: 'python3' is required on PATH (stdlib only)" >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "regen-types.sh: 'git' is required on PATH" >&2
  exit 2
fi

if [[ ! -d "${SCHEMAS_DIR}" ]]; then
  echo "regen-types.sh: schemas directory ${SCHEMAS_DIR} does not exist" >&2
  exit 2
fi

# --- compute the schema git SHA --------------------------------------------
# Use `git log -1` over the schema subtree so the SHA reflects the latest
# commit that touched any schema file. Falls back to HEAD when the working
# tree is dirty for the schemas (the script emits the HEAD SHA with a
# 'dirty' suffix so reviewers can see the regen drifted off the indexed tree).
cd "${WORKSPACE_ROOT}"
SCHEMA_HEAD_SHA="$(git log -1 --format=%H -- "spec/schemas/chio-wire/v1" 2>/dev/null || echo unknown)"
if [[ -z "${SCHEMA_HEAD_SHA}" ]]; then
  SCHEMA_HEAD_SHA="unknown"
fi
SCHEMA_DIRTY=""
if ! git diff --quiet -- "spec/schemas/chio-wire/v1" 2>/dev/null; then
  SCHEMA_DIRTY="-dirty"
fi
SCHEMA_SHA_STAMP="${SCHEMA_HEAD_SHA}${SCHEMA_DIRTY}"

# --- build a temp work area -------------------------------------------------
WORK_DIR="$(mktemp -d -t chio-go-regen.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

OPENAPI_PATH="${WORK_DIR}/chio-wire-v1.openapi.json"
RAW_OUTPUT_PATH="${WORK_DIR}/types.raw.go"

# --- preprocess JSON Schema 2020-12 -> OpenAPI 3.0 -------------------------
# JSON Schema features that need translation for oapi-codegen v2.4.1:
#   1. `const: X`              -> `enum: [X]`
#   2. property value `true`   -> `{}`        (any-value schema)
#   3. property value `false`  -> `not: {}`   (impossible schema; rarely used)
#   4. `oneOf` member with `type: "null"` -> drop the member, set
#      `nullable: true` on the parent (OpenAPI 3.0 nullable convention)
#   5. `$defs` -> lift into `components.schemas` and rewrite local
#      `$ref: "#/$defs/..."` into `$ref: "#/components/schemas/..."`
#   6. Top-level `$schema` and `$id` keys are stripped (oapi-codegen ignores
#      them; we keep the data flat under components.schemas).
#
# Component naming: `<DirPascal><FilePascal>` for top-level schemas (so
# `agent/heartbeat.schema.json` -> `AgentHeartbeat`,
# `kernel/heartbeat.schema.json` -> `KernelHeartbeat`,
# `trust-control/heartbeat.schema.json` -> `TrustControlHeartbeat`).
# Lifted `$defs` get `<TopComponentName><DefPascal>` suffixes so they don't
# collide across files (e.g. `CapabilityTokenChioScope`,
# `ReceiptRecordDecision`).
python3 - "${SCHEMAS_DIR}" "${OPENAPI_PATH}" <<'PY'
import json
import os
import sys
from pathlib import Path

schemas_dir = Path(sys.argv[1])
output_path = Path(sys.argv[2])

# Pascalize a string segment (e.g. "tool_call_request" -> "ToolCallRequest",
# "trust-control" -> "TrustControl"). Splits on `_`, `-`, and `.` so all
# three repository conventions normalize the same way.
def pascalize(value: str) -> str:
    out = []
    for part in value.replace("-", "_").replace(".", "_").split("_"):
        if not part:
            continue
        out.append(part[:1].upper() + part[1:])
    return "".join(out)


def collect_schema_files() -> list[Path]:
    files: list[Path] = []
    for root, _, names in os.walk(schemas_dir):
        for name in names:
            if name.endswith(".schema.json"):
                files.append(Path(root) / name)
    files.sort()
    return files


# Recursively rewrite a schema node in-place to be OpenAPI 3.0 compatible.
# `lifts` is the dict (`components.schemas`) we lift `$defs` into; `prefix`
# is the component-name prefix used to disambiguate lifted definitions.
def rewrite(node, lifts: dict, prefix: str):
    if isinstance(node, dict):
        # JSON Schema property whose value is the literal `true` is
        # represented in Python as the bool True after json.loads. Catch
        # that at the parent level (in the property loop below) - by the
        # time we recurse here, dicts are dicts.

        # `const: X` -> `enum: [X]`
        if "const" in node:
            value = node.pop("const")
            node["enum"] = [value]

        # oneOf with a `type: "null"` member -> drop that member and set
        # `nullable: true` on the parent. If only one non-null member
        # remains, inline it (oapi-codegen handles plain nullable types
        # better than a degenerate one-element oneOf).
        if "oneOf" in node and isinstance(node["oneOf"], list):
            non_null = []
            had_null = False
            for member in node["oneOf"]:
                if isinstance(member, dict) and member.get("type") == "null":
                    had_null = True
                    continue
                non_null.append(member)
            if had_null:
                node["oneOf"] = non_null
                node["nullable"] = True
                if len(non_null) == 1 and isinstance(non_null[0], dict):
                    inlined = non_null[0]
                    del node["oneOf"]
                    # Merge inlined keys into the parent (excluding $schema,
                    # $id, title which are spec-document level only).
                    for key, value in inlined.items():
                        if key in ("$schema", "$id"):
                            continue
                        node[key] = value

        # Lift `$defs` (JSON Schema 2020-12) into the components.schemas
        # bag. Rewrite local `$ref` strings to point at the lifted name.
        if "$defs" in node:
            defs = node.pop("$defs") or {}
            # Build the full ref-remap BEFORE recursing so that a $ref
            # inside one def that points at a sibling def resolves
            # correctly regardless of dict iteration order.
            ref_remap: dict[str, str] = {}
            for name in defs.keys():
                lifted_name = f"{prefix}{pascalize(name)}"
                ref_remap[f"#/$defs/{name}"] = (
                    f"#/components/schemas/{lifted_name}"
                )
            # Rewrite refs in every def body first, then recurse for the
            # other transformations (const, oneOf nullability, nested
            # $defs). Splitting the two passes keeps each idempotent.
            for name, def_schema in defs.items():
                _rewrite_refs(def_schema, ref_remap)
                rewrite(def_schema, lifts, prefix)
                lifted_name = f"{prefix}{pascalize(name)}"
                lifts[lifted_name] = def_schema
            # And rewrite refs in the rest of the parent tree.
            _rewrite_refs(node, ref_remap)

        # Handle properties: replace literal `True` (any-value schema) and
        # `False` (impossible) with their object equivalents.
        if "properties" in node and isinstance(node["properties"], dict):
            for key, value in list(node["properties"].items()):
                if value is True:
                    node["properties"][key] = {}
                elif value is False:
                    node["properties"][key] = {"not": {}}

        # Recurse.
        for key, value in list(node.items()):
            if key == "$defs":
                continue
            rewrite(value, lifts, prefix)

    elif isinstance(node, list):
        for idx, item in enumerate(node):
            if item is True:
                node[idx] = {}
            elif item is False:
                node[idx] = {"not": {}}
            else:
                rewrite(item, lifts, prefix)


def _rewrite_refs(node, mapping: dict[str, str]):
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            ref = node["$ref"]
            if ref in mapping:
                node["$ref"] = mapping[ref]
        for value in node.values():
            _rewrite_refs(value, mapping)
    elif isinstance(node, list):
        for item in node:
            _rewrite_refs(item, mapping)


schemas: dict = {}
for path in collect_schema_files():
    rel = path.relative_to(schemas_dir)
    parts = rel.parts
    # Component name = DirPascal + FilePascal. The schemas tree is two
    # levels deep (subtree/file.schema.json), so we expect parts of length
    # 2. Defensive fallback for deeper trees: join all dir segments.
    if len(parts) < 2:
        raise SystemExit(
            f"regen-types.sh: unexpected schema layout: {rel}"
        )
    dir_segments = parts[:-1]
    file_stem = parts[-1].removesuffix(".schema.json")
    name_prefix = "".join(pascalize(seg) for seg in dir_segments)
    component_name = name_prefix + pascalize(file_stem)

    raw = path.read_text(encoding="utf-8")
    schema = json.loads(raw)

    # Strip JSON Schema document keys; OpenAPI components.schemas is just
    # the schema body.
    schema.pop("$schema", None)
    schema.pop("$id", None)

    rewrite(schema, schemas, component_name)
    schemas[component_name] = schema

# Build the final OpenAPI 3.0 document. paths is required by oapi-codegen,
# even when empty. info.title carries the wire-version banner.
spec = {
    "openapi": "3.0.3",
    "info": {
        "title": "chio-wire/v1",
        "version": "1.0.0",
        "description": (
            "Auto-generated OpenAPI bundle of the JSON Schema files under "
            "spec/schemas/chio-wire/v1/. Consumed by sdks/go/chio-go-http/"
            "scripts/regen-types.sh; not published as an HTTP API."
        ),
    },
    "paths": {},
    "components": {
        "schemas": schemas,
    },
}

# Sort keys for determinism. json.dumps with sort_keys handles nested dicts.
output_path.write_text(
    json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(
    f"regen-types.sh: bundled {len(schemas)} schemas into "
    f"{output_path.name}",
    file=sys.stderr,
)
PY

# --- run oapi-codegen -------------------------------------------------------
# `-generate types,skip-prune` keeps every schema even when no operation
# references it (we have no operations - all schemas are model-only). The
# `skip-fmt` member is intentionally omitted so oapi-codegen runs gofmt on
# its output; we run gofmt again after prepending our header below for
# safety.
echo "regen-types.sh: invoking oapi-codegen ${OAPI_CODEGEN_VERSION}" >&2
GOFLAGS="" GOTOOLCHAIN=auto go run \
  "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -generate types,skip-prune \
  -package "${PACKAGE_NAME}" \
  -o "${RAW_OUTPUT_PATH}" \
  "${OPENAPI_PATH}"

if [[ ! -s "${RAW_OUTPUT_PATH}" ]]; then
  echo "regen-types.sh: oapi-codegen produced an empty file" >&2
  exit 3
fi

# --- prepend the chio header -----------------------------------------------
# Mirror the Rust generated header (crates/chio-spec-codegen/src/lib.rs
# GENERATED_HEADER) with Go-style `//` comments. The header lives BEFORE
# the oapi-codegen banner, which we keep as a secondary attribution stamp.
HEADER_FILE="${WORK_DIR}/header.txt"
cat > "${HEADER_FILE}" <<HEADER_EOF
// DO NOT EDIT - regenerate via 'sdks/go/chio-go-http/scripts/regen-types.sh'
// or 'cargo xtask codegen --lang go'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Schema git SHA: ${SCHEMA_SHA_STAMP}
// Tool:   oapi-codegen ${OAPI_CODEGEN_VERSION} (see xtask/codegen-tools.lock.toml)
//
// Manual edits will be overwritten by the next regeneration; the
// M01.P3.T5 spec-drift CI lane runs this script and 'git diff --exit-code'
// to enforce that this file matches the committed bytes.

HEADER_EOF

# Drop the leading "// Package chio provides primitives ..." line oapi-codegen
# emits, since we are using the package for both generated and hand-written
# files (the package doc comment lives in chio.go). Keep the "Code generated
# by ... DO NOT EDIT" banner so editors and tooling that look for it still
# recognize the file as generated.
#
# The oapi-codegen banner shape (verified on v2.4.1) is:
#   // Package chio provides primitives to interact with the openapi HTTP API.
#   //
#   // Code generated by github.com/oapi-codegen/oapi-codegen/v2 version vX DO NOT EDIT.
#   package chio
#
# We strip the first comment line (the misleading "primitives to interact
# with the openapi HTTP API" claim - we are not an HTTP API) and the blank
# comment line below it, but keep the "Code generated" banner.
TAIL_FILE="${WORK_DIR}/types.tail.go"
awk '
  BEGIN { skipped = 0 }
  NR == 1 && /^\/\/ Package .* provides primitives/ { skipped = 1; next }
  NR == 2 && skipped == 1 && /^\/\/$/ { next }
  { print }
' "${RAW_OUTPUT_PATH}" > "${TAIL_FILE}"

# Concatenate header + tail.
cat "${HEADER_FILE}" "${TAIL_FILE}" > "${OUTPUT_FILE}"

# Final pass: gofmt the file in-place. oapi-codegen already runs gofmt on
# its output, but our header prepend can shift line-numbering across
# versions; gofmt is idempotent so this is safe.
go fmt "${OUTPUT_FILE}" >/dev/null

echo "regen-types.sh: wrote ${OUTPUT_FILE}" >&2
