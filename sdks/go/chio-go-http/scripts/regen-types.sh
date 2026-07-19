#!/usr/bin/env bash
#
# regen-types.sh - regenerate sdks/go/chio-go-http/types.go from
# spec/schemas/chio-wire/v1/**/*.schema.json via oapi-codegen v2.4.1.
#
# Go uses a committed
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
#   spec/schemas/chio-wire/v1/**/*.schema.json (100 schema files, JSON Schema
#   draft 2020-12). The script walks them deterministically (sorted by path)
#   and bundles them into a single OpenAPI 3.0 document fed to oapi-codegen.
#
# Outputs:
#   sdks/go/chio-go-http/types.go (header-stamped, deterministic).
#
# Hard requirements:
#   - go on PATH (any 1.21+).
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
DEFAULT_OUTPUT_FILE="${WORKSPACE_ROOT}/sdks/go/chio-go-http/types.go"
if (( $# > 1 )); then
  echo "regen-types.sh: expected at most one output path argument" >&2
  exit 2
fi
OUTPUT_FILE="${1:-${DEFAULT_OUTPUT_FILE}}"
if [[ "${OUTPUT_FILE}" != /* ]]; then
  echo "regen-types.sh: output path must be absolute: ${OUTPUT_FILE}" >&2
  exit 2
fi
if [[ ! -d "$(dirname "${OUTPUT_FILE}")" ]]; then
  echo "regen-types.sh: output directory does not exist: $(dirname "${OUTPUT_FILE}")" >&2
  exit 2
fi
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

# --- build a temp work area -------------------------------------------------
WORK_DIR="$(mktemp -d -t chio-go-regen.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

SCHEMA_INVENTORY_PATH="${WORK_DIR}/schema-inventory.json"
OPENAPI_PATH="${WORK_DIR}/chio-wire-v1.openapi.json"
RAW_OUTPUT_PATH="${WORK_DIR}/types.raw.go"

# --- compute the schema content SHA ----------------------------------------
# The stamp is a content hash of the lex-sorted schema files, making it a
# deterministic function of the bytes feeding into oapi-codegen regardless of
# repository state (rebases, shallow clones, and dirty working trees do not
# shift it).
cd "${WORKSPACE_ROOT}"
SCHEMA_HEAD_SHA="$(
  python3 - "${WORKSPACE_ROOT}" "${SCHEMAS_DIR}" "${SCHEMA_INVENTORY_PATH}" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path

workspace = Path(sys.argv[1])
root = Path(sys.argv[2])
inventory_path = Path(sys.argv[3])
canonical_workspace = workspace.resolve()
expected_root = canonical_workspace / "spec/schemas/chio-wire/v1"
if root.is_symlink() or root.resolve() != expected_root:
    raise SystemExit(
        "regen-types.sh: schema root contains a symlink or path alias: "
        f"{root}"
    )

git_inventory = subprocess.run(
    [
        "git",
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "spec/schemas/chio-wire/v1",
    ],
    cwd=workspace,
    check=True,
    stdout=subprocess.PIPE,
).stdout
if git_inventory and not git_inventory.endswith(b"\0"):
    raise SystemExit("regen-types.sh: Git schema inventory is not NUL terminated")
authoritative = []
for raw_path in git_inventory.split(b"\0"):
    if not raw_path:
        continue
    try:
        relative = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(
            "regen-types.sh: Git schema inventory path is not valid UTF-8"
        ) from error
    if any(unicodedata.category(character) == "Cc" for character in relative):
        raise SystemExit(
            "regen-types.sh: Git schema inventory path contains a control character: "
            f"{relative!r}"
        )
    segments = relative.split("/")
    if (
        not relative.startswith("spec/schemas/chio-wire/v1/")
        or any(not segment or segment in (".", "..") for segment in segments)
        or "\\" in relative
    ):
        raise SystemExit(
            "regen-types.sh: Git schema inventory path is not normalized: "
            f"{relative}"
        )
    if relative.endswith(".schema.json"):
        authoritative.append(relative)
authoritative.sort()
if len(authoritative) != len(set(authoritative)):
    raise SystemExit("regen-types.sh: Git schema inventory contains duplicate paths")

filesystem = []
for parent, directories, names in os.walk(root, followlinks=False):
    for directory in directories:
        path = Path(parent) / directory
        if path.is_symlink():
            raise SystemExit(
                "regen-types.sh: schema tree contains a symlink: "
                f"{path}"
            )
    for name in names:
        path = Path(parent) / name
        if path.is_symlink():
            raise SystemExit(
                "regen-types.sh: schema tree contains a symlink: "
                f"{path}"
            )
        if name.endswith(".schema.json"):
            if not path.is_file() or path.resolve() != expected_root / path.relative_to(root):
                raise SystemExit(
                    "regen-types.sh: schema inventory entry is not a real in-root file: "
                    f"{path}"
                )
            filesystem.append(path.relative_to(workspace).as_posix())
filesystem.sort()
if filesystem != authoritative:
    extra = next((path for path in filesystem if path not in set(authoritative)), "none")
    missing = next((path for path in authoritative if path not in set(filesystem)), "none")
    raise SystemExit(
        "regen-types.sh: filesystem schema tree differs from the tracked plus "
        f"unignored Git inventory (extra: {extra}; missing: {missing})"
    )

inventory_path.write_text(
    json.dumps(authoritative, ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
hasher = hashlib.sha256()
for rel in authoritative:
    path = workspace / rel
    hasher.update(rel.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(path.read_bytes())
    hasher.update(b"\0")
print(hasher.hexdigest())
PY
)"
if [[ -z "${SCHEMA_HEAD_SHA}" ]]; then
  SCHEMA_HEAD_SHA="unknown"
fi

SCHEMA_SHA_STAMP="${SCHEMA_HEAD_SHA}"

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
#   7. Conditional applicators (`if`/`then`/`else`) are dropped, and any
#      `allOf` member that carried only those keywords is pruned. OpenAPI
#      3.0 cannot express them and oapi-codegen v2.4.1 collapses a schema
#      that carries them to a bare `interface{}` alias (losing every
#      sibling property). The canonical JSON Schema still enforces them.
#   8. Cross-file `$ref`s (e.g. "../receipt/record.schema.json") are
#      rewritten to the local component the target file lifts to (e.g.
#      "#/components/schemas/ReceiptRecord").
#
# Component naming: `<DirPascal><FilePascal>` for top-level schemas (so
# `agent/heartbeat.schema.json` -> `AgentHeartbeat`,
# `kernel/heartbeat.schema.json` -> `KernelHeartbeat`,
# `trust-control/heartbeat.schema.json` -> `TrustControlHeartbeat`).
# Lifted `$defs` get `<TopComponentName><DefPascal>` suffixes so they don't
# collide across files (e.g. `CapabilityTokenChioScope`,
# `ReceiptRecordDecision`).
python3 - "${WORKSPACE_ROOT}" "${SCHEMAS_DIR}" "${OPENAPI_PATH}" "${SCHEMA_INVENTORY_PATH}" <<'PY'
import json
import copy
import os
import re
import sys
from pathlib import Path

workspace_root = Path(sys.argv[1]).resolve()
schemas_dir = Path(sys.argv[2])
output_path = Path(sys.argv[3])
inventory_path = Path(sys.argv[4])
expected_schema_root = workspace_root / "spec/schemas/chio-wire/v1"
if schemas_dir.is_symlink() or schemas_dir.resolve() != expected_schema_root:
    raise SystemExit(
        "regen-types.sh: schema root contains a symlink or path alias: "
        f"{schemas_dir}"
    )

# Pascalize a string segment (e.g. "tool_call_request" -> "ToolCallRequest",
# "trust-control" -> "TrustControl"). Splits on `_`, `-`, and `.` so all
# three repository conventions normalize the same way.
def pascalize(value: str) -> str:
    out = []
    for part in re.split(r"[^A-Za-z0-9]+", value):
        if not part:
            continue
        out.append(part[:1].upper() + part[1:])
    rendered = "".join(out)
    if not rendered:
        raise SystemExit(
            "regen-types.sh: schema name cannot form a safe component: "
            f"{value!r}"
        )
    return rendered


def collect_schema_files() -> list[Path]:
    filesystem: list[str] = []
    for root, directories, names in os.walk(schemas_dir, followlinks=False):
        for directory in directories:
            path = Path(root) / directory
            if path.is_symlink():
                raise SystemExit(
                    "regen-types.sh: schema tree contains a symlink: "
                    f"{path}"
                )
        for name in names:
            path = Path(root) / name
            if path.is_symlink():
                raise SystemExit(
                    "regen-types.sh: schema tree contains a symlink: "
                    f"{path}"
                )
            if name.endswith(".schema.json"):
                if not path.is_file() or path.resolve() != expected_schema_root / path.relative_to(schemas_dir):
                    raise SystemExit(
                        "regen-types.sh: schema inventory entry is not a real in-root file: "
                        f"{path}"
                    )
                filesystem.append(path.relative_to(workspace_root).as_posix())
    filesystem.sort()
    authoritative = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(authoritative, list) or not all(
        isinstance(path, str) for path in authoritative
    ):
        raise SystemExit("regen-types.sh: persisted schema inventory is invalid")
    if filesystem != authoritative:
        raise SystemExit(
            "regen-types.sh: schema inventory changed during generation"
        )
    return [workspace_root / relative for relative in authoritative]


component_sources: dict[str, str] = {}
current_schema_source = ""


def register_component(components: dict, name: str, schema, source: str):
    previous = component_sources.get(name)
    if previous is not None:
        raise SystemExit(
            "regen-types.sh: generated component name collision for "
            f"{name}: {previous} and {source}"
        )
    component_sources[name] = source
    components[name] = schema


# Recursively rewrite a schema node in-place to be OpenAPI 3.0 compatible.
# `lifts` is the dict (`components.schemas`) we lift `$defs` into; `prefix`
# is the component-name prefix used to disambiguate lifted definitions.
def rewrite(node, lifts: dict, prefix: str):
    if isinstance(node, dict):
        # OpenAPI 3.0 cannot represent a null-only JSON Schema. Preserve the
        # nullable shape for generated bindings and leave exact null-only
        # enforcement to the canonical JSON Schema validator.
        if node.get("type") == "null":
            node.pop("type")
            node["nullable"] = True

        # JSON Schema property whose value is the literal `true` is
        # represented in Python as the bool True after json.loads. Catch
        # that at the parent level (in the property loop below) - by the
        # time we recurse here, dicts are dicts.

        # `const: X` -> `enum: [X]`. Preserve type information so
        # oapi-codegen does not fall back to interface{} for literal
        # discriminator fields.
        if "const" in node:
            value = node.pop("const")
            node["enum"] = [value]
            if isinstance(value, str):
                node.setdefault("type", "string")
            elif isinstance(value, bool):
                node.setdefault("type", "boolean")
            elif isinstance(value, int):
                node.setdefault("type", "integer")
                node.setdefault("format", "int64")
            elif isinstance(value, float):
                node.setdefault("type", "number")

        # JSON Schema enum-only string aliases need an explicit type for
        # oapi-codegen to emit a string type instead of interface{}.
        if "enum" in node and "type" not in node:
            enum_values = node["enum"]
            if isinstance(enum_values, list) and enum_values:
                if all(isinstance(value, str) for value in enum_values):
                    node["type"] = "string"
                elif all(isinstance(value, bool) for value in enum_values):
                    node["type"] = "boolean"
                elif all(isinstance(value, int) for value in enum_values):
                    node["type"] = "integer"
                    node.setdefault("format", "int64")

        # oapi-codegen v2.4.1 emits invalid Go for singleton boolean enums
        # (for example `map[]`). Keep the boolean shape in Go generation;
        # the canonical JSON schema still enforces the singleton value.
        if "enum" in node:
            enum_values = node["enum"]
            if (
                isinstance(enum_values, list)
                and len(enum_values) == 1
                and isinstance(enum_values[0], bool)
            ):
                node.pop("enum", None)

        # Wire numeric counters and timestamps can exceed platform-width
        # Go int on 32-bit targets. Emit int64 consistently for integer
        # schemas unless a schema has already chosen a narrower format.
        if node.get("type") == "integer":
            node.setdefault("format", "int64")

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
                    inlined = copy.deepcopy(non_null[0])
                    # OpenAPI 3.0 ignores siblings of `$ref`, so emitting
                    # `{nullable: true, $ref: ...}` loses nullability in
                    # oapi-codegen and turns required nullable fields into
                    # non-pointer Go values. Resolve already-lifted local
                    # definitions into the field schema. For forward or
                    # cross-file references that are not available yet,
                    # retain the reference under `allOf`, where OpenAPI 3.0
                    # permits nullable to apply to the composed schema.
                    ref = inlined.get("$ref")
                    if isinstance(ref, str) and ref.startswith(
                        "#/components/schemas/"
                    ):
                        target_name = ref.removeprefix(
                            "#/components/schemas/"
                        )
                        target = lifts.get(target_name)
                        if isinstance(target, dict):
                            inlined = copy.deepcopy(target)
                        else:
                            node["allOf"] = [inlined]
                            inlined = None
                    del node["oneOf"]
                    # Merge the inlined member's keys into the parent. Skip
                    # `$schema`, `$id`, and `title` so the member's `title`
                    # does not overwrite the parent's display name in the
                    # generated Go field comment.
                    if inlined is not None:
                        for key, value in inlined.items():
                            if key in ("$schema", "$id", "title"):
                                continue
                            node[key] = value

        # Drop JSON Schema 2020-12 conditional applicators (`if`/`then`/
        # `else`). OpenAPI 3.0 has no equivalent, and oapi-codegen v2.4.1
        # cannot represent them: a schema that carries `if`/`then`/`else`
        # (directly or inside an `allOf` member) degrades to a bare
        # `interface{}` alias, dropping every sibling property. These
        # keywords are validation-only constraints (they add no fields to
        # the object shape), so removing them preserves the generated
        # struct while discarding constraints the generator cannot encode.
        # The canonical JSON Schema still enforces the conditionals.
        for conditional_key in ("if", "then", "else"):
            node.pop(conditional_key, None)

        # Prune `allOf` members that carry only the conditional keywords
        # removed above (or are already empty) so a residual `allOf: [{}]`
        # does not itself collapse the parent to `interface{}`. This runs
        # before the generic recursion descends into surviving members, so
        # it matches conditional-only members by their keys directly rather
        # than relying on them having been emptied first. If no composable
        # member survives, drop the `allOf` entirely and keep the parent's
        # own `type`/`properties`/`required`.
        if "allOf" in node and isinstance(node["allOf"], list):
            conditional_only = {"if", "then", "else"}

            def _is_droppable_member(member) -> bool:
                if not isinstance(member, dict):
                    return False
                if not member:
                    return True
                return set(member.keys()).issubset(conditional_only)

            surviving = [
                member
                for member in node["allOf"]
                if not _is_droppable_member(member)
            ]
            if surviving:
                node["allOf"] = surviving
            else:
                del node["allOf"]

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
                ref_remap[name] = (
                    "#/components/schemas/"
                    f"{_json_pointer_escape(lifted_name)}"
                )
            # Rewrite refs in every def body first, then recurse for the
            # other transformations (const, oneOf nullability, nested
            # $defs). Splitting the two passes keeps each idempotent.
            for name, def_schema in defs.items():
                _rewrite_refs(def_schema, ref_remap)
                rewrite(def_schema, lifts, prefix)
                lifted_name = f"{prefix}{pascalize(name)}"
                register_component(
                    lifts,
                    lifted_name,
                    def_schema,
                    f"{current_schema_source}#/$defs/{_json_pointer_escape(name)}",
                )
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

        # JSON Schema `oneOf` members can rely on parent-level property
        # definitions while tightening `required` per variant. OpenAPI
        # generators materialize each member independently, so copy any
        # parent-defined required properties into the member before codegen.
        # Without this, generated Go branch structs for verdict unions drop
        # required payload fields such as deny.reason/deny.guard.
        if (
            "properties" in node
            and isinstance(node["properties"], dict)
            and "oneOf" in node
            and isinstance(node["oneOf"], list)
        ):
            parent_properties = node["properties"]
            for member in node["oneOf"]:
                if not isinstance(member, dict):
                    continue
                required = member.get("required")
                if not isinstance(required, list):
                    continue
                properties = member.setdefault("properties", {})
                if not isinstance(properties, dict):
                    continue
                for key in required:
                    if (
                        isinstance(key, str)
                        and key not in properties
                        and key in parent_properties
                    ):
                        properties[key] = copy.deepcopy(parent_properties[key])

        # Recurse. Do not rewrite enum arrays: their values are data, not
        # schema nodes. In particular, boolean enums produced from
        # `const: true` must stay `[true]`; rewriting that list to `[{}]`
        # makes oapi-codegen emit invalid Go constants.
        for key, value in list(node.items()):
            if key in ("$defs", "enum"):
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


def _json_pointer_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _strict_percent_decode_fragment(fragment: str, reference: str) -> str:
    raw = fragment.encode("utf-8")
    decoded = bytearray()
    index = 0
    hexadecimal = b"0123456789abcdefABCDEF"
    while index < len(raw):
        byte = raw[index]
        if byte != ord("%"):
            decoded.append(byte)
            index += 1
            continue
        if (
            index + 2 >= len(raw)
            or raw[index + 1] not in hexadecimal
            or raw[index + 2] not in hexadecimal
        ):
            raise SystemExit(
                "regen-types.sh: schema $ref has an invalid percent escape: "
                f"{reference}"
            )
        decoded.append(int(raw[index + 1:index + 3], 16))
        index += 3
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(
            "regen-types.sh: schema $ref fragment is not valid UTF-8: "
            f"{reference}"
        ) from error


def _decode_json_pointer_token(token: str, reference: str) -> str:
    decoded = []
    index = 0
    while index < len(token):
        character = token[index]
        if character != "~":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in ("0", "1"):
            raise SystemExit(
                "regen-types.sh: schema $ref has an invalid JSON Pointer escape: "
                f"{reference}"
            )
        decoded.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(decoded)


def _json_pointer_tokens_from_fragment(fragment: str, reference: str) -> list[str]:
    if fragment == "":
        return []
    decoded_fragment = _strict_percent_decode_fragment(fragment, reference)
    if not decoded_fragment.startswith("/"):
        raise SystemExit(
            "regen-types.sh: schema $ref fragment is not a JSON Pointer: "
            f"{reference}"
        )
    raw_tokens = decoded_fragment[1:].split("/")
    return [
        _decode_json_pointer_token(token, reference)
        for token in raw_tokens
    ]


def _definition_name_from_fragment(fragment: str, reference: str):
    tokens = _json_pointer_tokens_from_fragment(fragment, reference)
    if not tokens or tokens[0] != "$defs":
        return None
    if len(tokens) != 2 or not tokens[1]:
        raise SystemExit(
            "regen-types.sh: unsupported $defs schema fragment: "
            f"{reference}"
        )
    return tokens[1]


def _component_pointer(
    relative_target: Path,
    root_component: str,
    pointer_tokens: list[str],
    reference: str,
) -> str:
    target_component = root_component
    remaining_tokens = pointer_tokens
    if pointer_tokens and pointer_tokens[0] == "$defs":
        if len(pointer_tokens) < 2 or not pointer_tokens[1]:
            raise SystemExit(
                "regen-types.sh: unsupported $defs schema fragment: "
                f"{reference}"
            )
        definition_name = pointer_tokens[1]
        target_definitions = schema_definition_inventory.get(relative_target)
        if target_definitions is None or definition_name not in target_definitions:
            raise SystemExit(
                "regen-types.sh: schema $ref targets an absent definition: "
                f"{reference}"
            )
        target_component += pascalize(definition_name)
        remaining_tokens = pointer_tokens[2:]
    output_tokens = ["components", "schemas", target_component]
    output_tokens.extend(remaining_tokens)
    return "#/" + "/".join(_json_pointer_escape(token) for token in output_tokens)


def _set_localized_ref(node: dict, localized_ref: str) -> None:
    siblings = {key: value for key, value in node.items() if key != "$ref"}
    if not siblings:
        node["$ref"] = localized_ref
        return
    existing_all_of = siblings.get("allOf")
    if existing_all_of is not None and not isinstance(existing_all_of, list):
        raise SystemExit("regen-types.sh: schema allOf must be an array")
    conjunction = [{"$ref": localized_ref}]
    if existing_all_of is not None:
        conjunction.extend(existing_all_of)
    siblings["allOf"] = conjunction
    node.clear()
    node.update(siblings)


def _has_uri_scheme(value: str) -> bool:
    scheme, separator, _ = value.partition(":")
    if (
        not separator
        or not scheme
        or not scheme[0].isascii()
        or not scheme[0].isalpha()
    ):
        return False
    return all(
        character.isascii()
        and (character.isalnum() or character in "+-.")
        for character in scheme
    )


def _verify_reference_helper_contract() -> None:
    if not _has_uri_scheme("a+safe:value") or _has_uri_scheme("é:value"):
        raise SystemExit("regen-types.sh: ASCII URI scheme self-test failed")
    if _definition_name_from_fragment("/$defs/a~1b", "fixture") != "a/b":
        raise SystemExit("regen-types.sh: JSON Pointer slash decoding self-test failed")
    if _definition_name_from_fragment("%2F$defs%2Fa~0b", "fixture") != "a~b":
        raise SystemExit("regen-types.sh: URI fragment decoding self-test failed")
    if _json_pointer_escape("Component/a~b") != "Component~1a~0b":
        raise SystemExit("regen-types.sh: JSON Pointer escaping self-test failed")
    if _component_pointer(
        Path("security/fixture.schema.json"),
        "SecurityFixture",
        ["properties", "a/b"],
        "fixture",
    ) != "#/components/schemas/SecurityFixture/properties/a~1b":
        raise SystemExit("regen-types.sh: arbitrary pointer localization self-test failed")
    sibling_fixture = {"$ref": "target.schema.json", "required": ["field"]}
    _set_localized_ref(
        sibling_fixture,
        "#/components/schemas/Target",
    )
    if (
        sibling_fixture.get("required") != ["field"]
        or sibling_fixture.get("allOf")
        != [{"$ref": "#/components/schemas/Target"}]
        or "$ref" in sibling_fixture
    ):
        raise SystemExit("regen-types.sh: $ref sibling preservation self-test failed")
    try:
        _definition_name_from_fragment("/$defs/a~2b", "fixture")
    except SystemExit:
        pass
    else:
        raise SystemExit("regen-types.sh: malformed JSON Pointer self-test failed")


_verify_reference_helper_contract()


def _rewrite_refs(node, mapping: dict[str, str]):
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            ref = node["$ref"]
            if ref.startswith("#"):
                definition_name = _definition_name_from_fragment(ref[1:], ref)
                if definition_name is not None:
                    localized_ref = mapping.get(definition_name)
                    if localized_ref is None:
                        raise SystemExit(
                            "regen-types.sh: local $ref targets an absent definition: "
                            f"{ref}"
                        )
                    _set_localized_ref(node, localized_ref)
        for value in list(node.values()):
            _rewrite_refs(value, mapping)
    elif isinstance(node, list):
        for item in node:
            _rewrite_refs(item, mapping)


# Map a schema file path (relative to schemas_dir) to its top-level
# OpenAPI component name using the same DirPascal + FilePascal convention
# the main loop applies. Keeps cross-file ref targets in sync with the
# lifted component names.
def component_name_for(rel_path: Path) -> str:
    parts = rel_path.parts
    if len(parts) < 2:
        raise SystemExit(
            f"regen-types.sh: unexpected schema layout: {rel_path}"
        )
    dir_segments = parts[:-1]
    file_stem = parts[-1].removesuffix(".schema.json")
    name_prefix = "".join(pascalize(seg) for seg in dir_segments)
    return name_prefix + pascalize(file_stem)


# Rewrite cross-file `$ref` strings (e.g. "../receipt/record.schema.json")
# into local component refs ("#/components/schemas/ReceiptRecord"). JSON
# Schema 2020-12 resolves a relative ref against the referencing file's own
# location; oapi-codegen has no notion of the original directory layout
# once every schema is flattened into components.schemas, so it would 404
# trying to open the on-disk path. Canonical Chio wire-schema URLs are mapped
# to that same local tree. Every other external reference is rejected before
# the generator can access the filesystem or network.
def _exact_canonical_schema_target(reference_path: str) -> Path:
    if "\\" in reference_path:
        raise SystemExit(
            "regen-types.sh: canonical Chio $ref uses a backslash separator: "
            f"{reference_path}"
        )
    segments = reference_path.split("/")
    if not segments or any(
        not segment or segment in (".", "..") for segment in segments
    ):
        raise SystemExit(
            "regen-types.sh: canonical Chio $ref is not normalized: "
            f"{reference_path}"
        )
    return Path(*segments)


def _normalize_relative_schema_target(base_relative: Path, reference_path: str) -> Path:
    if "\\" in reference_path or reference_path.startswith("/"):
        raise SystemExit(
            "regen-types.sh: relative schema $ref uses an absolute or backslash path: "
            f"{reference_path}"
        )
    segments = list(base_relative.parts)
    for segment in reference_path.split("/"):
        if not segment or segment == ".":
            raise SystemExit(
                "regen-types.sh: relative schema $ref is not normalized: "
                f"{reference_path}"
            )
        if segment == "..":
            if not segments:
                raise SystemExit(
                    "regen-types.sh: relative schema $ref escapes the schema root: "
                    f"{reference_path}"
                )
            segments.pop()
        else:
            segments.append(segment)
    if not segments:
        raise SystemExit(
            "regen-types.sh: relative schema $ref does not identify a schema: "
            f"{reference_path}"
        )
    return Path(*segments)


def _rewrite_cross_file_refs(
    node,
    base_dir: Path,
    source_relative: Path,
    source_component: str,
):
    if isinstance(node, dict):
        if "$ref" in node and not isinstance(node["$ref"], str):
            raise SystemExit("regen-types.sh: schema $ref must be a string")
        ref = node.get("$ref")
        for key, value in list(node.items()):
            if key != "$ref":
                _rewrite_cross_file_refs(
                    value,
                    base_dir,
                    source_relative,
                    source_component,
                )
        if not isinstance(ref, str):
            return
        canonical_prefix = "https://chio.world/schemas/chio-wire/v1/"
        if ref.startswith(canonical_prefix):
            path_ref, separator, fragment = ref.removeprefix(canonical_prefix).partition("#")
            target_relative = _exact_canonical_schema_target(path_ref)
        elif ref.startswith("#"):
            path_ref, separator, fragment = "", "#", ref[1:]
            target_relative = source_relative
        elif ref == "":
            path_ref, separator, fragment = "", "", ""
            target_relative = source_relative
        else:
            path_ref, separator, fragment = ref.partition("#")
            if (
                _has_uri_scheme(path_ref)
                or path_ref.startswith("//")
                or "\\" in path_ref
            ):
                raise SystemExit(
                    "regen-types.sh: external schema $ref is forbidden: "
                    f"{ref}"
                )
            target_relative = _normalize_relative_schema_target(
                base_dir.relative_to(schemas_dir), path_ref
            )
        if path_ref and not path_ref.endswith(".schema.json"):
            raise SystemExit(
                "regen-types.sh: cross-file $ref is not an inventoried schema: "
                f"{ref}"
            )
        if path_ref:
            rel_target = schema_relative_inventory.get(target_relative)
            if rel_target is None:
                raise SystemExit(
                    "regen-types.sh: cross-file $ref escapes or is absent from the schema inventory: "
                    f"{ref}"
                )
        else:
            rel_target = target_relative
        component_name = (
            source_component
            if rel_target == source_relative
            else component_name_for(rel_target)
        )
        pointer_tokens = (
            _json_pointer_tokens_from_fragment(fragment, ref)
            if separator
            else []
        )
        localized_ref = _component_pointer(
            rel_target,
            component_name,
            pointer_tokens,
            ref,
        )
        _set_localized_ref(node, localized_ref)
    elif isinstance(node, list):
        for item in node:
            _rewrite_cross_file_refs(
                item,
                base_dir,
                source_relative,
                source_component,
            )


schemas: dict = {}
schema_files = collect_schema_files()
schema_root = schemas_dir.resolve()
schema_inventory: dict[Path, Path] = {}
schema_relative_inventory: dict[Path, Path] = {}
schema_definition_inventory: dict[Path, set[str]] = {}
schema_documents: dict[Path, dict] = {}
for schema_path in schema_files:
    relative_path = schema_path.relative_to(schemas_dir)
    canonical_path = schema_path.resolve()
    if canonical_path != schema_root / relative_path:
        raise SystemExit(
            "regen-types.sh: schema inventory contains a symlink or path alias: "
            f"{schema_path}"
        )
    if canonical_path in schema_inventory:
        raise SystemExit(
            "regen-types.sh: schema inventory contains duplicate file identity: "
            f"{schema_path}"
        )
    schema_inventory[canonical_path] = relative_path
    if relative_path in schema_relative_inventory:
        raise SystemExit(
            "regen-types.sh: schema inventory contains duplicate relative path: "
            f"{relative_path}"
        )
    schema_relative_inventory[relative_path] = relative_path
    raw_schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(raw_schema, dict):
        raise SystemExit(
            "regen-types.sh: top-level schema must be an object: "
            f"{schema_path}"
        )
    definitions = raw_schema.get("$defs", {})
    if not isinstance(definitions, dict) or not all(
        isinstance(name, str) for name in definitions
    ):
        raise SystemExit(
            "regen-types.sh: schema $defs must be an object with string keys: "
            f"{schema_path}"
        )
    schema_definition_inventory[relative_path] = set(definitions)
    schema_documents[relative_path] = raw_schema

for path in schema_files:
    rel = path.relative_to(schemas_dir)
    current_schema_source = rel.as_posix()
    # Component name = DirPascal + FilePascal. The schemas tree is two
    # levels deep (subtree/file.schema.json), so we expect parts of length
    # 2. Defensive fallback for deeper trees: join all dir segments.
    component_name = component_name_for(rel)

    schema = schema_documents[rel]

    # Strip JSON Schema document keys; OpenAPI components.schemas is just
    # the schema body.
    schema.pop("$schema", None)
    schema.pop("$id", None)

    # Resolve cross-file refs against this file's directory before the
    # local `$defs`/`const`/`oneOf` rewrites run.
    _rewrite_cross_file_refs(schema, path.parent, rel, component_name)

    rewrite(schema, schemas, component_name)
    register_component(schemas, component_name, schema, current_schema_source)

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
# its output; gofmt runs again after the header is prepended below, since
# that edit lands after oapi-codegen has formatted the file.
#
# `compatibility.always-prefix-enum-values: true` forces oapi-codegen to
# emit fully-qualified enum constants (`<TypeName><Value>`) rather than
# bare value names. Without it, single-instance enums like
# `TrustControlAttestationWorkloadIdentityScheme = ["spiffe"]` materialize
# as a top-level constant named `Spiffe`, and several distinct enums share
# bare names that pollute and shadow the package namespace
# (e.g. `Allow`, `Attested`, `LeaderHandoff`).
CONFIG_PATH="${WORK_DIR}/oapi-codegen.config.yaml"
cat > "${CONFIG_PATH}" <<CONFIG_EOF
package: ${PACKAGE_NAME}
output: ${RAW_OUTPUT_PATH}
generate:
  models: true
output-options:
  skip-prune: true
compatibility:
  always-prefix-enum-values: true
CONFIG_EOF

echo "regen-types.sh: invoking oapi-codegen ${OAPI_CODEGEN_VERSION}" >&2
GOFLAGS="" GOTOOLCHAIN=auto go run \
  "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -config "${CONFIG_PATH}" \
  "${OPENAPI_PATH}"

if [[ ! -s "${RAW_OUTPUT_PATH}" ]]; then
  echo "regen-types.sh: oapi-codegen produced an empty file" >&2
  exit 3
fi

# --- prepend the chio header -----------------------------------------------
# Mirror the Rust generated header (crates/tooling/chio-spec-codegen/src/lib.rs
# GENERATED_HEADER) with Go-style `//` comments. The header lives BEFORE
# the oapi-codegen banner, which we keep as a secondary attribution stamp.
HEADER_FILE="${WORK_DIR}/header.txt"
cat > "${HEADER_FILE}" <<HEADER_EOF
// DO NOT EDIT - regenerate via 'sdks/go/chio-go-http/scripts/regen-types.sh'
// or 'cargo xtask codegen --lang go'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Schema content SHA-256: ${SCHEMA_SHA_STAMP}
// Tool:   oapi-codegen ${OAPI_CODEGEN_VERSION} (see xtask/codegen-tools.lock.toml)
//
// The Schema content SHA-256 is computed from each lex-sorted workspace-relative
// path, a NUL byte, the schema bytes, and a trailing NUL byte. It does not use
// git history, so the stamp is stable across rebases, shallow clones, and dirty
// working trees and matches the Python and TypeScript generated headers.
//
// Manual edits will be overwritten by the next regeneration; the
// spec-drift CI lane runs this script and 'git diff --exit-code'
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

PROTOCOL_VECTOR_INDEX="${WORKSPACE_ROOT}/tests/bindings/vectors/security/protocol-primitives/index.json"
if [[ ! -f "${PROTOCOL_VECTOR_INDEX}" ]]; then
  echo "regen-types.sh: protocol vector index ${PROTOCOL_VECTOR_INDEX} does not exist" >&2
  exit 2
fi
ACTIVE_DEFENSE_VECTOR_INDEX="${WORKSPACE_ROOT}/tests/bindings/vectors/security/active-defense/index.json"
if [[ ! -f "${ACTIVE_DEFENSE_VECTOR_INDEX}" ]]; then
  echo "regen-types.sh: active-defense vector index ${ACTIVE_DEFENSE_VECTOR_INDEX} does not exist" >&2
  exit 2
fi

python3 - \
  "${OUTPUT_FILE}" \
  "${PROTOCOL_VECTOR_INDEX}" \
  "${ACTIVE_DEFENSE_VECTOR_INDEX}" \
  "${SCHEMAS_DIR}/security" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
protocol_vector_index_path = Path(sys.argv[2])
active_defense_vector_index_path = Path(sys.argv[3])
active_defense_schema_dir = Path(sys.argv[4])
text = path.read_text(encoding="utf-8")


def replace_once(needle: str, replacement: str) -> None:
    global text
    if needle not in text:
        raise SystemExit(
            f"regen-types.sh: generated hardening pattern missing: {needle[:80]!r}"
        )
    text = text.replace(needle, replacement, 1)


replace_once(
    """import (
	"encoding/json"
	"fmt"
""",
    """import (
	"bytes"
	"encoding/json"
	"fmt"
""",
)


def active_defense_model_type(schema_filename: str) -> str:
    suffix = ".schema.json"
    if not schema_filename.endswith(suffix):
        raise SystemExit(
            "regen-types.sh: active-defense schema filename has an invalid suffix: "
            f"{schema_filename}"
        )
    stem = schema_filename[: -len(suffix)]
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", stem) if part]
    if not parts:
        raise SystemExit(
            "regen-types.sh: active-defense schema filename cannot form a Go model: "
            f"{schema_filename}"
        )
    return "Security" + "".join(part[:1].upper() + part[1:] for part in parts)


def generated_struct_block(model_type: str) -> str:
    signature = f"type {model_type} struct {{"
    if text.count(signature) != 1:
        raise SystemExit(
            "regen-types.sh: active-defense generated model ownership is not unique for "
            f"{model_type}"
        )
    start = text.index(signature)
    end = text.find("\n}\n", start)
    if end < 0:
        raise SystemExit(
            "regen-types.sh: active-defense generated model boundary is missing for "
            f"{model_type}"
        )
    return text[start : end + 2]


def harden_active_defense_optional_pointer_tags(
    model_type: str, schema: dict[str, object]
) -> None:
    global text
    required_value = schema.get("required", [])
    properties_value = schema.get("properties")
    if (
        not isinstance(required_value, list)
        or any(not isinstance(field, str) for field in required_value)
        or not isinstance(properties_value, dict)
    ):
        raise SystemExit(
            "regen-types.sh: active-defense schema has an invalid object contract for "
            f"{model_type}"
        )
    required = set(required_value)
    properties = set(properties_value)
    block = generated_struct_block(model_type)
    lines = block.splitlines(keepends=True)
    depth = 0
    active_field = None

    def harden_tag(line_index: int, field_name: str, is_pointer: bool) -> None:
        if not is_pointer:
            return
        match = re.search(r'`json:"([^",]+)(,omitempty)?"`', lines[line_index])
        if match is None:
            raise SystemExit(
                "regen-types.sh: active-defense pointer field is missing a JSON tag: "
                f"{model_type}.{field_name}"
            )
        property_name = match.group(1)
        if property_name not in properties:
            raise SystemExit(
                "regen-types.sh: active-defense generated property is absent from schema: "
                f"{model_type}.{property_name}"
            )
        has_omitempty = match.group(2) is not None
        is_required = property_name in required
        if is_required and has_omitempty:
            raise SystemExit(
                "regen-types.sh: required active-defense pointer uses omitempty: "
                f"{model_type}.{property_name}"
            )
        if not is_required and not has_omitempty:
            lines[line_index] = (
                lines[line_index][: match.start()]
                + f'`json:"{property_name},omitempty"`'
                + lines[line_index][match.end() :]
            )

    for line_index, line in enumerate(lines):
        depth_before = depth
        code = line.split("//", 1)[0]
        opens = code.count("{")
        closes = code.count("}")
        depth_after = depth_before + opens - closes
        if depth_before == 1 and not line.lstrip().startswith("//"):
            field_match = re.match(r"^\t([A-Z][A-Za-z0-9_]*)\s+(.+)$", line)
            if field_match is not None:
                field_name = field_match.group(1)
                field_type = field_match.group(2).lstrip()
                is_pointer = field_type.startswith("*")
                if "`json:" in line:
                    harden_tag(line_index, field_name, is_pointer)
                elif depth_after > depth_before:
                    active_field = (field_name, is_pointer)
        if active_field is not None and depth_before > 1 and depth_after == 1:
            field_name, is_pointer = active_field
            harden_tag(line_index, field_name, is_pointer)
            active_field = None
        depth = depth_after
    if depth != 0 or active_field is not None:
        raise SystemExit(
            "regen-types.sh: active-defense generated model structure is unbalanced for "
            f"{model_type}"
        )
    hardened = "".join(lines)
    if hardened != block:
        replace_once(block, hardened)


try:
    active_defense_vector_index = json.loads(
        active_defense_vector_index_path.read_text(encoding="utf-8")
    )
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(
        f"regen-types.sh: cannot read active-defense vector index: {error}"
    ) from error
positive_active_defense_vectors = active_defense_vector_index.get("positive")
if not isinstance(positive_active_defense_vectors, list) or len(
    positive_active_defense_vectors
) != 24:
    raise SystemExit(
        "regen-types.sh: active-defense positive inventory must contain 24 entries"
    )
active_defense_schema_filenames = []
seen_active_defense_ids = set()
seen_active_defense_files = set()
schema_id_prefix = "https://chio.world/schemas/chio-wire/v1/security/"
for entry in positive_active_defense_vectors:
    if not isinstance(entry, dict):
        raise SystemExit("regen-types.sh: active-defense positive entry is not an object")
    identifier = entry.get("id")
    relative_file = entry.get("file")
    schema_id = entry.get("schema_id")
    if (
        not isinstance(identifier, str)
        or not isinstance(relative_file, str)
        or not isinstance(schema_id, str)
        or not schema_id.startswith(schema_id_prefix)
    ):
        raise SystemExit("regen-types.sh: active-defense positive entry is invalid")
    if identifier in seen_active_defense_ids or relative_file in seen_active_defense_files:
        raise SystemExit("regen-types.sh: active-defense positive inventory contains duplicates")
    seen_active_defense_ids.add(identifier)
    seen_active_defense_files.add(relative_file)
    schema_filename = schema_id[len(schema_id_prefix) :]
    if "/" in schema_filename or not schema_filename.endswith(".schema.json"):
        raise SystemExit(
            "regen-types.sh: active-defense schema ID is not a direct security schema: "
            f"{schema_id}"
        )
    if schema_filename not in active_defense_schema_filenames:
        active_defense_schema_filenames.append(schema_filename)

for schema_filename in active_defense_schema_filenames:
    schema_path = active_defense_schema_dir / schema_filename
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(
            "regen-types.sh: cannot read active-defense schema "
            f"{schema_filename}: {error}"
        ) from error
    expected_schema_id = schema_id_prefix + schema_filename
    if not isinstance(schema, dict) or schema.get("$id") != expected_schema_id:
        raise SystemExit(
            "regen-types.sh: active-defense schema ID does not match its inventory path: "
            f"{schema_filename}"
        )
    harden_active_defense_optional_pointer_tags(
        active_defense_model_type(schema_filename), schema
    )

replace_once(
    """func (t *SecurityDetectorHealthReceiptBodyV1GroupBinding) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}
""",
    """func (t *SecurityDetectorHealthReceiptBodyV1GroupBinding) UnmarshalJSON(b []byte) error {
	if err := validateSecurityDetectorHealthGroupBinding(b); err != nil {
		return err
	}
	return t.union.UnmarshalJSON(b)
}

func validateSecurityDetectorHealthGroupBinding(b []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil || object == nil {
		if err != nil {
			return fmt.Errorf("detector health group binding must be an object: %w", err)
		}
		return fmt.Errorf("detector health group binding must be an object")
	}
	rawKind, found := object["kind"]
	if !found || rawJsonIsNull(rawKind) {
		return fmt.Errorf("detector health group binding missing kind")
	}
	var kind string
	if err := json.Unmarshal(rawKind, &kind); err != nil {
		return fmt.Errorf("error reading detector health group binding kind: %w", err)
	}
	switch kind {
	case "unresolved":
		return validateDetectorHealthAllowedFieldsRaw(
			object,
			"detector health unresolved group binding",
			map[string]struct{}{"kind": {}},
		)
	case "resolved":
		if err := validateDetectorHealthAllowedFieldsRaw(
			object,
			"detector health resolved group binding",
			map[string]struct{}{"kind": {}, "group_key_hash": {}},
		); err != nil {
			return err
		}
		rawHash, found := object["group_key_hash"]
		if !found || rawJsonIsNull(rawHash) {
			return fmt.Errorf("detector health resolved group binding missing group_key_hash")
		}
		var digest []int64
		if err := json.Unmarshal(rawHash, &digest); err != nil {
			return fmt.Errorf("error reading detector health group_key_hash: %w", err)
		}
		if len(digest) != 32 {
			return fmt.Errorf("detector health group_key_hash must contain 32 bytes")
		}
		nonzero := false
		for _, value := range digest {
			if value < 0 || value > 255 {
				return fmt.Errorf("detector health group_key_hash byte is outside 0 through 255")
			}
			if value != 0 {
				nonzero = true
			}
		}
		if !nonzero {
			return fmt.Errorf("detector health group_key_hash must not be all zero")
		}
		return nil
	default:
		return fmt.Errorf("unsupported detector health group binding kind %q", kind)
	}
}
""",
)
replace_once(
    """func (t SecurityDetectorHealthReceiptBodyV1GroupBinding) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}
""",
    """func (t SecurityDetectorHealthReceiptBodyV1GroupBinding) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := validateSecurityDetectorHealthGroupBinding(b); err != nil {
		return nil, err
	}
	return b, nil
}
""",
)
replace_once(
    """func (t *SecurityDetectorHealthReceiptBodyV1Watermark) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}
""",
    """func (t *SecurityDetectorHealthReceiptBodyV1Watermark) UnmarshalJSON(b []byte) error {
	if err := validateSecurityDetectorHealthWatermark(b); err != nil {
		return err
	}
	return t.union.UnmarshalJSON(b)
}

func validateSecurityDetectorHealthWatermark(b []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil || object == nil {
		if err != nil {
			return fmt.Errorf("detector health watermark must be an object: %w", err)
		}
		return fmt.Errorf("detector health watermark must be an object")
	}
	rawKind, found := object["kind"]
	if !found || rawJsonIsNull(rawKind) {
		return fmt.Errorf("detector health watermark missing kind")
	}
	var kind string
	if err := json.Unmarshal(rawKind, &kind); err != nil {
		return fmt.Errorf("error reading detector health watermark kind: %w", err)
	}
	switch kind {
	case "unknown":
		return validateDetectorHealthAllowedFieldsRaw(
			object,
			"detector health unknown watermark",
			map[string]struct{}{"kind": {}},
		)
	case "committed":
		if err := validateDetectorHealthAllowedFieldsRaw(
			object,
			"detector health committed watermark",
			map[string]struct{}{"kind": {}, "unix_ms": {}},
		); err != nil {
			return err
		}
		rawUnixMs, found := object["unix_ms"]
		if !found || rawJsonIsNull(rawUnixMs) {
			return fmt.Errorf("detector health committed watermark missing unix_ms")
		}
		var unixMs int64
		if err := json.Unmarshal(rawUnixMs, &unixMs); err != nil {
			return fmt.Errorf("error reading detector health watermark unix_ms: %w", err)
		}
		if unixMs < 1 || unixMs > 9007199254740991 {
			return fmt.Errorf("detector health watermark unix_ms is outside the portable range")
		}
		return nil
	case "contradictory":
		if err := validateDetectorHealthAllowedFieldsRaw(
			object,
			"detector health contradictory watermark",
			map[string]struct{}{"kind": {}, "claimed_unix_ms": {}},
		); err != nil {
			return err
		}
		rawClaimedUnixMs, found := object["claimed_unix_ms"]
		if !found || rawJsonIsNull(rawClaimedUnixMs) {
			return fmt.Errorf("detector health contradictory watermark missing claimed_unix_ms")
		}
		var claimedUnixMs string
		if err := json.Unmarshal(rawClaimedUnixMs, &claimedUnixMs); err != nil {
			return fmt.Errorf("error reading detector health watermark claimed_unix_ms: %w", err)
		}
		if !validateDetectorHealthCanonicalU64String(claimedUnixMs) {
			return fmt.Errorf("detector health claimed_unix_ms is not a canonical u64")
		}
		return nil
	default:
		return fmt.Errorf("unsupported detector health watermark kind %q", kind)
	}
}

func validateDetectorHealthCanonicalU64String(value string) bool {
	if value == "" || len(value) > 20 || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return len(value) < 20 || value <= "18446744073709551615"
}

func validateDetectorHealthAllowedFieldsRaw(
	object map[string]json.RawMessage,
	context string,
	allowed map[string]struct{},
) error {
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s contains unknown field %q", context, key)
		}
	}
	return nil
}
""",
)
replace_once(
    """func (t SecurityDetectorHealthReceiptBodyV1Watermark) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}
""",
    """func (t SecurityDetectorHealthReceiptBodyV1Watermark) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := validateSecurityDetectorHealthWatermark(b); err != nil {
		return nil, err
	}
	return b, nil
}
""",
)


def harden_detector_health_union_constructors(
    union_name: str, variant_count: int, validator: str
) -> None:
    for index in range(variant_count):
        variant = f"{union_name}{index}"
        replace_once(
            f"""func (t *{union_name}) From{variant}(v {variant}) error {{
	b, err := json.Marshal(v)
	t.union = b
	return err
}}
""",
            f"""func (t *{union_name}) From{variant}(v {variant}) error {{
	b, err := json.Marshal(v)
	if err != nil {{
		return err
	}}
	if err := {validator}(b); err != nil {{
		return err
	}}
	t.union = b
	return nil
}}
""",
        )
        replace_once(
            f"""func (t *{union_name}) Merge{variant}(v {variant}) error {{
	b, err := json.Marshal(v)
	if err != nil {{
		return err
	}}

	merged, err := runtime.JSONMerge(t.union, b)
	t.union = merged
	return err
}}
""",
            f"""func (t *{union_name}) Merge{variant}(v {variant}) error {{
	b, err := json.Marshal(v)
	if err != nil {{
		return err
	}}
	if err := {validator}(b); err != nil {{
		return err
	}}
	merged, err := runtime.JSONMerge(t.union, b)
	if err != nil {{
		return err
	}}
	if err := {validator}(merged); err != nil {{
		return err
	}}
	t.union = merged
	return nil
}}
""",
        )


harden_detector_health_union_constructors(
    "SecurityDetectorHealthReceiptBodyV1GroupBinding",
    2,
    "validateSecurityDetectorHealthGroupBinding",
)
harden_detector_health_union_constructors(
    "SecurityDetectorHealthReceiptBodyV1Watermark",
    3,
    "validateSecurityDetectorHealthWatermark",
)


replace_once(
    """// AsSecurityDetectorHealthReceiptBodyV1GroupBinding0 returns the union data inside the SecurityDetectorHealthReceiptBodyV1GroupBinding as a SecurityDetectorHealthReceiptBodyV1GroupBinding0
""",
    """func (t SecurityDetectorHealthReceiptBodyV1) MarshalJSON() ([]byte, error) {
	type detectorHealthReceiptAlias SecurityDetectorHealthReceiptBodyV1
	b, err := json.Marshal(detectorHealthReceiptAlias(t))
	if err != nil {
		return nil, fmt.Errorf("invalid detector health receipt: %w", err)
	}
	var validated SecurityDetectorHealthReceiptBodyV1
	if err := validated.UnmarshalJSON(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (t *SecurityDetectorHealthReceiptBodyV1) UnmarshalJSON(b []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil || object == nil {
		if err != nil {
			return fmt.Errorf("detector health receipt must be an object: %w", err)
		}
		return fmt.Errorf("detector health receipt must be an object")
	}
	if err := validateDetectorHealthAllowedFieldsRaw(
		object,
		"detector health receipt",
		map[string]struct{}{
			"header": {}, "policy": {}, "rule_id": {}, "rule_version_hash": {},
			"group_binding": {}, "event_id": {}, "health_kind": {},
			"watermark": {}, "evidence_hash": {},
		},
	); err != nil {
		return err
	}
	for _, field := range []string{
		"header", "policy", "rule_id", "rule_version_hash", "group_binding",
		"event_id", "health_kind", "watermark", "evidence_hash",
	} {
		if raw, found := object[field]; !found || rawJsonIsNull(raw) {
			return fmt.Errorf("detector health receipt missing %s", field)
		}
	}
	type detectorHealthReceiptAlias SecurityDetectorHealthReceiptBodyV1
	var decoded detectorHealthReceiptAlias
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid detector health receipt: %w", err)
	}
	observed := int64(decoded.Header.OccurredAtUnixMs)
	if observed < 1 || observed > 9007199254740991 {
		return fmt.Errorf("detector health occurred_at_unix_ms is outside the portable range")
	}
	if err := validateDetectorHealthDigest(decoded.EvidenceHash, "evidence_hash"); err != nil {
		return err
	}
	if err := validateDetectorHealthDigest(decoded.Policy.PolicyHash, "policy_hash"); err != nil {
		return err
	}
	if err := validateDetectorHealthDigest(decoded.RuleVersionHash, "rule_version_hash"); err != nil {
		return err
	}
	switch decoded.HealthKind {
	case SecurityDetectorHealthReceiptBodyV1HealthKindCorruptEvent,
		SecurityDetectorHealthReceiptBodyV1HealthKindCorruptState,
		SecurityDetectorHealthReceiptBodyV1HealthKindStateOverflow,
		SecurityDetectorHealthReceiptBodyV1HealthKindStoreConflict,
		SecurityDetectorHealthReceiptBodyV1HealthKindStoreUnavailable,
		SecurityDetectorHealthReceiptBodyV1HealthKindTruncatedScan:
	default:
		return fmt.Errorf("unsupported detector health kind %q", decoded.HealthKind)
	}
	groupKind, err := detectorHealthTaggedKind(object["group_binding"], "group binding")
	if err != nil {
		return err
	}
	watermarkKind, err := detectorHealthTaggedKind(object["watermark"], "watermark")
	if err != nil {
		return err
	}
	if groupKind == "unresolved" && watermarkKind != "unknown" {
		return fmt.Errorf("unresolved detector group cannot assert watermark knowledge")
	}
	switch watermarkKind {
	case "committed":
		var watermark struct {
			UnixMs int64 `json:"unix_ms"`
		}
		if err := json.Unmarshal(object["watermark"], &watermark); err != nil {
			return fmt.Errorf("invalid committed detector watermark: %w", err)
		}
		if watermark.UnixMs > observed {
			return fmt.Errorf("committed detector watermark is after the observation")
		}
	case "contradictory":
		if groupKind != "resolved" || decoded.HealthKind != SecurityDetectorHealthReceiptBodyV1HealthKindCorruptState {
			return fmt.Errorf("contradictory detector watermark requires resolved corrupt state")
		}
		var watermark struct {
			ClaimedUnixMs string `json:"claimed_unix_ms"`
		}
		if err := json.Unmarshal(object["watermark"], &watermark); err != nil {
			return fmt.Errorf("invalid contradictory detector watermark: %w", err)
		}
		observedDecimal := fmt.Sprintf("%d", observed)
		if watermark.ClaimedUnixMs != "0" &&
			!detectorHealthDecimalGreaterThan(watermark.ClaimedUnixMs, observedDecimal) &&
			!detectorHealthDecimalGreaterThan(watermark.ClaimedUnixMs, "9007199254740991") {
			return fmt.Errorf("contradictory detector watermark carries a valid committed value")
		}
	}
	*t = SecurityDetectorHealthReceiptBodyV1(decoded)
	return nil
}

func detectorHealthTaggedKind(raw json.RawMessage, context string) (string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		if err != nil {
			return "", fmt.Errorf("detector health %s must be an object: %w", context, err)
		}
		return "", fmt.Errorf("detector health %s must be an object", context)
	}
	rawKind, found := object["kind"]
	if !found || rawJsonIsNull(rawKind) {
		return "", fmt.Errorf("detector health %s missing kind", context)
	}
	var kind string
	if err := json.Unmarshal(rawKind, &kind); err != nil {
		return "", fmt.Errorf("invalid detector health %s kind: %w", context, err)
	}
	return kind, nil
}

func detectorHealthDecimalGreaterThan(left string, right string) bool {
	return len(left) > len(right) || (len(left) == len(right) && left > right)
}

func validateDetectorHealthDigest(digest []int64, field string) error {
	if len(digest) != 32 {
		return fmt.Errorf("detector health %s must contain 32 bytes", field)
	}
	nonzero := false
	for _, value := range digest {
		if value < 0 || value > 255 {
			return fmt.Errorf("detector health %s byte is outside 0 through 255", field)
		}
		if value != 0 {
			nonzero = true
		}
	}
	if !nonzero {
		return fmt.Errorf("detector health %s must not be all zero", field)
	}
	return nil
}

// AsSecurityDetectorHealthReceiptBodyV1GroupBinding0 returns the union data inside the SecurityDetectorHealthReceiptBodyV1GroupBinding as a SecurityDetectorHealthReceiptBodyV1GroupBinding0
""",
)


ACTIVE_DEFENSE_RECEIPT_VALIDATIONS = (
    (
        "SecurityFlowDenialReceiptBodyV1",
        """return validateActiveDefensePortablePositiveInteger(
		int64(value.Header.OccurredAtUnixMs),
		"flow denial occurred_at_unix_ms",
	)""",
    ),
    (
        "SecurityDeclassificationConsumptionReceiptBodyV1",
        """return validateActiveDefensePortablePositiveInteger(
		int64(value.Header.OccurredAtUnixMs),
		"declassification consumption occurred_at_unix_ms",
	)""",
    ),
    (
        "SecurityDeclassificationOutcomeReceiptBodyV1",
        """return validateActiveDefensePortablePositiveInteger(
		int64(value.Header.OccurredAtUnixMs),
		"declassification outcome occurred_at_unix_ms",
	)""",
    ),
    (
        "SecurityTripwireObservationReceiptBodyV1",
        """return validateActiveDefensePortablePositiveInteger(
		int64(value.Header.OccurredAtUnixMs),
		"tripwire observation occurred_at_unix_ms",
	)""",
    ),
    (
        "SecurityCorrelatedFindingReceiptBodyV1",
        """observedAt := int64(value.Header.OccurredAtUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		observedAt,
		"correlated finding occurred_at_unix_ms",
	); err != nil {
		return err
	}
	first := int64(value.FirstEventTimeUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		first,
		"correlated finding first_event_time_unix_ms",
	); err != nil {
		return err
	}
	last := int64(value.LastEventTimeUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		last,
		"correlated finding last_event_time_unix_ms",
	); err != nil {
		return err
	}
	if first > last || last > observedAt {
		return fmt.Errorf("correlated finding event times are out of order")
	}
	return nil""",
    ),
    (
        "SecurityResponsePlanReceiptBodyV1",
        """observedAt := int64(value.Header.OccurredAtUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		observedAt,
		"response plan occurred_at_unix_ms",
	); err != nil {
		return err
	}
	expiresAt := int64(value.Response.PlanExpiresAtUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		expiresAt,
		"response plan plan_expires_at_unix_ms",
	); err != nil {
		return err
	}
	createdAt := int64(value.PlanCreatedAtUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		createdAt,
		"response plan plan_created_at_unix_ms",
	); err != nil {
		return err
	}
	if createdAt > observedAt || createdAt >= expiresAt {
		return fmt.Errorf("response plan times are out of order")
	}
	return nil""",
    ),
    (
        "SecurityResponseStateTransitionReceiptBodyV1",
        """if err := validateActiveDefenseResponseReceiptTimes(
		int64(value.Header.OccurredAtUnixMs),
		int64(value.Response.PlanExpiresAtUnixMs),
		"response state transition",
	); err != nil {
		return err
	}
	if err := validateActiveDefensePortablePositiveInteger(
		value.Generation,
		"response state transition generation",
	); err != nil {
		return err
	}
	if value.ApplyingLeaseExpiresAtUnixMs != nil {
		return validateActiveDefensePortablePositiveInteger(
			*value.ApplyingLeaseExpiresAtUnixMs,
			"response state transition applying_lease_expires_at_unix_ms",
		)
	}
	return nil""",
    ),
    (
        "SecurityEffectTransitionReceiptBodyV1",
        """if err := validateActiveDefenseResponseReceiptTimes(
		int64(value.Header.OccurredAtUnixMs),
		int64(value.Response.PlanExpiresAtUnixMs),
		"effect transition",
	); err != nil {
		return err
	}
	if err := validateActiveDefensePortablePositiveInteger(
		value.Generation,
		"effect transition generation",
	); err != nil {
		return err
	}
	return validateActiveDefensePortablePositiveInteger(
		value.SchedulerFencingToken,
		"effect transition scheduler_fencing_token",
	)""",
    ),
    (
        "SecurityResponseCompletionReceiptBodyV1",
        """return validateActiveDefenseResponseReceiptTimes(
		int64(value.Header.OccurredAtUnixMs),
		int64(value.Response.PlanExpiresAtUnixMs),
		"response completion",
	)""",
    ),
    (
        "SecurityLiftRollbackCompletionReceiptBodyV1",
        """return validateActiveDefenseResponseReceiptTimes(
		int64(value.Header.OccurredAtUnixMs),
		int64(value.Response.PlanExpiresAtUnixMs),
		"lift rollback completion",
	)""",
    ),
    (
        "SecuritySchedulerHealthReceiptBodyV1",
        """observedAt := int64(value.Header.OccurredAtUnixMs)
	if err := validateActiveDefenseResponseReceiptTimes(
		observedAt,
		int64(value.Response.PlanExpiresAtUnixMs),
		"scheduler health",
	); err != nil {
		return err
	}
	firstFailureAt := int64(value.FirstFailureAtUnixMs)
	if err := validateActiveDefensePortablePositiveInteger(
		firstFailureAt,
		"scheduler health first_failure_at_unix_ms",
	); err != nil {
		return err
	}
	if firstFailureAt > observedAt {
		return fmt.Errorf("scheduler health first failure is after observation")
	}
	if value.Attempts < 1 || value.Attempts > 4294967295 {
		return fmt.Errorf("scheduler health attempts is outside the unsigned 32-bit range")
	}
	return validateActiveDefensePortablePositiveInteger(
		value.SchedulerFencingToken,
		"scheduler health scheduler_fencing_token",
	)""",
    ),
)

active_defense_receipt_methods = """const maxActiveDefensePortableInteger int64 = 9007199254740991

func validateActiveDefensePortablePositiveInteger(value int64, field string) error {
	if value < 1 || value > maxActiveDefensePortableInteger {
		return fmt.Errorf("%s is outside the portable positive integer range", field)
	}
	return nil
}

func validateActiveDefenseResponseReceiptTimes(
	observedAt int64,
	expiresAt int64,
	context string,
) error {
	if err := validateActiveDefensePortablePositiveInteger(
		observedAt,
		context+" occurred_at_unix_ms",
	); err != nil {
		return err
	}
	return validateActiveDefensePortablePositiveInteger(
		expiresAt,
		context+" plan_expires_at_unix_ms",
	)
}

"""
active_defense_receipt_codec_template = """func (t __TYPE__) MarshalJSON() ([]byte, error) {
	if err := validate__TYPE__(&t); err != nil {
		return nil, err
	}
	type activeDefenseReceiptAlias __TYPE__
	return json.Marshal(activeDefenseReceiptAlias(t))
}

func (t *__TYPE__) UnmarshalJSON(b []byte) error {
	if t == nil {
		return fmt.Errorf("cannot decode __TYPE__ into a nil receiver")
	}
	if !json.Valid(b) {
		return fmt.Errorf("invalid __TYPE__ JSON")
	}
	type activeDefenseReceiptAlias __TYPE__
	var decoded activeDefenseReceiptAlias
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid __TYPE__: %w", err)
	}
	candidate := __TYPE__(decoded)
	if err := validate__TYPE__(&candidate); err != nil {
		return err
	}
	*t = candidate
	return nil
}

"""
active_defense_receipt_validation_template = """func validate__TYPE__(value *__TYPE__) error {
	__VALIDATION__
}

"""
generator_owned_active_defense_receipts = []
for receipt_type, validation in ACTIVE_DEFENSE_RECEIPT_VALIDATIONS:
    marshal_signature = f"func (t {receipt_type}) MarshalJSON() ([]byte, error) {{"
    unmarshal_signature = f"func (t *{receipt_type}) UnmarshalJSON(b []byte) error {{"
    generator_owns_marshal = marshal_signature in text
    generator_owns_unmarshal = unmarshal_signature in text
    if generator_owns_marshal != generator_owns_unmarshal:
        raise SystemExit(
            "regen-types.sh: oapi-codegen emitted only one JSON codec method for "
            f"{receipt_type}"
        )
    if generator_owns_marshal:
        generator_owned_active_defense_receipts.append(receipt_type)
    else:
        active_defense_receipt_methods += active_defense_receipt_codec_template.replace(
            "__TYPE__", receipt_type
        )
    active_defense_receipt_methods += (
        active_defense_receipt_validation_template.replace("__TYPE__", receipt_type)
        .replace("__VALIDATION__", validation)
    )

replace_once(
    """// AsSecurityDetectorHealthReceiptBodyV1GroupBinding0 returns the union data inside the SecurityDetectorHealthReceiptBodyV1GroupBinding as a SecurityDetectorHealthReceiptBodyV1GroupBinding0
""",
    active_defense_receipt_methods
    + """// AsSecurityDetectorHealthReceiptBodyV1GroupBinding0 returns the union data inside the SecurityDetectorHealthReceiptBodyV1GroupBinding as a SecurityDetectorHealthReceiptBodyV1GroupBinding0
""",
)


def harden_generator_owned_active_defense_receipt(receipt_type: str) -> None:
    global text
    marshal_prefix = (
        f"func (t {receipt_type}) MarshalJSON() ([]byte, error) {{\n"
        "\tb, err := t.union.MarshalJSON()\n"
    )
    replace_once(
        marshal_prefix,
        f"func (t {receipt_type}) MarshalJSON() ([]byte, error) {{\n"
        f"\tif err := validate{receipt_type}(&t); err != nil {{\n"
        "\t\treturn nil, err\n"
        "\t}\n"
        "\tb, err := t.union.MarshalJSON()\n",
    )
    unmarshal_prefix = (
        f"func (t *{receipt_type}) UnmarshalJSON(b []byte) error {{\n"
        "\terr := t.union.UnmarshalJSON(b)\n"
    )
    replace_once(
        unmarshal_prefix,
        f"func (t *{receipt_type}) UnmarshalJSON(b []byte) error {{\n"
        "\tif t == nil {\n"
        f"\t\treturn fmt.Errorf(\"cannot decode {receipt_type} into a nil receiver\")\n"
        "\t}\n"
        f"\ttype strictActiveDefenseReceiptAlias {receipt_type}\n"
        "\tvar strict strictActiveDefenseReceiptAlias\n"
        "\tdecoder := json.NewDecoder(bytes.NewReader(b))\n"
        "\tdecoder.DisallowUnknownFields()\n"
        "\tif err := decoder.Decode(&strict); err != nil {\n"
        f"\t\treturn fmt.Errorf(\"invalid {receipt_type}: %w\", err)\n"
        "\t}\n"
        "\terr := t.union.UnmarshalJSON(b)\n",
    )
    method_start = text.find(
        f"func (t *{receipt_type}) UnmarshalJSON(b []byte) error {{"
    )
    next_method = text.find(f"\n// As{receipt_type}", method_start)
    if method_start < 0 or next_method < 0:
        raise SystemExit(
            "regen-types.sh: generated union receipt codec boundary missing for "
            f"{receipt_type}"
        )
    method = text[method_start:next_method]
    method_tail = "\n\treturn err\n}\n"
    if not method.endswith(method_tail):
        raise SystemExit(
            "regen-types.sh: generated union receipt decoder tail changed for "
            f"{receipt_type}"
        )
    hardened_tail = (
        "\n\tif err != nil {\n"
        "\t\treturn err\n"
        "\t}\n"
        f"\treturn validate{receipt_type}(t)\n"
        "}\n"
    )
    method = method[: -len(method_tail)] + hardened_tail
    text = text[:method_start] + method + text[next_method:]


for receipt_type in generator_owned_active_defense_receipts:
    harden_generator_owned_active_defense_receipt(receipt_type)

for receipt_type, _ in ACTIVE_DEFENSE_RECEIPT_VALIDATIONS:
    marshal_signature = f"func (t {receipt_type}) MarshalJSON() ([]byte, error) {{"
    unmarshal_signature = f"func (t *{receipt_type}) UnmarshalJSON(b []byte) error {{"
    if text.count(marshal_signature) != 1 or text.count(unmarshal_signature) != 1:
        raise SystemExit(
            "regen-types.sh: active-defense receipt JSON codec ownership is not unique for "
            f"{receipt_type}"
        )


PROTOCOL_VECTOR_MODEL_TYPES = (
    ("aggregate_root_commitment", "CapabilityAggregateBudgetRootCommitment"),
    ("aggregate_root_binding_body", "CapabilityAggregateBudgetRootBindingBody"),
    ("aggregate_root_binding", "CapabilityAggregateBudgetRootBinding"),
    ("aggregate_invocation_budget", "CapabilityAggregateInvocationBudget"),
    ("capability_list_delegation_family", "KernelCapabilityList"),
    ("aggregate_family_preservation", "CapabilityAggregateFamilyPreservationEvidence"),
    ("threshold_proposal_body", "CapabilityThresholdApprovalProposalBody"),
    ("threshold_proposal", "CapabilityThresholdApprovalProposal"),
    ("governed_token_body_alice", "CapabilityGovernedApprovalTokenBody"),
    ("governed_token_alice", "CapabilityGovernedApprovalToken"),
    ("governed_token_body_bob", "CapabilityGovernedApprovalTokenBody"),
    ("governed_token_bob", "CapabilityGovernedApprovalToken"),
    ("tool_call_request_singular_approval", "AgentToolCallRequest"),
    ("tool_call_request_list_approval", "AgentToolCallRequest"),
    ("verified_approval_set", "CapabilityVerifiedApprovalSet"),
    ("admission_request_binding", "TrustControlAdmissionRequestBinding"),
    ("budget_admission_evidence", "TrustControlBudgetInvocationAdmissionEvidence"),
    ("admission_capture_metadata", "TrustControlAdmissionCaptureMetadata"),
)
if len(PROTOCOL_VECTOR_MODEL_TYPES) != 18:
    raise SystemExit("regen-types.sh: protocol Go model inventory must contain 18 entries")
mapped_protocol_ids = [identifier for identifier, _ in PROTOCOL_VECTOR_MODEL_TYPES]
if len(set(mapped_protocol_ids)) != len(mapped_protocol_ids):
    raise SystemExit("regen-types.sh: protocol Go model inventory contains duplicate IDs")
try:
    protocol_vector_index = json.loads(
        protocol_vector_index_path.read_text(encoding="utf-8")
    )
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(
        f"regen-types.sh: cannot read protocol vector index: {error}"
    ) from error
positive_protocol_vectors = protocol_vector_index.get("positive")
if not isinstance(positive_protocol_vectors, list):
    raise SystemExit("regen-types.sh: protocol vector index positive inventory is not a list")
indexed_protocol_ids = []
for entry in positive_protocol_vectors:
    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
        raise SystemExit("regen-types.sh: protocol vector index contains an invalid positive entry")
    indexed_protocol_ids.append(entry["id"])
if indexed_protocol_ids != mapped_protocol_ids:
    raise SystemExit(
        "regen-types.sh: protocol Go model inventory does not exactly cover the "
        "ordered positive vector inventory"
    )

protocol_model_types = tuple(
    dict.fromkeys(model_type for _, model_type in PROTOCOL_VECTOR_MODEL_TYPES)
)
generator_owned_protocol_models = []
for model_type in protocol_model_types:
    type_signature = f"type {model_type} struct {{"
    if text.count(type_signature) != 1:
        raise SystemExit(
            "regen-types.sh: protocol Go model ownership is not unique for "
            f"{model_type}"
        )
    marshal_signature = f"func (t {model_type}) MarshalJSON() ([]byte, error) {{"
    unmarshal_signature = f"func (t *{model_type}) UnmarshalJSON(b []byte) error {{"
    marshal_count = text.count(marshal_signature)
    unmarshal_count = text.count(unmarshal_signature)
    if marshal_count != unmarshal_count or marshal_count > 1:
        raise SystemExit(
            "regen-types.sh: protocol Go model JSON codec ownership is inconsistent for "
            f"{model_type}"
        )
    if unmarshal_count == 1:
        generator_owned_protocol_models.append(model_type)


def harden_generator_owned_protocol_model(model_type: str) -> None:
    unmarshal_prefix = f"func (t *{model_type}) UnmarshalJSON(b []byte) error {{\n"
    replace_once(
        unmarshal_prefix,
        unmarshal_prefix
        + "\tif t == nil {\n"
        + f"\t\treturn fmt.Errorf(\"cannot decode {model_type} into a nil receiver\")\n"
        + "\t}\n"
        + f"\ttype strictProtocolModelAlias {model_type}\n"
        + "\tvar strict strictProtocolModelAlias\n"
        + "\tdecoder := json.NewDecoder(bytes.NewReader(b))\n"
        + "\tdecoder.DisallowUnknownFields()\n"
        + "\tif err := decoder.Decode(&strict); err != nil {\n"
        + f"\t\treturn fmt.Errorf(\"invalid {model_type}: %w\", err)\n"
        + "\t}\n",
    )


for model_type in generator_owned_protocol_models:
    harden_generator_owned_protocol_model(model_type)

for identifier, model_type in PROTOCOL_VECTOR_MODEL_TYPES:
    unmarshal_signature = f"func (t *{model_type}) UnmarshalJSON(b []byte) error {{"
    if model_type in generator_owned_protocol_models:
        strict_marker = f"type strictProtocolModelAlias {model_type}"
        if text.count(unmarshal_signature) != 1 or text.count(strict_marker) != 1:
            raise SystemExit(
                "regen-types.sh: strict protocol union decoder is missing for "
                f"{identifier} ({model_type})"
            )


replace_once(
    """\tif t.Result != nil {
\t\tobject["result"], err = json.Marshal(t.Result)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'result': %w", err)
\t\t}
\t}
\tb, err = json.Marshal(object)
\treturn b, err
}
""",
    """\tif t.Result != nil {
\t\tobject["result"], err = json.Marshal(t.Result)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'result': %w", err)
\t\t}
\t}
\tif err := validateJsonrpcResponseObject(object); err != nil {
\t\treturn nil, err
\t}
\tb, err = json.Marshal(object)
\treturn b, err
}
""",
)
replace_once(
    """func (t *JsonrpcNotification_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

// AsJsonrpcRequestId0 returns the union data inside the JsonrpcRequest_Id as a JsonrpcRequestId0
""",
    """func (t *JsonrpcNotification_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

func (t JsonrpcNotification) MarshalJSON() ([]byte, error) {
\tobject := make(map[string]json.RawMessage)
\tvar err error

\tobject["jsonrpc"], err = json.Marshal(t.Jsonrpc)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'jsonrpc': %w", err)
\t}

\tobject["method"], err = json.Marshal(t.Method)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'method': %w", err)
\t}

\tif t.Params != nil {
\t\tobject["params"], err = json.Marshal(t.Params)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'params': %w", err)
\t\t}
\t}

\tif err := validateJsonrpcNotificationObject(object); err != nil {
\t\treturn nil, err
\t}
\treturn json.Marshal(object)
}

func (t *JsonrpcNotification) UnmarshalJSON(b []byte) error {
\tobject := make(map[string]json.RawMessage)
\tif err := json.Unmarshal(b, &object); err != nil {
\t\treturn err
\t}

\tif raw, found := object["jsonrpc"]; found {
\t\tif err := json.Unmarshal(raw, &t.Jsonrpc); err != nil {
\t\t\treturn fmt.Errorf("error reading 'jsonrpc': %w", err)
\t\t}
\t}
\tif raw, found := object["method"]; found {
\t\tif err := json.Unmarshal(raw, &t.Method); err != nil {
\t\t\treturn fmt.Errorf("error reading 'method': %w", err)
\t\t}
\t}
\tif raw, found := object["params"]; found {
\t\tif err := json.Unmarshal(raw, &t.Params); err != nil {
\t\t\treturn fmt.Errorf("error reading 'params': %w", err)
\t\t}
\t}

\treturn validateJsonrpcNotificationObject(object)
}

func validateJsonrpcNotificationObject(object map[string]json.RawMessage) error {
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc notification",
\t\tmap[string]struct{}{"jsonrpc": {}, "method": {}, "params": {}},
\t); err != nil {
\t\treturn err
\t}
\tif _, found := object["id"]; found {
\t\treturn fmt.Errorf("jsonrpc notification must not contain id")
\t}
\tif err := validateJsonrpcLiteralRaw(
\t\tobject,
\t\t"jsonrpc",
\t\tstring(JsonrpcNotificationJsonrpcN20),
\t\t"jsonrpc notification",
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcMethodRaw(object, "jsonrpc notification"); err != nil {
\t\treturn err
\t}
\treturn validateJsonrpcParamsRaw(object, "jsonrpc notification")
}

// AsJsonrpcRequestId0 returns the union data inside the JsonrpcRequest_Id as a JsonrpcRequestId0
""",
)
replace_once(
    """func (t *JsonrpcRequest_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

// AsJsonrpcResponse0 returns the union data inside the JsonrpcResponse as a JsonrpcResponse0
""",
    """func (t *JsonrpcRequest_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

func (t JsonrpcRequest) MarshalJSON() ([]byte, error) {
\tobject := make(map[string]json.RawMessage)
\tvar err error

\tobject["id"], err = json.Marshal(t.Id)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'id': %w", err)
\t}

\tobject["jsonrpc"], err = json.Marshal(t.Jsonrpc)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'jsonrpc': %w", err)
\t}

\tobject["method"], err = json.Marshal(t.Method)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'method': %w", err)
\t}

\tif t.Params != nil {
\t\tobject["params"], err = json.Marshal(t.Params)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'params': %w", err)
\t\t}
\t}

\tif err := validateJsonrpcRequestObject(object); err != nil {
\t\treturn nil, err
\t}
\treturn json.Marshal(object)
}

func (t *JsonrpcRequest) UnmarshalJSON(b []byte) error {
\tobject := make(map[string]json.RawMessage)
\tif err := json.Unmarshal(b, &object); err != nil {
\t\treturn err
\t}

\tif raw, found := object["id"]; found {
\t\tif err := json.Unmarshal(raw, &t.Id); err != nil {
\t\t\treturn fmt.Errorf("error reading 'id': %w", err)
\t\t}
\t}
\tif raw, found := object["jsonrpc"]; found {
\t\tif err := json.Unmarshal(raw, &t.Jsonrpc); err != nil {
\t\t\treturn fmt.Errorf("error reading 'jsonrpc': %w", err)
\t\t}
\t}
\tif raw, found := object["method"]; found {
\t\tif err := json.Unmarshal(raw, &t.Method); err != nil {
\t\t\treturn fmt.Errorf("error reading 'method': %w", err)
\t\t}
\t}
\tif raw, found := object["params"]; found {
\t\tif err := json.Unmarshal(raw, &t.Params); err != nil {
\t\t\treturn fmt.Errorf("error reading 'params': %w", err)
\t\t}
\t}

\treturn validateJsonrpcRequestObject(object)
}

func validateJsonrpcRequestObject(object map[string]json.RawMessage) error {
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc request",
\t\tmap[string]struct{}{"jsonrpc": {}, "id": {}, "method": {}, "params": {}},
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcLiteralRaw(
\t\tobject,
\t\t"jsonrpc",
\t\tstring(JsonrpcRequestJsonrpcN20),
\t\t"jsonrpc request",
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcMethodRaw(object, "jsonrpc request"); err != nil {
\t\treturn err
\t}
\trawID, found := object["id"]
\tif !found {
\t\treturn fmt.Errorf("jsonrpc request missing id")
\t}
\tif err := validateJsonrpcIdRaw(rawID, "jsonrpc request id"); err != nil {
\t\treturn err
\t}
\treturn validateJsonrpcParamsRaw(object, "jsonrpc request")
}

// AsJsonrpcResponse0 returns the union data inside the JsonrpcResponse as a JsonrpcResponse0
""",
)
replace_once(
    """\tif raw, found := object["result"]; found {
\t\terr = json.Unmarshal(raw, &t.Result)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'result': %w", err)
\t\t}
\t}

\treturn err
}

// AsJsonrpcResponseId0 returns the union data inside the JsonrpcResponse_Id as a JsonrpcResponseId0
""",
    """\tif raw, found := object["result"]; found {
\t\terr = json.Unmarshal(raw, &t.Result)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'result': %w", err)
\t\t}
\t}

\treturn validateJsonrpcResponseObject(object)
}

func validateJsonrpcResponseObject(object map[string]json.RawMessage) error {
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc response",
\t\tmap[string]struct{}{"jsonrpc": {}, "id": {}, "result": {}, "error": {}},
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcLiteralRaw(
\t\tobject,
\t\t"jsonrpc",
\t\tstring(JsonrpcResponseJsonrpcN20),
\t\t"jsonrpc response",
\t); err != nil {
\t\treturn err
\t}
\trawID, found := object["id"]
\tif !found {
\t\treturn fmt.Errorf("jsonrpc response missing id")
\t}
\tif err := validateJsonrpcIdRaw(rawID, "jsonrpc response id"); err != nil {
\t\treturn err
\t}
\t_, hasResult := object["result"]
\trawError, hasError := object["error"]
\tif hasResult == hasError {
\t\treturn fmt.Errorf("jsonrpc response must contain exactly one of result or error")
\t}
\tif hasError {
\t\tif err := validateJsonrpcErrorRaw(rawError); err != nil {
\t\t\treturn err
\t\t}
\t}
\treturn nil
}

// AsJsonrpcResponseId0 returns the union data inside the JsonrpcResponse_Id as a JsonrpcResponseId0
""",
)
replace_once(
    """\tobject["verdict"], err = json.Marshal(t.Verdict)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'verdict': %w", err)
\t}

\tb, err = json.Marshal(object)
\treturn b, err
}
""",
    """\tobject["verdict"], err = json.Marshal(t.Verdict)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'verdict': %w", err)
\t}

\tif err := validateProvenanceVerdictLinkObject(object); err != nil {
\t\treturn nil, err
\t}
\tb, err = json.Marshal(object)
\treturn b, err
}
""",
)
replace_once(
    """\tif raw, found := object["verdict"]; found {
\t\terr = json.Unmarshal(raw, &t.Verdict)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'verdict': %w", err)
\t\t}
\t}

\treturn err
}
""",
    """\tif raw, found := object["verdict"]; found {
\t\terr = json.Unmarshal(raw, &t.Verdict)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'verdict': %w", err)
\t\t}
\t}

\treturn validateProvenanceVerdictLinkObject(object)
}

func validateProvenanceVerdictLinkObject(object map[string]json.RawMessage) error {
\tif _, err := requiredNonEmptyJsonString(object, "chainId"); err != nil {
\t\treturn err
\t}
\tif _, err := requiredNonEmptyJsonString(object, "requestId"); err != nil {
\t\treturn err
\t}
\trenderedAt, err := requiredJsonInt64(object, "renderedAt")
\tif err != nil {
\t\treturn err
\t}
\tif renderedAt < 0 {
\t\treturn fmt.Errorf("provenance verdict link renderedAt must be non-negative")
\t}
\tif rawReceiptID, found := object["receiptId"]; found && !rawJsonIsNull(rawReceiptID) {
\t\tif _, err := requiredNonEmptyJsonString(object, "receiptId"); err != nil {
\t\t\treturn err
\t\t}
\t}
\tif rawEvidenceClass, found := object["evidenceClass"]; found && !rawJsonIsNull(rawEvidenceClass) {
\t\tvar evidenceClass ProvenanceVerdictLinkEvidenceClass
\t\tif err := json.Unmarshal(rawEvidenceClass, &evidenceClass); err != nil {
\t\t\treturn fmt.Errorf("error reading 'evidenceClass': %w", err)
\t\t}
\t\tswitch evidenceClass {
\t\tcase ProvenanceVerdictLinkEvidenceClassAsserted,
\t\t\tProvenanceVerdictLinkEvidenceClassObserved,
\t\t\tProvenanceVerdictLinkEvidenceClassVerified:
\t\tdefault:
\t\t\treturn fmt.Errorf("unsupported provenance evidenceClass %q", evidenceClass)
\t\t}
\t}
\trawVerdict, found := object["verdict"]
\tif !found || rawJsonIsNull(rawVerdict) {
\t\treturn fmt.Errorf("provenance verdict link missing verdict")
\t}
\tvar verdict ProvenanceVerdictLinkVerdict
\tif err := json.Unmarshal(rawVerdict, &verdict); err != nil {
\t\treturn fmt.Errorf("error reading 'verdict': %w", err)
\t}

\thasReason := jsonFieldPresentAndNonNull(object, "reason")
\thasGuard := jsonFieldPresentAndNonNull(object, "guard")
\tswitch verdict {
\tcase ProvenanceVerdictLinkVerdictAllow:
\t\tif _, found := object["reason"]; found {
\t\t\treturn fmt.Errorf("allow verdict must not include reason")
\t\t}
\t\tif _, found := object["guard"]; found {
\t\t\treturn fmt.Errorf("allow verdict must not include guard")
\t\t}
\tcase ProvenanceVerdictLinkVerdictDeny:
\t\tif !hasReason || !hasGuard {
\t\t\treturn fmt.Errorf("deny verdict must include reason and guard")
\t\t}
\tcase ProvenanceVerdictLinkVerdictCancel:
\t\tif !hasReason {
\t\t\treturn fmt.Errorf("cancel verdict must include reason")
\t\t}
\t\tif _, found := object["guard"]; found {
\t\t\treturn fmt.Errorf("cancel verdict must not include guard")
\t\t}
\tcase ProvenanceVerdictLinkVerdictIncomplete:
\t\tif !hasReason {
\t\t\treturn fmt.Errorf("incomplete verdict must include reason")
\t\t}
\t\tif _, found := object["guard"]; found {
\t\t\treturn fmt.Errorf("incomplete verdict must not include guard")
\t\t}
\tdefault:
\t\treturn fmt.Errorf("unsupported provenance verdict %q", verdict)
\t}
\treturn nil
}

func validateJsonrpcLiteralRaw(
\tobject map[string]json.RawMessage,
\tkey string,
\twant string,
\tcontext string,
) error {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("%s missing %s", context, key)
\t}
\tvar value string
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn fmt.Errorf("error reading '%s': %w", key, err)
\t}
\tif value != want {
\t\treturn fmt.Errorf("%s %s must be %q", context, key, want)
\t}
\treturn nil
}

func validateJsonrpcAllowedFieldsRaw(
\tobject map[string]json.RawMessage,
\tcontext string,
\tallowed map[string]struct{},
) error {
\tfor key := range object {
\t\tif _, ok := allowed[key]; !ok {
\t\t\treturn fmt.Errorf("%s contains unknown field %q", context, key)
\t\t}
\t}
\treturn nil
}

func validateJsonrpcMethodRaw(object map[string]json.RawMessage, context string) error {
\traw, found := object["method"]
\tif !found || rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("%s missing method", context)
\t}
\tvar method string
\tif err := json.Unmarshal(raw, &method); err != nil {
\t\treturn fmt.Errorf("error reading 'method': %w", err)
\t}
\tif method == "" {
\t\treturn fmt.Errorf("%s method must be non-empty", context)
\t}
\treturn nil
}

func validateJsonrpcIdRaw(raw json.RawMessage, context string) error {
\tif rawJsonIsNull(raw) {
\t\treturn nil
\t}
\tvar idString string
\tif err := json.Unmarshal(raw, &idString); err == nil {
\t\tif idString == "" {
\t\t\treturn fmt.Errorf("%s string must be non-empty", context)
\t\t}
\t\treturn nil
\t}
\tvar idInt int64
\tif err := json.Unmarshal(raw, &idInt); err == nil {
\t\treturn nil
\t}
\treturn fmt.Errorf("%s must be an integer, non-empty string, or null", context)
}

func validateJsonrpcParamsRaw(object map[string]json.RawMessage, context string) error {
\traw, found := object["params"]
\tif !found {
\t\treturn nil
\t}
\tif rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("%s params must not be null", context)
\t}
\tswitch firstJsonByte(raw) {
\tcase '{', '[':
\t\treturn nil
\tdefault:
\t\treturn fmt.Errorf("%s params must be an object or array", context)
\t}
}

func validateJsonrpcErrorRaw(raw json.RawMessage) error {
\tif rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("jsonrpc error response error must not be null")
\t}
\tvar object map[string]json.RawMessage
\tif err := json.Unmarshal(raw, &object); err != nil || object == nil {
\t\tif err != nil {
\t\t\treturn fmt.Errorf("jsonrpc error response error must be an object: %w", err)
\t\t}
\t\treturn fmt.Errorf("jsonrpc error response error must be an object")
\t}
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc error response error",
\t\tmap[string]struct{}{"code": {}, "message": {}, "data": {}},
\t); err != nil {
\t\treturn err
\t}
\tif _, err := requiredJsonInt64Field(object, "code", "jsonrpc error response error"); err != nil {
\t\treturn err
\t}
\tif _, err := requiredNonEmptyJsonStringField(
\t\tobject,
\t\t"message",
\t\t"jsonrpc error response error",
\t); err != nil {
\t\treturn err
\t}
\treturn nil
}

func requiredNonEmptyJsonStringField(
\tobject map[string]json.RawMessage,
\tkey string,
\tcontext string,
) (string, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn "", fmt.Errorf("%s missing %s", context, key)
\t}
\tvar value string
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn "", fmt.Errorf("error reading '%s': %w", key, err)
\t}
\tif value == "" {
\t\treturn "", fmt.Errorf("%s %s must be non-empty", context, key)
\t}
\treturn value, nil
}

func requiredJsonInt64Field(
\tobject map[string]json.RawMessage,
\tkey string,
\tcontext string,
) (int64, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn 0, fmt.Errorf("%s missing %s", context, key)
\t}
\tvar value int64
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn 0, fmt.Errorf("error reading '%s': %w", key, err)
\t}
\treturn value, nil
}

func firstJsonByte(raw json.RawMessage) byte {
\tfor _, b := range raw {
\t\tswitch b {
\t\tcase ' ', '\\n', '\\r', '\\t':
\t\t\tcontinue
\t\tdefault:
\t\t\treturn b
\t\t}
\t}
\treturn 0
}

func jsonFieldPresentAndNonNull(object map[string]json.RawMessage, key string) bool {
\traw, found := object[key]
\treturn found && !rawJsonIsNull(raw)
}

func requiredNonEmptyJsonString(object map[string]json.RawMessage, key string) (string, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn "", fmt.Errorf("provenance verdict link missing %s", key)
\t}
\tvar value string
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn "", fmt.Errorf("error reading '%s': %w", key, err)
\t}
\tif value == "" {
\t\treturn "", fmt.Errorf("provenance verdict link %s must be non-empty", key)
\t}
\treturn value, nil
}

func requiredJsonInt64(object map[string]json.RawMessage, key string) (int64, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn 0, fmt.Errorf("provenance verdict link missing %s", key)
\t}
\tvar value int64
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn 0, fmt.Errorf("error reading '%s': %w", key, err)
\t}
\treturn value, nil
}

func rawJsonIsNull(raw json.RawMessage) bool {
\treturn string(raw) == "null"
}
""",
)

path.write_text(text, encoding="utf-8")
PY

# Final pass: gofmt the file in-place. oapi-codegen already runs gofmt on
# its output, but our header prepend can shift line-numbering across
# versions; gofmt is idempotent so this is safe.
go fmt "${OUTPUT_FILE}" >/dev/null

echo "regen-types.sh: wrote ${OUTPUT_FILE}" >&2
