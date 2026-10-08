#!/usr/bin/env python3
"""Review tripwires for signed input, proof construction, and tenant SQL.

This is a source inventory, not a Rust/SQL verifier. Compile-fail tests enforce
the Rust API; owning runtime tests enforce authentication and row isolation.
"""
import argparse
import hashlib
import importlib.util
import sys
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "docs/security/trust-boundary-inventory.json"
STORE = "crates/platform/chio-store-sqlite/src"
# Share the calibrated Rust lexer. Examples inside documentation and strings
# cannot construct proof values or bypass a production reader.
_spec = importlib.util.spec_from_file_location("accounting_lexer", ROOT / "scripts/check-accounting-arithmetic.py")
_lexer = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _lexer
_spec.loader.exec_module(_lexer)
_contracts_spec = importlib.util.spec_from_file_location("trust_boundary_contracts", ROOT / "scripts/trust_boundary_contracts.py")
_contracts = importlib.util.module_from_spec(_contracts_spec)
_contracts_spec.loader.exec_module(_contracts)
_ingress_spec = importlib.util.spec_from_file_location("trust_boundary_ingress", ROOT / "scripts/trust_boundary_ingress.py")
_ingress = importlib.util.module_from_spec(_ingress_spec)
_ingress_spec.loader.exec_module(_ingress)
LITERALS = re.compile(r'r(?P<hashes>#{0,16})"(?P<raw>.*?)"(?P=hashes)|"(?P<quoted>(?:\\.|[^"\\])*)"', re.S)
CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(", re.I)
DECODERS = "from_str|from_slice|from_reader|from_value"
DECODER_KINDS = {
    "raw-input-baseline", "typed-value-conversion", "parser-internal-or-typed",
    "reviewed-signed-owner", "reviewed-protocol-reader", "example-or-fuzz",
    "reviewed-bounded-input", "bounded-original-reader",
    "bounded-original-and-typed-projection", "typed-field-deserializer",
    "durable-internal-state", "strict-preflight-reparse", "validated-worker-input",
}

# The reviewed debt cohort survives scoped caller repairs and direct-site
# migrations. Removing or promoting it requires an explicit source-gate review.
RAW_INPUT_BASELINE_IDENTITIES_SHA256 = "049948d58a6c6c1ee334f7dd0886724dc786227068ee1df88b5be862318b2922"
RETIRED_DIRECT_HELPERS = {
    "crates/products/chio-mercury/src/commands/shared/utils.rs": "read_json_file",
    "crates/sdk/chio-binding-helpers/src/receipt.rs": "parse_receipt_json",
}


def function_body(text, owner):
    """Pin actual source, including literals, in one uniquely resolved owner."""
    code = _lexer.blank_rust_noise(text)
    rows = [row for row in _contracts.functions(code) if row[0] == owner]
    if len(rows) != 1:
        return None, None
    row = rows[0]
    actual = text[row[1]:row[3]]
    calls = _contracts.owner_code(code, row)[row[2] - row[1] + 1:-1]
    return hashlib.sha256(actual.encode()).hexdigest(), calls


def local_helper_consumers(files, path, helper):
    """Require all named local-package callers, not a metadata-chosen subset."""
    prefix = path.split("/src/", 1)[0] + "/src/"
    found = set()
    for source_path, text in files.items():
        if not source_path.startswith(prefix) or not source_path.endswith(".rs"):
            continue
        code = _lexer.blank_rust_noise(text)
        for row in _contracts.functions(code):
            key = (source_path, row[0])
            body = _contracts.owner_code(code, row)[row[2] - row[1] + 1:-1]
            if key != (path, helper) and _contracts.calls(body, helper):
                found.add(key)
    return found


def retired_direct_contracts(catalog, found, files):
    """Retain debt for two reviewed wrappers, without declaring input closure."""
    errors = []
    contracts = catalog.get("decoder_file_contracts", {})
    baseline = sorted(path for path, row in contracts.items()
                      if row.get("kind") == "raw-input-baseline")
    digest = hashlib.sha256(json.dumps(baseline, separators=(",", ":")).encode()).hexdigest()
    if digest != RAW_INPUT_BASELINE_IDENTITIES_SHA256:
        errors.append("raw-input baseline debt identities changed")
    retired = catalog.get("retired_direct_readers", {})
    for path, review in retired.items():
        helper = RETIRED_DIRECT_HELPERS.get(path)
        if helper is None:
            errors.append(f"unreviewed retired direct reader: {path}")
            continue
        baseline_contract = contracts.get(path, {})
        contract_hash = hashlib.sha256(json.dumps(
            baseline_contract, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        if (baseline_contract.get("kind") != "raw-input-baseline"
                or review.get("baseline_kind") != "raw-input-baseline"
                or review.get("baseline_contract_sha256") != contract_hash):
            errors.append(f"retired direct-reader baseline is missing or changed: {path}")
        if path in found["decoder_census"]:
            errors.append(f"retired direct reader gained direct decoder: {path}")
        source = files.get(path)
        signature = f"{path}::{helper}::new#1::decode_signed"
        actual = [site for site in found["decoding_contracts"]
                  if site.startswith(f"{path}::{helper}::")]
        source_hash, _ = function_body(source or "", helper)
        if (review.get("helper") != helper or actual != [signature]
                or review.get("constructor_contract") != signature
                or source_hash is None or review.get("helper_source_sha256") != source_hash
                or review.get("ingress") != found["ingress_census"].get(path)):
            errors.append(f"retired direct-reader signed helper changed: {path}")
        consumers = review.get("consumers", [])
        custody_valid = bool(consumers)
        seen = set()
        for consumer in consumers:
            key = (consumer.get("path"), consumer.get("owner"))
            if key in seen or key == (path, helper):
                custody_valid = False
            seen.add(key)
            consumer_hash, body = function_body(files.get(key[0], ""), key[1])
            if (consumer_hash is None or consumer.get("source_sha256") != consumer_hash
                    or not _contracts.calls(body or "", helper)):
                custody_valid = False
        if not custody_valid:
            errors.append(f"retired direct-reader consumer custody changed: {path}")
        elif seen != local_helper_consumers(files, path, helper):
            errors.append(f"retired direct-reader consumer custody changed: {path}")
        if (review.get("status") != "direct-serde-site-migrated-original-debt-open"
                or not review.get("scope") or not review.get("remaining_acceptance")):
            errors.append(f"retired direct-reader remaining debt is missing: {path}")
    if set(contracts) != set(found["decoder_census"]) | set(retired):
        errors.append("workspace decoder file contracts are incomplete")
    return errors


def json_decoders(code):
    """Locate direct and imported serde JSON entry points, retaining multiplicity.

    This is a lexical tripwire, not name resolution. Custom Deserialize owners
    are recorded too, so adding a value visitor cannot bypass file classification.
    """
    patterns = [(rf"\bserde_json::({DECODERS})\b", None)]
    for alias in re.findall(r"\buse\s+serde_json\s+as\s+(\w+)\s*;", code):
        patterns.append((rf"\b{alias}::({DECODERS})\b", None))
    for alias in re.findall(r"\buse\s+serde_json::(?:de::)?Deserializer\s+as\s+(\w+)\s*;", code):
        patterns.append((rf"\b{alias}::(from_str|from_slice|from_reader)\b", None))
    if re.search(r"\buse\s+serde_json::\*\s*;", code):
        patterns.append((rf"\b({DECODERS})\s*(?=\(|::<)", None))
    for imported in re.finditer(r"\buse\s+serde_json::(\{[^;]+\}|\w+(?:\s+as\s+\w+)?)\s*;", code):
        for alias in re.findall(r"\bself\s+as\s+(\w+)", imported.group(1)):
            patterns.append((rf"\b{alias}::({DECODERS})\b", None))
        for alias in re.findall(r"\bDeserializer\s+as\s+(\w+)", imported.group(1)):
            patterns.append((rf"\b{alias}::(from_str|from_slice|from_reader)\b", None))
        for item in re.finditer(rf"\b({DECODERS})(?:\s+as\s+(\w+))?\b", imported.group(1)):
            name = item.group(2) or item.group(1)
            patterns.append((rf"\b{name}\s*(?=\(|::<)", item.group(1)))
    seen = set()
    for pattern, decoder in patterns:
        for match in re.finditer(pattern, code):
            site = (match.start(), decoder or match.group(1))
            if site not in seen:
                seen.add(site)
                yield site
    for match in re.finditer(r"\b(?:serde_json::)?Deserializer::(from_str|from_slice|from_reader)\b", code):
        yield match.start(), "Deserializer::" + match.group(1)
    for match in re.finditer(r"\bfn\s+deserialize\s*<", code):
        yield match.start(), "custom_deserialize"


def production(path):
    return not any(part in {"tests", "test_support", "fuzz", "benches"} or part.endswith("_tests") for part in path.parts) and path.stem != "tests" and not any(
        marker in path.stem for marker in ("_tests", "_test_support", "_test_fixture")
    )


def sources(root):
    for path in sorted((root / "crates").rglob("*")):
        if path.suffix in {".rs", ".inc", ".sql"} and production(path):
            text = without_test_items(path.read_text())
            yield path.relative_to(root).as_posix(), text


def without_test_items(text):
    # Mask strings/comments before balancing a cfg(test) item. A test helper
    # can appear before production methods, so truncating at cfg(test) is wrong.
    syntax = list(text)
    for match in LITERALS.finditer(text):
        syntax[match.start():match.end()] = " " * (match.end() - match.start())
    masked = "".join(syntax)
    for match in re.finditer(r"//[^\n]*|/\*.*?\*/", masked, re.S):
        syntax[match.start():match.end()] = " " * (match.end() - match.start())
    syntax = "".join(syntax)
    output = list(text)
    for match in re.finditer(r"#\[cfg\(test\)\]", syntax):
        start = match.end()
        while start < len(syntax) and syntax[start] not in "{;":
            start += 1
        end = start + 1
        if start < len(syntax) and syntax[start] == "{":
            depth = 1
            while end < len(syntax) and depth:
                depth += (syntax[end] == "{") - (syntax[end] == "}")
                end += 1
        output[match.start():end] = " " * (end - match.start())
    return "".join(output)


def schema_tables(text):
    for match in CREATE.finditer(text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            depth += (text[end] == "(") - (text[end] == ")")
            end += 1
        if re.search(r"\btenant_id\b", text[match.end():end]):
            yield match.group(1), match.start()


def owner_at(text, offset):
    functions = list(re.finditer(r"\bfn\s+(\w+)\s*(?:<[^{};]*>)?\s*\(", text[:offset]))
    return functions[-1].group(1) if functions else "schema"


def sql_statements(path, text):
    literals = [(0, text)] if path.endswith(".sql") else [
        (m.start(), m.group("raw") if m.group("raw") is not None else m.group("quoted"))
        for m in LITERALS.finditer(text)
    ]
    for offset, literal in literals:
        for statement in literal.split(";"):
            normalized = " ".join(re.sub(r"--[^\n]*", "", statement).replace("\\\n", " ").split())
            if re.match(r"(?:SELECT|WITH|UPDATE|DELETE)\b", normalized, re.I):
                yield owner_at(text, offset), normalized


def scan(root, catalog):
    found = {"constructors": [], "raw_decoders": [], "schemas": {}, "unscoped_sql": [], "decoder_census": {}, "decoding_contracts": [], "decoding_contract_errors": [], "reader_evidence": {}}
    files = dict(sources(root))
    production_code = {path: _lexer.blank_rust_noise(text) for path, text in files.items()}
    found["ingress_census"] = _ingress.scan(production_code, _contracts, json_decoders)
    supports = {path: _lexer.blank_rust_noise(files.get(path, "")) for path in _contracts.SUPPORT_PATHS}
    # Preserve literals only for the finite reject-only MCP source witness.
    # Test-scoped tokens are blanked through the same calibrated Rust lexer.
    mcp_http = "crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs"
    raw = files.get(mcp_http, "")
    syntax = _lexer.blank_rust_noise(raw)
    production = _lexer.blank_test_scoped_items(syntax)
    supports[mcp_http + "::initialize-reject-source"] = "".join(
        original if before == after else ("\n" if original == "\n" else " ")
        for original, before, after in zip(raw, syntax, production)
    )
    decoder_owners = set(catalog["signed_input_files"])
    for path, text in files.items():
        code = _lexer.blank_rust_noise(text)
        decoding, contract_errors = _contracts.decoding_contracts(code)
        found["decoding_contracts"].extend(f"{path}::{contract}" for contract in decoding)
        found["decoding_contract_errors"].extend(f"{path}: {error}" for error in contract_errors)
        decoders = list(json_decoders(code))
        if decoders:
            found["reader_evidence"][path] = _contracts.reader_evidence(
                path, code, decoders, _lexer.blank_test_scoped_items(code), supports
            )
            found["decoder_census"][path] = sorted(
                f"{owner_at(code, offset)}::{decoder}" for offset, decoder in decoders
            )
        for match in re.finditer(r"UntrustedJsonText::(new|from_wire)\s*\(", code):
            found["constructors"].append(f"{path}::{owner_at(code, match.start())}::{match.group(1)}")
        if path in decoder_owners:
            for offset, decoder in decoders:
                found["raw_decoders"].append(f"{path}::{owner_at(code, offset)}::{decoder}")
        if path.startswith(STORE):
            for table, _ in schema_tables(text):
                found["schemas"].setdefault(table, []).append(path)
    for table in found["schemas"]:
        found["schemas"][table] = sorted(set(found["schemas"][table]))
    tables = set(found["schemas"])
    for path, text in files.items():
        if not path.startswith(STORE):
            continue
        for owner, sql in sql_statements(path, text):
            touched = sorted(set(re.findall(r"\b(?:FROM|JOIN|UPDATE)\s+(?:\w+\.)?(\w+)", sql, re.I)) & tables)
            if not touched:
                continue
            # tenant_id in a SELECT list is not a predicate. Dynamic predicates
            # and administrative statements require an explicit reviewed entry.
            if re.search(r"\b(?:WHERE|AND|ON)\s+(?:\w+\.)?tenant_id\s*=", sql, re.I):
                continue
            digest = hashlib.sha256(sql.encode()).hexdigest()
            found["unscoped_sql"].append({"path": path, "owner": owner, "sha256": digest, "tables": touched, "sql": sql})
    for name in ("constructors", "raw_decoders", "decoding_contracts"):
        found[name].sort()
    found["unscoped_sql"].sort(key=lambda row: (row["path"], row["owner"], row["sha256"]))
    return found, files


def check(root, catalog):
    found, files = scan(root, catalog)
    errors = []
    errors.extend(found["decoding_contract_errors"])
    if found["ingress_census"] != catalog.get("ingress_census"):
        errors.append("framework/format/shared-reader census changed; classify each new input consumer")
    errors.extend(_ingress.check(root, found["ingress_census"], files, _contracts, _lexer.blank_rust_noise))
    if found["decoding_contracts"] != catalog.get("decoding_contracts"):
        errors.append("decoding contracts changed; review constructor, owner and method together")
    if found["decoder_census"] != catalog.get("decoder_census"):
        errors.append("workspace decoder census changed; classify new files and entry points")
    contracts = catalog.get("decoder_file_contracts", {})
    errors.extend(retired_direct_contracts(catalog, found, files))
    for path, contract in contracts.items():
        kind = contract.get("kind")
        if kind not in DECODER_KINDS:
            errors.append(f"reader evidence has an unknown classification: {path}")
        if contract.get("kind") == "raw-input-baseline":
            continue
        evidence = found["reader_evidence"].get(path, [])
        if not evidence or not all(row["checked"] for row in evidence) or contract.get("readers") != evidence:
            errors.append(f"reader evidence is missing, invalid or changed: {path}")
        if contract.get("kind") == "typed-value-conversion" and any(
            row["decoders"] != ["from_value"] * len(row["decoders"]) for row in evidence
        ):
            errors.append(f"reader evidence does not support typed-value-conversion: {path}")
        if kind == "typed-field-deserializer" and any(
            any(decoder != "custom_deserialize" for decoder in row["decoders"]) for row in evidence
        ):
            errors.append(f"reader evidence does not support typed-field-deserializer: {path}")
        if kind == "example-or-fuzz" and not ("examples" in path.split("/") or path.endswith("/fuzz.rs")):
            errors.append(f"reader evidence does not support example-or-fuzz: {path}")
    for registry, label in (("reviewed_kernel_sqlite_owners", "kernel/SQLite"),
                            ("reviewed_authority_owners", "authority"),
                            ("reviewed_product_readers", "product reader")):
        for path, review in catalog.get(registry, {}).items():
            if path not in files or path not in catalog["signed_input_files"] or not review.get("contract"):
                errors.append(f"reviewed {label} owner is unregistered: {path}")
            if contracts.get(path, {}).get("kind") == "raw-input-baseline":
                errors.append(f"reviewed {label} owner regressed to baseline: {path}")
    if any(
        not contract.get("kind") or not contract.get("contract") for contract in contracts.values()
    ):
        errors.append("workspace decoder file contracts are incomplete")
    for name in ("constructors", "raw_decoders", "schemas"):
        if found[name] != catalog[name]:
            errors.append(f"{name} changed; review and update {CATALOG}")
    if set(catalog["raw_decoder_contracts"]) != set(found["raw_decoders"]):
        errors.append("raw decoder contract coverage is incomplete")
    expected = [{k: row[k] for k in ("path", "owner", "sha256", "tables", "sql")} for row in catalog["unscoped_sql"]]
    if found["unscoped_sql"] != expected:
        errors.append("unscoped tenant SQL changed; tenant predicate or explicit principal review required")
    for row in catalog["unscoped_sql"]:
        if row.get("principal") not in catalog["principals"] or not row.get("contract"):
            errors.append(f"missing principal/contract: {row['path']}::{row['owner']}")
    if set(catalog["tables"]) != set(found["schemas"]):
        errors.append("tenant table classification is incomplete")
    families = catalog.get("tenant_runtime_families", {})
    for table, row in catalog["tables"].items():
        family = families.get(row.get("runtime_family"))
        if not family or not family.get("entry_points") or not family.get("evidence_kind"):
            errors.append(f"tenant runtime matrix is incomplete: {table}")
            continue
        if family["evidence_kind"] == "runtime-gap":
            if not family.get("remaining"):
                errors.append(f"tenant runtime gap lacks an explicit disposition: {table}")
        elif not family.get("tests"):
            errors.append(f"tenant runtime evidence is missing: {table}")
    for family in families.values():
        for case in family.get("tests", []):
            path = root / case["path"]
            if not path.is_file() or not re.search(r"\bfn\s+" + re.escape(case["test"]) + r"\b", path.read_text()):
                errors.append(f"tenant runtime case is missing: {case['path']}::{case['test']}")
    for table, paths in found["schemas"].items():
        for path in paths:
            if f"tenant-read-contract: {table}" not in files[path]:
                errors.append(f"missing schema read contract: {path}:{table}")
    for proof in catalog["proofs"]:
        text = files[proof["path"]]
        match = re.search(r"pub struct " + proof["type"] + r"(?:<[^{};]+>)?\s*\{([^}]+)\}", text, re.S)
        if not match or re.search(r"\bpub\b", match.group(1)):
            errors.append(f"proof fields are not sealed: {proof['type']}")
        code = _lexer.blank_rust_noise(text)
        declaration = re.search(r"pub struct " + proof["type"] + r"\b", code)
        prefix = code[:declaration.start()] if declaration else ""
        item_start = max(prefix.rfind("}"), prefix.rfind(";")) + 1
        derives = re.findall(r"#\[derive\(([^)]*)\)\]", prefix[item_start:])
        if any(re.search(r"\bDeserialize\b", derive) for derive in derives) or re.search(
            r"impl\s*(?:<[^{};]*>\s*)?(?:[\w:]+::)?Deserialize(?:<[^{};]*>)?\s+for\s+" + proof["type"] + r"\b", code
        ):
            errors.append(f"proof implements Deserialize: {proof['type']}")
    for path, text in files.items():
        if re.search(r"\.secret_bytes\s*\(", text) and path != catalog["frost_secret_owner"]:
            errors.append(f"FROST plaintext extracted outside encrypted custody: {path}")
        if "FrostAuthenticatedDkgPackage" in text:
            errors.append(f"removed shared FROST package reintroduced: {path}")
        if "with_strict_tenant_isolation" in text or "include_null_tenant" in text:
            errors.append(f"tenant compatibility fallback reintroduced: {path}")
    if len(re.findall(r"\.secret_bytes\s*\(", files[catalog["frost_secret_owner"]])) != catalog["frost_secret_extraction_sites"]:
        errors.append("encrypted custody FROST plaintext extraction inventory changed")
    return errors, found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--scan", action="store_true", help="print observations for manual review; never rewrites the approved catalog")
    args = parser.parse_args()
    catalog = json.loads((args.root / CATALOG).read_text())
    if args.scan:
        print(json.dumps(scan(args.root, catalog)[0], indent=2))
        return 0
    errors, found = check(args.root, catalog)
    if errors:
        print("\n".join(errors))
        return 1
    print(f"trust boundaries: {len(found['constructors'])} constructors, {len(found['schemas'])} tenant tables, {len(found['unscoped_sql'])} explicit SQL principal contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
