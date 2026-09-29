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
LITERALS = re.compile(r'r(?P<hashes>#{0,16})"(?P<raw>.*?)"(?P=hashes)|"(?P<quoted>(?:\\.|[^"\\])*)"', re.S)
CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(", re.I)
DECODERS = "from_str|from_slice|from_reader|from_value"


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
    found = {"constructors": [], "raw_decoders": [], "schemas": {}, "unscoped_sql": [], "decoder_census": {}}
    files = dict(sources(root))
    decoder_owners = set(catalog["signed_input_files"])
    for path, text in files.items():
        code = _lexer.blank_rust_noise(text)
        decoders = list(json_decoders(code))
        if decoders:
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
    for name in ("constructors", "raw_decoders"):
        found[name].sort()
    found["unscoped_sql"].sort(key=lambda row: (row["path"], row["owner"], row["sha256"]))
    return found, files


def check(root, catalog):
    found, files = scan(root, catalog)
    errors = []
    if found["decoder_census"] != catalog.get("decoder_census"):
        errors.append("workspace decoder census changed; classify new files and entry points")
    contracts = catalog.get("decoder_file_contracts", {})
    for registry, label in (("reviewed_kernel_sqlite_owners", "kernel/SQLite"),
                            ("reviewed_authority_owners", "authority")):
        for path, review in catalog.get(registry, {}).items():
            if path not in files or path not in catalog["signed_input_files"] or not review.get("contract"):
                errors.append(f"reviewed {label} owner is unregistered: {path}")
            if contracts.get(path, {}).get("kind") == "raw-input-baseline":
                errors.append(f"reviewed {label} owner regressed to baseline: {path}")
    if set(contracts) != set(found["decoder_census"]) or any(
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
