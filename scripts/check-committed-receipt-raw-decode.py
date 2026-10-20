#!/usr/bin/env python3
"""Refuse production raw JSON decodes of the strict receipt and lossless types.

A raw `serde_json` decode keeps the last of two duplicate keys inside any
`serde_json::Value` member, so production code decodes these types through
`UntrustedJsonText::decode_signed` (or `decode_document`), and HTTP routes use
the `SignedJson` extractor. A type that contains a strict type, at any depth,
is strict too.

Source is scanned with comments, literals and `#[cfg(test)]` items masked, so
multi-line calls and production items after a test module are both seen. A
raw decode is flagged when its target is strict by turbofish, by a `let`
annotation, or by the strict return type of the function that holds it, and
an extractor is flagged when its type argument is strict. Each exception in
ALLOWED names one exact `from_value` call in one function together with the
duplicate-refusing reader that produced its `Value`. The script checks itself
against fixture trees on every run before it scans the workspace.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_gate = _load("trust_boundaries_gate", ROOT / "scripts/check-trust-boundaries.py")
_lexer = _gate._lexer
_contracts = _gate._contracts

# The receipt types that carry a serde_json::Value member (action parameters,
# metadata). Derived impls already refuse a duplicate field of a Chio object;
# only a Value member can keep the last of two duplicate keys.
STRICT_TYPES = frozenset({
    "ChioReceipt",
    "ChioReceiptBody",
    "ChioReceiptIdInput",
    "ChioReceiptSigningBody",
    "ChildRequestReceipt",
    "ChildRequestReceiptBody",
    "ToolCallAction",
})

# Each entry names one call (whitespace-normalized) in one function, and the
# reader that produced the decoded Value.
ALLOWED = (
    {
        "path": "crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs",
        "owner": "decode_verified_chio_receipt",
        "call": "serde_json::from_value(value)",
        "producer": "decode_stored_json calls UntrustedJsonText::decode_signed",
    },
    {
        "path": "crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs",
        "owner": "decode_verified_child_receipt",
        "call": "serde_json::from_value(value)",
        "producer": "decode_stored_json calls UntrustedJsonText::decode_signed",
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/cluster/snapshots.rs",
        "owner": "recover_cluster_snapshot",
        "call": "serde_json::from_value(record.receipt.clone())",
        "producer": "the peer snapshot response is read by json_input::read, which calls decode_signed",
        "count": 2,
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs",
        "owner": "load_chio_receipt",
        "call": "serde_json::from_value(value)",
        "producer": "the receipt list response is read by json_input::read, which calls decode_signed",
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs",
        "owner": "load_child_receipt",
        "call": "serde_json::from_value(value)",
        "producer": "the receipt list response is read by json_input::read, which calls decode_signed",
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs",
        "owner": "sync_peer_tool_receipts",
        "call": "serde_json::from_value(record.receipt)",
        "producer": "the peer delta response is read by json_input::read, which calls decode_signed",
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs",
        "owner": "sync_peer_child_receipts",
        "call": "serde_json::from_value(record.receipt)",
        "producer": "the peer delta response is read by json_input::read, which calls decode_signed",
    },
    {
        "path": "crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes.rs",
        "owner": "verify_file",
        "call": "serde_json::from_value(signed.action.parameters.clone())",
        "producer": "receipt_verify::verify_original_receipt decodes the receipt text with input::decode, which calls decode_signed",
    },
    {
        "path": "crates/products/chio-mercury/src/commands/core_cli/commands.rs",
        "owner": "cmd_mercury_verify",
        "call": "serde_json::from_value(value)",
        "producer": "read_json_file reads through read_json_file_bounded, which calls decode_signed",
        "count": 2,
    },
    {
        "path": "crates/kernel/chio-runtime-core/src/buyer/proof_package.rs",
        "owner": "proof_package_contains_signed_receipt",
        "call": "serde_json::from_value(value.clone())",
        "producer": "buyer artifacts are hydrated by helpers::artifact_json, which calls decode_signed",
    },
    {
        "path": "crates/kernel/chio-runtime-core/src/buyer/proof_package.rs",
        "owner": "proof_package_receipt_subject",
        "call": "serde_json::from_value(receipt_value.clone())",
        "producer": "buyer artifacts are hydrated by helpers::artifact_json, which calls decode_signed",
    },
    {
        "path": "crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials/completed_result.rs",
        "owner": "verified_receipt",
        "call": "serde_json::from_value::<chio_core::receipt::body::ChioReceipt>(evidence[ ].clone(),)",
        "producer": "BroadcastJsonRpcWriter::flush_complete_lines decodes each worker line with decode_json, the lib.rs alias of input::decode, which calls decode_signed",
    },
)

RAW_CALL = re.compile(r"(?<![\w.:])(?:serde_json\s*::\s*)?from_(?:str|slice|reader|value)\s*(?=::|\()")
EXTRACTOR = re.compile(r"(?<![\w:])(?:axum\s*::\s*)?(?:extract\s*::\s*)?(?:Json|Query|Form)\s*<")
TYPE_DEFINITION = re.compile(r"\b(?:struct|enum)\s+(\w+)\b[^;{(]*([({])")
IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")


def without_test_items(code: str) -> str:
    """Blank every `#[cfg(test)]` item in code whose comments and literals are masked."""
    output = list(code)
    for match in re.finditer(r"#\[cfg\(test\)\]", code):
        start = match.end()
        while start < len(code) and code[start] not in "{;":
            start += 1
        end = start + 1
        if start < len(code) and code[start] == "{":
            end = _contracts.closing(code, start, "{", "}")
        output[match.start():end] = " " * (end - match.start())
    return "".join(output)


def production_files(root: Path) -> list[tuple[str, str]]:
    files = []
    for path in sorted((root / "crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if not _gate.production(path) or "examples" in rel.split("/") or path.name == "fuzz.rs":
            continue
        code = _lexer.blank_rust_noise(path.read_text(encoding="utf-8"))
        files.append((rel, without_test_items(code)))
    return files


def strict_closure(files: list[tuple[str, str]]) -> frozenset[str]:
    """Names whose every workspace definition holds a strict type at any depth.

    A name defined more than once with a non-strict body stays out, so an
    unrelated type that shares a name with a wrapper is not swept in. Error
    types carry receipts for reporting and are never decoded from input."""
    definitions: dict[str, list[str]] = {}
    for _, code in files:
        for match in TYPE_DEFINITION.finditer(code):
            opening = match.end(2) - 1
            right = ")" if code[opening] == "(" else "}"
            close = _contracts.closing(code, opening, code[opening], right)
            if not match.group(1).endswith("Error"):
                definitions.setdefault(match.group(1), []).append(code[opening:close])
    strict = set(STRICT_TYPES)
    changed = True
    while changed:
        changed = False
        for name, bodies in definitions.items():
            if name not in strict and all(set(IDENTIFIER.findall(body)) & strict for body in bodies):
                strict.add(name)
                changed = True
    return frozenset(strict)


def mentions_strict(text: str, strict: frozenset[str]) -> bool:
    return bool(set(IDENTIFIER.findall(text)) & strict)


def angle_argument(code: str, index: int) -> tuple[str, int]:
    """Return the text inside the `<...>` that opens at `index`."""
    close = _contracts.closing(code, index, "<", ">")
    return code[index + 1:close - 1], close


def return_type(fn_code: str) -> str:
    parameters = fn_code.find("(")
    after = _contracts.closing(fn_code, parameters)
    body = fn_code.find("{", after)
    signature = fn_code[after:body if body >= 0 else len(fn_code)]
    arrow = signature.find("->")
    if arrow < 0:
        return ""
    value = signature[arrow + 2:].split("where")[0].strip()
    wrapper = re.match(r"(?:[\w:]*::)?(?:Result|Option)\s*<", value)
    if wrapper:
        argument, _ = angle_argument(value, wrapper.end() - 1)
        depth = 0
        for index, char in enumerate(argument):
            depth += (char == "<") - (char == ">")
            if char == "," and depth == 0:
                return argument[:index]
        return argument
    return value


def normalized(text: str) -> str:
    return re.sub(r"\s+", "", text)


def call_text(code: str, start: int) -> str:
    paren = code.find("(", start)
    return normalized(code[start:_contracts.closing(code, paren)])


def let_annotation(fn_code: str, offset: int) -> str:
    statement_start = max(fn_code.rfind(";", 0, offset), fn_code.rfind("{", 0, offset)) + 1
    statement = fn_code[statement_start:offset]
    match = re.search(r"\blet\s+(?:mut\s+)?[\w()\s,]+:\s*(.+?)=\s*$", statement, re.S)
    return match.group(1) if match else ""


def returned(fn_code: str, offset: int) -> bool:
    """Whether the call at `offset` is the function's value: its tail or a `return`."""
    statement_start = max(fn_code.rfind(";", 0, offset), fn_code.rfind("{", 0, offset)) + 1
    prefix = fn_code[statement_start:offset].strip()
    if prefix.startswith("return") or re.fullmatch(r"(?:Ok|Some)\(", prefix):
        return True
    if prefix:
        return False
    paren = fn_code.find("(", offset)
    end = _contracts.closing(fn_code, paren)
    rest = fn_code[end:]
    rest = re.sub(r"^(?:\s*(?:\?|\.\s*\w+\s*(?:::<[^;{}]*?>)?\s*\([^;{}]*?\)))*", "", rest)
    return rest.strip() == "}"


def scan(root: Path) -> list[str]:
    files = production_files(root)
    strict = strict_closure(files)
    findings = []
    for rel, code in files:
        for row in _contracts.functions(code):
            owner = row[0]
            fn_code = _contracts.owner_code(code, row)
            arguments_start = fn_code.find("(")
            arguments = fn_code[arguments_start:_contracts.closing(fn_code, arguments_start)]
            for match in EXTRACTOR.finditer(arguments):
                target, _ = angle_argument(arguments, match.end() - 1)
                if mentions_strict(target, strict):
                    findings.append((rel, owner, normalized(match.group(0) + target + ">"), "extractor"))
            returns_strict = mentions_strict(return_type(fn_code), strict)
            body_start = row[2] - row[1]
            for match in RAW_CALL.finditer(fn_code, body_start):
                after = fn_code[match.end():].lstrip()
                if after.startswith("::"):
                    turbofish = fn_code.index("<", match.end())
                    target, _ = angle_argument(fn_code, turbofish)
                    strict_target = mentions_strict(target, strict)
                else:
                    annotation = let_annotation(fn_code, match.start())
                    if annotation:
                        strict_target = mentions_strict(annotation, strict)
                    else:
                        strict_target = returns_strict and returned(fn_code, match.start())
                if strict_target:
                    findings.append((rel, owner, call_text(fn_code, match.start()), "decode"))
    errors = []
    remaining = list(findings)
    for entry in ALLOWED:
        key = (entry["path"], entry["owner"], normalized(entry["call"]), "decode")
        count = entry.get("count", 1)
        matched = [finding for finding in remaining if finding == key]
        if len(matched) != count or not entry["call"].startswith("serde_json::from_value"):
            errors.append(f"{entry['path']}::{entry['owner']}: approved call {entry['call']} expects {count}, found {len(matched)}")
        for finding in matched:
            remaining.remove(finding)
    errors.extend(f"{rel}::{owner}: raw {kind} {text}" for rel, owner, text, kind in remaining)
    return errors


FIXTURES = {
    "direct raw decode": ("fn f(t: &str) { let r = serde_json::from_str::<ChioReceipt>(t); }", 1),
    "multi-line turbofish": ("fn f(t: &str) {\n    let r = serde_json::from_str::<\n        ChioReceipt,\n    >(t);\n}", 1),
    "annotated slice": ("fn f(b: &[u8]) -> Result<(), E> {\n    let body: ChioReceiptBody =\n        serde_json::from_slice(b)?;\n    Ok(())\n}", 1),
    "inferred return": ("fn f(t: &str) -> Result<ChioReceipt, serde_json::Error> {\n    serde_json::from_str(t)\n}", 1),
    "imported from_str": ("use serde_json::from_str;\nfn f(t: &str) -> Option<Vec<ChioReceipt>> { from_str(t).ok() }", 1),
    "after a test module": ("#[cfg(test)]\nmod tests { fn t() {} }\nfn f(t: &str) { serde_json::from_str::<ChioReceipt>(t); }", 1),
    "test module only": ("#[cfg(test)]\nmod tests { fn t() { serde_json::from_str::<ChioReceipt>(\"{}\"); } }", 0),
    "comment and literal": ("fn f() { // serde_json::from_str::<ChioReceipt>(t)\n let s = \"serde_json::from_str::<ChioReceipt>(t)\"; }", 0),
    "transitive wrapper": ("struct Wrapper { inner: Vec<ChioReceipt> }\nfn f(t: &str) { serde_json::from_str::<Wrapper>(t); }", 1),
    "wrapper extractor": ("struct Request { receipt: ChildRequestReceipt }\nasync fn h(Json(r): Json<Request>) {}", 1),
    "multi-line extractor": ("async fn h(\n    Json(r): Json<\n        ChioReceipt,\n    >,\n) {}", 1),
    "decode_signed": ("fn f(t: &str) -> Result<ChioReceipt, E> { UntrustedJsonText::new(t).decode_signed() }", 0),
    "unrelated decode": ("fn f(t: &str) -> Result<Other, E> { serde_json::from_str(t) }", 0),
}


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "crates/demo/src/lib.rs"
        source.parent.mkdir(parents=True)
        for label, (code, expected) in FIXTURES.items():
            source.write_text(code + "\n", encoding="utf-8")
            found = len(scan(root))
            if found != expected + len(ALLOWED):
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found - len(ALLOWED)}")
        allowed = ALLOWED[0]
        target = root / allowed["path"]
        target.parent.mkdir(parents=True)
        source.write_text("\n", encoding="utf-8")
        for label, body, expected in (
            ("approved call", "let receipt: ChioReceipt = serde_json::from_value(value)?;", 0),
            ("raw text at the approved path", "let receipt: ChioReceipt = serde_json::from_str(raw)?;", 2),
        ):
            target.write_text(
                f"fn {allowed['owner']}(raw: &str, value: Value) -> Result<ChioReceipt, E> {{\n    {body}\n    Ok(receipt)\n}}\n",
                encoding="utf-8",
            )
            found = len(scan(root)) - (len(ALLOWED) - 1)
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    self_test()
    errors = scan(args.root)
    if errors:
        print("raw JSON decode of a strict type outside decode_signed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"committed receipt raw decode: {len(STRICT_TYPES)} strict types, {len(ALLOWED)} pinned from_value calls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
