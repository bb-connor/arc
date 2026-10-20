#!/usr/bin/env python3
"""Refuse production raw JSON decodes of the strict receipt and lossless types.

A raw `serde_json` decode keeps the last of two duplicate keys inside any
`serde_json::Value` member, so production code decodes these types through
`UntrustedJsonText::decode_signed` (or `decode_document`), and HTTP routes use
the `SignedJson` extractor. Each `from_value` listed in ALLOWED decodes a Value
that a duplicate-refusing reader produced. The script checks itself against a
fixture tree on every run before it scans the workspace.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

STRICT_TYPES = (
    "ChioReceipt",
    "ChioReceiptBody",
    "ChioReceiptIdInput",
    "ChioReceiptSigningBody",
    "ChildRequestReceipt",
    "ChildRequestReceiptBody",
    "ToolCallAction",
    "Decision",
    "GuardEvidence",
    "ActorRef",
    "BbsReceiptSignature",
    "OperationTerminalState",
    "Constraint",
    "FindingSettlementSelector",
    "EconomicActionAuthorizationV1",
    "DetectorWatermarkEvidence",
    "DetectorGroupBindingEvidence",
    "ArtifactSinkV1",
    "ResponseDispatchApproval",
    "EffectExecutionStatus",
    "IssuanceFreezeOperationStatus",
    "ResponseApprovalRequirement",
    "ResponseRollbackOutcome",
)

# path -> (number of decodes, why the decoded Value is already duplicate-free)
ALLOWED = {
    "crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs": (
        2,
        "the Value comes from UntrustedJsonText::decode_signed in decode_stored_json",
    ),
    "crates/platform/chio-control-plane/src/trust_control/cluster/snapshots.rs": (
        2,
        "the snapshot response is read by json_input::read, which calls decode_signed",
    ),
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs": (
        2,
        "the receipt list response is read by json_input::read, which calls decode_signed",
    ),
    "crates/kernel/chio-runtime-core/src/buyer/proof_package.rs": (
        2,
        "the proof package is hydrated through decode_signed in buyer helpers",
    ),
    "crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials/completed_result.rs": (
        1,
        "the worker message Value is verified against the kernel signature; its reader is a listed follow-up",
    ),
}

_TYPE = r"(?:[A-Za-z_][A-Za-z0-9_]*::)*(?:" + "|".join(STRICT_TYPES) + r")\b"
_WRAPPED = r"(?:(?:Vec|Option|Box)<\s*)*" + _TYPE
PATTERNS = (
    re.compile(r"serde_json::from_(?:str|slice|reader|value)\s*::\s*<\s*" + _WRAPPED),
    re.compile(r"\bfrom_(?:str|slice|reader|value)\s*::\s*<\s*" + _WRAPPED),
    re.compile(r":\s*" + _WRAPPED + r"\s*>*\s*=\s*serde_json::from_(?:str|slice|reader|value)\b"),
    re.compile(r"\b(?:axum::)?(?:extract::)?(?:Json|Query|Form)\s*<\s*" + _WRAPPED),
)


def production_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.glob("crates/**/*.rs")):
        rel = path.relative_to(root).as_posix()
        parts = rel.split("/")
        if any(part in ("tests", "benches", "examples", "fuzz") or part.endswith("_tests") for part in parts):
            continue
        name = parts[-1]
        if name in ("tests.rs", "test_support.rs") or name.endswith("_tests.rs"):
            continue
        files.append(path)
    return files


def production_lines(text: str) -> list[tuple[int, str]]:
    source = text.splitlines()
    lines = []
    for number, line in enumerate(source, start=1):
        if line.startswith("#[cfg(test)]"):
            following = [l for l in source[number:] if l.strip() and not l.startswith("#[")]
            if following and re.match(r"(pub(\([^)]*\))? )?mod ", following[0]):
                break
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        lines.append((number, line))
    return lines


def scan(root: Path) -> list[str]:
    findings: dict[str, list[str]] = {}
    for path in production_files(root):
        rel = path.relative_to(root).as_posix()
        for number, line in production_lines(path.read_text(encoding="utf-8")):
            if any(pattern.search(line) for pattern in PATTERNS):
                findings.setdefault(rel, []).append(f"{rel}:{number}: {line.strip()}")
    errors = []
    for rel, hits in sorted(findings.items()):
        allowed = ALLOWED.get(rel)
        if allowed is not None and allowed[0] == len(hits):
            continue
        errors.extend(hits)
    for rel, (count, _) in sorted(ALLOWED.items()):
        if (root / rel).is_file() and len(findings.get(rel, [])) != count:
            errors.append(f"{rel}: allowlist expects {count} decodes, found {len(findings.get(rel, []))}")
    return errors


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        crate = root / "crates/demo/src"
        crate.mkdir(parents=True)
        (crate / "lib.rs").write_text(
            "fn ok(text: &str) {\n"
            "    let _: ChioReceipt = UntrustedJsonText::new(text).decode_signed().unwrap();\n"
            "}\n",
            encoding="utf-8",
        )
        if scan(root):
            raise SystemExit("self-test: decode_signed was flagged")
        for bad in (
            "let receipt = serde_json::from_str::<ChioReceipt>(text);",
            "let body: ChioReceiptBody = serde_json::from_slice(bytes)?;",
            "async fn handle(Json(receipt): Json<ChildRequestReceipt>) {}",
            "let items = serde_json::from_value::<Vec<chio_core::receipt::body::ChioReceipt>>(v);",
        ):
            (crate / "bad.rs").write_text(bad + "\n", encoding="utf-8")
            if not scan(root):
                raise SystemExit(f"self-test: raw decode not flagged: {bad}")
        (crate / "bad.rs").write_text(
            "#[cfg(test)]\nmod tests { fn t() { serde_json::from_str::<ChioReceipt>(\"{}\"); } }\n",
            encoding="utf-8",
        )
        if scan(root):
            raise SystemExit("self-test: a test module was flagged")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    self_test()
    errors = scan(args.root)
    if errors:
        print("raw JSON decode of a strict type outside decode_signed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"committed receipt raw decode: {len(STRICT_TYPES)} strict types, no raw production decode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
