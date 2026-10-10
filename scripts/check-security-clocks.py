#!/usr/bin/env python3
"""Forbid new ambient wall-clock reads and independent clock traits in the TCB.

The inventory includes fixtures as well as production. It pins existing debt
by file and function; moving or adding a call requires a real migration. The
native shared adapter is the sole permanent wall-clock exception. This gate
does not claim that the inventoried remaining production calls are migrated.
"""

import argparse
import importlib.util
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_clock_compositions import COMPOSITION_CONTRACTS

ROOT = Path(__file__).resolve().parent.parent
SCOPE_EVIDENCE = "docs/security/clock-scope-evidence-2026-10-02.json"
SCOPE_EVIDENCE_SHA256 = (
    "147bfd548e7b1a68e49a46f4f8fb62cd29c820eb3590b0270e57e63fb9dc4b5d"
)
INVENTORY = ROOT / "scripts/security-clock-inventory.json"
LEGACY_ROOTS = (
    "crates/security/",
    "crates/economy/chio-anchor/src/witness/rekor.rs",
    "crates/economy/chio-anchor/src/witness/rekor/",
    "crates/kernel/",
    "crates/guards/",
    "crates/platform/chio-control-plane/",
    "crates/platform/chio-store-sqlite/",
    "crates/platform/chio-http-core/src/authority.rs",
    "crates/platform/chio-finding-hosted-edge/src/server.rs",
    "crates/platform/chio-finding-worker/src/executor.rs",
    "crates/protocol/chio-mcp-edge/",
    "crates/protocol/chio-mcp-adapter/",
    "crates/protocol/chio-a2a-adapter/",
    "crates/protocol/chio-openai-adapter/",
    "crates/protocol/chio-mcp-remote/",
    "crates/protocol/chio-a2a-edge/",
    "crates/protocol/chio-acp-edge/",
    "crates/protocol/chio-acp-proxy/",
)
ADAPTER = "crates/security/chio-security-types/src/clock/system.rs"
PORT = "crates/security/chio-security-types/src/clock.rs"


def clock_roots(root):
    """Cover complete crates that contain a reviewed boundary or TCB library.

    Whole-crate coverage prevents a sibling module from escaping the inventory.
    The legacy roots retain fixture coverage while catalogs evolve.
    """
    boundaries = json.loads(
        (root / "docs/security/trust-boundary-inventory.json").read_text()
    )
    hardening = json.loads(
        (root / "docs/security/toolchain/rust-hardening.json").read_text()
    )
    paths = [*boundaries["signed_input_files"], *hardening["tcb_libraries"].values()]
    return tuple(
        sorted(
            set(LEGACY_ROOTS)
            | {
                "/".join(Path(path).parts[:3]) + "/"
                for path in paths
                if Path(path).parts[0] == "crates" and len(Path(path).parts) >= 4
            }
        )
    )


ROOTS = clock_roots(ROOT)
spec = importlib.util.spec_from_file_location(
    "negative_assertions", ROOT / "scripts/check-negative-assertions.py"
)
lexer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lexer
spec.loader.exec_module(lexer)


def sql_clock_literals(source):
    """Inspect Rust string literals for database clock functions, not comments.

    This catches direct SQL text only. Generated SQL and database-side triggers
    require review independently of the Rust-source census.
    """
    position = 0
    sql_statement = re.compile(
        r"\b(?:SELECT|CREATE|ALTER|UPDATE|INSERT|DELETE|DEFAULT|VALUES|RETURNING|WHERE)\b",
        re.IGNORECASE,
    )
    pattern = re.compile(
        r"\b(?:CURRENT_TIMESTAMP|CURRENT_DATE|CURRENT_TIME)\b|"
        r"\b(?:unixepoch|julianday|datetime|date|time|now|clock_timestamp|statement_timestamp|transaction_timestamp)\s*\(\s*\)|"
        r"\b(?:strftime|unixepoch|julianday|datetime|date|time)\s*\([^;)]*['\"]now\\?['\"]",
        re.IGNORECASE,
    )
    while match := lexer.RUST_NOISE.search(source, position):
        token = match.group(0)
        end = match.end()
        if token == "/*":
            depth = 1
            while depth and end < len(source):
                opened, closed = source.find("/*", end), source.find("*/", end)
                if closed == -1:
                    end = len(source)
                    break
                if opened != -1 and opened < closed:
                    depth += 1
                    end = opened + 2
                else:
                    depth -= 1
                    end = closed + 2
        elif match.group(1) is not None:
            terminator = '"' + match.group(1)
            close = source.find(terminator, end)
            end = len(source) if close < 0 else close + len(terminator)
            literal = source[match.end() : end]
            if sql_statement.search(literal):
                for observed in pattern.finditer(literal):
                    yield match.end() + observed.start()
        elif (
            not token.startswith("//") and '"' in token and sql_statement.search(token)
        ):
            for observed in pattern.finditer(token):
                yield match.start() + observed.start()
        position = end


def sites(path, source):
    scanned = lexer.blank_rust_noise(source)
    functions = [(m.start(), m.group(1)) for m in lexer.FN_ITEM.finditer(scanned)]
    names = {"SystemTime", "Utc", "Local", "OffsetDateTime"}
    adapters = {"SystemClock", "AdvancingSystemClock"}
    epochs = {"UNIX_EPOCH"}
    for group in (names, adapters, epochs):
        while True:
            alternatives = "|".join(sorted(group))
            aliases = set(
                re.findall(r"\b(?:" + alternatives + r")\s+as\s+(\w+)", scanned)
            )
            aliases.update(
                re.findall(
                    r"\btype\s+(\w+)\s*=\s*(?:\w+\s*::\s*)*(?:"
                    + alternatives
                    + r")\s*;",
                    scanned,
                )
            )
            if aliases <= group:
                break
            group.update(aliases)
    # Declarations establish names, not observations. Retain offsets for owners.
    scanned = re.sub(
        r"\buse\s+[^;]+;|\btype\s+\w+\s*=[^;]+;", lambda m: " " * len(m[0]), scanned
    )
    calls = re.compile(
        r"\b(?:" + "|".join(sorted(names)) + r")\s*::\s*(?:now|now_utc)\b"
    )
    result = Counter()
    for offset in sql_clock_literals(source):
        result[f"{path}::{lexer.enclosing_function(functions, offset)}::sql-clock"] += 1
    if path != ADAPTER:
        for match in calls.finditer(scanned):
            result[f"{path}::{lexer.enclosing_function(functions, match.start())}"] += 1
        for match in re.finditer(
            r"\b(?:" + "|".join(sorted(epochs)) + r")\s*\.\s*elapsed\b", scanned
        ):
            result[f"{path}::{lexer.enclosing_function(functions, match.start())}"] += 1
        for match in re.finditer(
            r"\b(?:" + "|".join(sorted(adapters)) + r")\b", scanned
        ):
            result[
                f"{path}::{lexer.enclosing_function(functions, match.start())}::native-adapter"
            ] += 1
    for match in re.finditer(r"\btrait\s+(\w+)[^;{]*\{", scanned):
        depth, end = 1, match.end()
        while end < len(scanned) and depth:
            depth += (scanned[end] == "{") - (scanned[end] == "}")
            end += 1
        body = scanned[match.end() : end]
        time_port = match.group(1).endswith("Clock") or re.search(
            r"\bfn\s+(?:now|unix_millis|unix_seconds|now_ms|now_secs)\b|"
            r"->\s*(?:Result\s*<\s*)?(?:\w+::)*(?:ClockReading|UnixMillis|SystemTime|DateTime)\b",
            body,
        )
        if path != PORT and time_port:
            result[f"{path}::trait {match.group(1)}"] += 1
    return result


def inventory(root):
    paths = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "crates/*.rs",
            "crates/*.inc",
        ],
        text=True,
    )
    found = Counter()
    roots = clock_roots(root)
    for path in set(paths.splitlines()):
        if path.startswith(roots) and (root / path).is_file():
            found.update(sites(path, (root / path).read_text()))
    return found


def owner_fingerprint(source, owner):
    """Pin the reviewed function bodies, ignoring formatting, comments and strings.

    This is a source tripwire, not a Rust semantic proof. Duplicate method names
    in a source file are pinned together, so another impl cannot borrow a permit.
    """
    scanned = lexer.blank_rust_noise(source)
    bodies = []
    for match in lexer.FN_ITEM.finditer(scanned):
        if match.group(1) != owner:
            continue
        opening = scanned.find("{", match.end())
        if opening < 0:
            continue
        depth, end = 1, opening + 1
        while end < len(scanned) and depth:
            depth += (scanned[end] == "{") - (scanned[end] == "}")
            end += 1
        bodies.append(re.sub(r"\s+", "", scanned[match.start() : end]))
    return hashlib.sha256("\n".join(bodies).encode()).hexdigest()


def allowed_sites(root, baseline):
    evidence_bytes = (root / SCOPE_EVIDENCE).read_bytes()
    if hashlib.sha256(evidence_bytes).hexdigest() != SCOPE_EVIDENCE_SHA256:
        raise ValueError(
            "expanded clock scope evidence differs from reviewed base source"
        )
    evidence = json.loads(evidence_bytes)
    legacy = Counter(baseline["sites"])
    expanded = Counter(baseline["expanded_preexisting_sites"])
    for category in (legacy, expanded):
        if any(type(n) is not int or n <= 0 for n in category.values()):
            raise ValueError("clock debt counts must be positive integers")
    if legacy.keys() & expanded.keys():
        raise ValueError("legacy and expanded clock debt overlap")
    debt = legacy + expanded
    if debt - Counter(evidence["sites"]):
        raise ValueError("clock inventory permits observations absent from base source")
    if set(baseline["composition_sites"]) != set(COMPOSITION_CONTRACTS):
        raise ValueError("composition inventory differs from source-pinned owners")
    composition = Counter()
    for key, expected in COMPOSITION_CONTRACTS.items():
        path, owner, kind = key.split("::")
        if kind != "native-adapter" or key in debt:
            raise ValueError(f"invalid native composition contract: {key}")
        if owner_fingerprint((root / path).read_text(), owner) != expected:
            raise ValueError(f"native composition source changed: {key}")
        composition[key] = 1
    return debt + composition


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ratchet", action="store_true")
    args = parser.parse_args()
    baseline = json.loads(
        (args.root / "scripts/security-clock-inventory.json").read_text()
    )
    try:
        allowed = allowed_sites(args.root, baseline)
    except (ValueError, KeyError, OSError) as error:
        parser.error(str(error))
    found = inventory(args.root)
    added = found - allowed
    if added:
        for key, count in sorted(added.items()):
            print(f"new clock bypass: {key} (+{count})", file=sys.stderr)
        raise SystemExit(1)
    if args.ratchet:
        for category in ("sites", "expanded_preexisting_sites"):
            baseline[category] = dict(
                sorted((Counter(baseline[category]) & found).items())
            )
        (args.root / "scripts/security-clock-inventory.json").write_text(
            json.dumps(baseline, indent=2) + "\n"
        )
    compositions = sum(found[key] for key in COMPOSITION_CONTRACTS)
    print(
        f"Security clocks: {sum(found.values()) - compositions} remaining debt observations "
        f"(including fixtures), {compositions} pinned native compositions; no additions"
    )


if __name__ == "__main__":
    main()
