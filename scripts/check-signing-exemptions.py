#!/usr/bin/env python3
"""Fail unless every non-test exempt signing or verification call matches the closed allowlist.

An exempt call is `SigningMessage::exempt`, `Keypair::sign_exempt` or `verify_exempt`, in any
spelling: fully qualified, imported, renamed on import, or method syntax. Each observed call is
keyed by (file, enclosing fn, ExemptFormat) and counted; the multiset must equal ALLOWLIST. A call
whose format cannot be resolved to an `ExemptFormat` variant fails. The gate also fails when the
deterministic ML-DSA KAT signer is reachable from a production build.

Usage: check-signing-exemptions.py [--root DIR] [--print]
"""

import argparse
import collections
import re
import sys
from pathlib import Path

FORMATS = ("JwsSigningInput", "DssePae")

# (file, enclosing fn, format): allowed non-test call count.
ALLOWLIST = {
    ('crates/products/chio-cli/src/cli/dispatch/proof/collect.rs', 'write_bundle_signature_to_path', 'DssePae'): 1,
    ('crates/products/chio-cli/src/cli/dispatch/proof/export.rs', 'redact_public_bundle_signature', 'DssePae'): 1,
    ('crates/products/chio-proof-room/src/bundle_a.rs', 'verify_bundle_signature', 'DssePae'): 1,
    ('crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/helpers.rs', 'sign_jwt', 'JwsSigningInput'): 1,
    ('crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs', 'verify_ed25519_jwt_signature', 'JwsSigningInput'): 1,
    ('crates/trust/chio-credentials/src/oid4vp.rs', 'sign_jwt_value', 'JwsSigningInput'): 1,
    ('crates/trust/chio-credentials/src/oid4vp.rs', 'verify_oid4vp_direct_post_response', 'JwsSigningInput'): 1,
    ('crates/trust/chio-credentials/src/oid4vp.rs', 'verify_signed_oid4vp_request_object', 'JwsSigningInput'): 1,
    ('crates/trust/chio-credentials/src/portable_jwt_vc.rs', 'verify_chio_passport_jwt_vc_json', 'JwsSigningInput'): 1,
    ('crates/trust/chio-credentials/src/portable_sd_jwt.rs', 'issue_chio_passport_sd_jwt_vc', 'JwsSigningInput'): 1,
    ('crates/trust/chio-credentials/src/portable_sd_jwt.rs', 'verify_chio_passport_sd_jwt_vc', 'JwsSigningInput'): 1,
    ('crates/trust/chio-federation-transport-iroh/src/lanes/bilateral.rs', 'cosign_inner', 'DssePae'): 2,
    ('crates/trust/chio-federation/src/bilateral.rs', 'request_dsse_cosignature', 'DssePae'): 2,
    ('crates/trust/chio-federation/src/bilateral_dsse/sign.rs', 'co_sign_signature_slice', 'DssePae'): 2,
    ('crates/trust/chio-federation/src/bilateral_dsse/sign.rs', 'sign_chio_bilateral_dsse_envelope', 'DssePae'): 2,
    ('crates/trust/chio-federation/src/bilateral_dsse/sign.rs', 'sign_dsse_envelope_full', 'DssePae'): 2,
    ('crates/trust/chio-federation/src/bilateral_dsse/typestate_handlers.rs', 'request_cosignature', 'DssePae'): 1,
    ('crates/trust/chio-federation/src/bilateral_dsse/typestate_handlers.rs', 'sign_host', 'DssePae'): 1,
    ('crates/trust/chio-federation/src/bilateral_dsse/verify.rs', 'verify_chio_bilateral_dsse_envelope_inner', 'DssePae'): 2,
    ('crates/trust/chio-federation/src/bilateral_dsse/verify.rs', 'verify_dsse_envelope', 'DssePae'): 2,
}

# Files that define the exempt API itself.
DEFINITION_FILES = {
    "crates/core/chio-core-types/src/crypto.rs",
    "crates/core/chio-core-types/src/crypto/wrapper.rs",
}

NAMES = ("exempt", "sign_exempt", "verify_exempt")
TEST_PATH = re.compile(r"(^|/)(tests|benches|examples|fixtures)/|(^|/)tests\.rs$|_tests?\.rs$|_tests/|test_support")
CFG_TEST = re.compile(r"#\[cfg\((?:test|any\([^)]*\btest\b[^)]*\))\)\]")


def gated_module_files(root):
    gated = set()
    for path in root.joinpath("crates").rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text):
            name = m.group(1)
            before = text[: m.start()]
            explicit = re.search(r"#\[path\s*=\s*\"([^\"]+)\"\]\s*$", before.rstrip())
            base = path.parent if path.stem in ("mod", "lib", "main") else path.parent / path.stem
            for cand in ([path.parent / explicit.group(1)] if explicit else []) + [
                base / f"{name}.rs",
                base / name / "mod.rs",
                path.parent / f"{name}.rs",
            ]:
                if cand.exists():
                    gated.add(cand.resolve())
                    if cand.name == "mod.rs":
                        gated.update(p.resolve() for p in cand.parent.rglob("*.rs"))
    return gated


def strip_test_items(text):
    """Blank out every item that a #[cfg(test)] attribute gates, preserving line numbers."""
    out = list(text)
    for m in CFG_TEST.finditer(text):
        i = m.end()
        depth = 0
        started = False
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
                started = True
            elif c == "}":
                depth -= 1
                if started and depth == 0:
                    i += 1
                    break
            elif c == ";" and not started:
                i += 1
                break
            i += 1
        for j in range(m.start(), min(i, len(out))):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


def split_args(text, start):
    depth = 0
    args = []
    cur = start + 1
    for i in range(start, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[cur:i])
                return args
        elif c == "," and depth == 1:
            args.append(text[cur:i])
            cur = i + 1
    return args


def scan(root):
    gated = gated_module_files(root)
    observed = collections.Counter()
    unresolved = []
    for path in sorted(root.joinpath("crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if rel in DEFINITION_FILES or TEST_PATH.search(rel) or path.resolve() in gated:
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = strip_test_items(raw)
        text = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
        aliases = {n: n for n in NAMES}
        fmt_alias = {"ExemptFormat": "ExemptFormat"}
        for m in re.finditer(r"\buse\s+[^;]*;", text, re.S):
            for a in re.finditer(r"\b(SigningMessage|sign_exempt|verify_exempt|ExemptFormat)\s+as\s+(\w+)", m.group(0)):
                if a.group(1) == "ExemptFormat":
                    fmt_alias[a.group(2)] = "ExemptFormat"
                elif a.group(1) == "SigningMessage":
                    aliases[f"{a.group(2)}::exempt"] = "exempt"
                else:
                    aliases[a.group(2)] = a.group(1)
        pattern = re.compile(
            r"\b(?:SigningMessage\s*::\s*exempt|"
            + "|".join(re.escape(k) for k in aliases if k != "exempt")
            + r")\s*\("
        )
        fns = [(m.start(), m.group(1)) for m in re.finditer(r"\bfn\s+(\w+)", text)]
        for m in pattern.finditer(text):
            if re.search(r"\bfn\s+$", text[max(0, m.start() - 8) : m.start()]):
                continue
            head = re.sub(r"\s", "", m.group(0))[:-1].split("::")[-1]
            kind = aliases.get(head, head)
            args = split_args(text, m.end() - 1)
            index = 1 if kind == "verify_exempt" else 0
            fmt = None
            if len(args) > index:
                fm = re.search(r"\b(\w+)\s*::\s*(\w+)\s*$", args[index].strip())
                if fm and fmt_alias.get(fm.group(1)) == "ExemptFormat" and fm.group(2) in FORMATS:
                    fmt = fm.group(2)
            enclosing = "<module>"
            for pos, name in fns:
                if pos < m.start():
                    enclosing = name
            line = text.count("\n", 0, m.start()) + 1
            if fmt is None:
                unresolved.append(f"{rel}:{line} {enclosing}: exempt format not resolvable")
                continue
            observed[(rel, enclosing, fmt)] += 1
    return observed, unresolved


def check_gates(root):
    errors = []
    pq = root / "crates/core/chio-core-types/src/pq.rs"
    if pq.exists():
        text = pq.read_text()
        m = re.search(r"((?:#\[[^\]]*\]\s*)*)pub fn sign_bytes_with_seed", text)
        if not m or '#[cfg(any(test, feature = "pq-kat"))]' not in m.group(1):
            errors.append("MlDsa65Backend::sign_bytes_with_seed must be gated by #[cfg(any(test, feature = \"pq-kat\"))]")
    for manifest in sorted(root.glob("**/Cargo.toml")):
        rel = manifest.relative_to(root).as_posix()
        if "/target/" in f"/{rel}" or rel.startswith("target/"):
            continue
        section = ""
        for raw in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("["):
                section = line
                continue
            for feature in ("pq-kat",):
                if f'"{feature}"' not in line and f"/{feature}" not in line:
                    continue
                if section == "[features]" and rel in (
                    "crates/core/chio-core-types/Cargo.toml",
                    "crates/core/chio-core/Cargo.toml",
                ):
                    continue
                if section.startswith("[dev-dependencies") or section == "[[test]]":
                    continue
                errors.append(f"{rel} {section}: production build enables {feature}")
    core = root / "crates/core/chio-core/Cargo.toml"
    if core.exists():
        text = core.read_text()
        if re.search(r"^default\s*=\s*\[[^\]]*pq-kat", text, re.M):
            errors.append("chio-core default features enable pq-kat")
    types_manifest = root / "crates/core/chio-core-types/Cargo.toml"
    if types_manifest.exists() and re.search(
        r"^default\s*=\s*\[[^\]]*pq-kat", types_manifest.read_text(), re.M
    ):
        errors.append("chio-core-types default features enable pq-kat")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    observed, unresolved = scan(root)
    if args.print:
        for key, count in sorted(observed.items()):
            print(f"{key}: {count}")
        for item in unresolved:
            print("UNRESOLVED", item)
        return 0
    errors = list(unresolved) + check_gates(root)
    expected = collections.Counter(ALLOWLIST)
    for key in sorted(set(observed) | set(expected)):
        if observed[key] != expected[key]:
            errors.append(f"{key}: observed {observed[key]}, allowed {expected[key]}")
    if errors:
        print("check-signing-exemptions: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"check-signing-exemptions: ok ({sum(observed.values())} exempt call sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
