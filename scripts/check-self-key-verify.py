#!/usr/bin/env python3
"""Fail on any production verify call that trusts a key the verified artifact carries itself.

Two kinds of site are tracked outside tests, each keyed by (file, enclosing fn) with its class
and call count:

  SELF_KEY_SITES        a verify call whose key argument is a field of the artifact under
                        verification (signer_key, kernel_key, issuer, authority_key, ...)
  EMBEDDED_KEY_CALLERS  a call to a chio-core-types verify_integrity_embedded_key* method

Classes:

  PINNED                         the carried key is compared with a trusted key first
  GUARDED                        a trusted key or membership check on the carried key gates use
  INTEGRITY-ONLY                 no authorization decision depends on the result
  NEEDS-TRUST-CONTEXT:<row id>   an authorization path whose trusted key arrives in <row id>

Each observed multiset must equal its list: a new site fails, a removed site fails until its
entry is deleted, so the lists only shrink.

Usage: check-self-key-verify.py [--root DIR] [--print]
"""

import argparse
import collections
import re
import sys
from pathlib import Path

CLASSES = re.compile(r"^(PINNED|GUARDED|INTEGRITY-ONLY|NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-[A-Z0-9-]+)$")

# (file, enclosing fn): (class, count)
SELF_KEY_SITES: dict[tuple[str, str], tuple[str, int]] = {}
EMBEDDED_KEY_CALLERS: dict[tuple[str, str], tuple[str, int]] = {}

CARRIED = r"(?:signer_key|kernel_key|issuer|authority_key|signer|producer_key|root_issuer|approver|delegator|public_key|policy_authority)"
CALL = re.compile(
    r"\b(?:verify_signature(?:_with_floor|_against)?|verify_wrapped(?:_bytes)?)\(\s*&?\s*(?P<expr>(?:self|[a-z_][\w]*)(?:\.[a-z_][\w]*|\(\))*\."
    + CARRIED
    + r")\b"
)
EMBEDDED = re.compile(r"\bverify_integrity_embedded_key\w*\s*\(")
TEST_PATH = re.compile(r"(^|/)(tests|benches|examples|fixtures)/|(^|/)tests\.rs$|_tests?\.rs$|_tests/|test_support")
CFG_TEST = re.compile(r"#\[cfg\((?:test|any\([^)]*\btest\b[^)]*\))\)\]")


def gated_module_files(root):
    gated = set()
    for path in root.joinpath("crates").rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text):
            name = m.group(1)
            explicit = re.search(r"#\[path\s*=\s*\"([^\"]+)\"\]\s*$", text[: m.start()].rstrip())
            base = path.parent if path.stem in ("mod", "lib", "main") else path.parent / path.stem
            candidates = [path.parent / explicit.group(1)] if explicit else []
            candidates += [base / f"{name}.rs", base / name / "mod.rs", path.parent / f"{name}.rs"]
            for cand in candidates:
                if cand.exists():
                    gated.add(cand.resolve())
                    if cand.name == "mod.rs":
                        gated.update(p.resolve() for p in cand.parent.rglob("*.rs"))
    return gated


def strip_test_items(text):
    out = list(text)
    for m in CFG_TEST.finditer(text):
        i, depth, started = m.end(), 0, False
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


def scan(root):
    gated = gated_module_files(root)
    self_key = collections.Counter()
    embedded = collections.Counter()
    for path in sorted(root.joinpath("crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if TEST_PATH.search(rel) or path.resolve() in gated:
            continue
        text = strip_test_items(path.read_text(encoding="utf-8", errors="replace"))
        text = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
        fns = [(m.start(), m.group(1)) for m in re.finditer(r"\bfn\s+(\w+)", text)]
        for pattern, observed in ((CALL, self_key), (EMBEDDED, embedded)):
            for m in pattern.finditer(text):
                if text[: m.start()].rstrip().endswith("fn"):
                    continue
                enclosing = "<module>"
                for pos, name in fns:
                    if pos < m.start():
                        enclosing = name
                if observed is embedded and enclosing.startswith("verify_integrity_embedded_key"):
                    continue
                observed[(rel, enclosing)] += 1
    return self_key, embedded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    self_key, embedded = scan(root)
    tracked = (
        ("SELF_KEY_SITES", "self-key verify", self_key, SELF_KEY_SITES),
        ("EMBEDDED_KEY_CALLERS", "embedded-key verify", embedded, EMBEDDED_KEY_CALLERS),
    )
    if args.print:
        for list_name, _, observed, _ in tracked:
            print(f"{list_name} = {{")
            for (rel, fn), count in sorted(observed.items()):
                print(f'    ("{rel}", "{fn}"): ("UNCLASSIFIED", {count}),')
            print("}")
        return 0
    errors = []
    for list_name, label, observed, allowlist in tracked:
        for key, (cls, _) in sorted(allowlist.items()):
            if not CLASSES.match(cls):
                errors.append(f"{list_name} {key}: invalid class {cls}")
        for key in sorted(set(observed) | set(allowlist)):
            allowed = allowlist.get(key, (None, 0))[1]
            if observed[key] != allowed:
                errors.append(f"{list_name} {key}: observed {observed[key]} {label} call(s), allowed {allowed}")
    if errors:
        print("check-self-key-verify: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(
        f"check-self-key-verify: ok ({sum(self_key.values())} self-key sites, "
        f"{sum(embedded.values())} embedded-key callers)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
