#!/usr/bin/env python3
"""Fail on any production verify call that trusts a key the verified artifact carries itself.

A self-key verify passes a field of the artifact under verification (signer_key, kernel_key,
issuer, authority_key, ...) as the verifying key. Every such site outside tests must appear in
ALLOWLIST, keyed by (file, enclosing fn), with its class and call count:

  INTEGRITY-ONLY                 no authorization decision depends on the result
  NEEDS-TRUST-CONTEXT:<row id>   an authorization path whose trusted key arrives in <row id>

The observed multiset must equal ALLOWLIST: a new site fails, a removed site fails until its
entry is deleted, so the list only shrinks.

Usage: check-self-key-verify.py [--root DIR] [--print]
"""

import argparse
import collections
import re
import sys
from pathlib import Path

CLASSES = re.compile(r"^(INTEGRITY-ONLY|NEEDS-TRUST-CONTEXT:SELF-KEY-PIN-[A-Z0-9-]+)$")

# (file, enclosing fn): (class, count)
ALLOWLIST: dict[tuple[str, str], tuple[str, int]] = {}

CARRIED = r"(?:signer_key|kernel_key|issuer|authority_key|signer|producer_key|root_issuer|approver|delegator|public_key)"
CALL = re.compile(
    r"\b(?:verify_signature(?:_with_floor)?|verify_wrapped(?:_bytes)?)\(\s*&?\s*(?P<expr>(?:self|[a-z_][\w]*)(?:\.[a-z_][\w]*|\(\))*\."
    + CARRIED
    + r")\b"
)
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
    observed = collections.Counter()
    for path in sorted(root.joinpath("crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if TEST_PATH.search(rel) or path.resolve() in gated:
            continue
        text = strip_test_items(path.read_text(encoding="utf-8", errors="replace"))
        text = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
        fns = [(m.start(), m.group(1)) for m in re.finditer(r"\bfn\s+(\w+)", text)]
        for m in CALL.finditer(text):
            enclosing = "<module>"
            for pos, name in fns:
                if pos < m.start():
                    enclosing = name
            observed[(rel, enclosing)] += 1
    return observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    observed = scan(root)
    if args.print:
        for (rel, fn), count in sorted(observed.items()):
            print(f'    ("{rel}", "{fn}"): ("UNCLASSIFIED", {count}),')
        return 0
    errors = []
    for key, (cls, _) in sorted(ALLOWLIST.items()):
        if not CLASSES.match(cls):
            errors.append(f"{key}: invalid class {cls}")
    for key in sorted(set(observed) | set(ALLOWLIST)):
        allowed = ALLOWLIST.get(key, (None, 0))[1]
        if observed[key] != allowed:
            errors.append(f"{key}: observed {observed[key]} self-key verify call(s), allowed {allowed}")
    if errors:
        print("check-self-key-verify: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"check-self-key-verify: ok ({sum(observed.values())} classified self-key sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
