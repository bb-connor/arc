#!/usr/bin/env python3
"""Self-test for scripts/check-error-urn-registry.py."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(os.environ.get("CHECK_ERROR_URN_REGISTRY", Path(__file__).resolve().parent.parent / "check-error-urn-registry.py"))

REGISTRY = """schema: "chio.error-urn-registry.v1"
codes:
  - urn: "urn:chio:error:kernel:known"
    domain: kernel
  - urn: "urn:chio:error:transport:family-alpha"
    domain: transport
"""

failures: list[str] = []


def run(files: dict[str, str] | None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        if files is not None:
            (root / "spec/errors").mkdir(parents=True)
            (root / "spec/errors/registry.yaml").write_text(REGISTRY, encoding="utf-8")
            for relative, text in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def expect(name: str, files: dict[str, str] | None, exit_code: int, mentions: str = "") -> None:
    result = run(files)
    if result.returncode != exit_code:
        failures.append(f"{name}: expected exit {exit_code}, got {result.returncode}\n{result.stdout}{result.stderr}")
    elif mentions and mentions not in result.stderr:
        failures.append(f"{name}: expected {mentions!r} in\n{result.stderr}")


LIB = "crates/kernel/demo/src/lib.rs"


def code(literal: str) -> str:
    return f'pub fn code() -> &\'static str {{ "{literal}" }}\n'


expect("registered literal", {LIB: code("urn:chio:error:kernel:known")}, 0)
expect("unknown literal", {LIB: code("urn:chio:error:kernel:unknown")}, 1, "urn:chio:error:kernel:unknown: crates/kernel/demo/src/lib.rs:1")
expect("uppercase suffix after a registered code", {LIB: code("urn:chio:error:kernel:knownXYZ")}, 1, "urn:chio:error:kernel:knownXYZ")
expect("dotted suffix after a registered code", {LIB: code("urn:chio:error:kernel:known.v2")}, 1, "urn:chio:error:kernel:known.v2")
expect("exact family stem without interpolation", {LIB: code("urn:chio:error:transport:family-")}, 1, "urn:chio:error:transport:family-")
expect("registered family stem with interpolation", {LIB: 'format!("urn:chio:error:transport:family-{rule}")\n'}, 0)
expect("positional interpolation", {LIB: 'format!("urn:chio:error:transport:family-{}", rule)\n'}, 0)
expect("unregistered stem with interpolation", {LIB: 'format!("urn:chio:error:transport:missing-{rule}")\n'}, 1, "urn:chio:error:transport:missing-")
expect("escaped brace is not interpolation", {LIB: 'format!("urn:chio:error:transport:family-{{x}}")\n'}, 1, "urn:chio:error:transport:family-")
expect("registered family prefix test", {LIB: 'fn f(c: &str) -> bool { c.starts_with("urn:chio:error:transport:family-") }\n'}, 0)
expect("unregistered family prefix test", {LIB: 'fn f(c: &str) -> bool { c.starts_with("urn:chio:error:transport:other-") }\n'}, 1, "urn:chio:error:transport:other-")
expect("bare namespace", {LIB: 'let prefix = "urn:chio:error:";\n'}, 0)
expect("literal on a later line", {"crates/kernel/demo/src/a/b.rs": '\n\nconst X: &str =\n    "urn:chio:error:kernel:other";\n'}, 1, "crates/kernel/demo/src/a/b.rs:4")
expect("raw string", {LIB: 'const X: &str = r#"{"code":"urn:chio:error:kernel:raw"}"#;\n'}, 1, "urn:chio:error:kernel:raw")
expect("byte string", {LIB: 'const X: &[u8] = b"urn:chio:error:kernel:bytes";\n'}, 1, "urn:chio:error:kernel:bytes")
expect("escaped quote before the code", {LIB: 'const X: &str = "say \\"x\\" urn:chio:error:kernel:escaped";\n'}, 1, "urn:chio:error:kernel:escaped")
expect("line comment", {LIB: '// "urn:chio:error:kernel:comment"\n'}, 0)
expect("block comment", {LIB: '/* outer /* nested */ "urn:chio:error:kernel:comment" */\n'}, 0)
expect("lifetime before a literal", {LIB: "fn f<'a>(x: &'a str) -> &'a str { \"urn:chio:error:kernel:after-lifetime\" }\n"}, 1, "urn:chio:error:kernel:after-lifetime")
expect("quote character literal", {LIB: "const Q: char = '\"'; const X: &str = \"urn:chio:error:kernel:after-char\";\n"}, 1, "urn:chio:error:kernel:after-char")
expect(
    "compiled non-registry generated module",
    {LIB: "mod _generated; pub use _generated::code;\n", "crates/kernel/demo/src/_generated/mod.rs": code("urn:chio:error:kernel:unknown")},
    1,
    "crates/kernel/demo/src/_generated/mod.rs:1",
)
expect(
    "registry generated module",
    {"crates/core/chio-errors/src/_generated/error_codes.rs": code("urn:chio:error:kernel:unknown")},
    0,
)
expect(
    "compiled .inc fragment",
    {LIB: 'include!("codes.inc");\n', "crates/kernel/demo/src/codes.inc": code("urn:chio:error:kernel:unknown")},
    1,
    "crates/kernel/demo/src/codes.inc:1",
)
expect(
    "include! target outside src",
    {LIB: 'include!("../shared/codes.rs");\n', "crates/kernel/demo/shared/codes.rs": code("urn:chio:error:kernel:shared")},
    1,
    "crates/kernel/demo/shared/codes.rs:1",
)
expect("percent-encoded suffix", {LIB: code("urn:chio:error:kernel:known%2Fextra")}, 1, "urn:chio:error:kernel:known%2Fextra")
expect("slash suffix", {LIB: code("urn:chio:error:kernel:known/extra")}, 1, "urn:chio:error:kernel:known/extra")
expect("plus suffix", {LIB: code("urn:chio:error:kernel:known+extra")}, 1, "urn:chio:error:kernel:known+extra")
expect("hex escape forming a valid slug", {LIB: code("urn:chio:error:kernel:known\\x2dextra")}, 1, "urn:chio:error:kernel:known-extra")
expect("unicode escape forming a valid slug", {LIB: code("urn:chio:error:kernel:known\\u{2d}extra")}, 1, "urn:chio:error:kernel:known-extra")
expect("line continuation inside a code", {LIB: 'const X: &str = "urn:chio:error:kernel:kn\\\n        own";\n'}, 0)
expect("escaped registered code", {LIB: code("urn:chio:error:kernel:know\\x6e")}, 0)
expect("placeholder in an ordinary literal", {LIB: code("urn:chio:error:transport:family-{unknown}")}, 1, "urn:chio:error:transport:family-")
expect("placeholder in a write! format string", {LIB: 'fn f(o: &mut String, r: &str) { let _ = write!(o, "urn:chio:error:transport:family-{r}"); }\n'}, 0)
expect("placeholder in format_args!", {LIB: 'fn f(r: &str) { let _ = format_args!("urn:chio:error:transport:family-{}", r); }\n'}, 0)
expect("placeholder in a non-format macro", {LIB: 'fn f() { let _ = vec!["urn:chio:error:transport:family-{x}"]; }\n'}, 1, "urn:chio:error:transport:family-")
expect(
    "raw include! outside src",
    {LIB: 'include!(r#"../shared/codes.fragment"#);\n', "crates/kernel/demo/shared/codes.fragment": code("urn:chio:error:kernel:unknown")},
    1,
    "crates/kernel/demo/shared/codes.fragment:1",
)
expect(
    "recursive include! outside src",
    {
        LIB: 'include!("../shared/chain.fragment");\n',
        "crates/kernel/demo/shared/chain.fragment": 'include!("codes.fragment");\n',
        "crates/kernel/demo/shared/codes.fragment": code("urn:chio:error:kernel:unknown"),
    },
    1,
    "crates/kernel/demo/shared/codes.fragment:1",
)
expect(
    "registered code through include!",
    {LIB: 'include!("../shared/codes.fragment");\n', "crates/kernel/demo/shared/codes.fragment": code("urn:chio:error:kernel:known")},
    0,
)
expect("missing include! target", {LIB: 'include!("../shared/absent.fragment");\n'}, 1, "absent.fragment")
expect("include! target outside the repository", {LIB: 'include!("../../../../../outside.rs");\n'}, 1, "outside.rs")
for test_only in (
    "crates/kernel/demo/src/tests.rs",
    "crates/kernel/demo/src/store_tests.rs",
    "crates/kernel/demo/src/tests/case.rs",
    "crates/kernel/demo/src/hosted_tests/case.rs",
    "crates/kernel/demo/tests/integration.rs",
):
    expect(f"skipped {test_only}", {test_only: code("urn:chio:error:kernel:unknown")}, 0)
expect("missing registry", None, 2)

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("check-error-urn-registry.test.py: all assertions passed")
