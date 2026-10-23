#!/usr/bin/env python3
"""Behavior tests for scripts/check-signing-exemptions.py over synthetic trees."""

import collections
import importlib.util
import sys
import tempfile
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-signing-exemptions.py"
spec = importlib.util.spec_from_file_location("check_signing_exemptions", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

FILE = "crates/demo/chio-demo/src/jws.rs"
ALLOWED = {(FILE, "sign_jws", "JwsSigningInput"): 1}

CLEAN = """
use chio_core::crypto::ExemptFormat;

pub fn sign_jws(key: &Keypair, input: &str) -> Signature {
    key.sign_exempt(ExemptFormat::JwsSigningInput, input.as_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn untracked() {
        let _ = key.sign_exempt(ExemptFormat::DssePae, b"x");
    }
}
"""


def tree(files):
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text))
    return root


def result(files):
    observed, unresolved = gate.scan(tree(files))
    expected = collections.Counter(ALLOWED)
    mismatched = [k for k in set(observed) | set(expected) if observed[k] != expected[k]]
    return not unresolved and not mismatched


def test_clean_tree_passes():
    assert result({FILE: CLEAN})


def test_extra_call_in_allowed_function_fails():
    extra = CLEAN.replace(
        "    key.sign_exempt(ExemptFormat::JwsSigningInput, input.as_bytes())\n",
        "    key.sign_exempt(ExemptFormat::JwsSigningInput, b\"a\");\n"
        "    key.sign_exempt(ExemptFormat::JwsSigningInput, input.as_bytes())\n",
    )
    assert not result({FILE: extra})


def test_extra_call_in_allowed_file_other_function_fails():
    extra = CLEAN + """
pub fn another(key: &Keypair) -> Signature {
    key.sign_exempt(ExemptFormat::JwsSigningInput, b"other")
}
"""
    assert not result({FILE: extra})


def test_imported_renamed_and_qualified_spellings_are_counted():
    spellings = [
        "use chio_core::crypto::SigningMessage;\nfn x() { backend.sign_bytes(SigningMessage::exempt(ExemptFormat::DssePae, b)); }\n",
        "use chio_core::crypto::{SigningMessage as Msg};\nfn x() { backend.sign_bytes(Msg::exempt(ExemptFormat::DssePae, b)); }\n",
        "fn x() { chio_core::crypto::verify_exempt(&k, chio_core::crypto::ExemptFormat::DssePae, b, &s); }\n",
        "use chio_core::crypto::verify_exempt as check;\nfn x() { check(&k, ExemptFormat::DssePae, b, &s); }\n",
    ]
    for body in spellings:
        observed, unresolved = gate.scan(tree({FILE: CLEAN, "crates/demo/chio-demo/src/extra.rs": body}))
        assert not unresolved, body
        assert observed[("crates/demo/chio-demo/src/extra.rs", "x", "DssePae")] == 1, body
        assert not result({FILE: CLEAN, "crates/demo/chio-demo/src/extra.rs": body})


def test_removed_allowlisted_call_fails():
    removed = CLEAN.replace(
        "    key.sign_exempt(ExemptFormat::JwsSigningInput, input.as_bytes())\n", "    todo()\n"
    )
    assert not result({FILE: removed})


def test_changed_format_fails():
    assert not result({FILE: CLEAN.replace("ExemptFormat::JwsSigningInput", "ExemptFormat::DssePae", 1)})


def test_call_in_unlisted_file_fails():
    assert not result({FILE: CLEAN, "crates/demo/chio-demo/src/new.rs": "fn y() { k.sign_exempt(ExemptFormat::JwsSigningInput, b); }\n"})


def test_unresolvable_format_fails():
    observed, unresolved = gate.scan(tree({FILE: CLEAN, "crates/demo/chio-demo/src/var.rs": "fn z(f: ExemptFormat) { k.sign_exempt(f, b); }\n"}))
    assert unresolved


def test_kat_signer_without_gate_fails():
    root = tree({"crates/core/chio-core-types/src/pq.rs": "    pub fn sign_bytes_with_seed(&self) {}\n"})
    assert gate.check_gates(root)
    root = tree({"crates/core/chio-core-types/src/pq.rs": '    #[cfg(any(test, feature = "pq-kat"))]\n    pub fn sign_bytes_with_seed(&self) {}\n'})
    assert not gate.check_gates(root)


def test_production_feature_enable_fails():
    root = tree({"crates/x/chio-x/Cargo.toml": '[dependencies]\nchio-core-types = { workspace = true, features = ["wrapper-capture"] }\n'})
    assert gate.check_gates(root)
    root = tree({"crates/x/chio-x/Cargo.toml": '[dev-dependencies]\nchio-core-types = { workspace = true, features = ["wrapper-capture"] }\n'})
    assert not gate.check_gates(root)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"ok {test.__name__}")
    print(f"{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
