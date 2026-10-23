#!/usr/bin/env python3
"""Behavior tests for scripts/check-self-key-verify.py over synthetic trees."""

import collections
import importlib.util
import sys
import tempfile
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-self-key-verify.py"
spec = importlib.util.spec_from_file_location("check_self_key_verify", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

FILE = "crates/economy/chio-demo/src/envelope.rs"
KERNEL = "crates/kernel/chio-demo-kernel/src/admit.rs"

SOURCE = """
impl Envelope {
    pub fn verify_integrity_embedded_key(&self) -> Result<bool> {
        wrapped_verdict(verify_wrapped(&self.body.submitter, SCHEMA, &self.body, &self.signature))
    }
}

pub fn admit(envelope: &Envelope, trusted: &PublicKey) -> Result<()> {
    if envelope.body.submitter != *trusted || !envelope.verify_integrity_embedded_key()? {
        return Err(Error::Untrusted);
    }
    verify_wrapped(trusted, SCHEMA, &envelope.body, &envelope.signature)
}

pub fn method_form(envelope: &Envelope) -> Result<bool> {
    envelope
        .proof
        .verify_signature(&envelope.proof.declared_public_key)
}

pub fn exempt_form(jws: &Jws) -> Result<()> {
    verify_exempt(&jws.header.key, ExemptFormat::JwsSigningInput, jws.input(), &jws.signature)
}

pub fn literal(text: &str) {
    let _ = "verify_wrapped(&self.signer_key, SCHEMA, &self.body, &self.signature)";
    // verify_wrapped(&env.signer_key, SCHEMA, &env.body, &env.signature)
}

#[cfg(all(test, not(loom)))]
mod tests {
    fn untracked(env: &Envelope) {
        let _ = verify_wrapped(&env.signer_key, SCHEMA, &env.body, &env.signature);
        let _ = env.verify_integrity_embedded_key();
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


def observed(files):
    return gate.scan(tree(files))


def test_structural_self_key_sites_are_found():
    self_key, _ = observed({FILE: SOURCE})
    assert self_key == collections.Counter(
        {
            (FILE, "verify_integrity_embedded_key"): 1,
            (FILE, "method_form"): 1,
            (FILE, "exempt_form"): 1,
        }
    ), self_key


def test_pinned_key_argument_is_not_a_self_key_site():
    self_key, _ = observed({FILE: SOURCE})
    assert (FILE, "admit") not in self_key


def test_embedded_callers_are_tracked_outside_test_code():
    _, embedded = observed({FILE: SOURCE})
    assert embedded == collections.Counter({(FILE, "admit"): 1}), embedded


def test_new_unlisted_site_fails():
    self_key, embedded = observed({FILE: SOURCE})
    allowed_self = {key: ("INTEGRITY-ONLY", count) for key, count in self_key.items()}
    allowed_embedded = {key: ("GUARDED", count) for key, count in embedded.items()}
    assert not gate.check(self_key, embedded, allowed_self, allowed_embedded)
    del allowed_self[(FILE, "method_form")]
    errors = gate.check(self_key, embedded, allowed_self, allowed_embedded)
    assert any("method_form" in error for error in errors), errors


def test_stale_entry_fails():
    self_key, embedded = observed({FILE: SOURCE})
    allowed_self = {key: ("INTEGRITY-ONLY", count) for key, count in self_key.items()}
    allowed_self[(FILE, "removed")] = ("PINNED", 1)
    errors = gate.check(self_key, embedded, allowed_self, {k: ("GUARDED", c) for k, c in embedded.items()})
    assert any("removed" in error for error in errors), errors


def test_kernel_sites_must_be_pinned_or_guarded():
    self_key, embedded = observed({KERNEL: SOURCE})
    allowed_embedded = {key: ("GUARDED", count) for key, count in embedded.items()}
    integrity = {key: ("INTEGRITY-ONLY", count) for key, count in self_key.items()}
    errors = gate.check(self_key, embedded, integrity, allowed_embedded)
    assert any("kernel sites must be PINNED or GUARDED" in error for error in errors), errors
    guarded = {key: ("GUARDED", count) for key, count in self_key.items()}
    assert not gate.check(self_key, embedded, guarded, allowed_embedded)


def test_invalid_class_fails():
    self_key, embedded = observed({FILE: SOURCE})
    allowed_self = {key: ("UNCLASSIFIED", count) for key, count in self_key.items()}
    errors = gate.check(self_key, embedded, allowed_self, {k: ("GUARDED", c) for k, c in embedded.items()})
    assert any("invalid class UNCLASSIFIED" in error for error in errors), errors


def main():
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"check-self-key-verify tests: {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
