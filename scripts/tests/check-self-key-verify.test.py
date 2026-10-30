#!/usr/bin/env python3
"""Behavior tests for scripts/check-self-key-verify.py over synthetic trees."""

import collections
import hashlib
import importlib.util
import subprocess
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


CHECKPOINTS = """
pub fn carried(checkpoint: &KernelCheckpoint) -> Result<()> {
    validate_checkpoint(checkpoint, std::slice::from_ref(&checkpoint.body.kernel_key))
}

pub fn carried_from_element(checkpoints: &[KernelCheckpoint]) -> Result<()> {
    validate_checkpoint_transparency(checkpoints, &[checkpoints[0].body.kernel_key.clone()])
}

pub fn pinned(checkpoint: &KernelCheckpoint, trusted: &[PublicKey]) -> Result<()> {
    validate_checkpoint(checkpoint, trusted)
}

pub fn pinned_to_receipt(checkpoint: &KernelCheckpoint, receipt: &ChioReceipt) -> Result<()> {
    verify_checkpoint_signature(checkpoint, std::slice::from_ref(&receipt.kernel_key))
}
"""


def test_checkpoint_entry_trusting_its_own_kernel_key_is_a_self_key_site():
    self_key, _ = observed({FILE: CHECKPOINTS})
    assert self_key == collections.Counter(
        {
            (FILE, "carried"): 1,
            (FILE, "carried_from_element"): 1,
        }
    ), self_key

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


HEADER = "file\tfn\tcount\tarea\tfollow_up\n"
ROWS = (
    f"{FILE}\texempt_form\t1\tSELF-KEY-PIN-ECONOMY\tdemo exempt trust source\n"
    f"{FILE}\tmethod_form\t1\tSELF-KEY-PIN-ECONOMY\tdemo method trust source\n"
)
EMBEDDED_ONLY = {(FILE, "admit"): ("GUARDED", 1)}
QUIET = """
pub fn admit(envelope: &Envelope, trusted: &PublicKey) -> Result<()> {
    if envelope.body.submitter != *trusted || !envelope.verify_integrity_embedded_key()? {
        return Err(Error::Untrusted);
    }
    Ok(())
}
"""


def baseline_errors(text):
    self_key, embedded = observed({FILE: SOURCE})
    try:
        rows = gate.parse_baseline(text)
    except gate.BaselineError as error:
        return [str(error)]
    return gate.check(self_key, embedded, {}, EMBEDDED_ONLY, rows)


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_approved_initial_baseline_passes():
    text = HEADER + ROWS
    assert not baseline_errors(text)
    original = gate.APPROVED_INITIAL_BASELINE_SHA256
    gate.APPROVED_INITIAL_BASELINE_SHA256 = digest(text)
    try:
        assert not gate.check_against_base(text, gate.parse_baseline(text), None, False)
    finally:
        gate.APPROVED_INITIAL_BASELINE_SHA256 = original


def test_initial_baseline_digest_mismatch_fails():
    text = HEADER + ROWS
    errors = gate.check_against_base(text, gate.parse_baseline(text), None, False)
    assert any("is not the approved" in error for error in errors), errors


def test_base_with_gate_but_no_baseline_fails():
    text = HEADER + ROWS
    errors = gate.check_against_base(text, gate.parse_baseline(text), None, True)
    assert any("without" in error for error in errors), errors


def test_extra_baseline_row_fails():
    text = HEADER + ROWS + f"{FILE}\tvanished\t1\tSELF-KEY-PIN-ECONOMY\tdemo\n"
    errors = baseline_errors(text)
    assert any("vanished" in error for error in errors), errors


def test_stale_baseline_row_fails():
    text = HEADER + f"{FILE}\texempt_form\t2\tSELF-KEY-PIN-ECONOMY\tdemo\n" + ROWS.splitlines(True)[1]
    errors = baseline_errors(text)
    assert any("exempt_form" in error and "baseline 2" in error for error in errors), errors


def test_observed_site_missing_from_baseline_fails():
    errors = baseline_errors(HEADER + ROWS.splitlines(True)[0])
    assert any("method_form" in error for error in errors), errors


def test_missing_baseline_file_fails_closed():
    root = tree({FILE: SOURCE})
    try:
        gate.read_baseline(root)
    except gate.BaselineError as error:
        assert "unreadable" in str(error)
    else:
        raise AssertionError("a missing baseline must fail closed")


def test_unreadable_baseline_file_fails_closed():
    root = tree({FILE: SOURCE})
    (root / gate.BASELINE).parent.mkdir(parents=True, exist_ok=True)
    (root / gate.BASELINE).write_bytes(b"\xff\xfe")
    try:
        gate.read_baseline(root)
    except gate.BaselineError as error:
        assert "unreadable" in str(error)
    else:
        raise AssertionError("an undecodable baseline must fail closed")
    for text in ("", "file,fn,count,area,follow_up\n", HEADER + ROWS + ROWS.splitlines(True)[0]):
        assert baseline_errors(text), text
    unsorted = HEADER + "".join(reversed(ROWS.splitlines(True)))
    assert any("sorted" in error for error in baseline_errors(unsorted))
    for bad in ("0", "-1", "x"):
        row = f"{FILE}\texempt_form\t{bad}\tSELF-KEY-PIN-ECONOMY\tdemo\n"
        assert any("count" in error for error in baseline_errors(HEADER + row)), bad
    for row in (
        f"{FILE}\texempt_form\t1\tSELF-KEY-PIN-ECONOMY\t \n",
        f"{FILE}\texempt_form\t1\tSELF-KEY-PIN-UNKNOWN\tdemo\n",
    ):
        assert baseline_errors(HEADER + row), row


def test_wildcard_baseline_row_fails():
    for file, fn in ((FILE, "*"), ("crates/economy/*/src/envelope.rs", "exempt_form"), (FILE, "exempt_[a-z]")):
        errors = baseline_errors(HEADER + f"{file}\t{fn}\t1\tSELF-KEY-PIN-ECONOMY\tdemo\n")
        assert any("literal" in error for error in errors), (file, fn, errors)


def test_kernel_baseline_row_fails():
    errors = baseline_errors(HEADER + f"{KERNEL}\tmethod_form\t1\tSELF-KEY-PIN-ECONOMY\tdemo\n")
    assert any("kernel sites cannot be baselined" in error for error in errors), errors


def test_embedded_needs_trust_context_entry_fails():
    self_key, embedded = observed({FILE: SOURCE})
    allowed_self = {key: ("NEEDS-TRUST-CONTEXT", count) for key, count in self_key.items()}
    errors = gate.check(self_key, embedded, allowed_self, EMBEDDED_ONLY, {})
    assert any("invalid class NEEDS-TRUST-CONTEXT" in error for error in errors), errors


def test_shrunk_baseline_passes_against_base():
    base = HEADER + ROWS
    lowered = f"{FILE}\texempt_form\t1\tSELF-KEY-PIN-ECONOMY\tdemo exempt trust source\n"
    base_raised = HEADER + f"{FILE}\texempt_form\t2\tSELF-KEY-PIN-ECONOMY\tdemo exempt trust source\n" + ROWS.splitlines(True)[1]
    for working in (HEADER + ROWS.splitlines(True)[1], HEADER + lowered):
        assert not gate.check_against_base(working, gate.parse_baseline(working), base_raised, True), working
    assert not gate.check_against_base(base, gate.parse_baseline(base), base, True)


def test_grown_baseline_fails_against_base():
    base = HEADER + ROWS.splitlines(True)[0]
    added = HEADER + ROWS
    errors = gate.check_against_base(added, gate.parse_baseline(added), base, True)
    assert any("row added" in error for error in errors), errors
    raised = HEADER + f"{FILE}\texempt_form\t2\tSELF-KEY-PIN-ECONOMY\tdemo exempt trust source\n"
    errors = gate.check_against_base(raised, gate.parse_baseline(raised), base, True)
    assert any("count raised" in error for error in errors), errors
    renamed = HEADER + f"{FILE}\texempt_form\t1\tSELF-KEY-PIN-ECONOMY\tanother follow-up\n"
    errors = gate.check_against_base(renamed, gate.parse_baseline(renamed), base, True)
    assert any("follow_up changed" in error for error in errors), errors


def release_errors(files, baseline_text):
    root = tree(files)
    if baseline_text is not None:
        (root / gate.BASELINE).parent.mkdir(parents=True, exist_ok=True)
        (root / gate.BASELINE).write_text(baseline_text)
    self_key, embedded = gate.scan(root)
    errors, _ = gate.evaluate(root, self_key, embedded, release=True, self_key_list={}, embedded_list=EMBEDDED_ONLY)
    return errors


def test_release_fails_while_baseline_has_a_row():
    errors = release_errors({FILE: SOURCE}, HEADER + ROWS)
    assert errors == [f"{gate.BASELINE}: release requires an empty baseline, 2 row(s) remain"], errors


def test_release_passes_with_empty_baseline():
    root_errors = release_errors({FILE: QUIET}, HEADER)
    assert root_errors == [], root_errors
    assert any("unreadable" in error for error in release_errors({FILE: QUIET}, None))


def test_base_ref_that_cannot_be_read_fails():
    root = tree({FILE: QUIET})
    (root / gate.BASELINE).parent.mkdir(parents=True, exist_ok=True)
    (root / gate.BASELINE).write_text(HEADER)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    self_key, embedded = gate.scan(root)
    errors, _ = gate.evaluate(root, self_key, embedded, base="no-such-ref", self_key_list={}, embedded_list=EMBEDDED_ONLY)
    assert any("not a readable commit" in error for error in errors), errors

def main():
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"check-self-key-verify tests: {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
