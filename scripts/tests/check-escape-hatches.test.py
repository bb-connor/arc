#!/usr/bin/env python3
"""Prove the escape-hatch gate fails on each violating fixture and passes on main."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

root = Path(__file__).resolve().parents[2]
checker = root / "scripts/check-escape-hatches.py"
spec = importlib.util.spec_from_file_location("escape_hatches", checker)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

KERNEL = "crates/kernel/chio-kernel/src/token.rs"
STORE = "crates/platform/chio-store-sqlite/src/cache.rs"
BASE = """
pub struct Sealed(u64);
impl Sealed {
    pub fn verify(raw: u64) -> Option<Self> { (raw > 0).then_some(Self(raw)) }
    #[cfg(test)]
    pub(crate) fn for_test(raw: u64) -> Self { Self(raw) }
}
"""
ALLOWED = {f"{KERNEL}::for_test": 1}

VIOLATING = {
    "unlisted test constructor": (
        {KERNEL: BASE + "impl Sealed { pub fn new_for_test() -> Self { Self(1) } }"},
        ALLOWED,
        f"new escape hatch: {KERNEL}::new_for_test (+1)",
    ),
    "unchecked constructor": (
        {KERNEL: BASE + "impl Sealed { pub fn new_unchecked(raw: u64) -> Self { Self(raw) } }"},
        ALLOWED,
        f"new escape hatch: {KERNEL}::new_unchecked (+1)",
    ),
    "raw and storage exits": (
        {
            KERNEL: BASE
            + "impl Sealed { pub fn from_raw(raw: u64) -> Self { Self(raw) }"
            + " pub fn into_raw_for_storage(self) -> u64 { self.0 } }"
        },
        ALLOWED,
        f"new escape hatch: {KERNEL}::from_raw (+1)",
    ),
    "trusted-caller constructor": (
        {KERNEL: BASE + "impl Sealed { pub(crate) fn from_trusted_context(raw: u64) -> Self { Self(raw) } }"},
        ALLOWED,
        f"new escape hatch: {KERNEL}::from_trusted_context (+1)",
    ),
    "kani assumption helper": (
        {KERNEL: BASE + "#[cfg(kani)] fn assume_nonzero(value: u64) { kani::assume(value > 0); }"},
        ALLOWED,
        f"new escape hatch: {KERNEL}::assume_nonzero (+1)",
    ),
    "second impl borrows a listed name": (
        {KERNEL: BASE + "pub struct Other(u64);\nimpl Other { pub fn for_test() -> Self { Self(0) } }"},
        ALLOWED,
        f"new escape hatch: {KERNEL}::for_test (+1)",
    ),
    "listed hatch moved to another file": (
        {"crates/kernel/chio-kernel/src/moved.rs": BASE},
        ALLOWED,
        "new escape hatch: crates/kernel/chio-kernel/src/moved.rs::for_test (+1)",
    ),
    "hatch in a TCB crate outside the declared roots": (
        {KERNEL: BASE, STORE: "impl Row { fn from_stored(raw: u64) -> Self { Self(raw) } }"},
        ALLOWED,
        f"new escape hatch: {STORE}::from_stored (+1)",
    ),
    "listed hatch removed": (
        {KERNEL: BASE.replace("for_test", "with_value")},
        ALLOWED,
        f"removed escape hatch still listed: {KERNEL}::for_test (-1); run --ratchet",
    ),
}

PASSING = {
    "listed hatch": ({KERNEL: BASE}, ALLOWED),
    "comments, literals, tests and non-TCB crates": (
        {
            KERNEL: BASE
            + """
// fn from_raw(raw: u64) -> Self
/* fn new_unchecked() {} */
const NOTE: &str = "fn into_raw_for_storage(self)";
pub fn checked_sub(a: u64, b: u64) -> Option<u64> { a.checked_sub(b) }
#[cfg(test)]
mod tests {
    #[test]
    fn from_raw_rejects_zero() {}
    #[tokio::test(flavor = "current_thread")]
    async fn unchecked_input_is_refused() {}
}
""",
            "crates/kernel/chio-kernel/tests/support.rs": "fn sealed_for_test() {}",
            "crates/kernel/chio-kernel/benches/raw.rs": "fn from_raw() {}",
            "crates/products/chio-cli/src/lib.rs": "fn from_raw() {}",
        },
        ALLOWED,
    ),
}


def run_gate(sources, allowed, *extra):
    with tempfile.TemporaryDirectory() as directory:
        case = Path(directory)
        hardening = case / "docs/security/toolchain/rust-hardening.json"
        hardening.parent.mkdir(parents=True)
        hardening.write_text(
            json.dumps(
                {
                    "tcb_libraries": {
                        "chio-kernel": "crates/kernel/chio-kernel/src/lib.rs",
                        "chio-store-sqlite": "crates/platform/chio-store-sqlite/src/lib.rs",
                    }
                }
            )
        )
        (case / gate.INVENTORY).parent.mkdir(parents=True)
        (case / gate.INVENTORY).write_text(
            json.dumps({"schema": gate.SCHEMA, "hatches": allowed})
        )
        for path, source in sources.items():
            (case / path).parent.mkdir(parents=True, exist_ok=True)
            (case / path).write_text(source)
        subprocess.run(["git", "init", "-q", str(case)], check=True)
        result = subprocess.run(
            [sys.executable, str(checker), "--root", str(case), *extra],
            capture_output=True,
            text=True,
        )
        inventory = json.loads((case / gate.INVENTORY).read_text())
    return result, inventory


class EscapeHatchGateTests(unittest.TestCase):
    def test_each_violating_fixture_fails(self):
        for label, (sources, allowed, message) in VIOLATING.items():
            with self.subTest(label):
                result, _ = run_gate(sources, allowed)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)

    def test_listed_and_non_hatch_sources_pass(self):
        for label, (sources, allowed) in PASSING.items():
            with self.subTest(label):
                result, _ = run_gate(sources, allowed)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Escape hatches: 1 listed across 1 files", result.stdout)

    def test_ratchet_drops_removed_hatches_and_never_adds(self):
        result, inventory = run_gate(
            {KERNEL: BASE.replace("for_test", "with_value")}, ALLOWED, "--ratchet"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(inventory["hatches"], {})
        result, inventory = run_gate(
            {KERNEL: BASE + "fn new_unchecked() {}"}, ALLOWED, "--ratchet"
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(inventory["hatches"], ALLOWED)

    def test_malformed_inventory_is_rejected(self):
        for allowed in (
            {f"{KERNEL}::for_test": 0},
            {f"{KERNEL}::verify": 1},
            {"for_test": 1},
        ):
            with self.subTest(allowed=allowed):
                result, _ = run_gate({KERNEL: BASE}, allowed)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_repository_passes_with_its_inventory(self):
        _, allowed = gate.load_allowed(root)
        self.assertEqual(gate.inventory(root), allowed)


if __name__ == "__main__":
    unittest.main()
