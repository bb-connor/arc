#!/usr/bin/env python3
"""Calibrate policy removal, exception laundering and secret derive checks."""
import importlib.util
from pathlib import Path
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('hardening', ROOT / 'scripts/check-rust-hardening.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class HardeningCalibration(unittest.TestCase):
    def test_accounting_include_requires_enforced_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'part.rs').write_text('fn accounting() {}')
            owner = root / 'owner.rs'
            owner.write_text('include!("part.rs");')
            catalog = {'part.rs': 'owner.rs'}
            self.assertTrue(gate.accounting_include_errors(root, catalog))
            owner.write_text('#![deny(clippy::arithmetic_side_effects)]\ninclude!("part.rs");')
            self.assertFalse(gate.accounting_include_errors(root, catalog))
            owner.write_text('#![deny(clippy::arithmetic_side_effects)]')
            self.assertTrue(gate.accounting_include_errors(root, catalog))

    def test_missing_forbid_is_rejected(self):
        self.assertTrue(gate.library_errors('lib.rs', 'pub fn api() {}', {}))

    def test_deny_is_not_forbid(self):
        self.assertTrue(gate.library_errors('lib.rs', '#![deny(unsafe_code)]', {}))

    def test_commented_forbid_is_not_policy(self):
        self.assertTrue(gate.library_errors('lib.rs', '// #![forbid(unsafe_code)]', {}))

    def test_inner_module_cannot_stand_in_for_library_policy(self):
        self.assertTrue(gate.library_errors('lib.rs', 'mod child { #![forbid(unsafe_code)] }', {}))
        self.assertFalse(gate.has_deny('mod child { #![deny(clippy::panic)] }', 'clippy::panic'))

    def test_documented_unsafe_exception(self):
        self.assertFalse(gate.library_errors('lib.rs', '', {'lib.rs': 'Calls a reviewed libc syscall.'}))

    def test_forbid_closes_library(self):
        self.assertFalse(gate.library_errors('lib.rs', '#![forbid(unsafe_code)]', {}))

    def test_reason_required_for_allow_and_expect(self):
        for kind in ['allow', 'expect']:
            with self.subTest(kind=kind):
                self.assertTrue(gate.exception_errors(f'#[{kind}(clippy::indexing_slicing)] fn f() {{}}'))
                self.assertFalse(gate.exception_errors(f'#[{kind}(clippy::indexing_slicing, reason = "fixed two-element array")] fn f() {{}}'))

    def test_nested_conditional_allow_requires_reason(self):
        self.assertTrue(gate.exception_errors('#![cfg_attr(test, allow(clippy::panic))]'))

    def test_empty_reason_is_not_a_justification(self):
        self.assertTrue(gate.exception_errors('#[allow(clippy::panic, reason = " ")]'))

    def test_comment_or_string_cannot_supply_a_reason(self):
        self.assertTrue(gate.exception_errors('#[allow(clippy::panic /* reason = "valid" */)]'))
        self.assertFalse(gate.exception_errors('let text = "#[allow(clippy::panic)]";'))

    def test_raw_secret_derives_refused(self):
        for trait in ['Debug', 'Serialize', 'serde::Serialize']:
            self.assertTrue(gate.secret_errors(f'#[derive({trait})] struct Key {{ key: Zeroizing<String> }}'))

    def test_wrapped_secret_serialization_refused(self):
        self.assertTrue(gate.secret_errors('#[derive(Serialize)] struct Key(SecretString);'))

    def test_split_derive_attributes_cannot_hide_secret_traits(self):
        for trait, field in [('Debug', 'Zeroizing<String>'),
                             ('serde::Serialize', 'Zeroizing<Vec<u8>>'),
                             ('Serialize', 'SecretString')]:
            with self.subTest(trait=trait, field=field):
                self.assertTrue(gate.secret_errors(
                    f'#[derive(Clone)] #[derive({trait})] struct Key {{ key: {field} }}'))
                self.assertTrue(gate.secret_errors(
                    f'#[derive(Clone)] #[cfg_attr(test, derive({trait}))] struct Key({field});'))

    def test_array_fields_cannot_hide_later_secrets(self):
        self.assertTrue(gate.secret_errors(
            '#[derive(Debug)] struct Key { nonce: [u8; 32], key: Zeroizing<String> }'))
        self.assertTrue(gate.secret_errors(
            '#[derive(Serialize)] struct Key([u8; 32], SecretString);'))
        self.assertFalse(gate.secret_errors(
            '#[derive(Debug)] struct Public { nonce: [u8; 32] } struct Key(Zeroizing<String>);'))

    def test_wrapped_secret_redaction_allowed(self):
        self.assertFalse(gate.secret_errors('#[derive(Debug)] struct Key { key: SecretString }'))

    def test_nonsecret_and_manual_custody_projection_allowed(self):
        self.assertFalse(gate.secret_errors('#[derive(Serialize)] struct Export<\'a> { key: &\'a str }'))

    def test_test_only_or_inactive_denies_are_not_production_policy(self):
        for condition in ['test', 'any()', 'all(test, feature = "unused")']:
            with self.subTest(condition=condition):
                self.assertFalse(gate.has_deny(
                    f'#![cfg_attr({condition}, deny(clippy::panic))]', 'clippy::panic'))
        self.assertTrue(gate.has_deny('#![deny(clippy::panic)]', 'clippy::panic'))

    def test_policy_must_be_an_active_deny_attribute(self):
        lint='clippy::panic'
        self.assertFalse(gate.has_deny('// #![deny(clippy::panic)]', lint))
        self.assertFalse(gate.has_deny('#![warn(clippy::panic)]', lint))
        self.assertTrue(gate.has_deny('#![cfg_attr(not(test), deny(clippy::panic))]', lint))


if __name__ == '__main__':
    unittest.main()
