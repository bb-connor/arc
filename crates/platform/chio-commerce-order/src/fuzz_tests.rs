use std::path::Path;

use chio_core_types::receipt::body::ChioReceipt;
use chio_test_support::prelude::*;

use super::{verify_commerce_receipt, CommerceReceiptVerification};
use crate::error::CommerceOrderError;

const DISPATCH: &str = "receipt-settlement-dispatch-commerce-001";
const INTENT: &str = "receipt-intent-commerce-001";
const MANDATE: &str = "receipt-mandate-commerce-001";

fn seed(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fuzz/corpus/commerce_receipt_verify")
        .join(name);
    std::fs::read(path).test_expect("commerce receipt seed reads")
}

fn run(name: &str) -> CommerceReceiptVerification {
    verify_commerce_receipt(&seed(name)).test_expect("seed carries a header")
}

fn decode_error(name: &str) -> CommerceOrderError {
    let bytes = seed(name);
    match crate::input::decode::<ChioReceipt>(&bytes[2..]) {
        Ok(_) => panic!("seed {name} must not decode"),
        Err(error) => error,
    }
}

#[test]
fn fixture_receipts_verify_raw_and_resigned() {
    for name in ["valid-dispatch.bin", "valid-intent-resigned.bin"] {
        let outcome = run(name);
        assert_eq!(outcome.replay, Ok(()), "{name}");
        assert_eq!(outcome.settlement, Ok(()), "{name}");
    }
}

#[test]
fn resigned_action_hash_mismatch_uses_digest_class() {
    assert_eq!(
        run("wrong-action-hash-dispatch.bin"),
        CommerceReceiptVerification {
            receipt_ref: DISPATCH.to_owned(),
            replay: Err(CommerceOrderError::ReplayDigestMismatch(format!(
                "authority receipt action hash invalid: {DISPATCH}"
            ))),
            settlement: Err(CommerceOrderError::SettlementDigestMismatch(format!(
                "settlement dispatch receipt action hash invalid: {DISPATCH}"
            ))),
        }
    );
}

#[test]
fn resigned_tampered_parameters_use_digest_class() {
    assert_eq!(
        run("tampered-parameters-mandate.bin"),
        CommerceReceiptVerification {
            receipt_ref: MANDATE.to_owned(),
            replay: Err(CommerceOrderError::ReplayDigestMismatch(format!(
                "authority receipt action hash invalid: {MANDATE}"
            ))),
            settlement: Ok(()),
        }
    );
}

#[test]
fn unsigned_action_hash_change_stops_at_signature() {
    assert_eq!(
        run("wrong-action-hash-unsigned.bin"),
        CommerceReceiptVerification {
            receipt_ref: INTENT.to_owned(),
            replay: Err(CommerceOrderError::ReplaySignatureInvalid(format!(
                "authority receipt signature invalid: {INTENT}"
            ))),
            settlement: Ok(()),
        }
    );
}

#[test]
fn undecodable_dispatch_receipts_keep_input_class() {
    for name in [
        "non-canonical-number.bin",
        "truncated.bin",
        "duplicate-key.bin",
    ] {
        let outcome = run(name);
        assert!(
            matches!(decode_error(name), CommerceOrderError::Input(_)),
            "{name}"
        );
        assert_eq!(outcome.receipt_ref, DISPATCH, "{name}");
        let expected = format!("{:?}", Err::<(), _>(decode_error(name)));
        assert_eq!(format!("{:?}", outcome.replay), expected, "{name}");
        assert_eq!(format!("{:?}", outcome.settlement), expected, "{name}");
    }
}

#[test]
fn inputs_without_a_header_are_skipped() {
    assert_eq!(verify_commerce_receipt(&[]), None);
    assert_eq!(verify_commerce_receipt(&[7]), None);
}

#[test]
fn every_seed_holds_the_invariants() {
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/commerce_receipt_verify");
    let mut count = 0;
    for entry in std::fs::read_dir(dir).test_expect("corpus directory reads") {
        let path = entry.test_expect("corpus entry reads").path();
        let bytes = std::fs::read(&path).test_expect("seed reads");
        super::commerce_receipt_verify(&bytes);
        count += 1;
    }
    assert_eq!(count, 8);
}
