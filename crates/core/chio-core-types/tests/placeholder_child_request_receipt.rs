#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::verify_wrapped;
use chio_core_types::receipt::lineage::{ChildRequestReceipt, CHIO_CHILD_REQUEST_RECEIPT_SCHEMA};
use chio_core_types::Error;

const SEED: &str =
    include_str!("../../../../fuzz/corpus/capability_receipt/child-request-receipt.json");

#[test]
fn committed_placeholder_child_request_receipt_is_refused() {
    let receipt: ChildRequestReceipt = serde_json::from_str(SEED).unwrap();
    assert!(matches!(
        verify_wrapped(
            &receipt.kernel_key,
            CHIO_CHILD_REQUEST_RECEIPT_SCHEMA,
            &receipt.body(),
            &receipt.signature,
        ),
        Err(Error::SignatureRejected)
    ));
    assert!(!receipt.verify_integrity_embedded_key().unwrap());
}
