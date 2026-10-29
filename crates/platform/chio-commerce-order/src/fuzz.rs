//! libFuzzer entry point for commerce authority receipt verification.
//!
//! Gated behind the `fuzz` Cargo feature so these symbols only compile into
//! the standalone `chio-fuzz` workspace at `../../../fuzz`. Production builds
//! never expose them.
//!
//! # Input layout
//!
//! `[slot, mode, receipt_bytes @ ..]`. `slot` selects which authority receipt
//! of the offline PSP fixture order is replaced (modulo the receipt count).
//! When bit 0 of `mode` is set, the receipt bytes are decoded and re-signed
//! with the fixture kernel key, with `kernel_key` and `content_hash` pinned to
//! the replaced receipt, so mutated actions reach the action hash check behind
//! a valid signature. Otherwise the bytes are routed unchanged.
//!
//! # Invariants
//!
//! Replay and settlement verification never panic. A receipt that passes the
//! checks ahead of the action hash surfaces an `Ok(false)` action hash as the
//! digest-mismatch class and an action hash encoding fault as the plain
//! failure class, never the other way round. A receipt identical to the
//! fixture receipt verifies.

use std::sync::OnceLock;

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::body::{ChioReceipt, CHIO_RECEIPT_SCHEMA};

use crate::error::CommerceOrderError;
use crate::mandate::CommerceMandateLedger;
use crate::replay::{replay_event_log, CommerceEventLog};
use crate::settlement::validate_settlement_packet;
use crate::types::{
    decode_authority_receipt, CommerceEventAuthorityReceiptArtifact, CommerceOrderContext,
    CommercePaymentLifecycle, CommerceSettlementPacket,
};

macro_rules! fixture {
    ($($part:literal),+) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/proof-room/commerce-payments/offline-psp-valid/",
            $($part),+
        ))
    };
}

macro_rules! receipt_fixture {
    ($name:literal) => {
        (
            $name,
            fixture!("authority-receipts/", $name, ".json").as_slice(),
        )
    };
}

const FIXTURE_SIGNER_SEED: [u8; 32] = [7; 32];

const RECEIPTS: [(&str, &[u8]); 10] = [
    receipt_fixture!("receipt-intent-commerce-001"),
    receipt_fixture!("receipt-provider-commerce-001"),
    receipt_fixture!("receipt-quote-commerce-001"),
    receipt_fixture!("receipt-mandate-commerce-001"),
    receipt_fixture!("receipt-budget-commerce-001"),
    receipt_fixture!("receipt-payment-commerce-001"),
    receipt_fixture!("receipt-fulfillment-commerce-001"),
    receipt_fixture!("receipt-settlement-dispatch-commerce-001"),
    receipt_fixture!("receipt-reconciliation-commerce-001"),
    receipt_fixture!("receipt-complete-commerce-001"),
];

struct Fixture {
    context: CommerceOrderContext,
    payment: CommercePaymentLifecycle,
    mandate: CommerceMandateLedger,
    settlement: CommerceSettlementPacket,
    events: CommerceEventLog,
    receipts: Vec<CommerceEventAuthorityReceiptArtifact>,
    originals: Vec<ChioReceipt>,
    signer: Keypair,
    dispatch_receipt_ref: String,
    dispatch_event_sha256: String,
}

fn decode_fixture<T: serde::de::DeserializeOwned>(name: &str, bytes: &[u8]) -> T {
    match crate::input::decode(bytes) {
        Ok(value) => value,
        Err(error) => panic!("commerce fuzz fixture {name} must decode: {error}"),
    }
}

fn load_fixture() -> Fixture {
    let receipts: Vec<_> = RECEIPTS
        .iter()
        .map(
            |(receipt_ref, bytes)| CommerceEventAuthorityReceiptArtifact {
                receipt_ref: (*receipt_ref).to_owned(),
                schema: CHIO_RECEIPT_SCHEMA.to_owned(),
                receipt_bytes: bytes.to_vec(),
            },
        )
        .collect();
    let originals = receipts
        .iter()
        .map(|artifact| decode_fixture(&artifact.receipt_ref, &artifact.receipt_bytes))
        .collect();
    let mut fixture = Fixture {
        context: decode_fixture("order context", fixture!("order-context.json")),
        payment: decode_fixture("payment lifecycle", fixture!("payment-lifecycle.json")),
        mandate: decode_fixture("mandate ledger", fixture!("mandate-allowance-ledger.json")),
        settlement: decode_fixture("settlement packet", fixture!("settlement-packet.json")),
        events: decode_fixture("event log", fixture!("event-log.json")),
        receipts,
        originals,
        signer: Keypair::from_seed(&FIXTURE_SIGNER_SEED),
        dispatch_receipt_ref: String::new(),
        dispatch_event_sha256: String::new(),
    };
    let replay = match fixture.replay(&fixture.receipts) {
        Ok(replay) => replay,
        Err(error) => panic!("commerce fuzz fixture must replay: {error}"),
    };
    let (Some(receipt_ref), Some(event_sha256)) = (
        replay.settlement_dispatch_receipt_ref,
        replay.settlement_dispatch_event_sha256,
    ) else {
        panic!("commerce fuzz fixture must replay a settlement dispatch");
    };
    fixture.dispatch_receipt_ref = receipt_ref;
    fixture.dispatch_event_sha256 = event_sha256;
    if let Err(error) = fixture.settle(&fixture.receipts) {
        panic!("commerce fuzz fixture must settle: {error}");
    }
    fixture
}

impl Fixture {
    fn trusted_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    fn replay(
        &self,
        receipts: &[CommerceEventAuthorityReceiptArtifact],
    ) -> Result<crate::replay::CommerceReplayResult, CommerceOrderError> {
        replay_event_log(
            &self.events,
            &self.context,
            &self.payment,
            &self.mandate,
            receipts,
            &[self.trusted_key()],
        )
    }

    fn settle(
        &self,
        receipts: &[CommerceEventAuthorityReceiptArtifact],
    ) -> Result<(), CommerceOrderError> {
        validate_settlement_packet(
            &self.context,
            &self.payment,
            &self.settlement,
            receipts,
            &[self.trusted_key()],
            Some(&self.dispatch_receipt_ref),
            Some(&self.dispatch_event_sha256),
        )
    }

    fn resign(&self, bytes: &[u8], original: &ChioReceipt) -> Option<Vec<u8>> {
        let receipt: ChioReceipt = crate::input::decode(bytes).ok()?;
        let mut body = receipt.body();
        body.kernel_key = self.trusted_key();
        body.content_hash.clone_from(&original.content_hash);
        let signed = ChioReceipt::sign(body, &self.signer).ok()?;
        serde_json::to_vec(&signed).ok()
    }
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(load_fixture)
}

/// Replay and settlement results for one fuzz input.
#[derive(Debug, PartialEq, Eq)]
pub struct CommerceReceiptVerification {
    pub receipt_ref: String,
    pub replay: Result<(), CommerceOrderError>,
    pub settlement: Result<(), CommerceOrderError>,
}

/// Route one fuzz input through replay and settlement and check the receipt
/// error-class invariants; returns `None` when the input has no header.
pub fn verify_commerce_receipt(data: &[u8]) -> Option<CommerceReceiptVerification> {
    let [slot, mode, receipt_bytes @ ..] = data else {
        return None;
    };
    let fixture = fixture();
    let index = usize::from(*slot) % fixture.receipts.len();
    let original = fixture.originals.get(index)?;
    let mut receipts = fixture.receipts.clone();
    let artifact = receipts.get_mut(index)?;
    artifact.receipt_bytes = if mode & 1 == 1 {
        fixture
            .resign(receipt_bytes, original)
            .unwrap_or_else(|| receipt_bytes.to_vec())
    } else {
        receipt_bytes.to_vec()
    };
    let artifact = artifact.clone();

    let replay = fixture.replay(&receipts).map(|_| ());
    let decoded = decode_authority_receipt(&artifact, "authority receipt");
    check_replay(fixture, &artifact.receipt_ref, &decoded, original, &replay);

    let settlement = fixture.settle(&receipts);
    if artifact.receipt_ref == fixture.dispatch_receipt_ref {
        let decoded = decode_authority_receipt(&artifact, "settlement dispatch receipt");
        check_settlement(
            fixture,
            &artifact.receipt_ref,
            &decoded,
            original,
            &settlement,
        );
    } else {
        assert_eq!(
            settlement,
            Ok(()),
            "settlement must ignore authority receipts other than the dispatch receipt"
        );
    }

    Some(CommerceReceiptVerification {
        receipt_ref: artifact.receipt_ref,
        replay,
        settlement,
    })
}

/// libFuzzer entry point; see the module documentation.
pub fn commerce_receipt_verify(data: &[u8]) {
    verify_commerce_receipt(data);
}

enum ActionHashGate {
    Mismatch,
    Encoding(chio_core_types::error::Error),
    Unreached,
}

fn action_hash_gate(receipt: &ChioReceipt, reaches_action_hash: bool) -> ActionHashGate {
    let hash = receipt.action.verify_hash();
    if !reaches_action_hash {
        return ActionHashGate::Unreached;
    }
    match hash {
        Ok(true) => ActionHashGate::Unreached,
        Ok(false) => ActionHashGate::Mismatch,
        Err(error) => ActionHashGate::Encoding(error),
    }
}

/// Input errors compare by identity, so independent decodes of the same bytes
/// are matched by their variant and rule code.
fn same_failure(left: &CommerceOrderError, right: &CommerceOrderError) -> bool {
    format!("{left:?}") == format!("{right:?}")
}

fn same_receipt(left: &ChioReceipt, right: &ChioReceipt) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn passes_key_and_signature(fixture: &Fixture, receipt: &ChioReceipt) -> bool {
    receipt.kernel_key == fixture.trusted_key()
        && matches!(receipt.verify_integrity_embedded_key(), Ok(true))
}

fn check_replay(
    fixture: &Fixture,
    receipt_ref: &str,
    decoded: &Result<ChioReceipt, CommerceOrderError>,
    original: &ChioReceipt,
    actual: &Result<(), CommerceOrderError>,
) {
    let receipt = match decoded {
        Ok(receipt) => receipt,
        Err(error) => {
            assert!(
                matches!(actual, Err(actual) if same_failure(actual, error)),
                "replay decode class: expected {error:?}, got {actual:?}"
            );
            return;
        }
    };
    let mismatch = Err(CommerceOrderError::ReplayDigestMismatch(format!(
        "authority receipt action hash invalid: {receipt_ref}"
    )));
    let encoding_prefix = format!("authority receipt action hash invalid: {receipt_ref}: ");
    let reaches = passes_key_and_signature(fixture, receipt);
    match action_hash_gate(receipt, reaches) {
        ActionHashGate::Mismatch => assert_eq!(actual, &mismatch, "replay action hash class"),
        ActionHashGate::Encoding(error) => assert_eq!(
            actual,
            &Err(crate::replay::action_hash_encoding_error(
                receipt_ref,
                error
            )),
            "replay action hash encoding class"
        ),
        ActionHashGate::Unreached => {
            assert_ne!(actual, &mismatch, "replay action hash class");
            assert!(
                !matches!(actual, Err(CommerceOrderError::ReplayFailed(message))
                    if message.starts_with(&encoding_prefix)),
                "replay reported an action hash encoding fault for an encodable action"
            );
        }
    }
    if same_receipt(receipt, original) {
        assert_eq!(actual, &Ok(()), "the fixture receipt must replay");
    }
}

fn check_settlement(
    fixture: &Fixture,
    receipt_ref: &str,
    decoded: &Result<ChioReceipt, CommerceOrderError>,
    original: &ChioReceipt,
    actual: &Result<(), CommerceOrderError>,
) {
    let receipt = match decoded {
        Ok(receipt) => receipt,
        Err(error) => {
            assert!(
                matches!(actual, Err(actual) if same_failure(actual, error)),
                "settlement decode class: expected {error:?}, got {actual:?}"
            );
            return;
        }
    };
    let mismatch = Err(CommerceOrderError::SettlementDigestMismatch(format!(
        "settlement dispatch receipt action hash invalid: {receipt_ref}"
    )));
    let encoding_prefix =
        format!("settlement dispatch receipt action hash invalid: {receipt_ref}: ");
    let reaches = receipt.content_hash == fixture.dispatch_event_sha256
        && passes_key_and_signature(fixture, receipt);
    match action_hash_gate(receipt, reaches) {
        ActionHashGate::Mismatch => assert_eq!(actual, &mismatch, "settlement action hash class"),
        ActionHashGate::Encoding(error) => assert_eq!(
            actual,
            &Err(crate::settlement::action_hash_encoding_error(
                receipt_ref,
                error
            )),
            "settlement action hash encoding class"
        ),
        ActionHashGate::Unreached => {
            assert_ne!(actual, &mismatch, "settlement action hash class");
            assert!(
                !matches!(actual, Err(CommerceOrderError::SettlementFailed(message))
                    if message.starts_with(&encoding_prefix)),
                "settlement reported an action hash encoding fault for an encodable action"
            );
        }
    }
    if same_receipt(receipt, original) {
        assert_eq!(actual, &Ok(()), "the fixture receipt must settle");
    }
}

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod tests;
