use std::collections::BTreeSet;

use chio_egress_contract::PrivateNetworkAllowance;

use crate::payment::{
    AcpPaymentAdapter, PaymentAdapter, PaymentError, PaymentJournalRecord, PaymentJournalState,
    PaymentRailMode, EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST,
};
use crate::ChioKernel;

fn journal_under(digest: &str) -> PaymentJournalRecord {
    PaymentJournalRecord {
        operation_id: "op-egress".to_owned(),
        journal_version: 1,
        request_namespace_digest: "a".repeat(64),
        request_id: "request-egress".to_owned(),
        capability_id: "capability-egress".to_owned(),
        grant_index: 0,
        hold_id: Some("hold-egress".to_owned()),
        rail: "acp".to_owned(),
        rail_mode: PaymentRailMode::ReversibleHold,
        rail_egress_allowance_digest: digest.to_owned(),
        authorization_id: None,
        transaction_id: None,
        amount_units: 125,
        authorized_amount_units: Some(125),
        authorization_attempt: None,
        settle_action: None,
        settle_amount_units: None,
        release_authority: None,
        currency: "USD".to_owned(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1_700_000_000_000,
    }
}

fn vpc_rail() -> AcpPaymentAdapter {
    AcpPaymentAdapter::new("https://facilitator.vpc.internal:8443")
        .with_private_network_allowances(&BTreeSet::from([PrivateNetworkAllowance {
            host: "facilitator.vpc.internal".to_owned(),
            port: 8443,
            cidr: "10.20.0.0/24".parse().expect("cidr"),
        }]))
        .expect("allowance for the rail's own authority")
}

#[test]
fn recovery_refuses_a_rail_whose_allowance_changed() {
    let adapter = vpc_rail();
    assert_ne!(
        adapter.egress_allowance_digest(),
        EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST
    );
    let refusal = ChioKernel::validate_durable_payment_authorization_intent(
        &adapter,
        &journal_under(EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST),
        125,
        "USD",
    )
    .expect_err("a changed allowance must refuse recovery");
    assert!(
        matches!(
            &refusal,
            PaymentError::RailError(message)
                if message == "durable payment adapter does not match the persisted rail profile"
        ),
        "{refusal:?}"
    );
}

#[test]
fn recovery_accepts_the_allowance_it_was_journaled_under() {
    let adapter = vpc_rail();
    ChioKernel::validate_durable_payment_authorization_intent(
        &adapter,
        &journal_under(adapter.egress_allowance_digest()),
        125,
        "USD",
    )
    .expect("the journaled allowance is unchanged");
}

#[test]
fn journal_refuses_a_malformed_allowance_digest() {
    let error = journal_under("not-a-digest")
        .validate()
        .expect_err("digest must be 64 lowercase hex");
    assert!(
        error.to_string().contains("rail_egress_allowance_digest"),
        "{error}"
    );
}
