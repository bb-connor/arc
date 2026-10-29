use chio_egress_contract::{EgressAllowanceSet, PrivateNetworkAllowance};

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
        .with_private_network_allowances(
            &EgressAllowanceSet::new([PrivateNetworkAllowance {
                host: "facilitator.vpc.internal".to_owned(),
                port: 8443,
                cidr: "10.20.0.0/24".parse().expect("cidr"),
            }])
            .expect("valid allowance set"),
        )
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

struct DelegatingRail {
    inner: AcpPaymentAdapter,
}

impl PaymentAdapter for DelegatingRail {
    fn rail_id(&self) -> &'static str {
        self.inner.rail_id()
    }

    fn egress_allowance_digest(&self) -> &str {
        self.inner.egress_allowance_digest()
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.inner.rail_mode()
    }

    fn authorize(
        &self,
        request: &crate::payment::PaymentAuthorizeRequest,
    ) -> Result<crate::payment::PaymentAuthorization, PaymentError> {
        self.inner.authorize(request)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        self.inner
            .capture(authorization_id, amount_units, currency, reference)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        self.inner.release(authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }

    fn replayed_authorization_metadata(
        &self,
        authorization_id: &str,
    ) -> Result<serde_json::Value, PaymentError> {
        self.inner.replayed_authorization_metadata(authorization_id)
    }
}

fn vpc_rail_on(cidr: &str) -> AcpPaymentAdapter {
    AcpPaymentAdapter::new("https://facilitator.vpc.internal:8443")
        .with_private_network_allowances(
            &EgressAllowanceSet::new([PrivateNetworkAllowance {
                host: "facilitator.vpc.internal".to_owned(),
                port: 8443,
                cidr: cidr.parse().expect("cidr"),
            }])
            .expect("valid allowance set"),
        )
        .expect("allowance for the rail's own authority")
}

#[test]
fn delegating_rail_reports_its_inner_allowance_digest() {
    let inner = vpc_rail_on("10.20.0.0/24");
    let expected = inner.egress_allowance_digest().to_owned();
    let wrapper = DelegatingRail { inner };
    assert_eq!(wrapper.egress_allowance_digest(), expected);
}

#[test]
fn recovery_refuses_a_delegating_rail_whose_inner_cidr_changed() {
    let journaled = DelegatingRail {
        inner: vpc_rail_on("10.20.0.0/24"),
    };
    let journal = journal_under(journaled.egress_allowance_digest());
    let widened = DelegatingRail {
        inner: vpc_rail_on("10.20.0.0/23"),
    };
    let refusal =
        ChioKernel::validate_durable_payment_authorization_intent(&widened, &journal, 125, "USD")
            .expect_err("a changed inner allowance must refuse recovery");
    assert!(
        matches!(
            &refusal,
            PaymentError::RailError(message)
                if message == "durable payment adapter does not match the persisted rail profile"
        ),
        "{refusal:?}"
    );
    ChioKernel::validate_durable_payment_authorization_intent(&journaled, &journal, 125, "USD")
        .expect("the journaled inner allowance is unchanged");
}
