use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chio_egress_contract::{private_network_allowance_digest, PrivateNetworkAllowance};
use chio_security_types::clock::FixedClock;

use crate::payment::{
    AcpPaymentAdapter, PaymentAdapter, PaymentAuthorizeRequest, PaymentError, X402Network,
    X402PaymentAdapter, X402RailConfig, EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST,
};
use crate::InMemoryExecutionNonceStore;

const BLACKHOLE_RAIL: &str = "https://10.255.255.254:9";

fn allowance(host: &str, port: u16, cidr: &str) -> PrivateNetworkAllowance {
    PrivateNetworkAllowance {
        host: host.to_owned(),
        port,
        cidr: cidr.parse().expect("cidr"),
    }
}

fn blackhole_allowance() -> BTreeSet<PrivateNetworkAllowance> {
    BTreeSet::from([allowance("10.255.255.254", 9, "10.255.255.254/32")])
}

fn authorize_request() -> PaymentAuthorizeRequest {
    PaymentAuthorizeRequest {
        amount_units: 125,
        currency: "USD".to_owned(),
        payer: "agent-1".to_owned(),
        payee: "tool-server".to_owned(),
        reference: "payment-egress".to_owned(),
        governed: None,
        commerce: None,
        x402: None,
        authority_expires_at: None,
        reference_is_durable: false,
    }
}

fn x402_rail() -> X402RailConfig {
    X402RailConfig::new(
        X402Network::allowlisted("eip155:84532").expect("allowlisted network"),
        "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        "USDC",
        6,
        "0x2000000000000000000000000000000000000002",
    )
    .expect("valid rail")
}

fn x402_at(
    url: &str,
    allowances: &BTreeSet<PrivateNetworkAllowance>,
) -> Result<X402PaymentAdapter, PaymentError> {
    X402PaymentAdapter::new(
        url,
        x402_rail(),
        allowances,
        Arc::new(FixedClock::from_millis(0)),
        Arc::new(InMemoryExecutionNonceStore::default()),
    )
}

fn is_rail_error(error: &PaymentError, expected: &str) -> bool {
    matches!(error, PaymentError::RailError(message) if message == expected)
}

#[test]
fn allowed_private_rail_is_dialed() {
    let error = AcpPaymentAdapter::new(BLACKHOLE_RAIL)
        .with_timeout(Duration::from_millis(300))
        .with_private_network_allowances(&blackhole_allowance())
        .expect("allowance for the rail's own authority")
        .authorize(&authorize_request())
        .expect_err("nothing listens on the blackhole rail");
    assert!(
        matches!(&error, PaymentError::Unavailable(message) if message == "payment rail transport failed"),
        "an allowed private rail reaches the socket: {error:?}"
    );

    x402_at(BLACKHOLE_RAIL, &blackhole_allowance()).expect("allowed private facilitator");
}

#[test]
fn unlisted_private_rail_is_refused() {
    let error = AcpPaymentAdapter::new(BLACKHOLE_RAIL)
        .with_timeout(Duration::from_millis(300))
        .authorize(&authorize_request())
        .expect_err("no allowance");
    assert!(is_rail_error(&error, "payment rail egress denied"), "{error:?}");

    let other_host = BTreeSet::from([allowance("10.255.255.253", 9, "10.255.255.253/32")]);
    let error = x402_at(BLACKHOLE_RAIL, &other_host).expect_err("allowance for another host");
    assert!(is_rail_error(&error, "payment rail egress denied"), "{error:?}");
}

#[test]
fn rail_takes_only_its_own_allowance() {
    let mixed = BTreeSet::from([
        allowance("facilitator.vpc.internal", 8443, "10.20.0.0/24"),
        allowance("other.vpc.internal", 8443, "10.30.0.0/24"),
        allowance("facilitator.vpc.internal", 9443, "10.40.0.0/24"),
    ]);
    let adapter = AcpPaymentAdapter::new("https://facilitator.vpc.internal:8443")
        .with_private_network_allowances(&mixed)
        .expect("allowance");
    let own = BTreeSet::from([allowance("facilitator.vpc.internal", 8443, "10.20.0.0/24")]);
    assert_eq!(
        adapter.egress_allowance_digest(),
        private_network_allowance_digest(&own).expect("digest")
    );

    let public = AcpPaymentAdapter::new("https://acp.example")
        .with_private_network_allowances(&mixed)
        .expect("no entry for this rail");
    assert_eq!(
        public.egress_allowance_digest(),
        EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST
    );
}

#[test]
fn plaintext_rail_cannot_carry_an_allowance() {
    let allowances = BTreeSet::from([allowance("localhost", 8080, "10.20.0.0/24")]);
    let error = AcpPaymentAdapter::new("http://localhost:8080")
        .with_private_network_allowances(&allowances)
        .expect_err("http rail with an allowance");
    assert!(
        is_rail_error(&error, "payment rail egress allowance is invalid"),
        "{error:?}"
    );
}

#[test]
fn metadata_or_broad_allowance_is_refused_at_load() {
    for cidr in ["100.100.0.0/16", "169.254.169.0/24", "10.0.0.0/8"] {
        let allowances = BTreeSet::from([allowance("facilitator.vpc.internal", 8443, cidr)]);
        let error = x402_at("https://facilitator.vpc.internal:8443", &allowances)
            .expect_err("allowance must be refused at load");
        assert!(
            is_rail_error(&error, "payment rail egress allowance is invalid"),
            "{cidr}: {error:?}"
        );
        let error = AcpPaymentAdapter::new("https://facilitator.vpc.internal:8443")
            .with_private_network_allowances(&allowances)
            .expect_err("allowance must be refused at load");
        assert!(
            is_rail_error(&error, "payment rail egress allowance is invalid"),
            "{cidr}: {error:?}"
        );
    }
}
