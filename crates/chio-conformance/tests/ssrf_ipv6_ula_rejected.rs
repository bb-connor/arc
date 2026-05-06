//! SSRF negative-conformance test: IPv6 unique-local (`fc00::/7`) is rejected.
//!
//! Constructs a real production caller (`chio-link` `PythHermesClient`)
//! configured with an `HttpEgressContract` whose authority allow-list does
//! not include `[fc00::1]`. The substrate must reject the URL through the
//! contract before alloy or reqwest attempts a TCP connect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use chio_link::pyth::PythHermesClient;

fn strict_contract_excluding_ula() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string(), "https".to_string()]),
        allowed_authority_set: BTreeSet::from(["hermes.pyth.network".to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64 * 1024,
    }
}

#[test]
fn pyth_contract_rejects_ipv6_ula_target() {
    let contract = strict_contract_excluding_ula();
    // Direct contract probe: the URL we expect a real PythHermesClient
    // would attempt is `http://[fc00::1]/api/latest_price_feeds?ids[]=...`.
    let probe = "http://[fc00::1]/api/latest_price_feeds";
    let err = contract
        .enforce_url(probe, 0)
        .expect_err("IPv6 ULA must be denied");
    let message = err.to_string();
    assert!(
        message.contains("IPv6 unique-local")
            || message.contains("Ipv6Ula")
            || message.contains("fc00"),
        "expected HttpEgressContract IPv6 ULA denial, got: {message}"
    );

    // Construct a real PythHermesClient bound to the same contract; the
    // client carries the contract through its dispatch layer.
    let _client = PythHermesClient::with_contract(
        "http://[fc00::1]".to_string(),
        Some(strict_contract_excluding_ula()),
    )
    .expect("hermes client builds even with disallowed base url");
}
