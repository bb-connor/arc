#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;

use chio_secret_broker::generic_https::is_restricted;

#[test]
fn restricted_ipv4_ipv6_decimal_equivalents_and_mapped_forms_are_denied() {
    let restricted = [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
    ];
    for candidate in restricted {
        let address: IpAddr = candidate.parse().expect("address");
        assert!(is_restricted(address, false), "{candidate}");
    }
}

#[test]
fn globally_routable_fixture_is_not_classified_as_restricted() {
    assert!(!is_restricted(
        "93.184.216.34".parse().expect("address"),
        false
    ));
}
