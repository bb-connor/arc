use super::{
    private_network_allowance_digest, AllowanceScheme, EgressAllowanceSet, HttpEgressContract,
    HttpEgressError, IpCidr, PrivateNetworkAllowance, PrivateNetworkAllowanceError,
    EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

const FACILITATOR: &str = "facilitator.vpc.internal";

fn cidr(value: &str) -> IpCidr {
    value.parse().expect("cidr")
}

fn allowance(host: &str, port: u16, network: &str) -> PrivateNetworkAllowance {
    PrivateNetworkAllowance {
        host: host.to_string(),
        port,
        scheme: AllowanceScheme::Https,
        cidr: cidr(network),
    }
}

fn http_allowance(host: &str, port: u16, network: &str) -> PrivateNetworkAllowance {
    PrivateNetworkAllowance {
        scheme: AllowanceScheme::Http,
        ..allowance(host, port, network)
    }
}

fn dual_scheme(mut contract: HttpEgressContract) -> HttpEgressContract {
    contract.allowed_schemes.insert("http".to_string());
    contract
}

fn vpc_contract(allowances: &[PrivateNetworkAllowance]) -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "payment-rail".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string()]),
        allowed_authority_set: BTreeSet::from([
            format!("{FACILITATOR}:8443"),
            "10.0.4.7:8443".to_string(),
            "[fd12:3456::7]:8443".to_string(),
            "public.example".to_string(),
        ]),
        deny_loopback: true,
        deny_link_local: true,
        max_redirect_chain: 0,
        max_response_bytes: 1024,
        private_network_allowances: allowances.iter().cloned().collect(),
    }
}

fn facilitator_contract() -> HttpEgressContract {
    vpc_contract(&[allowance(FACILITATOR, 8443, "10.20.0.0/24")])
}

fn resolved(
    contract: &HttpEgressContract,
    host: &str,
    ip: &str,
    port: u16,
) -> Result<(), HttpEgressError> {
    let address: IpAddr = ip.parse().expect("ip");
    contract
        .prepare()?
        .contract()
        .enforce_resolved_address(host, SocketAddr::new(address, port))
}

#[test]
fn allowed_private_host_resolves_inside_its_cidr() {
    let contract = facilitator_contract();
    assert_eq!(resolved(&contract, FACILITATOR, "10.20.0.5", 8443), Ok(()));
    assert_eq!(
        resolved(&contract, "Facilitator.VPC.Internal.", "10.20.0.200", 8443),
        Ok(())
    );
}

#[test]
fn unlisted_private_host_is_refused() {
    let contract = vpc_contract(&[]);
    assert_eq!(
        resolved(&contract, FACILITATOR, "10.20.0.5", 8443),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: format!("{FACILITATOR} resolved to 10.20.0.5")
        })
    );
    let other_host = vpc_contract(&[allowance("10.0.4.7", 8443, "10.0.4.7/32")]);
    assert_eq!(
        resolved(&other_host, FACILITATOR, "10.0.4.7", 8443),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: format!("{FACILITATOR} resolved to 10.0.4.7")
        })
    );
}

#[test]
fn allowance_port_is_exact() {
    let contract = facilitator_contract();
    assert_eq!(
        resolved(&contract, FACILITATOR, "10.20.0.5", 443),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: format!("{FACILITATOR} resolved to 10.20.0.5")
        })
    );
}

#[test]
fn pinned_host_refuses_every_address_outside_its_cidr() {
    let contract = facilitator_contract();
    for stray in ["10.21.0.5", "34.1.2.3", "fd12::1"] {
        assert_eq!(
            resolved(&contract, FACILITATOR, stray, 8443),
            Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
                host: FACILITATOR.to_string(),
                port: 8443,
                address: stray.parse().expect("ip"),
            }),
            "{stray}"
        );
    }
}

#[test]
fn mapped_ipv6_answer_is_compared_as_ipv4() {
    let contract = facilitator_contract();
    assert_eq!(
        resolved(&contract, FACILITATOR, "::ffff:10.20.0.5", 8443),
        Ok(())
    );
    assert_eq!(
        resolved(&contract, FACILITATOR, "::ffff:10.21.0.5", 8443),
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: FACILITATOR.to_string(),
            port: 8443,
            address: "10.21.0.5".parse().expect("ip"),
        })
    );
    assert_eq!(
        resolved(&contract, FACILITATOR, "64:ff9b::a14:5", 8443),
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: FACILITATOR.to_string(),
            port: 8443,
            address: "64:ff9b::a14:5".parse().expect("ip"),
        })
    );
}

#[test]
fn metadata_addresses_are_refused_whatever_the_flags() {
    let mut open = HttpEgressContract::permissive_for_tests("metadata.test:80");
    open.deny_link_local = false;
    for address in ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"] {
        let ip: IpAddr = address.parse().expect("ip");
        let shown = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        assert_eq!(
            open.enforce_resolved_address("metadata.test", SocketAddr::new(ip, 80)),
            Err(HttpEgressError::ReservedAddressDenied {
                host: format!("metadata.test resolved to {shown}")
            }),
            "{address}"
        );
    }
    assert_eq!(
        open.enforce_resolved_address(
            "metadata.test",
            SocketAddr::new("100.100.100.200".parse().expect("ip"), 80)
        ),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: "metadata.test resolved to 100.100.100.200".to_string()
        })
    );
    assert_eq!(
        resolved(&vpc_contract(&[]), FACILITATOR, "169.254.169.254", 8443),
        Err(HttpEgressError::LinkLocalDenied {
            host: format!("{FACILITATOR} resolved to 169.254.169.254")
        })
    );
    assert_eq!(
        resolved(
            &facilitator_contract(),
            FACILITATOR,
            "169.254.169.254",
            8443
        ),
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: FACILITATOR.to_string(),
            port: 8443,
            address: "169.254.169.254".parse().expect("ip"),
        })
    );
    assert_eq!(
        open.enforce_url("http://[fd00:ec2::254]/latest/meta-data", 0),
        Err(HttpEgressError::ReservedAddressDenied {
            host: "fd00:ec2::254".to_string()
        })
    );
}

#[test]
fn private_literal_url_needs_its_allowance() {
    let allowed = vpc_contract(&[
        allowance("10.0.4.7", 8443, "10.0.4.7/32"),
        allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
    ]);
    allowed
        .enforce_url("https://10.0.4.7:8443/verify", 0)
        .expect("allowed IPv4 literal");
    allowed
        .enforce_url("https://[fd12:3456::7]:8443/verify", 0)
        .expect("allowed IPv6 literal");
    assert_eq!(
        vpc_contract(&[]).enforce_url("https://10.0.4.7:8443/verify", 0),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: "10.0.4.7".to_string()
        })
    );
}

fn load_error(allowances: &[PrivateNetworkAllowance]) -> HttpEgressError {
    vpc_contract(allowances)
        .validate()
        .expect_err("allowance must be refused at load")
}

#[test]
fn metadata_inside_a_declared_cidr_is_refused_at_load() {
    for (host, network, reserved) in [
        (FACILITATOR, "100.100.0.0/16", "100.100.100.200/32"),
        (FACILITATOR, "fd00:ec2::/48", "fd00:ec2::/32"),
        (FACILITATOR, "169.254.0.0/16", "169.254.0.0/16"),
        (FACILITATOR, "fe80::/64", "fe80::/10"),
    ] {
        assert_eq!(
            load_error(&[allowance(host, 8443, network)]),
            HttpEgressError::InvalidAllowance(
                PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
                    cidr: network.to_string(),
                    reserved: reserved.to_string(),
                }
            ),
            "{network}"
        );
    }
}

#[test]
fn cidr_broader_than_the_bound_is_refused_at_load() {
    for (network, min_prefix) in [
        ("0.0.0.0/0", 16),
        ("10.0.0.0/8", 16),
        ("10.0.0.0/15", 16),
        ("::/0", 48),
        ("fd12::/47", 48),
    ] {
        assert_eq!(
            load_error(&[allowance(FACILITATOR, 8443, network)]),
            HttpEgressError::InvalidAllowance(PrivateNetworkAllowanceError::CidrTooBroad {
                cidr: network.to_string(),
                min_prefix,
            }),
            "{network}"
        );
    }
    vpc_contract(&[allowance(FACILITATOR, 8443, "10.20.0.0/16")])
        .validate()
        .expect("a /16 is inside the bound");
}

#[test]
fn cidr_outside_the_private_ranges_is_refused_at_load() {
    for network in [
        "8.8.0.0/16",
        "127.0.0.0/16",
        "192.0.2.0/24",
        "2001:db8::/48",
        "100.128.0.0/16",
    ] {
        assert_eq!(
            load_error(&[allowance(FACILITATOR, 8443, network)]),
            HttpEgressError::InvalidAllowance(
                PrivateNetworkAllowanceError::CidrOutsidePrivateRanges {
                    cidr: network.to_string()
                }
            ),
            "{network}"
        );
    }
    vpc_contract(&[allowance(FACILITATOR, 8443, "100.64.0.0/16")])
        .validate()
        .expect("shared address space outside the metadata host is unlockable");
}

#[test]
fn http_is_refused_for_an_allowance_that_does_not_name_it() {
    let contract = dual_scheme(facilitator_contract())
        .prepare()
        .expect("contract");
    contract
        .enforce_url(&format!("https://{FACILITATOR}:8443/pay"), 0)
        .expect("https is the default scheme");
    assert_eq!(
        contract.enforce_url(&format!("http://{FACILITATOR}:8443/pay"), 0),
        Err(HttpEgressError::PrivateNetworkAllowanceSchemeMismatch {
            host: FACILITATOR.to_string(),
            port: 8443,
            scheme: "http".to_string(),
        })
    );
}

#[test]
fn named_http_is_admitted_only_on_its_pinned_host_port_and_cidr() {
    let contract = dual_scheme(vpc_contract(&[http_allowance(
        FACILITATOR,
        8443,
        "10.20.0.0/24",
    )]));
    let prepared = contract.prepare().expect("contract");
    prepared
        .enforce_url(&format!("http://{FACILITATOR}:8443/pay"), 0)
        .expect("named http on its pinned host and port");
    assert_eq!(resolved(&contract, FACILITATOR, "10.20.0.5", 8443), Ok(()));
    assert_eq!(
        resolved(&contract, FACILITATOR, "10.21.0.5", 8443),
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: FACILITATOR.to_string(),
            port: 8443,
            address: "10.21.0.5".parse().expect("ip"),
        })
    );
    assert_eq!(
        prepared.enforce_url(&format!("https://{FACILITATOR}:8443/pay"), 0),
        Err(HttpEgressError::PrivateNetworkAllowanceSchemeMismatch {
            host: FACILITATOR.to_string(),
            port: 8443,
            scheme: "https".to_string(),
        })
    );
    assert_eq!(
        prepared.enforce_url(&format!("http://{FACILITATOR}:9443/pay"), 0),
        Err(HttpEgressError::AuthorityDenied {
            authority: format!("{FACILITATOR}:9443"),
        })
    );
    assert_eq!(
        prepared.enforce_url("http://10.0.4.7:8443/pay", 0),
        Err(HttpEgressError::PrivateNetworkDenied {
            host: "10.0.4.7".to_string(),
        })
    );
}

#[test]
fn allowance_scheme_must_be_allowed_by_the_contract() {
    let contract = vpc_contract(&[http_allowance(FACILITATOR, 8443, "10.20.0.0/24")]);
    assert_eq!(
        contract.validate(),
        Err(HttpEgressError::InvalidAllowance(
            PrivateNetworkAllowanceError::SchemeNotAllowed {
                host: FACILITATOR.to_string(),
                port: 8443,
                scheme: "http".to_string(),
            }
        ))
    );
}

#[test]
fn bare_authority_admits_the_default_port_of_the_allowance_scheme() {
    let mut contract = dual_scheme(vpc_contract(&[http_allowance(
        "public.example",
        80,
        "10.30.0.0/24",
    )]));
    contract
        .validate()
        .expect("a bare authority stands for port 80 over http");
    contract.private_network_allowances =
        BTreeSet::from([http_allowance("public.example", 443, "10.30.0.0/24")]);
    assert_eq!(
        contract.validate(),
        Err(HttpEgressError::InvalidAllowance(
            PrivateNetworkAllowanceError::HostNotInAuthoritySet {
                host: "public.example".to_string(),
                port: 443,
            }
        ))
    );
}

#[test]
fn contract_takes_the_http_entries_of_its_own_authorities() {
    let set =
        EgressAllowanceSet::new([http_allowance(FACILITATOR, 8443, "10.20.0.0/24")]).expect("set");
    let contract = dual_scheme(vpc_contract(&[])).with_private_network_allowances(&set);
    assert_eq!(
        contract.private_network_allowances,
        BTreeSet::from([http_allowance(FACILITATOR, 8443, "10.20.0.0/24")])
    );
    contract
        .validate()
        .expect("http entry admitted by its contract");
}

#[test]
fn an_entry_for_a_scheme_the_contract_lacks_is_refused_not_dropped() {
    let set =
        EgressAllowanceSet::new([http_allowance(FACILITATOR, 8443, "10.20.0.0/24")]).expect("set");
    let contract = vpc_contract(&[]).with_private_network_allowances(&set);
    assert_eq!(
        contract.prepare().map(|_| ()),
        Err(HttpEgressError::InvalidAllowance(
            PrivateNetworkAllowanceError::SchemeNotAllowed {
                host: FACILITATOR.to_string(),
                port: 8443,
                scheme: "http".to_string(),
            }
        ))
    );
    let bare = EgressAllowanceSet::new([http_allowance("public.example", 80, "10.30.0.0/24")])
        .expect("set");
    assert_eq!(
        vpc_contract(&[])
            .with_private_network_allowances(&bare)
            .prepare()
            .map(|_| ()),
        Err(HttpEgressError::InvalidAllowance(
            PrivateNetworkAllowanceError::SchemeNotAllowed {
                host: "public.example".to_string(),
                port: 80,
                scheme: "http".to_string(),
            }
        ))
    );
}

#[test]
fn allowance_scheme_is_part_of_the_digest() {
    let https = BTreeSet::from([allowance(FACILITATOR, 8443, "10.20.0.0/24")]);
    let http = BTreeSet::from([http_allowance(FACILITATOR, 8443, "10.20.0.0/24")]);
    assert_ne!(
        private_network_allowance_digest(&https).expect("digest"),
        private_network_allowance_digest(&http).expect("digest")
    );
}

#[test]
fn allowance_scheme_defaults_to_https_and_rejects_unknown_values() {
    let named: PrivateNetworkAllowance = serde_json::from_value(serde_json::json!({
        "host": FACILITATOR,
        "port": 8443,
        "scheme": "http",
        "cidr": "10.20.0.0/24"
    }))
    .expect("named scheme");
    assert_eq!(named, http_allowance(FACILITATOR, 8443, "10.20.0.0/24"));
    for scheme in ["ftp", "HTTP", ""] {
        let error = serde_json::from_value::<PrivateNetworkAllowance>(serde_json::json!({
            "host": FACILITATOR,
            "port": 8443,
            "scheme": scheme,
            "cidr": "10.20.0.0/24"
        }))
        .expect_err("unknown scheme");
        assert!(error.to_string().contains("unknown variant"), "{error}");
    }
}

#[test]
fn malformed_allowances_are_refused_at_load() {
    let cases = [
        (
            allowance("*.vpc.internal", 8443, "10.20.0.0/24"),
            PrivateNetworkAllowanceError::WildcardHost {
                host: "*.vpc.internal".to_string(),
            },
        ),
        (
            allowance("", 8443, "10.20.0.0/24"),
            PrivateNetworkAllowanceError::WildcardHost {
                host: String::new(),
            },
        ),
        (
            allowance("Facilitator.vpc.internal", 8443, "10.20.0.0/24"),
            PrivateNetworkAllowanceError::HostNotNormalized {
                host: "Facilitator.vpc.internal".to_string(),
            },
        ),
        (
            allowance("facilitator.vpc.internal.", 8443, "10.20.0.0/24"),
            PrivateNetworkAllowanceError::HostNotNormalized {
                host: "facilitator.vpc.internal.".to_string(),
            },
        ),
        (
            allowance("[fd12:3456::7]", 8443, "fd12:3456::7/128"),
            PrivateNetworkAllowanceError::HostNotNormalized {
                host: "[fd12:3456::7]".to_string(),
            },
        ),
        (
            allowance(FACILITATOR, 0, "10.20.0.0/24"),
            PrivateNetworkAllowanceError::PortZero {
                host: FACILITATOR.to_string(),
            },
        ),
        (
            allowance(FACILITATOR, 9443, "10.20.0.0/24"),
            PrivateNetworkAllowanceError::HostNotInAuthoritySet {
                host: FACILITATOR.to_string(),
                port: 9443,
            },
        ),
        (
            allowance("10.0.4.7", 8443, "10.0.4.0/24"),
            PrivateNetworkAllowanceError::LiteralHostCidrMismatch {
                host: "10.0.4.7".to_string(),
                cidr: "10.0.4.0/24".to_string(),
            },
        ),
    ];
    for (entry, expected) in cases {
        assert_eq!(
            load_error(std::slice::from_ref(&entry)),
            HttpEgressError::InvalidAllowance(expected),
            "{entry:?}"
        );
    }
    assert_eq!(
        load_error(&[
            allowance(FACILITATOR, 8443, "10.20.0.0/24"),
            allowance(FACILITATOR, 8443, "10.21.0.0/24"),
        ]),
        HttpEgressError::InvalidAllowance(PrivateNetworkAllowanceError::DuplicateAllowance {
            host: FACILITATOR.to_string(),
            port: 8443,
        })
    );
}

#[test]
fn public_host_on_the_default_port_may_be_pinned() {
    let contract = vpc_contract(&[allowance("public.example", 443, "10.30.0.0/24")]);
    contract.validate().expect("bare authority admits port 443");
    assert_eq!(
        resolved(&contract, "public.example", "10.30.0.9", 443),
        Ok(())
    );
    assert_eq!(
        resolved(&contract, "public.example", "93.184.216.34", 443),
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: "public.example".to_string(),
            port: 443,
            address: "93.184.216.34".parse().expect("ip"),
        })
    );
}

#[test]
fn cidr_text_must_be_canonical() {
    for (text, expected) in [
        (
            "10.20.0.1/24",
            PrivateNetworkAllowanceError::CidrHostBitsSet {
                cidr: "10.20.0.1/24".to_string(),
            },
        ),
        (
            "::ffff:10.20.0.0/120",
            PrivateNetworkAllowanceError::MappedCidr {
                cidr: "::ffff:10.20.0.0/120".to_string(),
            },
        ),
        (
            "10.20.0.0/33",
            PrivateNetworkAllowanceError::InvalidCidr {
                cidr: "10.20.0.0/33".to_string(),
            },
        ),
        (
            "10.20.0.0/024",
            PrivateNetworkAllowanceError::InvalidCidr {
                cidr: "10.20.0.0/024".to_string(),
            },
        ),
        (
            "10.20.0.0",
            PrivateNetworkAllowanceError::InvalidCidr {
                cidr: "10.20.0.0".to_string(),
            },
        ),
        (
            "FD12::/48",
            PrivateNetworkAllowanceError::InvalidCidr {
                cidr: "FD12::/48".to_string(),
            },
        ),
    ] {
        assert_eq!(text.parse::<IpCidr>(), Err(expected), "{text}");
    }
}

#[test]
fn contract_and_allowance_refuse_unknown_fields() {
    let contract = serde_json::json!({
        "tenant_egress_namespace": "t",
        "allowed_schemes": ["https"],
        "allowed_authority_set": ["a.example"],
        "deny_loopback": true,
        "deny_link_local": true,
        "max_redirect_chain": 0,
        "max_response_bytes": 1,
        "allow_private": true
    });
    let error =
        serde_json::from_value::<HttpEgressContract>(contract).expect_err("unknown contract field");
    assert!(
        error.to_string().contains("unknown field `allow_private`"),
        "{error}"
    );

    let entry = serde_json::json!({
        "host": FACILITATOR,
        "port": 8443,
        "cidr": "10.20.0.0/24",
        "wildcard": true
    });
    let error = serde_json::from_value::<PrivateNetworkAllowance>(entry)
        .expect_err("unknown allowance field");
    assert!(
        error.to_string().contains("unknown field `wildcard`"),
        "{error}"
    );

    let parsed: PrivateNetworkAllowance = serde_json::from_value(serde_json::json!({
        "host": FACILITATOR,
        "port": 8443,
        "cidr": "10.20.0.0/24"
    }))
    .expect("allowance");
    assert_eq!(parsed, allowance(FACILITATOR, 8443, "10.20.0.0/24"));
}

#[test]
fn allowance_digest_is_tagged_ordered_and_content_bound() {
    assert_eq!(
        private_network_allowance_digest(&BTreeSet::new()).expect("digest"),
        EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST
    );
    let first = allowance(FACILITATOR, 8443, "10.20.0.0/24");
    let second = allowance("10.0.4.7", 8443, "10.0.4.7/32");
    let forward = BTreeSet::from([first.clone(), second.clone()]);
    let reverse = BTreeSet::from([second, first]);
    let digest = private_network_allowance_digest(&forward).expect("digest");
    assert_eq!(
        digest,
        private_network_allowance_digest(&reverse).expect("digest")
    );
    assert_eq!(digest.len(), 64);
    let widened = BTreeSet::from([allowance(FACILITATOR, 8443, "10.20.0.0/23")]);
    assert_ne!(
        private_network_allowance_digest(&widened).expect("digest"),
        private_network_allowance_digest(&BTreeSet::from([allowance(
            FACILITATOR,
            8443,
            "10.20.0.0/24"
        )]))
        .expect("digest")
    );
    assert_eq!(
        facilitator_contract()
            .private_network_allowance_digest()
            .expect("digest"),
        private_network_allowance_digest(&BTreeSet::from([allowance(
            FACILITATOR,
            8443,
            "10.20.0.0/24"
        )]))
        .expect("digest")
    );
}

#[test]
fn contract_takes_only_the_set_entries_for_its_authorities() {
    let set = EgressAllowanceSet::new([
        allowance(FACILITATOR, 8443, "10.20.0.0/24"),
        allowance(FACILITATOR, 9443, "10.21.0.0/24"),
        allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
        allowance("public.example", 443, "10.30.0.0/24"),
        allowance("unrelated.vpc.internal", 8443, "10.40.0.0/24"),
    ])
    .expect("valid set");
    let contract = vpc_contract(&[]).with_private_network_allowances(&set);
    assert_eq!(
        contract.private_network_allowances,
        BTreeSet::from([
            allowance(FACILITATOR, 8443, "10.20.0.0/24"),
            allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
            allowance("public.example", 443, "10.30.0.0/24"),
        ])
    );
    contract
        .validate()
        .expect("filtered allowances fit the contract");
    assert_eq!(resolved(&contract, FACILITATOR, "10.20.0.5", 8443), Ok(()));

    let empty = vpc_contract(&[allowance(FACILITATOR, 8443, "10.20.0.0/24")])
        .with_private_network_allowances(&EgressAllowanceSet::default());
    assert!(empty.private_network_allowances.is_empty());
}

#[test]
fn allowance_set_validates_each_entry_and_refuses_duplicates() {
    assert_eq!(
        EgressAllowanceSet::new([allowance(FACILITATOR, 8443, "100.100.0.0/16")]),
        Err(PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
            cidr: "100.100.0.0/16".to_string(),
            reserved: "100.100.100.200/32".to_string(),
        })
    );
    assert_eq!(
        EgressAllowanceSet::new([
            allowance(FACILITATOR, 8443, "10.20.0.0/24"),
            allowance(FACILITATOR, 8443, "10.21.0.0/24"),
        ]),
        Err(PrivateNetworkAllowanceError::DuplicateAllowance {
            host: FACILITATOR.to_string(),
            port: 8443,
        })
    );
}

#[test]
fn reserved_addresses_are_link_local_and_metadata() {
    for address in [
        "169.254.169.254",
        "169.254.0.1",
        "100.100.100.200",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
    ] {
        assert!(
            super::address_is_reserved(address.parse().expect("ip")),
            "{address}"
        );
    }
    for address in [
        "10.0.0.1",
        "100.100.100.201",
        "fd00::1",
        "127.0.0.1",
        "8.8.8.8",
    ] {
        assert!(
            !super::address_is_reserved(address.parse().expect("ip")),
            "{address}"
        );
    }
}

fn ula_contract(allowances: serde_json::Value) -> HttpEgressContract {
    serde_json::from_value(serde_json::json!({
        "tenant_egress_namespace": "ula",
        "allowed_schemes": ["https"],
        "allowed_authority_set": [
            "ula.example:8443",
            "other.example:8443",
            "[fd12:3456:789a::7]:8443"
        ],
        "deny_loopback": true,
        "deny_link_local": true,
        "max_redirect_chain": 0,
        "max_response_bytes": 1,
        "private_network_allowances": allowances
    }))
    .expect("contract parses")
}

#[test]
fn unique_local_dial_is_admitted_only_through_a_pinned_allowance() {
    let ula: SocketAddr = "[fd12:3456:789a::7]:8443".parse().expect("addr");
    let literal = "https://[fd12:3456:789a::7]:8443/";

    let unpinned = ula_contract(serde_json::json!([]));
    assert_eq!(
        unpinned.enforce_resolved_address("ula.example", ula),
        Err(HttpEgressError::Ipv6UlaDenied {
            host: "ula.example resolved to fd12:3456:789a::7".to_string()
        })
    );
    assert_eq!(
        unpinned.enforce_url(literal, 0),
        Err(HttpEgressError::Ipv6UlaDenied {
            host: "fd12:3456:789a::7".to_string()
        })
    );

    let pinned = ula_contract(serde_json::json!([
        {"host": "ula.example", "port": 8443, "cidr": "fd12:3456:789a::/48"},
        {"host": "fd12:3456:789a::7", "port": 8443, "cidr": "fd12:3456:789a::7/128"}
    ]));
    assert_eq!(pinned.enforce_resolved_address("ula.example", ula), Ok(()));
    assert!(pinned.enforce_url(literal, 0).is_ok());
    assert_eq!(
        pinned.enforce_resolved_address("other.example", ula),
        Err(HttpEgressError::Ipv6UlaDenied {
            host: "other.example resolved to fd12:3456:789a::7".to_string()
        })
    );
}

#[test]
fn contract_refuses_a_unique_local_opt_out() {
    let error = serde_json::from_value::<HttpEgressContract>(serde_json::json!({
        "tenant_egress_namespace": "ula",
        "allowed_schemes": ["https"],
        "allowed_authority_set": ["[fd12:3456:789a::7]:8443"],
        "deny_loopback": true,
        "deny_link_local": true,
        "deny_ipv6_ula": false,
        "max_redirect_chain": 0,
        "max_response_bytes": 1
    }))
    .expect_err("unique-local opt-out");
    assert!(
        error.to_string().contains("unknown field `deny_ipv6_ula`"),
        "{error}"
    );
}

#[test]
fn unpinned_unique_local_metadata_reports_the_reserved_range() {
    let unpinned = ula_contract(serde_json::json!([]));
    assert_eq!(
        unpinned
            .enforce_resolved_address("ula.example", "[fd00:ec2::254]:8443".parse().expect("addr")),
        Err(HttpEgressError::ReservedAddressDenied {
            host: "ula.example resolved to fd00:ec2::254".to_string()
        })
    );
}

#[test]
fn one_host_port_pinned_under_both_schemes_is_a_scheme_conflict() {
    let contract = dual_scheme(vpc_contract(&[
        allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
        http_allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
    ]));
    let error = contract.validate().expect_err("both schemes");
    assert_eq!(
        error.to_string(),
        "invalid private network allowance: allowance for fd12:3456::7:8443 names both http and https"
    );
    let error = EgressAllowanceSet::new([
        allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
        http_allowance("fd12:3456::7", 8443, "fd12:3456::7/128"),
    ])
    .expect_err("both schemes");
    assert_eq!(
        error.to_string(),
        "allowance for fd12:3456::7:8443 names both http and https"
    );
}
