use std::error::Error;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use chio_egress_contract::{
    ContractLookup, EgressAllowanceSet, HttpEgressError, PrivateNetworkAllowance,
};

use super::factory::{
    build_client, build_client_with_lookup, build_cluster_peer_client, control_client_contract,
    MixedLoopbackControlEndpoints,
};
use crate::trust_control::caller_credentials::tests as credentials;
use crate::trust_control::caller_credentials::{TrustAccess, TrustAccessConfig};
use crate::CliError;

const TOKEN: &str = "egress-regression-token";

fn egress_refusal(error: &CliError) -> Option<HttpEgressError> {
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(cause) = current {
        if let Some(refusal) = cause.downcast_ref::<HttpEgressError>() {
            return Some(refusal.clone());
        }
        current = cause.source();
    }
    None
}

fn refused(control_url: &str) -> HttpEgressError {
    let Err(error) = build_client(control_url, TOKEN, &EgressAllowanceSet::default()) else {
        panic!("control endpoint {control_url} must be refused");
    };
    egress_refusal(&error).unwrap_or_else(|| panic!("untyped refusal for {control_url}: {error}"))
}

#[test]
fn link_local_control_endpoint_is_refused_at_construction() {
    assert_eq!(
        refused("https://169.254.169.254"),
        HttpEgressError::LinkLocalDenied {
            host: "169.254.169.254".to_string()
        }
    );
    assert_eq!(
        refused("https://[fe80::1]:8443"),
        HttpEgressError::LinkLocalDenied {
            host: "fe80::1".to_string()
        }
    );
    assert_eq!(
        refused("https://control.example,https://169.254.169.254:9443"),
        HttpEgressError::LinkLocalDenied {
            host: "169.254.169.254".to_string()
        }
    );
}

#[test]
fn unlisted_private_control_endpoint_is_refused() {
    assert_eq!(
        refused("https://10.20.0.5:8443"),
        HttpEgressError::PrivateNetworkDenied {
            host: "10.20.0.5".to_string()
        }
    );
}

fn allowance_set(host: &str, port: u16, cidr: &str) -> EgressAllowanceSet {
    EgressAllowanceSet::new([PrivateNetworkAllowance {
        host: host.to_string(),
        port,
        cidr: cidr.parse().expect("cidr"),
    }])
    .expect("valid allowance set")
}

/// Accept connections on `listener` until `stop`, counting each.
fn count_accepts(listener: TcpListener, stop: Arc<AtomicBool>) -> JoinHandle<usize> {
    listener.set_nonblocking(true).expect("nonblocking");
    std::thread::spawn(move || {
        let mut accepted = 0;
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted += 1;
                    drop(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        accepted
    })
}

const PRIVATE_HOST: &str = "control.vpc.internal";
const PRIVATE_PORT: u16 = 8443;

/// Answers every lookup with `address`, counting the lookups.
fn answering(address: IpAddr, lookups: &Arc<AtomicUsize>) -> ContractLookup {
    let lookups = Arc::clone(lookups);
    ContractLookup::new(move |_host: &str, port: u16| {
        lookups.fetch_add(1, Ordering::SeqCst);
        Ok(vec![SocketAddr::new(address, port)])
    })
}

fn private_control_url() -> String {
    format!("https://{PRIVATE_HOST}:{PRIVATE_PORT}")
}

#[test]
fn allowed_private_control_endpoint_resolves_inside_its_allowance() {
    let allowances = allowance_set(PRIVATE_HOST, PRIVATE_PORT, "10.20.0.0/24");
    let contract = control_client_contract(&[private_control_url()], &allowances)
        .expect("an allowed private control endpoint is admitted");
    contract
        .enforce_resolved_address(
            PRIVATE_HOST,
            SocketAddr::from(([10, 20, 0, 5], PRIVATE_PORT)),
        )
        .expect("an answer inside the allowance is dialed");
    assert_eq!(
        contract.enforce_resolved_address(
            PRIVATE_HOST,
            SocketAddr::from(([10, 30, 0, 5], PRIVATE_PORT))
        ),
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: PRIVATE_HOST.to_string(),
            port: PRIVATE_PORT,
            address: IpAddr::from([10, 30, 0, 5]),
        })
    );
}

#[test]
fn private_answer_outside_its_allowance_is_never_dialed() {
    let lookups = Arc::new(AtomicUsize::new(0));
    let client = build_client_with_lookup(
        &private_control_url(),
        TOKEN,
        &allowance_set(PRIVATE_HOST, PRIVATE_PORT, "10.20.0.0/24"),
        answering(IpAddr::from([10, 30, 0, 5]), &lookups),
    )
    .expect("the endpoint passes construction");
    let error = client
        .authority_status()
        .expect_err("the answer lies outside the allowance");
    assert_eq!(
        egress_refusal(&error),
        Some(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host: PRIVATE_HOST.to_string(),
            port: PRIVATE_PORT,
            address: IpAddr::from([10, 30, 0, 5]),
        })
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[test]
fn private_answer_without_its_allowance_is_never_dialed() {
    for allowances in [
        EgressAllowanceSet::default(),
        allowance_set(PRIVATE_HOST, PRIVATE_PORT + 1, "10.20.0.0/24"),
    ] {
        let lookups = Arc::new(AtomicUsize::new(0));
        let client = build_client_with_lookup(
            &private_control_url(),
            TOKEN,
            &allowances,
            answering(IpAddr::from([10, 20, 0, 5]), &lookups),
        )
        .expect("a DNS endpoint passes construction");
        let error = client
            .authority_status()
            .expect_err("an unlisted private answer is refused");
        assert_eq!(
            egress_refusal(&error),
            Some(HttpEgressError::PrivateNetworkDenied {
                host: format!("{PRIVATE_HOST} resolved to 10.20.0.5"),
            })
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }
}

fn access_with_peer_at(internal_url: &str) -> Arc<TrustAccess> {
    let node_b = "https://node-b.example:9101";
    let body = format!(
        "{}{}",
        credentials::credential(
            "reader",
            "caller",
            "reader-secret",
            &["receipts:read"],
            None
        ),
        credentials::peer(
            node_b,
            &credentials::test_node_keypair(node_b),
            credentials::REPLICA_SCOPES
        )
        .replace(
            &format!("internal_url = \"{node_b}\""),
            &format!("internal_url = \"{internal_url}\""),
        ),
    );
    let config = TrustAccessConfig::from_toml_str(&credentials::config(&body)).expect("config");
    Arc::new(
        TrustAccess::from_parts(
            config,
            Some(credentials::test_node_keypair(credentials::SELF_NODE)),
        )
        .expect("access"),
    )
}

#[test]
fn pinned_peer_at_a_private_url_needs_its_allowance() {
    let access = access_with_peer_at("https://10.20.0.5:9101");
    let Err(error) = build_cluster_peer_client(
        &access,
        "https://node-b.example:9101",
        &EgressAllowanceSet::default(),
    ) else {
        panic!("a peer at an unlisted private URL must be refused");
    };
    assert_eq!(
        egress_refusal(&error),
        Some(HttpEgressError::PrivateNetworkDenied {
            host: "10.20.0.5".to_string()
        })
    );
    build_cluster_peer_client(
        &access,
        "https://node-b.example:9101",
        &allowance_set("10.20.0.5", 9101, "10.20.0.5/32"),
    )
    .expect("a peer inside its allowance is admitted");
}

#[test]
fn contract_refusal_at_connect_aborts_without_failover() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let fallback = listener.local_addr().expect("address");
    let stop = Arc::new(AtomicBool::new(false));
    let accepts = count_accepts(listener, Arc::clone(&stop));
    let client = build_client(
        &format!("https://localhost:9443,https://{fallback}"),
        TOKEN,
        &allowance_set("localhost", 9443, "10.20.0.0/24"),
    )
    .expect("both endpoints pass construction");
    let error = client
        .authority_status()
        .expect_err("localhost resolves outside its allowance");
    stop.store(true, Ordering::SeqCst);
    let Some(HttpEgressError::PrivateNetworkAllowanceMismatch {
        host,
        port,
        address,
    }) = egress_refusal(&error)
    else {
        panic!("expected an allowance mismatch, got {error}");
    };
    assert_eq!((host.as_str(), port), ("localhost", 9443));
    assert!(address.is_loopback(), "{address}");
    assert_eq!(
        accepts.join().expect("listener"),
        0,
        "a contract refusal must not fail over to the next endpoint"
    );
}

fn innermost_cause(error: &CliError) -> String {
    let mut current: &(dyn Error + 'static) = error;
    while let Some(cause) = current.source() {
        current = cause;
    }
    current.to_string()
}

#[test]
fn loopback_literal_beside_another_endpoint_is_refused_at_construction() {
    for (control_url, loopback, other) in [
        (
            "https://control.example:9443,http://127.0.0.1:8940",
            "127.0.0.1:8940",
            "control.example:9443",
        ),
        (
            "https://localhost:8940,https://control.example",
            "localhost:8940",
            "control.example",
        ),
        (
            "http://[::1]:8940,https://10.20.0.5:8443",
            "[::1]:8940",
            "10.20.0.5:8443",
        ),
    ] {
        let Err(error) = build_client(
            control_url,
            TOKEN,
            &allowance_set("10.20.0.5", 8443, "10.20.0.5/32"),
        ) else {
            panic!("mixed endpoint list {control_url} was accepted");
        };
        assert_eq!(
            error.report().message,
            "trust-control endpoints mix loopback and non-loopback hosts",
            "{control_url}"
        );
        let mut cause: Option<&(dyn Error + 'static)> = Some(&error);
        let mut typed = None;
        while let Some(current) = cause {
            typed = typed.or_else(|| current.downcast_ref::<MixedLoopbackControlEndpoints>());
            cause = current.source();
        }
        assert_eq!(
            typed,
            Some(&MixedLoopbackControlEndpoints {
                loopback: loopback.to_string(),
                other: other.to_string(),
            }),
            "{control_url}"
        );
        assert_eq!(
            innermost_cause(&error),
            format!(
                "control endpoints mix loopback `{loopback}` with non-loopback `{other}`; \
                 a client dials loopback literals only or no loopback at all"
            ),
            "{control_url}"
        );
    }
}

#[test]
fn endpoint_lists_on_one_side_of_loopback_are_accepted() {
    for control_url in [
        "http://127.0.0.1:8940,https://localhost:8941,http://[::1]:8942",
        "https://control.example:9443,https://control-b.example:9443",
    ] {
        build_client(control_url, TOKEN, &EgressAllowanceSet::default())
            .unwrap_or_else(|error| panic!("{control_url} was refused: {error}"));
    }
}
