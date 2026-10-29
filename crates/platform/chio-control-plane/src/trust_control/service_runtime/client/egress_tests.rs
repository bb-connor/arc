use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use chio_egress_contract::{EgressAllowanceSet, HttpEgressError, PrivateNetworkAllowance};

use super::factory::{build_client, build_cluster_peer_client};
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

/// A private IPv4 address of this host, the source address it uses toward a
/// private destination. A host with no private interface cannot run the
/// allowed-dial tests.
fn local_private_ipv4() -> Ipv4Addr {
    let probe = UdpSocket::bind("0.0.0.0:0").expect("bind probe");
    probe
        .connect("10.255.255.254:9")
        .expect("route to a private address");
    match probe.local_addr().expect("probe address").ip() {
        IpAddr::V4(address) if address.is_private() => address,
        other => panic!("this host has no private IPv4 interface (routed source {other})"),
    }
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

#[test]
fn allowed_private_control_endpoint_is_dialed() {
    let address = local_private_ipv4();
    let listener = TcpListener::bind((address, 0)).expect("bind private listener");
    let port = listener.local_addr().expect("listener address").port();
    let stop = Arc::new(AtomicBool::new(false));
    let accepts = count_accepts(listener, Arc::clone(&stop));
    let client = build_client(
        &format!("https://{address}:{port}"),
        TOKEN,
        &allowance_set(&address.to_string(), port, &format!("{address}/32")),
    )
    .expect("an allowed private control endpoint is admitted");
    let error = client
        .authority_status()
        .expect_err("the listener does not speak TLS");
    stop.store(true, Ordering::SeqCst);
    assert_eq!(accepts.join().expect("listener"), 1, "{error}");
    assert_eq!(egress_refusal(&error), None, "{error}");
}

#[test]
fn private_control_endpoint_without_its_allowance_is_never_dialed() {
    let address = local_private_ipv4();
    let listener = TcpListener::bind((address, 0)).expect("bind private listener");
    let port = listener.local_addr().expect("listener address").port();
    let stop = Arc::new(AtomicBool::new(false));
    let accepts = count_accepts(listener, Arc::clone(&stop));
    let other_port = if port == u16::MAX { port - 1 } else { port + 1 };
    for allowances in [
        EgressAllowanceSet::default(),
        allowance_set(&address.to_string(), other_port, &format!("{address}/32")),
    ] {
        let Err(error) = build_client(&format!("https://{address}:{port}"), TOKEN, &allowances)
        else {
            panic!("an unlisted private control endpoint must be refused");
        };
        assert_eq!(
            egress_refusal(&error),
            Some(HttpEgressError::PrivateNetworkDenied {
                host: address.to_string()
            })
        );
    }
    stop.store(true, Ordering::SeqCst);
    assert_eq!(accepts.join().expect("listener"), 0);
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
