//! The reqwest dispatcher checks every DNS answer against the request's own
//! port, so an allowance pinning one port of a host leaves its other ports to
//! the address-class policy.
use super::ContractDnsResolver;
use crate::{
    client_builder_with_contract, send_with_contract, HttpEgressContract, HttpEgressError,
    PrivateNetworkAllowance,
};
use reqwest::dns::{Name, Resolve};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::net::TcpListener;

const PINNED_PORT: u16 = 8443;

fn localhost_contract(open_port: u16) -> Result<HttpEgressContract, Box<dyn std::error::Error>> {
    Ok(HttpEgressContract {
        tenant_egress_namespace: "port-bound-resolver".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string()]),
        allowed_authority_set: BTreeSet::from([
            format!("localhost:{PINNED_PORT}"),
            format!("localhost:{open_port}"),
        ]),
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 1024,
        private_network_allowances: BTreeSet::from([PrivateNetworkAllowance {
            host: "localhost".to_string(),
            port: PINNED_PORT,
            cidr: "10.20.0.0/24".parse()?,
        }]),
    })
}

async fn count_accepts(listener: TcpListener, accepted: Arc<AtomicUsize>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        accepted.fetch_add(1, Ordering::SeqCst);
        drop(stream);
    }
}

#[tokio::test]
async fn unpinned_port_of_a_pinned_host_is_dialed() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let open_port = listener.local_addr()?.port();
    assert_ne!(open_port, PINNED_PORT);
    let accepted = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(count_accepts(listener, accepted.clone()));

    let contract = localhost_contract(open_port)?;
    let client = client_builder_with_contract(&contract)
        .timeout(Duration::from_secs(5))
        .build()?;
    let request = client
        .get(format!("https://localhost:{open_port}/"))
        .build()?;
    let outcome = send_with_contract(&contract, &client, request).await;
    server.abort();

    assert!(
        matches!(outcome, Err(HttpEgressError::Transport(_))),
        "a plain TCP listener cannot complete TLS: {outcome:?}"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the dispatcher never dialed the checked loopback answer"
    );
    Ok(())
}

async fn resolve_localhost(
    contract: &HttpEgressContract,
    port: u16,
) -> Result<Result<Vec<SocketAddr>, HttpEgressError>, Box<dyn std::error::Error>> {
    let resolver = ContractDnsResolver {
        contract: contract.clone(),
        port,
    };
    match resolver.resolve(Name::from_str("localhost")?).await {
        Ok(addrs) => Ok(Ok(addrs.collect())),
        Err(error) => match error.downcast::<HttpEgressError>() {
            Ok(error) => Ok(Err(*error)),
            Err(other) => Err(other),
        },
    }
}

#[tokio::test]
async fn resolver_checks_each_answer_with_its_own_port() -> Result<(), Box<dyn std::error::Error>> {
    let open_port = 9443;
    let contract = localhost_contract(open_port)?;

    let open = resolve_localhost(&contract, open_port).await??;
    assert!(!open.is_empty());
    for addr in &open {
        assert!(addr.ip().is_loopback(), "{addr}");
        assert_eq!(
            addr.port(),
            open_port,
            "answers are bound to the checked port"
        );
    }

    match resolve_localhost(&contract, PINNED_PORT).await? {
        Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
            host,
            port,
            address,
        }) => {
            assert_eq!(host, "localhost");
            assert_eq!(port, PINNED_PORT);
            assert!(address.is_loopback(), "{address}");
        }
        other => panic!("a pinned port must refuse answers outside its CIDR: {other:?}"),
    }
    Ok(())
}
