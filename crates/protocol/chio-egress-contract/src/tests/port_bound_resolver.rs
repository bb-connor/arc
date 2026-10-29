//! The reqwest dispatcher checks every DNS answer against the request's own
//! port, so an allowance pinning one port of a host leaves its other ports to
//! the address-class policy.
use crate::{
    client_builder_with_contract, send_with_contract, HttpEgressContract, HttpEgressError,
    PrivateNetworkAllowance,
};
use std::collections::BTreeSet;
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
