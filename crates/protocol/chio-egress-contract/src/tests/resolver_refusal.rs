//! A refusal raised by the contract resolver keeps its refusal class.
use crate::{
    client_builder_with_contract, send_with_contract, HttpEgressContract, HttpEgressError,
};
use std::collections::BTreeSet;
use tokio::net::TcpListener;

/// Send through a client whose resolver enforces `dialing` while the request
/// itself is checked against a contract that admits the loopback target, so
/// the URL check passes and the refusal is raised while reqwest dials.
async fn dial_refusal(
    dialing: impl FnOnce(&mut HttpEgressContract, u16),
) -> Result<HttpEgressError, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let authority = format!("localhost:{port}");
    let checked = HttpEgressContract::permissive_for_tests(&authority);
    let mut resolver_contract = checked.clone();
    dialing(&mut resolver_contract, port);
    let client = client_builder_with_contract(&resolver_contract).build()?;
    let request = client.get(format!("http://{authority}/")).build()?;
    let error = send_with_contract(&checked, &client, request)
        .await
        .err()
        .ok_or("resolver refusal was accepted")?;
    Ok(error)
}

#[tokio::test]
async fn resolver_refusal_on_the_dial_keeps_its_refusal_class(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        dial_refusal(|contract, _| contract.deny_loopback = true).await?,
        HttpEgressError::LoopbackDenied {
            host: "localhost".to_string()
        }
    );
    assert_eq!(
        dial_refusal(|contract, port| {
            contract.allowed_authority_set = BTreeSet::from([format!("other.example:{port}")]);
        })
        .await?,
        HttpEgressError::AuthorityDenied {
            authority: "localhost".to_string()
        }
    );
    Ok(())
}
