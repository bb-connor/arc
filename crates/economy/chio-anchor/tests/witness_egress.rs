#![cfg(feature = "web3")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chio_anchor::{
    build_anchor_batch, AnchorBatch, AnchorBatchWitness, AnchorBatchWitnessKind,
    AnchorWitnessClient, AnchorWitnessError, OtsClient, RekorClient,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;
use chio_egress_contract::{HttpEgressContract, HttpEgressError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sample_batch() -> Result<AnchorBatch, Box<dyn std::error::Error>> {
    Ok(build_anchor_batch(
        vec!["ck-1".to_owned()],
        AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Ots,
            witness_id: "ots:pending".to_owned(),
            root: Hash::zero(),
            observed_at: Some(1_700_000_000),
        },
        1_700_000_000,
        &Keypair::from_seed(&[5; 32]),
    )?)
}

async fn respond_once(listener: TcpListener, response: String) -> Result<(), std::io::Error> {
    let (mut stream, _) = listener.accept().await?;
    let mut request = [0_u8; 8192];
    let _ = stream.read(&mut request).await?;
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[tokio::test]
async fn ots_publish_never_dials_a_redirect_target_outside_the_calendar() -> TestResult {
    let calendar = TcpListener::bind("127.0.0.1:0").await?;
    let elsewhere = TcpListener::bind("127.0.0.1:0").await?;
    let calendar_url = format!("http://{}", calendar.local_addr()?);
    let elsewhere_url = format!("http://{}/digest", elsewhere.local_addr()?);
    let redirect = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let calendar_task = tokio::spawn(respond_once(calendar, redirect));
    let dialed = Arc::new(AtomicBool::new(false));
    let elsewhere_task = {
        let dialed = Arc::clone(&dialed);
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = elsewhere.accept().await {
                dialed.store(true, Ordering::SeqCst);
                let _ = stream
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        })
    };

    let contract =
        HttpEgressContract::permissive_for_tests(calendar_url.trim_start_matches("http://"));
    let client = OtsClient::new(calendar_url, &contract, 0)?;
    let result = client.publish(&sample_batch()?).await;
    calendar_task.await??;
    elsewhere_task.abort();

    assert!(
        matches!(
            &result,
            Err(AnchorWitnessError::Egress(
                HttpEgressError::AuthorityDenied { .. }
            ))
        ),
        "{result:?}"
    );
    assert!(
        !dialed.load(Ordering::SeqCst),
        "OTS publish followed a redirect to an authority outside its calendar"
    );
    Ok(())
}

#[test]
fn witness_clients_refuse_endpoints_outside_their_contract() -> TestResult {
    let contract = HttpEgressContract::permissive_for_tests("calendar.example:443");
    assert!(matches!(
        OtsClient::new("https://other.example", &contract, 0),
        Err(AnchorWitnessError::Egress(
            HttpEgressError::AuthorityDenied { .. }
        ))
    ));
    assert!(matches!(
        RekorClient::new("https://other.example", &contract, 0),
        Err(AnchorWitnessError::Egress(
            HttpEgressError::AuthorityDenied { .. }
        ))
    ));
    let mut metadata = HttpEgressContract::permissive_for_tests("169.254.169.254:80");
    metadata.deny_link_local = true;
    assert!(matches!(
        OtsClient::new("http://169.254.169.254", &metadata, 0),
        Err(AnchorWitnessError::Egress(
            HttpEgressError::LinkLocalDenied { .. }
        ))
    ));
    assert!(matches!(
        RekorClient::new("http://169.254.169.254", &metadata, 0),
        Err(AnchorWitnessError::Egress(
            HttpEgressError::LinkLocalDenied { .. }
        ))
    ));
    Ok(())
}
