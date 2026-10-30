//! A protocol refusal must never replay one native HTTP attempt.
use super::ContractClient;
use crate::{
    client_builder_with_contract, send_with_contract, HttpEgressContract, HttpEgressError,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn refuse_http2_streams(
    listener: TcpListener,
    observed: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut preface = [0; 24];
        stream.read_exact(&mut preface).await?;
        if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
            return Err(std::io::Error::other("HTTP/2 preface required"));
        }
        stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
        loop {
            let mut header = [0; 9];
            if let Err(error) = stream.read_exact(&mut header).await {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) {
                    break;
                }
                return Err(error);
            }
            let length =
                ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
            if length > 65536 {
                return Err(std::io::Error::other("HTTP/2 frame exceeds fixture bound"));
            }
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).await?;
            match header[3] {
                4 if header[4] & 1 == 0 => {
                    stream.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await?;
                }
                1 => {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let mut refusal = [0, 0, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 7];
                    refusal[5..9].copy_from_slice(&header[5..9]);
                    stream.write_all(&refusal).await?;
                }
                7 => break,
                _ => {}
            }
        }
    }
}

fn assert_remote_refusal(error: &(dyn std::error::Error + 'static)) {
    let mut cause = error;
    while let Some(source) = cause.source() {
        cause = source;
    }
    assert_eq!(
        cause.to_string(),
        "stream error received: refused stream before processing any application logic"
    );
}

async fn refused_attempts(
    client: impl FnOnce(&HttpEgressContract) -> Result<ContractClient, reqwest::Error>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let authority = listener.local_addr()?.to_string();
    let observed = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(refuse_http2_streams(listener, observed.clone()));
    let mut contract = HttpEgressContract::permissive_for_tests(&authority);
    contract.max_redirect_chain = 0;
    let client = client(&contract)?;
    let request = client
        .post(format!("http://{authority}/native-attempt"))
        .version(reqwest::Version::HTTP_2)
        .body("one-native-submission")
        .build()?;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        send_with_contract(&contract, &client, request),
    )
    .await;
    server.abort();
    match server.await {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.into()),
    }
    let error = result?.err().ok_or("REFUSED_STREAM was accepted")?;
    assert!(matches!(&error, HttpEgressError::Transport(_)), "{error:?}");
    assert_eq!(error.to_string(), "urn:chio:error:transport:http-failed");
    assert_remote_refusal(&error);
    Ok(observed.load(Ordering::SeqCst))
}

#[tokio::test]
async fn contract_client_does_not_retry_http2_refused_stream(
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = refused_attempts(|contract| {
        client_builder_with_contract(contract)
            .timeout(Duration::from_secs(5))
            .build_tuned(reqwest::ClientBuilder::http2_prior_knowledge)
    })
    .await?;
    assert_eq!(observed, 1, "one native attempt was replayed");
    Ok(())
}

#[tokio::test]
async fn default_policy_retries_the_same_http2_refusal_fixture(
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = refused_attempts(|contract| {
        let default_policy = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .http2_prior_knowledge()
            .build()?;
        let dispatchers = contract
            .allowed_authority_set
            .iter()
            .filter_map(|authority| authority.rsplit_once(':'))
            .filter_map(|(_, port)| port.parse::<u16>().ok())
            .map(|port| (port, default_policy.clone()))
            .collect();
        Ok(ContractClient {
            inner: default_policy,
            dispatchers: Arc::new(dispatchers),
        })
    })
    .await?;
    assert_eq!(
        observed, 3,
        "default protocol retry control did not replay twice"
    );
    Ok(())
}
