//! A protocol refusal must never replay one native HTTP attempt.
use crate::{client_builder_with_contract, send_with_contract, HttpEgressContract};
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

#[tokio::test]
async fn contract_client_does_not_retry_http2_refused_stream(
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let authority = listener.local_addr()?.to_string();
    let observed = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(refuse_http2_streams(listener, observed.clone()));
    let mut contract = HttpEgressContract::permissive_for_tests(&authority);
    contract.max_redirect_chain = 0;
    let client = client_builder_with_contract(&contract)
        .timeout(Duration::from_secs(5))
        .inner
        .http2_prior_knowledge()
        .build()?;
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
    let server_result = server.await;
    if let Ok(result) = server_result {
        result?;
    }
    let result = result?;
    if let Err(error) = &result {
        eprintln!(
            "HTTP2_FIXTURE_DISPATCH_ERROR observed_requests={} error={error}",
            observed.load(Ordering::SeqCst)
        );
    }
    assert!(
        result.is_err(),
        "provider REFUSED_STREAM must return an error"
    );
    assert_eq!(
        observed.load(Ordering::SeqCst),
        1,
        "one native attempt was replayed after a protocol refusal"
    );
    Ok(())
}
