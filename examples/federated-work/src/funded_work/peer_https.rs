//! One authenticated verifier route. Observation configuration is receiver-owned.
use super::{peer_verifier as peer, process::SocketSource, verification, verifier_operator};
use crate::common::Result;
use chio_core_types::canonical_json_bytes;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use tiny_http::{Header, Method, Request, Response, StatusCode};

fn header<'a>(request: &'a Request, name: &'static str) -> Result<&'a str> {
    let mut values = request.headers().iter().filter(|h| h.field.equiv(name));
    let value = values.next().ok_or("missing HTTP header")?.value.as_str();
    if values.next().is_some() {
        return Err("duplicate HTTP header".into());
    }
    Ok(value)
}

fn body(request: &mut Request, origin: &str) -> Result<Vec<u8>> {
    let url = peer::origin(origin)?;
    if request.method() != &Method::Post
        || request.url() != peer::ROUTE
        || header(request, "Host")? != &url[url::Position::BeforeHost..url::Position::AfterPort]
        || header(request, "Content-Type")? != "application/json"
        || request.headers().iter().any(|h| {
            ["Transfer-Encoding", "Content-Encoding", "Expect"]
                .iter()
                .any(|n| h.field.equiv(*n))
        })
    {
        return Err("unsupported verifier HTTP request".into());
    }
    let length = header(request, "Content-Length")?;
    let size: usize = length.parse()?;
    if size == 0 || size > super::wire::MAX_ARTIFACT_BYTES || size.to_string() != length {
        return Err("invalid verifier request length".into());
    }
    let mut raw = Vec::new();
    request
        .as_reader()
        .take(size as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() != size {
        return Err("truncated verifier request".into());
    }
    Ok(raw)
}

/// The service cannot prepare or broadcast transactions, even when its operator
/// accidentally supplies a socket with broader methods. Defaults deny writes.
struct ReadOnly(SocketSource);
impl super::observer::FundingSource for ReadOnly {
    fn observe(&self, allocation: &str) -> Result<super::observer::Observation> {
        self.0.observe(allocation)
    }
    fn observe_transaction(
        &self,
        prepared: &super::settlement::Prepared,
    ) -> Result<super::observer::Observation> {
        self.0.observe_transaction(prepared)
    }
}

pub fn serve(state: &Path, socket: &Path, config: crate::https::HttpsConfig<'_>) -> Result<()> {
    // An OS lock is released on process death. Restart cannot steal a live
    // listener's backend socket, and needs neither seed nor new custody.
    let lock_path = state.join("verifier-https.lock");
    if lock_path
        .symlink_metadata()
        .is_ok_and(|m| !m.file_type().is_file())
    {
        return Err("verifier service lock must be a regular file".into());
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.try_lock()?;
    let enrollment = verifier_operator::enrollment(state)?;
    let listener = crate::https::listen_bounded(state, config, super::wire::MAX_ARTIFACT_BYTES)?;
    let source = ReadOnly(SocketSource(socket.to_owned()));
    let checker = verification::PythonChecker(
        std::env::var_os("CHIO_FUNDED_PYTHON")
            .unwrap_or_else(|| "python3".into())
            .into(),
    );
    println!("{}", serde_json::json!({"origin":listener.origin}));
    std::io::stdout().flush()?;
    for mut request in listener.server.incoming_requests() {
        let result = body(&mut request, &listener.origin)
            .and_then(|raw| peer::authenticate(&raw, &enrollment, &listener.origin));
        let (status, bytes) = match result {
            Err(_) => (
                400,
                b"{\"error\":\"invalid authenticated verifier call\"}".to_vec(),
            ),
            Ok(call) => {
                match verifier_operator::decide(state, &call.body.request, &source, &checker)
                    .and_then(|decision| Ok(canonical_json_bytes(&decision)?))
                {
                    Ok(raw) if raw.len() <= super::wire::MAX_ARTIFACT_BYTES => (200, raw),
                    _ => (
                        503,
                        b"{\"error\":\"verifier decision unavailable\"}".to_vec(),
                    ),
                }
            }
        };
        let response = Response::from_data(bytes)
            .with_status_code(StatusCode(status))
            .with_header(
                Header::from_bytes("Content-Type", "application/json")
                    .map_err(|_| "invalid constant header")?,
            )
            .with_header(
                Header::from_bytes("Connection", "close").map_err(|_| "invalid constant header")?,
            );
        // Delivery failure leaves first-response custody intact for exact retry.
        let _ = request.respond(response);
    }
    drop(listener.runtime);
    drop(lock);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::funded_work::{observer::FundingSource, settlement};

    #[test]
    fn receiver_source_cannot_prepare_or_broadcast_through_an_available_socket() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("observer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        let source = ReadOnly(SocketSource(socket));
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/scripts/fixtures/work-claim-vectors.json"
        ))?;
        let action = settlement::ActionRequest {
            action: settlement::Action::Submit,
            allocation_id: format!("0x{}", "ab".repeat(32)),
            terms: serde_json::from_value(vector["terms"].clone())?,
            commitment: None,
            decision: None,
        };
        assert!(source.prepare(&action).is_err());
        let prepared = settlement::Prepared {
            intent: serde_json::json!(null),
            nonce: "0".into(),
            raw_transaction: "0x00".into(),
            transaction_hash: format!("0x{}", "ab".repeat(32)),
        };
        assert!(source.transact(&prepared).is_err());
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("write unexpectedly contacted observer")?
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        Ok(())
    }
}
