//! Persistence acknowledgement for authenticated restricted-session refusals.

use super::*;

pub(super) async fn persist_restricted_refusal_response(
    session: Option<&RemoteSession>,
    message: AccountedMessage,
    mut response: Response,
    reason: chio_kernel::ProtocolRefusalReason,
) -> Response {
    let receipt = match (session, message.request_digest().cloned()) {
        (Some(session), Some(digest)) => {
            let summary = chio_kernel::ProtocolRefusalSummary::new(
                reason,
                message
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                message
                    .pointer("/params/name")
                    .or_else(|| message.pointer("/params/uri"))
                    .and_then(Value::as_str),
                digest,
            );
            match session.record_protocol_refusal(message, summary) {
                Ok(acknowledgement) => match tokio::task::spawn_blocking(move || {
                    acknowledgement.recv_timeout(Duration::from_secs(5))
                })
                .await
                {
                    Ok(Ok(Ok(receipt))) => Some(receipt),
                    _ => None,
                },
                Err(_) => None,
            }
        }
        _ => None,
    };
    response.headers_mut().insert(
        HeaderName::from_static("chio-refusal-evidence"),
        HeaderValue::from_static(if receipt.is_some() {
            "retained"
        } else {
            "unavailable"
        }),
    );
    if let Some(receipt) = receipt {
        if let Ok(id) = HeaderValue::from_str(&receipt.id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("chio-refusal-receipt-id"), id);
        }
    }
    response
}
