use crate::RecordError;
use chio_provider_adapter_core::http::{HttpTransport, HttpTransportConfig, ProviderHttpTransport};
use serde_json::Value;

pub(crate) fn post_json_capture(
    _provider: &'static str,
    url: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> Result<String, RecordError> {
    let mut config = HttpTransportConfig::new(url);
    for (name, value) in headers {
        config = config.with_header(*name, value);
    }
    let transport = HttpTransport::new(config)?;
    let body_bytes = chio_core::canonical_json_bytes(body)
        .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        if body.get("stream").and_then(Value::as_bool) == Some(true) {
            transport.post_sse("", &body_bytes).await
        } else {
            transport
                .post_json("", &body_bytes)
                .await
                .map(|response| response.body)
        }
    })?;
    String::from_utf8(response).map_err(|error| {
        chio_core::canonical::UntrustedJsonError::NotUtf8(error.utf8_error()).into()
    })
}
