use super::EvaluateRequest;
use chio_core_types::canonical::UntrustedJsonText;
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Deserialize)]
struct OriginalCapability<'a> {
    #[serde(borrow)]
    capability: Option<&'a RawValue>,
}

pub(super) fn decode_evaluate_request(body: &[u8]) -> Result<EvaluateRequest, String> {
    let text = std::str::from_utf8(body)
        .map_err(|error| format!("failed to decode evaluate request: {error}"))?;
    let request = UntrustedJsonText::new(text)
        .decode_document()
        .map_err(|error| format!("failed to decode evaluate request: {error}"))?;
    let original: OriginalCapability<'_> = serde_json::from_str(text)
        .map_err(|error| format!("failed to decode evaluate request: {error}"))?;
    if let Some(capability) = original.capability {
        let _: serde_json::Value = UntrustedJsonText::new(capability.get())
            .decode_signed()
            .map_err(|error| format!("failed to decode evaluate request: {error}"))?;
    }
    Ok(request)
}
