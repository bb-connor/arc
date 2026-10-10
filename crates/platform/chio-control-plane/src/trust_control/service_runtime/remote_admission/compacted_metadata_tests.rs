use super::*;
use chio_kernel::admission_operation::AdmissionDigest;
use serde::Deserialize;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn retention_error() -> Result<AdmissionAuthorityWireError, Box<dyn std::error::Error>> {
    Ok(AdmissionAuthorityWireError {
        code: AdmissionAuthorityErrorCode::Invariant,
        message: "terminal raw invocation payload was compacted; immutable digest and size remain retained".into(),
        compacted_raw: Some(CompactedRawMetadata::new(AdmissionDigest::try_new("test", "a".repeat(64))?, 3727)?),
    })
}

#[test]
fn compacted_payload_rpc_roundtrip_keeps_typed_retention_and_old_clients_fail_closed() -> TestResult
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OldWireError {
        #[serde(rename = "code")]
        _code: AdmissionAuthorityErrorCode,
        #[serde(rename = "message")]
        _message: String,
    }
    let error = retention_error()?;
    let old_error = serde_json::from_slice::<OldWireError>(&serde_json::to_vec(&error)?)
        .err()
        .ok_or("old strict client must reject new metadata")?;
    assert!(old_error.is_data());
    assert!(old_error
        .to_string()
        .contains("unknown field `compacted_raw`"));
    let response = AdmissionAuthorityResponse {
        schema: "chio.admission-authority-response.v1".into(),
        result: None,
        error: Some(error),
    };
    let response = serde_json::from_slice(&serde_json::to_vec(&response)?)?;
    let error = decode_response::<Option<serde_json::Value>>(response)
        .err()
        .ok_or("known retention must remain an error")?;
    assert!(
        matches!(outcome_error(error), ToolOutcomeStoreError::Compacted { raw_output_digest, raw_output_size_bytes:3727 } if raw_output_digest.as_str() == "a".repeat(64))
    );
    Ok(())
}

#[test]
fn compacted_payload_rpc_rejects_metadata_under_inconsistent_error_categories() -> TestResult {
    for code in [
        AdmissionAuthorityErrorCode::NotFound,
        AdmissionAuthorityErrorCode::Fenced,
        AdmissionAuthorityErrorCode::Unavailable,
        AdmissionAuthorityErrorCode::InvalidRequest,
        AdmissionAuthorityErrorCode::Conflict,
        AdmissionAuthorityErrorCode::CasConflict,
        AdmissionAuthorityErrorCode::OutcomeUnknown,
        AdmissionAuthorityErrorCode::Unsupported,
        AdmissionAuthorityErrorCode::Timeout,
    ] {
        let mut error = retention_error()?;
        error.code = code;
        let response = AdmissionAuthorityResponse {
            schema: "chio.admission-authority-response.v1".into(),
            result: None,
            error: Some(error),
        };
        let response = serde_json::from_slice(&serde_json::to_vec(&response)?)?;
        let error = decode_response::<Option<serde_json::Value>>(response)
            .err()
            .ok_or("inconsistent retention must fail")?;
        assert!(matches!(error, RemoteAdmissionError::Protocol(_)), "compacted metadata under {code:?} must reject before any missing-record or other-category mapping: {error:?}");
    }
    Ok(())
}
