//! Recovery-only transport retains actual errors before the legacy CLI maps.
use super::*;

#[derive(Debug, thiserror::Error)]
#[error("recovery authority refused the request ({code:?})")]
struct RecoveryAuthorityRefusal {
    code: AdmissionAuthorityErrorCode,
}

#[derive(Debug, thiserror::Error)]
#[error("recovery authority answered HTTP {status}")]
struct RecoveryHttpStatus {
    status: u16,
}

impl RemoteAdmissionAuthority {
    pub(super) fn call_recovery<B: Serialize, T: DeserializeOwned>(
        &self,
        action: AdmissionAuthorityAction,
        payload: &B,
    ) -> Result<T, AdmissionRecoveryPortError> {
        let request = AdmissionAuthorityRequest::new(Some(self.fence.clone()), action, payload)
            .map_err(json_error)?;
        let body = serde_json::to_vec(&request).map_err(json_error)?;
        let mut last_error = None;
        for index in self.client.endpoint_order() {
            let endpoint = self
                .client
                .endpoints
                .get(index)
                .ok_or_else(|| protocol_error(RecoveryProtocolError::Endpoint))?;
            let url = format!("{endpoint}{INTERNAL_ADMISSION_AUTHORITY_PATH}");
            let sent = self.client.http.post(&url).and_then(|request| {
                request
                    .header(
                        AUTHORIZATION.as_str(),
                        &format!("Bearer {}", self.client.token),
                    )
                    .header(CONTENT_TYPE.as_str(), "application/json")
                    .send_bytes(&body)
            });
            match sent {
                Ok(response) if response.status() < 400 => {
                    self.client.mark_preferred(index);
                    let cap = usize::try_from(ADMISSION_AUTHORITY_RESPONSE_LIMIT)
                        .map_err(|_| protocol_error(RecoveryProtocolError::PageBounds))?;
                    let response =
                        crate::json_input::read(response.body(), cap).map_err(|error| {
                            let kind = match &error {
                                CliError::Io(_) | CliError::Clock(_) => {
                                    RemoteRecoveryFailureKind::Unavailable
                                }
                                _ => RemoteRecoveryFailureKind::Invariant,
                            };
                            AdmissionRecoveryPortError::remote(kind, error)
                        })?;
                    return decode_recovery_response(response);
                }
                Ok(response)
                    if crate::trust_control::service_runtime::client::should_retry_status(
                        response.status(),
                    ) =>
                {
                    last_error = Some(AdmissionRecoveryPortError::remote(
                        RemoteRecoveryFailureKind::Unavailable,
                        RecoveryHttpStatus {
                            status: response.status(),
                        },
                    ));
                }
                Ok(response) => {
                    return Err(AdmissionRecoveryPortError::remote(
                        RemoteRecoveryFailureKind::Unavailable,
                        RecoveryHttpStatus {
                            status: response.status(),
                        },
                    ));
                }
                Err(error)
                    if crate::trust_control::service_runtime::client::is_transport_failure(
                        &error,
                    ) =>
                {
                    last_error = Some(AdmissionRecoveryPortError::remote(
                        RemoteRecoveryFailureKind::Unavailable,
                        error,
                    ));
                }
                Err(error) => {
                    return Err(AdmissionRecoveryPortError::remote(
                        RemoteRecoveryFailureKind::Invariant,
                        error,
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            AdmissionRecoveryPortError::remote(
                RemoteRecoveryFailureKind::Unavailable,
                RecoveryProtocolError::Endpoint,
            )
        }))
    }
}

fn json_error(error: serde_json::Error) -> AdmissionRecoveryPortError {
    AdmissionRecoveryPortError::remote(RemoteRecoveryFailureKind::Invariant, error)
}

fn decode_recovery_response<T: DeserializeOwned>(
    response: AdmissionAuthorityResponse,
) -> Result<T, AdmissionRecoveryPortError> {
    if !response.schema_is_valid() {
        return Err(protocol_error(RecoveryProtocolError::ResponseSchema));
    }
    if response
        .error
        .as_ref()
        .is_some_and(|error| error.compacted_raw.is_some())
    {
        return Err(protocol_error(RecoveryProtocolError::CompactionMetadata));
    }
    match (response.result, response.error) {
        (Some(result), None) => serde_json::from_value(result.value).map_err(json_error),
        (None, Some(error)) => {
            let kind = match error.code {
                AdmissionAuthorityErrorCode::Unavailable
                | AdmissionAuthorityErrorCode::Unsupported
                | AdmissionAuthorityErrorCode::Timeout
                | AdmissionAuthorityErrorCode::Stopped => RemoteRecoveryFailureKind::Unavailable,
                AdmissionAuthorityErrorCode::OutputWithheld => {
                    RemoteRecoveryFailureKind::OutputWithheld
                }
                AdmissionAuthorityErrorCode::Fenced => RemoteRecoveryFailureKind::Fenced,
                AdmissionAuthorityErrorCode::NotFound => RemoteRecoveryFailureKind::NotFound,
                AdmissionAuthorityErrorCode::Conflict
                | AdmissionAuthorityErrorCode::CasConflict => RemoteRecoveryFailureKind::Conflict,
                AdmissionAuthorityErrorCode::Invariant
                | AdmissionAuthorityErrorCode::InvalidRequest => {
                    RemoteRecoveryFailureKind::Invariant
                }
                AdmissionAuthorityErrorCode::OutcomeUnknown => {
                    RemoteRecoveryFailureKind::OutcomeUnknown
                }
            };
            Err(AdmissionRecoveryPortError::remote(
                kind,
                RecoveryAuthorityRefusal { code: error.code },
            ))
        }
        _ => Err(protocol_error(RecoveryProtocolError::ResponseOutcome)),
    }
}
