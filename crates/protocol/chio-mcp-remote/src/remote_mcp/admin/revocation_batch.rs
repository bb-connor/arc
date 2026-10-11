//! Confirmed, retryable session revocation with truthful partial progress.
use super::*;

#[derive(thiserror::Error)]
enum Failure {
    #[error("control revocation operation failed")]
    Control(#[from] CliError),
    #[error("local revocation operation failed")]
    Local(#[from] chio_kernel::RevocationStoreError),
    #[error("backend did not confirm the requested capability")]
    InvalidConfirmation,
    #[error("capability remains unrevoked")]
    NotConfirmed,
}

impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Debug)]
struct BatchFailure(Vec<Failure>);
impl std::fmt::Display for BatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("session revocation incomplete")
    }
}
impl std::error::Error for BatchFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .first()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

enum Backend {
    Remote(trust_control::TrustControlClient),
    Local(chio_store_sqlite::SqliteRevocationStore),
}
impl Backend {
    fn open(state: &RemoteAppState) -> Result<Self, Response> {
        match control_client(state)? {
            Some(client) => Ok(Self::Remote(client)),
            None => open_revocation_store(state).map(Self::Local),
        }
    }
    fn revoke(&self, id: &str) -> Result<bool, Failure> {
        match self {
            Self::Remote(client) => {
                let response = client.revoke_capability(id)?;
                if response.capability_id != id || !response.revoked {
                    return Err(Failure::InvalidConfirmation);
                }
                Ok(response.newly_revoked)
            }
            Self::Local(store) => Ok(store.revoke(id)?),
        }
    }
    fn readback(&self, id: &str) -> Result<bool, Failure> {
        match self {
            Self::Remote(client) => {
                let response = client.list_revocations(&RevocationQuery {
                    capability_id: Some(id.to_owned()),
                    limit: Some(1),
                })?;
                if !response.configured || response.capability_id.as_deref() != Some(id) {
                    return Err(Failure::InvalidConfirmation);
                }
                response.revoked.ok_or(Failure::InvalidConfirmation)
            }
            Self::Local(store) => Ok(store.is_revoked(id)?),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityOutcome {
    capability_id: String,
    issuer_public_key: String,
    subject_public_key: String,
    revoked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<&'static str>,
}

struct Batch {
    newly_revoked: usize,
    capabilities: Vec<CapabilityOutcome>,
    failures: Vec<Failure>,
}
impl Batch {
    fn execute(backend: Backend, capabilities: Vec<RemoteSessionCapability>) -> Self {
        let mut batch = Self {
            newly_revoked: 0,
            capabilities: Vec::with_capacity(capabilities.len()),
            failures: Vec::new(),
        };
        for capability in capabilities {
            let mut failure = None;
            match backend.revoke(&capability.id) {
                Ok(true) => batch.newly_revoked += 1,
                Ok(false) => (),
                Err(error) => {
                    failure = Some("write_failed");
                    batch.failures.push(error);
                }
            }
            // Read even after an uncertain write so partial results retain known state.
            let revoked = match backend.readback(&capability.id) {
                Ok(revoked) => {
                    if !revoked {
                        failure.get_or_insert("not_confirmed");
                        batch.failures.push(Failure::NotConfirmed);
                    }
                    Some(revoked)
                }
                Err(error) => {
                    failure.get_or_insert("readback_failed");
                    batch.failures.push(error);
                    None
                }
            };
            batch.capabilities.push(CapabilityOutcome {
                capability_id: capability.id,
                issuer_public_key: capability.issuer_public_key,
                subject_public_key: capability.subject_public_key,
                revoked,
                failure,
            });
        }
        batch
    }
}

pub(super) async fn revoke(
    state: RemoteAppState,
    record: RemoteSessionDiagnosticRecord,
) -> Response {
    let capabilities = record.capabilities.clone();
    let result = tokio::task::spawn_blocking(move || {
        Backend::open(&state).map(|backend| Batch::execute(backend, capabilities))
    })
    .await;
    let batch = match result {
        Ok(Ok(batch)) => batch,
        Ok(Err(response)) => return response,
        Err(error) => {
            return input::with_source(
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "session revocation unavailable",
                ),
                error,
            )
        }
    };
    let complete = batch.failures.is_empty();
    let status = if complete {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let response = (
        status,
        Json(json!({
            "sessionId": record.session_id,
            "revoked": complete,
            "newlyRevokedCount": batch.newly_revoked,
            "authContext": record.auth_context,
            "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version),
            "ownership": record.ownership,
            "capabilities": batch.capabilities,
        })),
    )
        .into_response();
    if complete {
        response
    } else {
        input::with_source(response, BatchFailure(batch.failures))
    }
}
