use crate::security::{ResponseWorkerHealth, ResponseWorkerLifecycle};
use chio_quarantine::CorrelationStatus;
use chio_security_types::ports::{PortError, PortErrorKind, UnverifiedSecurityEvent};
use serde::Serialize;

use super::report_validation::validate_service_auth;
use super::*;

#[derive(Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ActiveDefenseHealthResponse {
    enabled: bool,
    ready: bool,
    lifecycle: Option<&'static str>,
    ticks_attempted: u64,
    ticks_completed: u64,
    last_error: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ActiveDefenseEventResponse {
    event_id: String,
    rules: Vec<ActiveDefenseRuleResponse>,
    attested_finding_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ActiveDefenseRuleResponse {
    rule_id: String,
    status: &'static str,
    automatic_response_suppressed: bool,
    watermark_unix_ms: u64,
}

pub(crate) async fn handle_active_defense_health(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let response = active_defense_health_response(&state);
    let status = if response.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(response)).into_response()
}

pub(crate) async fn handle_active_defense_event(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(event): Json<UnverifiedSecurityEvent>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if !state.active_defense.is_enabled() {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "active defense is not enabled for this service",
        );
    }
    let service = state.active_defense.clone();
    let result = tokio::task::spawn_blocking(move || service.consume(&event)).await;
    match result {
        Ok(Ok(report)) => Json(ActiveDefenseEventResponse {
            event_id: report.event_id.as_str().to_string(),
            rules: report
                .rules
                .into_iter()
                .map(|rule| ActiveDefenseRuleResponse {
                    rule_id: rule.rule_id.as_str().to_string(),
                    status: correlation_status_name(rule.status),
                    automatic_response_suppressed: rule.automatic_response_suppressed,
                    watermark_unix_ms: rule.watermark_unix_ms,
                })
                .collect(),
            attested_finding_ids: report
                .attested_finding_ids
                .into_iter()
                .map(|finding_id| finding_id.as_str().to_string())
                .collect(),
        })
        .into_response(),
        Ok(Err(error)) => active_defense_port_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "active-defense event consumer is unavailable",
        ),
    }
}

pub(crate) fn active_defense_public_health(state: &TrustServiceState) -> Value {
    let response = active_defense_health_response(state);
    json!({
        "enabled": response.enabled,
        "ready": response.ready,
        "lifecycle": response.lifecycle,
        "ticksAttempted": response.ticks_attempted,
        "ticksCompleted": response.ticks_completed,
    })
}

fn active_defense_health_response(state: &TrustServiceState) -> ActiveDefenseHealthResponse {
    active_defense_health_response_for_service(&state.active_defense)
}

fn active_defense_health_response_for_service(
    active_defense: &super::service_runtime::TrustControlActiveDefenseService,
) -> ActiveDefenseHealthResponse {
    let health = active_defense.worker_health();
    let readiness_error = active_defense.ensure_ready().err();
    let ready = active_defense.is_enabled() && readiness_error.is_none();
    let last_error = readiness_error
        .map(|error| error.to_string())
        .or_else(|| health.as_ref().and_then(|health| health.last_error.clone()));
    ActiveDefenseHealthResponse {
        enabled: active_defense.is_enabled(),
        ready,
        lifecycle: health.as_ref().map(worker_lifecycle_name),
        ticks_attempted: health.as_ref().map_or(0, |health| health.ticks_attempted),
        ticks_completed: health.as_ref().map_or(0, |health| health.ticks_completed),
        last_error,
    }
}

fn worker_lifecycle_name(health: &ResponseWorkerHealth) -> &'static str {
    match health.lifecycle {
        ResponseWorkerLifecycle::Created => "created",
        ResponseWorkerLifecycle::Running => "running",
        ResponseWorkerLifecycle::Ready => "ready",
        ResponseWorkerLifecycle::Degraded => "degraded",
        ResponseWorkerLifecycle::Failed => "failed",
        ResponseWorkerLifecycle::Stopped => "stopped",
    }
}

fn correlation_status_name(status: CorrelationStatus) -> &'static str {
    match status {
        CorrelationStatus::Accepted => "accepted",
        CorrelationStatus::AdvisoryOnly => "advisory_only",
        CorrelationStatus::Deferred => "deferred",
        CorrelationStatus::Duplicate => "duplicate",
        CorrelationStatus::Irrelevant => "irrelevant",
        CorrelationStatus::Matched => "matched",
        CorrelationStatus::Suppressed => "suppressed",
        CorrelationStatus::TooLate => "too_late",
    }
}

fn active_defense_port_error(error: PortError) -> Response {
    let (status, message) = match error.kind() {
        PortErrorKind::InvalidData => (StatusCode::BAD_REQUEST, "active-defense event is invalid"),
        PortErrorKind::Conflict => (
            StatusCode::CONFLICT,
            "active-defense event conflicts with durable state",
        ),
        PortErrorKind::IntegrityFailure => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "active-defense event evidence failed verification",
        ),
        PortErrorKind::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "active-defense event authorities are unavailable",
        ),
    };
    plain_http_error(status, message)
}

#[cfg(test)]
mod readiness_tests {
    use std::sync::Arc;

    use crate::security::{
        ActiveDefenseServices, ResponseWorkerHealth, ResponseWorkerLifecycle,
        ResponseWorkerTickError,
    };
    use crate::trust_control::service_runtime::TrustControlActiveDefenseService;
    use chio_security_types::ports::PortError;

    use super::active_defense_health_response_for_service;

    #[derive(Clone, Copy)]
    enum ReadinessFailure {
        WedgedTick,
        ConsumerDependency,
    }

    struct UnreadyActiveDefenseServices {
        failure: ReadinessFailure,
    }

    impl ActiveDefenseServices for UnreadyActiveDefenseServices {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            match self.failure {
                ReadinessFailure::WedgedTick => {
                    Err(ResponseWorkerTickError::WorkerProgressStalled {
                        started_sequence: Some(2),
                        completed_sequence: Some(1),
                    })
                }
                ReadinessFailure::ConsumerDependency => {
                    Err(ResponseWorkerTickError::Port(PortError::unavailable()))
                }
            }
        }

        fn worker_health(&self) -> ResponseWorkerHealth {
            let mut health = ResponseWorkerHealth::created();
            health.lifecycle = ResponseWorkerLifecycle::Ready;
            health.ticks_attempted = 3;
            health.ticks_completed = 2;
            health
        }
    }

    fn service(failure: ReadinessFailure) -> TrustControlActiveDefenseService {
        let services: Arc<dyn ActiveDefenseServices> =
            Arc::new(UnreadyActiveDefenseServices { failure });
        TrustControlActiveDefenseService::from_services_for_test(services)
    }

    #[test]
    fn wedged_synchronous_tick_fails_health_despite_ready_worker_metrics() {
        let response =
            active_defense_health_response_for_service(&service(ReadinessFailure::WedgedTick));

        assert!(response.enabled);
        assert!(!response.ready);
        assert_eq!(response.lifecycle, Some("ready"));
        assert!(response
            .last_error
            .is_some_and(|error| error.contains("progress stalled")));
    }

    #[test]
    fn consumer_dependency_failure_fails_health_despite_ready_worker_metrics() {
        let response = active_defense_health_response_for_service(&service(
            ReadinessFailure::ConsumerDependency,
        ));

        assert!(response.enabled);
        assert!(!response.ready);
        assert_eq!(response.lifecycle, Some("ready"));
        assert!(response
            .last_error
            .is_some_and(|error| error.contains("port failed")));
    }
}
