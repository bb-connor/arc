//! Partial legacy responses cannot invent fields of a durable usage projection.
use super::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The stop signal also releases an unused listener when a negative oracle fails.
pub(super) struct ProjectionServer {
    pub(super) url: String,
    body: std::sync::Arc<std::sync::Mutex<String>>,
    stop: std::sync::Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    finished: std::sync::mpsc::Receiver<Result<(), String>>,
}

impl ProjectionServer {
    pub(super) fn spawn(body: &str) -> TestResult<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let body = std::sync::Arc::new(std::sync::Mutex::new(body.to_string()));
        let response = body.clone();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (done, finished) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let outcome = (|| -> Result<(), String> {
                while !stopping.load(Ordering::SeqCst) {
                    let mut stream = match listener.accept() {
                        Ok((stream, _)) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => return Err(error.to_string()),
                    };
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .map_err(|error| error.to_string())?;
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                        .map_err(|error| error.to_string())?;
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    let deadline = std::time::Instant::now()
                        .checked_add(std::time::Duration::from_secs(5))
                        .ok_or("projection request deadline overflowed")?;
                    loop {
                        let remaining = deadline
                            .checked_duration_since(std::time::Instant::now())
                            .filter(|remaining| !remaining.is_zero())
                            .ok_or("projection request exceeded its deadline")?;
                        stream
                            .set_read_timeout(Some(remaining))
                            .map_err(|error| error.to_string())?;
                        let length = stream
                            .read(&mut buffer)
                            .map_err(|error| error.to_string())?;
                        if length == 0 {
                            return Err("projection request ended before its headers".to_string());
                        }
                        request.extend_from_slice(
                            buffer
                                .get(..length)
                                .ok_or("request length exceeded buffer")?,
                        );
                        let Some(position) =
                            request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(
                            request
                                .get(..position)
                                .ok_or("missing projection request headers")?,
                        );
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if request.len()
                            >= position.saturating_add(4).saturating_add(content_length)
                        {
                            break;
                        }
                    }
                    let response = response.lock().map_err(|_| "response lock poisoned")?;
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response)
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            })();
            let _ = done.send(outcome);
        });
        Ok(Self {
            url,
            body,
            stop,
            worker: Some(worker),
            finished,
        })
    }

    pub(super) fn set_body(&self, body: &str) {
        *self.body.lock().test_unwrap() = body.to_string();
    }
}

impl Drop for ProjectionServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        match self
            .finished
            .recv_timeout(std::time::Duration::from_secs(15))
        {
            Ok(outcome) => {
                let Some(worker) = self.worker.take() else {
                    return;
                };
                let joined = worker.join();
                if !std::thread::panicking() {
                    joined.test_unwrap();
                    outcome.test_unwrap();
                }
            }
            Err(error) => {
                if matches!(error, std::sync::mpsc::RecvTimeoutError::Disconnected) {
                    if let Some(worker) = self.worker.take() {
                        let joined = worker.join();
                        if !std::thread::panicking() {
                            joined.test_unwrap();
                        }
                    }
                }
                if !std::thread::panicking() {
                    panic!("projection server did not finish: {error}");
                }
            }
        }
    }
}

fn usage() -> BudgetUsageRecord {
    BudgetUsageRecord {
        capability_id: "projection-cap".to_string(),
        grant_index: 0,
        seq: 5,
        invocation_count: 3,
        total_cost_exposed: 300,
        total_cost_realized_spend: 25,
        updated_at: 42,
    }
}

pub(super) fn list_body(records: &[BudgetUsageRecord]) -> TestResult<String> {
    Ok(serde_json::to_string(&BudgetListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id: None,
        count: records.len(),
        usages: records
            .iter()
            .map(|record| BudgetUsageView {
                capability_id: record.capability_id.clone(),
                grant_index: record.grant_index,
                invocation_count: record.invocation_count,
                total_cost_exposed: record.total_cost_exposed,
                total_cost_realized_spend: record.total_cost_realized_spend,
                updated_at: record.updated_at,
                seq: Some(record.seq),
            })
            .collect(),
    })?)
}

fn store(server: &ProjectionServer) -> TestResult<RemoteBudgetStore> {
    Ok(RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        recovery_fence: None,
    })
}

fn capture_body(record: &BudgetUsageRecord) -> TestResult<String> {
    Ok(serde_json::to_string(&mutation_response(
        record,
        false,
        StructuredBudgetMutationDecisionView::Applied,
    )?)?)
}

fn mutation_response(
    record: &BudgetUsageRecord,
    cancel: bool,
    decision: StructuredBudgetMutationDecisionView,
) -> TestResult<StructuredBudgetMutationResponse> {
    let event_id = if cancel {
        "projection-cancel"
    } else {
        "projection-capture"
    };
    let response = StructuredBudgetMutationResponse::from_core(
        record.capability_id.clone(), record.grant_index, "projection-hold".to_string(),
        event_id.to_string(), decision,
        BudgetHoldMutationDecision {
            hold_id: Some("projection-hold".to_string()), admission_binding: None,
            exposure_units: 100, realized_spend_units: 0,
            committed_cost_units_after: record.committed_cost_units()?,
            invocation_count_after: record.invocation_count, invocation_quota_usages: Vec::new(),
            cumulative_approval: None,
            invocation_state: if cancel { BudgetInvocationState::Reversed } else { BudgetInvocationState::Captured },
            monetary_state: if cancel { BudgetMonetaryState::Reversed } else { BudgetMonetaryState::Exposed },
            metadata: BudgetCommitMetadata {
                authority: None, guarantee_level: BudgetGuaranteeLevel::AdvisoryPosthoc,
                budget_profile: chio_kernel::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
                metering_profile: chio_kernel::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                budget_commit_index: Some(6), event_id: Some(event_id.to_string()),
                recorded_at_unix_seconds: Some(43),
            },
        }, StructuredBudgetUsageView::from(record.clone()),
    ).map_err(std::io::Error::other)?;
    Ok(response)
}

fn capture(store: &RemoteBudgetStore) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
    store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "projection-cap".to_string(),
        grant_index: 0,
        hold_id: "projection-hold".to_string(),
        event_id: "projection-capture".to_string(),
        trusted_time: None,
        authority: None,
    })
}

#[test]
fn partial_legacy_usage_hydrates_the_durable_timestamp_from_a_full_read() -> TestResult {
    let expected = usage();
    let server = ProjectionServer::spawn(&list_body(std::slice::from_ref(&expected))?)?;
    let store = store(&server)?;
    store.cache_usage("projection-cap", 0, Some(5), Some(3), Some(300), Some(25))?;
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(expected));
    Ok(())
}

#[test]
fn structured_capture_hydrates_unobserved_time_without_changing_known_fields() -> TestResult {
    let expected = usage();
    let server = ProjectionServer::spawn(&capture_body(&expected)?)?;
    let store = store(&server)?;
    store.cache_usage("projection-cap", 0, Some(5), Some(3), Some(300), Some(25))?;
    assert!(matches!(
        capture(&store)?,
        BudgetInvocationCaptureDecision::Captured(_)
    ));
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(expected));
    Ok(())
}

#[test]
fn authoritative_same_sequence_time_count_and_cost_changes_refuse_without_cache_poison(
) -> TestResult {
    let baseline = usage();
    let server = ProjectionServer::spawn(&list_body(std::slice::from_ref(&baseline))?)?;
    let store = store(&server)?;
    assert_eq!(
        store.get_usage("projection-cap", 0)?,
        Some(baseline.clone())
    );
    for field in ["time", "count", "exposed", "realized"] {
        let mut changed = baseline.clone();
        match field {
            "time" => changed.updated_at = 43,
            "count" => changed.invocation_count = 4,
            "exposed" => changed.total_cost_exposed = 350,
            "realized" => changed.total_cost_realized_spend = 50,
            _ => return Err("unknown projection field".into()),
        }
        server.set_body(&capture_body(&changed)?);
        assert!(
            matches!(capture(&store), Err(BudgetStoreError::Invariant(message))
            if message == "structured remote replay changed the exact usage projection"),
            "{field}"
        );
        assert_eq!(
            store.get_usage("projection-cap", 0)?,
            Some(baseline.clone())
        );
        server.set_body(&list_body(&[changed])?);
        assert!(
            matches!(store.list_usages(10, Some("projection-cap")), Err(BudgetStoreError::Invariant(message))
            if message == "remote budget cache replay changed state at the same sequence"),
            "{field}"
        );
        assert_eq!(
            store.get_usage("projection-cap", 0)?,
            Some(baseline.clone())
        );
    }
    Ok(())
}

#[test]
fn hydration_checks_each_observed_partial_counter_and_cost() -> TestResult {
    for field in ["count", "exposed", "realized"] {
        let mut incoming = usage();
        match field {
            "count" => incoming.invocation_count = 4,
            "exposed" => incoming.total_cost_exposed = 350,
            "realized" => incoming.total_cost_realized_spend = 50,
            _ => return Err("unknown projection field".into()),
        }
        let server = ProjectionServer::spawn(&list_body(&[incoming])?)?;
        let store = store(&server)?;
        store.cache_usage(
            "projection-cap",
            0,
            Some(5),
            (field == "count").then_some(3),
            (field == "exposed").then_some(300),
            (field == "realized").then_some(25),
        )?;
        let before = store.cached_usage("projection-cap", 0);
        assert!(
            matches!(store.get_usage("projection-cap", 0), Err(BudgetStoreError::Invariant(message))
            if message == "remote budget cache replay changed state at the same sequence"),
            "{field}"
        );
        assert_eq!(store.cached_usage("projection-cap", 0), before);
        let valid = usage();
        server.set_body(&list_body(std::slice::from_ref(&valid))?);
        assert_eq!(store.get_usage("projection-cap", 0)?, Some(valid));
    }
    Ok(())
}

#[test]
fn newer_partial_usage_requires_current_hydration_and_preserves_same_sequence_time() -> TestResult {
    let baseline = usage();
    let server = ProjectionServer::spawn(&list_body(std::slice::from_ref(&baseline))?)?;
    let store = store(&server)?;
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(baseline));
    store.cache_usage("projection-cap", 0, Some(6), Some(4), Some(350), None)?;
    let partial = store.cached_usage("projection-cap", 0);
    assert!(
        matches!(store.get_usage("projection-cap", 0), Err(BudgetStoreError::Invariant(message))
        if message == "remote budget list could not complete a known usage projection")
    );
    assert_eq!(store.cached_usage("projection-cap", 0), partial);
    let mut newer = usage();
    newer.seq = 6;
    newer.invocation_count = 4;
    newer.total_cost_exposed = 350;
    newer.total_cost_realized_spend = 75;
    newer.updated_at = 44;
    server.set_body(&list_body(&[newer.clone()])?);
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(newer.clone()));
    store.cache_usage("projection-cap", 0, Some(6), Some(4), None, None)?;
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(newer));
    Ok(())
}

#[test]
fn missing_hydration_cannot_hide_a_known_partial_usage() -> TestResult {
    let server = ProjectionServer::spawn(&list_body(&[])?)?;
    let store = store(&server)?;
    store.cache_usage("projection-cap", 0, Some(5), Some(3), Some(300), Some(25))?;
    let partial = store.cached_usage("projection-cap", 0);
    assert!(
        matches!(store.get_usage("projection-cap", 0), Err(BudgetStoreError::Invariant(message))
        if message == "remote budget list could not complete a known usage projection")
    );
    assert!(
        matches!(store.list_usages(10, None), Err(BudgetStoreError::Invariant(message))
        if message == "remote budget list could not complete a known usage projection")
    );
    assert_eq!(store.cached_usage("projection-cap", 0), partial);
    Ok(())
}

#[test]
fn metadata_only_new_sequence_cannot_serve_the_prior_complete_projection() -> TestResult {
    let baseline = usage();
    let server = ProjectionServer::spawn(&list_body(std::slice::from_ref(&baseline))?)?;
    let store = store(&server)?;
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(baseline));
    store.cache_usage("projection-cap", 0, Some(6), None, None, None)?;
    let partial = store
        .cached_usage("projection-cap", 0)
        .ok_or("new sequence was not retained")?;
    assert_eq!(partial.seq, 6);
    assert!(
        matches!(store.get_usage("projection-cap", 0), Err(BudgetStoreError::Invariant(message))
        if message == "remote budget list could not complete a known usage projection")
    );
    server.set_body(&list_body(&[])?);
    assert!(
        matches!(store.get_usage("projection-cap", 0), Err(BudgetStoreError::Invariant(message))
        if message == "remote budget list could not complete a known usage projection")
    );
    assert_eq!(store.cached_usage("projection-cap", 0), Some(partial));
    let mut current = usage();
    current.seq = 6;
    current.invocation_count = 4;
    current.total_cost_exposed = 350;
    current.total_cost_realized_spend = 75;
    current.updated_at = 44;
    server.set_body(&list_body(&[current.clone()])?);
    assert_eq!(store.get_usage("projection-cap", 0)?, Some(current));
    Ok(())
}

fn ambiguous_decision_does_not_commit_cache(cancel: bool, existing: bool) -> TestResult {
    let mut baseline = usage();
    baseline.seq = 4;
    baseline.updated_at = 40;
    baseline.invocation_count = 2;
    let initial = if existing {
        vec![baseline.clone()]
    } else {
        Vec::new()
    };
    let server = ProjectionServer::spawn(&list_body(&initial)?)?;
    let store = store(&server)?;
    if existing {
        assert_eq!(
            store.get_usage("projection-cap", 0)?,
            Some(baseline.clone())
        );
    }
    let before = store.cached_usage("projection-cap", 0);
    let mut incoming = usage();
    if cancel {
        incoming.seq = 6;
    }
    let response = mutation_response(
        &incoming,
        cancel,
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
    )?;
    server.set_body(&serde_json::to_string(&response)?);
    let result = if cancel {
        store
            .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
                capability_id: "projection-cap".to_string(),
                grant_index: 0,
                hold_id: "projection-hold".to_string(),
                event_id: "projection-cancel".to_string(),
                authority: None,
            })
            .map(|_| ())
    } else {
        capture(&store).map(|_| ())
    };
    let expected = if cancel {
        "remote captured cancellation omitted exact replay status"
    } else {
        "remote invocation capture omitted exact replay status"
    };
    assert!(matches!(result, Err(BudgetStoreError::Invariant(message)) if message == expected));
    assert_eq!(store.cached_usage("projection-cap", 0), before);
    server.set_body(&list_body(&initial)?);
    assert_eq!(
        store.get_usage("projection-cap", 0)?,
        existing.then_some(baseline)
    );
    Ok(())
}

#[test]
fn ambiguous_capture_decision_keeps_a_fresh_cache_empty() -> TestResult {
    ambiguous_decision_does_not_commit_cache(false, false)
}

#[test]
fn ambiguous_capture_decision_preserves_a_complete_cache() -> TestResult {
    ambiguous_decision_does_not_commit_cache(false, true)
}

#[test]
fn ambiguous_cancel_decision_keeps_a_fresh_cache_empty() -> TestResult {
    ambiguous_decision_does_not_commit_cache(true, false)
}

#[test]
fn ambiguous_cancel_decision_preserves_a_complete_cache() -> TestResult {
    ambiguous_decision_does_not_commit_cache(true, true)
}
