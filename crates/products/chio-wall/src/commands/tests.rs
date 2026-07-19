use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::receipt::decision::Decision;
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportFuture;
use chio_siem::{Exporter, ExporterManager, SiemConfig};
use tokio::sync::watch;

fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

#[derive(Clone, Default)]
struct CapturingExporter {
    events: Arc<Mutex<Vec<SiemEvent>>>,
}

impl CapturingExporter {
    fn events(&self) -> Vec<SiemEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl Exporter for CapturingExporter {
    fn name(&self) -> &str {
        "chio-wall-capturing-exporter"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        let sink = self.events.clone();
        let owned = events.to_vec();
        Box::pin(async move {
            sink.lock().expect("events lock").extend(owned.clone());
            Ok(owned.len())
        })
    }
}

#[test]
fn build_guard_outcome_allows_research_tool_when_present_in_policy() {
    let mut context = build_authorization_context();
    context.tool_name = CHIO_WALL_ALLOWED_TOOLS[0].to_string();
    let policy = build_policy_snapshot();

    let outcome = build_guard_outcome(&context, &policy);
    assert_eq!(outcome.decision, ChioWallGuardDecision::Allow);
    assert_eq!(outcome.evaluated_tool, CHIO_WALL_ALLOWED_TOOLS[0]);
    assert!(outcome.reason.contains("is allowed"));
    outcome.validate().expect("allow outcome validates");
}

#[test]
fn build_denied_access_record_rejects_allow_outcome() {
    let mut context = build_authorization_context();
    context.tool_name = CHIO_WALL_ALLOWED_TOOLS[0].to_string();
    let policy = build_policy_snapshot();
    let outcome = build_guard_outcome(&context, &policy);

    let error = build_denied_access_record(&context, &outcome)
        .expect_err("allow outcome should not generate denied-access record");
    assert!(error
        .to_string()
        .contains("expects the bounded control-path scenario to deny"));
}

#[test]
fn ensure_empty_directory_rejects_non_empty_dir() {
    let dir = unique_test_dir("chio-wall-non-empty");
    fs::create_dir_all(&dir).expect("create temp dir");
    fs::write(dir.join("sentinel.txt"), b"occupied").expect("write sentinel");

    let error = ensure_empty_directory(&dir).expect_err("non-empty dir should fail");
    assert!(error.to_string().contains("output directory must be empty"));

    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn ensure_empty_directory_rejects_symlink_dir() {
    let target = unique_test_dir("chio-wall-output-target");
    let link = unique_test_dir("chio-wall-output-link");
    fs::create_dir_all(&target).expect("create target dir");
    std::os::unix::fs::symlink(&target, &link).expect("create output symlink");

    let error = ensure_empty_directory(&link).expect_err("symlink dir should fail");

    assert!(error.to_string().contains("symlink"));
    let _ = fs::remove_file(link);
    let _ = fs::remove_dir_all(target);
}

#[test]
fn validate_pipeline_emits_bounded_control_room_decision() {
    let output = unique_test_dir("chio-wall-validate-unit");

    cmd_chio_wall_control_path_validate(&output, false).expect("validate pipeline succeeds");

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("validation-report.json")).expect("read"))
            .expect("parse validation report");
    assert_eq!(report["decision"].as_str(), Some(CHIO_WALL_DECISION));
    assert_eq!(
        report["buyerMotion"].as_str(),
        Some(ChioWallBuyerMotion::ControlRoomBarrierReview.as_str())
    );
    assert_eq!(
        report["controlSurface"].as_str(),
        Some(ChioWallControlSurface::ToolAccessDomainBoundary.as_str())
    );

    let decision: serde_json::Value = serde_json::from_slice(
        &fs::read(output.join("expansion-decision.json")).expect("read decision"),
    )
    .expect("parse decision record");
    assert_eq!(decision["decision"].as_str(), Some(CHIO_WALL_DECISION));
    assert_eq!(
        decision["selectedBuyerMotion"].as_str(),
        Some(ChioWallBuyerMotion::ControlRoomBarrierReview.as_str())
    );
    assert!(decision["deferredScope"]
        .as_array()
        .expect("deferred scope")
        .iter()
        .any(|item| item.as_str() == Some("generic barrier-platform breadth")));

    let _ = fs::remove_dir_all(output);
}

#[test]
fn control_path_export_reconciliation_rejects_missing_artifact_file() {
    let output = unique_test_dir("chio-wall-export-reconcile");
    let summary = export_control_path(&output).expect("export control path");
    fs::remove_file(output.join("guard-outcome.json")).expect("remove guard outcome");

    let error = verify_control_path_export(&output, &summary)
        .expect_err("missing guard outcome should fail reconciliation");

    assert!(error.to_string().contains("guard-outcome.json"));
    let _ = fs::remove_dir_all(output);
}

#[test]
fn control_path_export_keeps_sqlite_staging_outside_package() {
    let output = unique_test_dir("chio-wall-export-staging");
    fs::create_dir_all(&output).expect("create output directory");
    let started = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let saw_sqlite_staging = Arc::new(AtomicBool::new(false));
    let monitor = {
        let output = output.clone();
        let started = Arc::clone(&started);
        let stop = Arc::clone(&stop);
        let saw_sqlite_staging = Arc::clone(&saw_sqlite_staging);
        thread::spawn(move || {
            started.wait();
            while !stop.load(Ordering::Acquire) {
                let found = fs::read_dir(&output)
                    .expect("read output directory")
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".chio-wall-receipts.sqlite3")
                    });
                if found {
                    saw_sqlite_staging.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        })
    };

    started.wait();
    let export = export_control_path(&output);
    stop.store(true, Ordering::Release);
    monitor.join().expect("join package monitor");

    export.expect("export control path");
    assert!(!saw_sqlite_staging.load(Ordering::Acquire));
    let _ = fs::remove_dir_all(output);
}

#[test]
fn control_path_export_reconciliation_rejects_unexpected_top_level_artifact() {
    let output = unique_test_dir("chio-wall-export-closed");
    let summary = export_control_path(&output).expect("export control path");
    fs::write(output.join(".chio-wall-receipts.sqlite3"), b"stale db")
        .expect("write undeclared artifact");

    let error = verify_control_path_export(&output, &summary)
        .expect_err("undeclared top-level artifact should fail reconciliation");

    assert!(error
        .to_string()
        .contains("unexpected Chio-Wall package entry"));
    assert!(error.to_string().contains(".chio-wall-receipts.sqlite3"));
    let _ = fs::remove_dir_all(output);
}

#[tokio::test]
async fn chio_wall_denied_receipt_exports_through_chio_siem() {
    let output = unique_test_dir("chio-wall-siem");
    fs::create_dir_all(&output).expect("create temp dir");

    let authorization_context = build_authorization_context();
    let policy_snapshot = build_policy_snapshot();
    let guard_outcome = build_guard_outcome(&authorization_context, &policy_snapshot);
    assert_eq!(guard_outcome.decision, ChioWallGuardDecision::Deny);

    let denied_access_record = build_denied_access_record(&authorization_context, &guard_outcome)
        .expect("deny outcome should build record");
    let receipt_db_path = output.join("chio-wall-integration.sqlite3");
    create_chio_wall_receipt_db(
        &receipt_db_path,
        &authorization_context,
        &guard_outcome,
        &denied_access_record,
        &policy_snapshot,
    )
    .expect("create Chio-Wall receipt db");

    let exporter = CapturingExporter::default();
    let mut manager = ExporterManager::new(SiemConfig {
        db_path: receipt_db_path.clone(),
        poll_interval: std::time::Duration::from_millis(25),
        batch_size: 10,
        max_retries: 0,
        base_backoff_ms: 0,
        dlq_capacity: 100,
        rate_limit: None,
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    })
    .expect("open ExporterManager");
    manager.add_exporter(Box::new(exporter.clone()));

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let run_handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cancel_tx.send(true).expect("cancel signal sends");
    let manager = run_handle.await.expect("manager task completes");

    let events = exporter.events();
    assert_eq!(events.len(), 1, "one Chio-Wall receipt should be exported");
    assert_eq!(events[0].receipt.tool_server, "chio-wall");
    assert_eq!(events[0].receipt.tool_name, CHIO_WALL_REQUESTED_TOOL);
    match &events[0].receipt.decision {
        Some(Decision::Deny { guard, .. }) => assert_eq!(guard, "mcp-tool"),
        other => panic!("expected denied Chio-Wall receipt, got {other:?}"),
    }
    assert_eq!(manager.dlq_len(), 0, "successful export should not DLQ");

    let _ = fs::remove_dir_all(output);
}

/// A no-network alert backend so serve-mode alerting wiring can be exercised
/// without an external PagerDuty/OpsGenie endpoint.
struct StubAlertBackend {
    route: String,
}

impl chio_siem::AlertBackend for StubAlertBackend {
    fn name(&self) -> &str {
        &self.route
    }

    fn dispatch<'a>(
        &'a self,
        _alert: &'a chio_siem::Alert,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), chio_siem::ExportError>> + Send + 'a>,
    > {
        Box::pin(async { Ok(()) })
    }
}

fn serve_deny_event(guard: &str) -> SiemEvent {
    use chio_core::receipt::kinds;
    use chio_core::receipt::metadata::GuardEvidence;

    let keypair = Keypair::generate();
    let action =
        ToolCallAction::from_parameters(serde_json::json!({})).expect("hash receipt parameters");
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "serve-alert-rcpt".to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Deny {
                reason: "denied".to_string(),
                guard: guard.to_string(),
            }),
            receipt_kind: kinds::ReceiptKind::MediatedDecision,
            boundary_class: kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: kinds::ToolOrigin::CallerExecuted,
            redaction_mode: kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: guard.to_string(),
                verdict: false,
                details: None,
            }],
            metadata: None,
            trust_level: kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign serve-mode deny receipt");
    SiemEvent::from_receipt(receipt)
}

/// The serve-mode alerting wiring installs the registry metrics sink into a
/// real AlertingExporter, so a real dispatch emits chio_alert_dispatch_total.
#[tokio::test]
async fn serve_alerting_wiring_emits_real_alert_dispatch_metric() {
    use chio_siem::Exporter;

    // Unique route so the process-global counter is not shared with any
    // other test in this binary.
    let route = "chio-wall-serve-alert-dispatch-test";
    let sink: std::sync::Arc<dyn chio_siem::SiemMetricsSink> =
        std::sync::Arc::new(crate::registry_metrics_sink::RegistryMetricsSink);
    let backend = Box::new(StubAlertBackend {
        route: route.to_string(),
    });

    let (exporter, routes) = build_serve_alerting_exporter(vec![backend], sink)
        .expect("a configured backend yields an alerting exporter");
    assert_eq!(routes, vec![route.to_string()]);

    // ForbiddenPathGuard derives High severity, meeting the default alerting
    // threshold, so the exporter dispatches to the recording backend.
    let event = serve_deny_event("ForbiddenPathGuard");
    let processed = exporter
        .export_batch(std::slice::from_ref(&event))
        .await
        .expect("recording dispatch succeeds");
    assert_eq!(processed, 1, "the single deny event is dispatched");

    let mut body = String::new();
    chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.render(&mut body);
    assert!(
        body.contains(&format!(
            "chio_alert_dispatch_total{{route=\"{route}\",outcome=\"success\"}} 1"
        )),
        "the wired serve-mode sink must emit a real alert_dispatch value: {body}"
    );
}

/// The serve path seeds soc_export/dlq_depth (always) and alert_dispatch
/// (only when alerting is configured) at zero, so the absent-metric
/// backstops fire only on a true scrape gap.
#[test]
fn serve_metrics_preregister_seeds_series_at_zero() {
    let exporter = "chio-wall-serve-seed-exporter";
    let route = "chio-wall-serve-seed-route";

    preregister_serve_metrics(&[exporter], &[route]);

    let mut soc = String::new();
    chio_metrics_spec::runtime::families::SOC_EXPORT_TOTAL.render(&mut soc);
    assert!(
        soc.contains(&format!(
            "chio_soc_export_total{{exporter=\"{exporter}\",outcome=\"success\"}} 0"
        )),
        "configured exporter soc_export must seed the success outcome at zero: {soc}"
    );
    assert!(
        soc.contains("chio_soc_export_total{exporter=\"_deserialize\",outcome=\"malformed\"} 0"),
        "the always-on _deserialize baseline must seed at zero: {soc}"
    );

    let mut dlq = String::new();
    chio_metrics_spec::runtime::families::DLQ_DEPTH.render(&mut dlq);
    assert!(
        dlq.contains(&format!("chio_dlq_depth{{exporter=\"{exporter}\"}} 0")),
        "configured exporter dlq_depth must seed at zero: {dlq}"
    );

    let mut alert = String::new();
    chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.render(&mut alert);
    assert!(
        alert.contains(&format!(
            "chio_alert_dispatch_total{{route=\"{route}\",outcome=\"success\"}} 0"
        )),
        "configured alert route must seed success at zero: {alert}"
    );
    assert!(
        alert.contains(&format!(
            "chio_alert_dispatch_total{{route=\"{route}\",outcome=\"error\"}} 0"
        )),
        "configured alert route must seed error at zero: {alert}"
    );
}

/// The siem-export serve path renders the full alert pack but does not run
/// the chio-cli tracing init that seeds the FIXED alert-pack series.
/// `preregister_serve_metrics` must therefore seed them (fail-open /
/// dispatch-failure / revocation-lag) so their absent_over_time backstops
/// cannot false-fire on a healthy-but-quiet siem-export deploy.
#[test]
fn serve_metrics_preregister_seeds_fixed_alert_pack_series() {
    preregister_serve_metrics(&[], &[]);

    let mut body = String::new();
    chio_metrics_spec::runtime::render_alert_pack_families(&mut body);
    assert!(
        body.contains("chio_fail_open_suspected_total{surface=\"tower\"}"),
        "fixed fail-open series must be present at zero on the serve path: {body}"
    );
    assert!(
        body.contains("chio_dispatch_failure_total{"),
        "fixed dispatch-failure series must be present on the serve path: {body}"
    );
    assert!(
        body.contains("chio_capability_revocation_lag_seconds"),
        "fixed revocation-lag series must be present on the serve path: {body}"
    );
}

/// Alerting is operator-configured: with no alert backend, the serve wiring
/// builds no AlertingExporter (and thus seeds no alert_dispatch series), so a
/// legitimately alerting-disabled deploy does not falsely advertise the
/// pipeline.
#[test]
fn serve_alerting_disabled_builds_no_exporter() {
    let sink: std::sync::Arc<dyn chio_siem::SiemMetricsSink> =
        std::sync::Arc::new(crate::registry_metrics_sink::RegistryMetricsSink);
    assert!(build_serve_alerting_exporter(Vec::new(), sink).is_none());
}

/// The serve mode must fail closed when no consumer is configured, rather
/// than silently advancing the cursor over receipts nothing exports.
#[test]
fn serve_fails_closed_with_no_configured_consumer() {
    let error = ensure_serve_has_consumer(&[]).expect_err("zero consumers must fail closed");
    assert!(
        error.to_string().contains("SOC export sink"),
        "unexpected error: {error}"
    );
}

#[test]
fn serve_accepts_a_real_soc_export_sink() {
    // A real SOC export sink (Splunk/Elastic/Webhook/...) satisfies the gate.
    assert!(ensure_serve_has_consumer(&["splunk".to_string()]).is_ok());
    // Alerting running ALONGSIDE a SOC sink is also fine.
    assert!(ensure_serve_has_consumer(&["alerting".to_string(), "splunk".to_string()]).is_ok());
}

/// The serve path wires a real SOC export sink from the CHIO_SIEM_WEBHOOK_*
/// env, so a deploy that configures a webhook endpoint builds a real
/// "webhook" consumer that satisfies the fail-closed gate. Only this test
/// touches CHIO_SIEM_WEBHOOK_URL, so the set/remove cannot race another
/// test's configured_soc_exporters() call.
#[test]
fn serve_soc_webhook_wiring_builds_a_real_consumer_and_passes_the_gate() {
    // Unconfigured: no SOC sink is fabricated, so the gate still fails closed.
    std::env::remove_var(WEBHOOK_URL_ENV);
    assert!(
        configured_soc_exporters()
            .expect("no SOC endpoint configured is not an error")
            .is_empty(),
        "no phantom consumer when unconfigured"
    );

    // Configured: a real "webhook" SOC consumer is built and satisfies the
    // gate that alerting alone cannot.
    std::env::set_var(WEBHOOK_URL_ENV, "https://soc.example.test/ingest");
    let exporters = configured_soc_exporters().expect("a webhook endpoint builds a SOC sink");
    std::env::remove_var(WEBHOOK_URL_ENV);

    let names: Vec<String> = exporters.iter().map(|e| e.name().to_string()).collect();
    assert_eq!(
        names,
        vec!["webhook".to_string()],
        "one real webhook SOC sink is registered"
    );
    assert!(
        ensure_serve_has_consumer(&names).is_ok(),
        "a wired SOC sink satisfies the fail-closed gate"
    );
}

/// Alerting is a notification overlay, not a SOC export sink. It returns
/// every event as "processed" (so the manager advances the high-water mark)
/// but only delivers high-severity denials and drops every allow/low-severity
/// receipt. An alerting-ONLY serve config must be rejected at startup so the
/// cursor never advances past audit rows no durable SOC export sink received.
#[test]
fn serve_fails_closed_when_only_alerting_is_configured() {
    let error = ensure_serve_has_consumer(&["alerting".to_string()])
        .expect_err("an alerting-only serve config must fail closed");
    assert!(
        error.to_string().contains("SOC export sink"),
        "unexpected error: {error}"
    );
}

/// The receipt-log watchdog samples health via a READ-ONLY open. A missing
/// receipt DB must be reported as missing and must NOT be created (a
/// create-on-open path would spawn an empty DB on a mistyped path and fail
/// outright on a read-only mount).
#[test]
fn watchdog_sample_receipt_health_does_not_create_a_missing_db() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let missing = std::env::temp_dir().join(format!(
        "chio-wall-watchdog-missing-{}-{nonce}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);
    assert!(
        !missing.exists(),
        "precondition: the DB path must be absent"
    );

    let error = sample_receipt_health(&missing)
        .expect_err("a missing receipt DB must report missing, not be created");
    assert!(
        error.contains("does not exist"),
        "unexpected error: {error}"
    );
    assert!(
        !missing.exists(),
        "the watchdog must not create the missing receipt DB"
    );

    let _ = std::fs::remove_file(&missing);
}

/// `non_empty_env` returns a trimmed value, so a mounted secret with a
/// trailing newline is not handed back verbatim. Uses a unique key so it
/// cannot race.
#[test]
fn non_empty_env_returns_trimmed_value() {
    const KEY: &str = "CHIO_SIEM_TEST_TRIM_1218_UNIQUE";
    std::env::set_var(KEY, "  https://soc.example.test/ingest\n");
    let value = non_empty_env(KEY);
    std::env::remove_var(KEY);
    assert_eq!(
        value,
        Some("https://soc.example.test/ingest".to_string()),
        "surrounding whitespace/newlines must be trimmed"
    );

    std::env::set_var(KEY, "   \n\t ");
    let blank = non_empty_env(KEY);
    std::env::remove_var(KEY);
    assert_eq!(blank, None, "a whitespace-only value is treated as absent");
}

/// A SOC-only serve (no PagerDuty/OpsGenie configured) still ships the alert
/// pack, whose ChioAlertDispatchMetricsMissing rule is unconditional, so
/// preregister_serve_metrics must seed a zero chio_alert_dispatch_total
/// baseline (under the `disabled` sentinel route) or the deployment pages on
/// an intentionally silent alert pipeline.
#[test]
fn soc_only_serve_seeds_a_disabled_alert_dispatch_baseline() {
    preregister_serve_metrics(&["webhook"], &[]);
    let mut rendered = String::new();
    chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.render(&mut rendered);
    assert!(
        rendered.contains("chio_alert_dispatch_total{route=\"disabled\""),
        "a SOC-only serve must seed a disabled alert-dispatch baseline: {rendered}"
    );
}
