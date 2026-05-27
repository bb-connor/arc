pub(super) use std::{fs, sync::Arc};

pub(super) use async_trait::async_trait;
pub(super) use chio_core_types::canonical::canonical_json_bytes;
pub(super) use chio_core_types::crypto::sha256_hex;
pub(super) use chio_core_types::Keypair;
pub(super) use chio_federation::{
    PheromoneDepositGossip, PheromoneGossipBatch, PheromoneTransitChain, PheromoneTransitHop,
    PHEROMONE_GOSSIP_BATCH_SCHEMA, PHEROMONE_GOSSIP_SCHEMA,
};
pub(super) use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, sign_deposit, PheromoneDepositBody,
    Severity, PHEROMONE_DEPOSIT_SCHEMA,
};
pub(super) use chio_pheromone_relay::{
    deliver_due_batches, evaluate_relay_alert_acknowledgement, evaluate_relay_alert_delivery,
    evaluate_relay_alert_handoff, evaluate_relay_alerts,
    generate_relay_alert_assurance_archive_report, generate_relay_alert_assurance_closeout_report,
    generate_relay_alert_assurance_external_retention_review_report,
    generate_relay_alert_assurance_package, generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    relay_alert_assurance_external_retention_profile_from_json,
    generate_relay_alert_delivery_drift_report, generate_relay_alert_handoff_drift_report,
    generate_relay_alert_route_review_packet, generate_relay_trend_report,
    normalize_relay_alert_delivery_evidence, promote_peer_directory_candidate,
    relay_alert_delivery_evidence_from_json, relay_alert_delivery_profile_from_json,
    relay_alert_handoff_profile_from_json, relay_alert_routing_profile_from_json,
    relay_alert_suppression_state_from_json, sign_peer_directory_bundle,
    sign_relay_alert_assurance_export_bundle, sign_relay_http_request,
    verify_relay_alert_assurance_export_bundle, CatchupRequest, CatchupResponse, PeerDirectory,
    PeerDirectoryBundleSigningInput, PeerDirectoryBundleTrust, PeerDirectoryDocument,
    PeerDirectoryEntry, PeerDirectoryStateDocument, PheromoneRelayClient, PheromoneRelayConfig,
    PheromoneRelayError, PheromoneRelayService,     RelayAlertAcknowledgementInput, RelayAlertCheck,
    RelayAlertAssuranceArchiveBundleCandidate, RelayAlertAssuranceArchiveInput,
    RelayAlertAssuranceArchivePackageReport, RelayAlertAssuranceArchiveProfileDocument,
    RelayAlertAssuranceArchiveRestoreDrillReport,
    RelayAlertAssuranceArchiveRestorePackageReview, RelayAlertAssuranceCloseoutInput,
    RelayAlertAssuranceExternalRetentionProfileDocument,
    RelayAlertAssuranceExternalRetentionReviewInput,
    RelayAlertAssurancePhysicalArchiveDrillReport, RelayAlertAssuranceRetentionHandoffReport,
    RelayAlertAssuranceCloseoutProfileDocument, RelayAlertAssuranceExportBuildInput,
    RelayAlertAssuranceInput, RelayAlertAssuranceRecoveryDrillInput,
    RelayAlertAssuranceReplayInput, RelayAlertAssuranceRetentionInput,
    RelayAlertAssuranceRetentionProfileDocument, RelayAlertAssuranceRetentionRule,
    RelayAlertAssuranceTrustedExporter, RelayAlertAssuranceTrustedExportersDocument,
    RelayAlertDeliveryDriftInput, RelayAlertDeliveryEvidence, RelayAlertDeliveryInput,
    RelayAlertDeliveryProfileDocument, RelayAlertDeliveryReceiver, RelayAlertDeliveryStatus,
    RelayAlertEvaluationInput, RelayAlertHandoffDriftInput, RelayAlertHandoffEscalation,
    RelayAlertHandoffInput, RelayAlertHandoffProfileDocument, RelayAlertHandoffReceiver,
    RelayAlertHandoffSinkKind, RelayAlertNormalizationInput,
    RelayAlertNormalizationProfileDocument, RelayAlertRoute, RelayAlertRouteKind,
    RelayAlertRouteOwner, RelayAlertRouteOwnerProfileDocument, RelayAlertRouteReviewInput,
    RelayAlertRoutingProfileDocument, RelayAlertRule, RelayAlertSeverity,
    RelayAlertSuppressionEntry, RelayAlertSuppressionStateDocument, RelayBatchReceiver,
    RelayEventReport, RelayHttpSigningInput, RelayHttpVerificationContext, RelayLadderRef,
    RelayMetricsFormat, RelayNonceRecorder, RelayNonceSet, RelayObservabilityInput,
    RelayObservabilityReport, RelayProfile, RelayProfileLimits, RelayRole, RelayTrendInput,
    SqlitePheromoneRelayStore, TrustedPeerDirectoryIssuer, PHEROMONE_BATCH_RELAY_PATH,
    PHEROMONE_CATCHUP_RELAY_PATH, PHEROMONE_CATCHUP_REQUEST_SCHEMA,
    PHEROMONE_PEER_DIRECTORY_SCHEMA, PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA, PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA, PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA, PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA,
    PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA, PHEROMONE_RELAY_OBSERVABILITY_PATH,
    PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA, PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA,
    PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
};
pub(super) use chio_pheromone_runtime::{
    PheromoneBatchOutcome, PheromoneFrameReport, PheromoneReceiveReport,
    PHEROMONE_RECEIVE_REPORT_SCHEMA,
};
pub(super) use serde::{Deserialize, Serialize};
pub(super) use serde_json::json;

pub(super) const NOW: u64 = 1_766_000_000_500;

pub(super) fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

pub(super) fn sample_batch() -> PheromoneGossipBatch {
    let passport_key = key(31);
    let public_key = passport_key.public_key();
    let deposit = sign_deposit(
        PheromoneDepositBody {
            schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
            kernel_id: "did:chio:llamaworks".to_string(),
            agent_passport_key_hash: agent_passport_key_hash(&public_key),
            agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public_key),
            subject_class: "support.prompt_injection".to_string(),
            subject_class_namespace: "dev.chio.support".to_string(),
            indicator: json!({"digest": "a".repeat(64)}),
            severity: Severity::High,
            confidence: 0.8,
            timestamp_unix_ms: NOW,
            decay_half_life_secs: 3_600.0,
            evaporation_floor: Some(0.01),
            nonce: "nonce-live-relay-001".to_string(),
            treaty_scope: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            cost_commitment: None,
            workflow_context: None,
        },
        &passport_key,
    )
    .unwrap();
    PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        frames: vec![PheromoneDepositGossip {
            schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
            deposit,
            origin_kernel_id: "did:chio:llamaworks".to_string(),
            gossiping_peer_kernel_id: "did:chio:llamaworks".to_string(),
            treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
            ts_unix_ms: NOW,
            transit_chain: None,
        }],
        flushed_at_unix_ms: NOW,
    }
}

pub(super) fn directory(sender: &Keypair, endpoint: String) -> PeerDirectoryDocument {
    PeerDirectoryDocument {
        schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        peers: vec![PeerDirectoryEntry {
            kernel_id: "did:chio:llamaworks".to_string(),
            public_key: sender.public_key(),
            endpoint,
            treaty_subscriptions: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            relay_role: RelayRole::Origin,
            allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
            accepted_ladder_refs: vec![RelayLadderRef {
                ladder_manifest_id: "ladder:llamaworks:support:v1".to_string(),
                ladder_manifest_sha256: "a".repeat(64),
                expires_at_unix_ms: NOW + 60_000,
            }],
            max_batch_frames: 8,
            max_catchup_frames: 16,
            max_catchup_bytes: 64_000,
        }],
    }
}

pub(super) fn client_directory(recipient: &Keypair, endpoint: String) -> PeerDirectoryDocument {
    PeerDirectoryDocument {
        schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
        local_kernel_id: "did:chio:llamaworks".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        peers: vec![PeerDirectoryEntry {
            kernel_id: "did:chio:buyer-kernel".to_string(),
            public_key: recipient.public_key(),
            endpoint,
            treaty_subscriptions: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            relay_role: RelayRole::Receiver,
            allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
            accepted_ladder_refs: vec![RelayLadderRef {
                ladder_manifest_id: "ladder:buyer:support:v1".to_string(),
                ladder_manifest_sha256: "b".repeat(64),
                expires_at_unix_ms: NOW + 60_000,
            }],
            max_batch_frames: 8,
            max_catchup_frames: 16,
            max_catchup_bytes: 64_000,
        }],
    }
}

pub(super) fn degraded_observability_report() -> RelayObservabilityReport {
    RelayObservabilityReport {
        schema: PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: "degraded".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW,
        directory: chio_pheromone_relay::RelayDirectorySummary {
            active_version: Some(4),
            active_bundle_sha256: Some("a".repeat(64)),
            directory_sha256: Some("b".repeat(64)),
            issuer: Some("did:chio:relay-ops".to_string()),
            expires_at_unix_ms: Some(NOW + 600_000),
            removed_peer_count: 0,
            removed_peer_ids: Vec::new(),
            rejected_candidate_count: 0,
            last_rejection_code: None,
            profile: RelayProfile::Production,
        },
        queue: chio_pheromone_relay::RelayQueueSummary {
            pending: 0,
            retry: 4,
            leased: 0,
            delivered: 12,
            dead_letter: 1,
            oldest_pending_age_ms: Some(300_000),
            stale_lease_count: 0,
            inbox_count: 12,
            cursor_count: 3,
            catchup_event_count: 2,
        },
        recent_failures: vec![chio_pheromone_relay::RelayFailureSummary {
            code: "endpoint_denied".to_string(),
            count: 1,
        }],
        recommendations: vec![
            chio_pheromone_relay::RelayOperatorRecommendation {
                code: "dead_letters_present".to_string(),
                severity: "warning".to_string(),
            },
            chio_pheromone_relay::RelayOperatorRecommendation {
                code: "retries_pending".to_string(),
                severity: "info".to_string(),
            },
            chio_pheromone_relay::RelayOperatorRecommendation {
                code: "endpoint_denied".to_string(),
                severity: "warning".to_string(),
            },
        ],
    }
}

pub(super) fn alert_profile() -> RelayAlertRoutingProfileDocument {
    RelayAlertRoutingProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_source_age_ms: 300_000,
        max_suppression_ms: 3_600_000,
        allowed_label_names: vec![
            "notification_route".to_string(),
            "opsgenie".to_string(),
            "service".to_string(),
            "severity".to_string(),
        ],
        routes: vec![
            RelayAlertRoute {
                route_id: "pagerduty-primary".to_string(),
                kind: RelayAlertRouteKind::PagerDuty,
                notification_route: "pagerduty-primary".to_string(),
                opsgenie: "relay-oncall".to_string(),
                target_ref: "alertmanager:pagerduty-primary".to_string(),
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage"
                    .to_string(),
            },
            RelayAlertRoute {
                route_id: "ops-digest".to_string(),
                kind: RelayAlertRouteKind::Slack,
                notification_route: "slack-ops-digest".to_string(),
                opsgenie: "relay-oncall".to_string(),
                target_ref: "alertmanager:slack-ops-digest".to_string(),
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox".to_string(),
            },
        ],
        rules: vec![
            RelayAlertRule {
                alert_code: "dead_letters_present".to_string(),
                route_id: "pagerduty-primary".to_string(),
                severity: RelayAlertSeverity::Critical,
                min_window_ms: 300_000,
                unsuppressible: true,
                require_event_evidence: true,
            },
            RelayAlertRule {
                alert_code: "retries_pending".to_string(),
                route_id: "ops-digest".to_string(),
                severity: RelayAlertSeverity::Info,
                min_window_ms: 600_000,
                unsuppressible: false,
                require_event_evidence: false,
            },
            RelayAlertRule {
                alert_code: "endpoint_denied".to_string(),
                route_id: "pagerduty-primary".to_string(),
                severity: RelayAlertSeverity::Critical,
                min_window_ms: 300_000,
                unsuppressible: true,
                require_event_evidence: false,
            },
        ],
    }
}

pub(super) fn alert_event(code: &str) -> RelayEventReport {
    RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: code.to_string(),
        detail: "relay alert evidence".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW - 30_000,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: Some(code.to_string()),
    }
}

pub(super) fn canonical_hash<T: Serialize>(value: &T) -> String {
    sha256_hex(&canonical_json_bytes(value).unwrap())
}

pub(super) fn handoff_profile() -> RelayAlertHandoffProfileDocument {
    RelayAlertHandoffProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_alert_report_age_ms: 300_000,
        max_trend_report_age_ms: 900_000,
        receivers: vec![
            RelayAlertHandoffReceiver {
                receiver_id: "alertmanager-pagerduty-primary".to_string(),
                kind: RelayAlertHandoffSinkKind::Alertmanager,
                target_ref: "alertmanager:pagerduty-primary".to_string(),
                notification_route: "pagerduty-primary".to_string(),
                opsgenie: "relay-oncall".to_string(),
                severity_floor: RelayAlertSeverity::Critical,
                escalation_ref: "relay-critical-page".to_string(),
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage"
                    .to_string(),
            },
            RelayAlertHandoffReceiver {
                receiver_id: "alertmanager-slack-digest".to_string(),
                kind: RelayAlertHandoffSinkKind::Alertmanager,
                target_ref: "alertmanager:slack-ops-digest".to_string(),
                notification_route: "slack-ops-digest".to_string(),
                opsgenie: "relay-oncall".to_string(),
                severity_floor: RelayAlertSeverity::Info,
                escalation_ref: "relay-digest".to_string(),
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox".to_string(),
            },
        ],
        escalations: vec![
            RelayAlertHandoffEscalation {
                escalation_ref: "relay-critical-page".to_string(),
                severity: RelayAlertSeverity::Critical,
                max_delay_ms: 300_000,
                recommendation_code: "page-primary".to_string(),
            },
            RelayAlertHandoffEscalation {
                escalation_ref: "relay-digest".to_string(),
                severity: RelayAlertSeverity::Info,
                max_delay_ms: 3_600_000,
                recommendation_code: "ops-digest".to_string(),
            },
        ],
    }
}

pub(super) fn delivery_profile() -> RelayAlertDeliveryProfileDocument {
    RelayAlertDeliveryProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_handoff_report_age_ms: 300_000,
        max_evidence_age_ms: 300_000,
        max_acknowledgement_age_ms: 300_000,
        receivers: vec![
            RelayAlertDeliveryReceiver {
                receiver_id: "alertmanager-pagerduty-primary".to_string(),
                kind: RelayAlertHandoffSinkKind::Alertmanager,
                target_ref: "alertmanager:pagerduty-primary".to_string(),
                notification_route: "pagerduty-primary".to_string(),
                opsgenie: "relay-oncall".to_string(),
                severity_floor: RelayAlertSeverity::Critical,
                max_delay_ms: 300_000,
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage"
                    .to_string(),
            },
            RelayAlertDeliveryReceiver {
                receiver_id: "alertmanager-slack-digest".to_string(),
                kind: RelayAlertHandoffSinkKind::Alertmanager,
                target_ref: "alertmanager:slack-ops-digest".to_string(),
                notification_route: "slack-ops-digest".to_string(),
                opsgenie: "relay-oncall".to_string(),
                severity_floor: RelayAlertSeverity::Info,
                max_delay_ms: 3_600_000,
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox".to_string(),
            },
        ],
    }
}

pub(super) fn normalization_profile() -> RelayAlertNormalizationProfileDocument {
    RelayAlertNormalizationProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_source_age_ms: 300_000,
        receivers: delivery_profile().receivers,
    }
}

pub(super) fn route_owner_profile() -> RelayAlertRouteOwnerProfileDocument {
    RelayAlertRouteOwnerProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_report_age_ms: 900_000,
        owners: vec![
            RelayAlertRouteOwner {
                owner_alias: "relay-primary-owner".to_string(),
                receiver_ids: vec!["alertmanager-pagerduty-primary".to_string()],
                notification_routes: vec!["pagerduty-primary".to_string()],
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage"
                    .to_string(),
            },
            RelayAlertRouteOwner {
                owner_alias: "relay-digest-owner".to_string(),
                receiver_ids: vec!["alertmanager-slack-digest".to_string()],
                notification_routes: vec!["slack-ops-digest".to_string()],
                runbook: "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox".to_string(),
            },
        ],
    }
}

pub(super) fn generated_alert_trend_handoff() -> (
    chio_pheromone_relay::RelayAlertReport,
    chio_pheromone_relay::RelayTrendReport,
    chio_pheromone_relay::RelayAlertHandoffReport,
) {
    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let events = vec![alert_event("dead_letters_present")];
    let alert_report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &degraded_observability_report(),
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &events,
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let trend_report = generate_relay_trend_report(RelayTrendInput {
        local_kernel_id: "did:chio:buyer-kernel",
        observability_reports: &[degraded_observability_report()],
        event_reports: &events,
        routing_profile: &profile,
        since_unix_ms: NOW - 60_000,
        until_unix_ms: NOW + 60_000,
    })
    .unwrap();
    let handoff = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&handoff_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let handoff_report = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap();
    (alert_report, trend_report, handoff_report)
}

pub(super) fn generated_handoff_report() -> chio_pheromone_relay::RelayAlertHandoffReport {
    generated_alert_trend_handoff().2
}

pub(super) fn delivery_evidence(
    handoff_hash: &str,
    receiver: &RelayAlertDeliveryReceiver,
    alert_code: &str,
    severity: RelayAlertSeverity,
    status: RelayAlertDeliveryStatus,
) -> RelayAlertDeliveryEvidence {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        "notification_route".to_string(),
        receiver.notification_route.clone(),
    );
    labels.insert("opsgenie".to_string(), receiver.opsgenie.clone());
    labels.insert("service".to_string(), "chio-pheromone-relay".to_string());
    labels.insert("severity".to_string(), severity.as_str().to_string());
    labels.insert("status".to_string(), status.as_str().to_string());
    labels.insert("receiver".to_string(), receiver.receiver_id.clone());
    RelayAlertDeliveryEvidence {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        observed_at_unix_ms: NOW + 61_000,
        result_id: format!("delivery:{alert_code}"),
        receiver_id: receiver.receiver_id.clone(),
        kind: receiver.kind,
        target_ref: receiver.target_ref.clone(),
        notification_route: receiver.notification_route.clone(),
        opsgenie: receiver.opsgenie.clone(),
        alert_code: alert_code.to_string(),
        dedupe_key: format!("chio-relay:did:chio:buyer-kernel:{alert_code}:delivery"),
        severity,
        runbook: receiver.runbook.clone(),
        status,
        source_handoff_report_sha256: handoff_hash.to_string(),
        downstream_evidence_sha256: "d".repeat(64),
        labels,
    }
}

pub(super) fn delivery_evidence_set(
    handoff_hash: &str,
    profile: &RelayAlertDeliveryProfileDocument,
) -> Vec<RelayAlertDeliveryEvidence> {
    vec![
        delivery_evidence(
            handoff_hash,
            &profile.receivers[0],
            "dead_letters_present",
            RelayAlertSeverity::Critical,
            RelayAlertDeliveryStatus::Delivered,
        ),
        delivery_evidence(
            handoff_hash,
            &profile.receivers[0],
            "endpoint_denied",
            RelayAlertSeverity::Critical,
            RelayAlertDeliveryStatus::Accepted,
        ),
        delivery_evidence(
            handoff_hash,
            &profile.receivers[1],
            "retries_pending",
            RelayAlertSeverity::Info,
            RelayAlertDeliveryStatus::Delivered,
        ),
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NegativeCorpus {
    pub(super) cases: Vec<NegativeCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NegativeCase {
    pub(super) id: String,
    pub(super) expected_code: String,
}

pub(super) fn delivery_negative_code(case_id: &str) -> String {
    let mut handoff_report = generated_handoff_report();
    let handoff_hash = canonical_hash(&handoff_report);
    let mut profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 60_000,
    )
    .unwrap();
    let mut evidence = delivery_evidence_set(&handoff_hash, &profile);

    let err = match case_id {
        "live-url" => {
            profile.receivers[0].target_ref = "https://alerts.example.test/relay".to_string();
            relay_alert_delivery_profile_from_json(&serde_json::to_string(&profile).unwrap(), NOW)
                .unwrap_err()
        }
        "inline-token" => {
            profile.receivers[0].target_ref = "alertmanager:secret-token".to_string();
            relay_alert_delivery_profile_from_json(&serde_json::to_string(&profile).unwrap(), NOW)
                .unwrap_err()
        }
        "unbounded-label" => {
            evidence[0]
                .labels
                .insert("peer_id".to_string(), "did:chio:vendor-a".to_string());
            relay_alert_delivery_evidence_from_json(&serde_json::to_string(&evidence[0]).unwrap())
                .unwrap_err()
        }
        "unknown-receiver" => {
            evidence[0].receiver_id = "alertmanager-unknown".to_string();
            evidence[0]
                .labels
                .insert("receiver".to_string(), "alertmanager-unknown".to_string());
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "route-mismatch" => {
            evidence[0].notification_route = "slack-ops-digest".to_string();
            evidence[0].labels.insert(
                "notification_route".to_string(),
                "slack-ops-digest".to_string(),
            );
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "dedupe-missing" => {
            evidence[0].dedupe_key.clear();
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "stale-handoff" => {
            handoff_report.generated_at_unix_ms = NOW - 600_000;
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "source-hash-mismatch" => {
            evidence[0].source_handoff_report_sha256 = "a".repeat(64);
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "duplicate-result" => {
            evidence[1].result_id = evidence[0].result_id.clone();
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "missing-critical-delivery" => {
            evidence.retain(|item| item.alert_code != "endpoint_denied");
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "severity-weakened" => {
            evidence[0].severity = RelayAlertSeverity::Warning;
            evidence[0]
                .labels
                .insert("severity".to_string(), "warning".to_string());
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        "runbook-drift" => {
            evidence[0].runbook = "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#other".to_string();
            evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
                handoff_report: &handoff_report,
                delivery_profile: &profile,
                evidence: &evidence,
                now_unix_ms: NOW + 70_000,
            })
            .unwrap_err()
        }
        other => panic!("unsupported delivery negative case {other}"),
    };
    err.code().to_string()
}

pub(super) struct GeneratedAssuranceChain {
    pub(super) alert_report: chio_pheromone_relay::RelayAlertReport,
    pub(super) trend_report: chio_pheromone_relay::RelayTrendReport,
    pub(super) handoff_report: chio_pheromone_relay::RelayAlertHandoffReport,
    pub(super) normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport,
    pub(super) delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport,
    pub(super) acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport,
    pub(super) drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReport,
    pub(super) review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket,
    pub(super) assurance_package: chio_pheromone_relay::RelayAlertAssurancePackage,
}

pub(super) fn generated_assurance_chain() -> GeneratedAssuranceChain {
    let (alert_report, trend_report, handoff_report) = generated_alert_trend_handoff();
    let handoff_hash = canonical_hash(&handoff_report);
    let delivery_profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 90_000,
    )
    .unwrap();
    let normalization_report =
        normalize_relay_alert_delivery_evidence(RelayAlertNormalizationInput {
            profile: &normalization_profile(),
            sources: &delivery_evidence_set(&handoff_hash, &delivery_profile)
                .into_iter()
                .map(|evidence| serde_json::to_value(evidence).unwrap())
                .collect::<Vec<_>>(),
            now_unix_ms: NOW + 70_000,
        })
        .unwrap();
    let delivery_report = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &delivery_profile,
        evidence: &normalization_report.evidence,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();
    let acknowledgement_report =
        evaluate_relay_alert_acknowledgement(RelayAlertAcknowledgementInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            delivery_profile: &delivery_profile,
            now_unix_ms: NOW + 80_000,
        })
        .unwrap();
    let drift_report = generate_relay_alert_delivery_drift_report(RelayAlertDeliveryDriftInput {
        handoff_reports: std::slice::from_ref(&handoff_report),
        delivery_reports: std::slice::from_ref(&delivery_report),
        delivery_profile: &delivery_profile,
        since_unix_ms: NOW,
        until_unix_ms: NOW + 90_000,
    })
    .unwrap();
    let review_packet = generate_relay_alert_route_review_packet(RelayAlertRouteReviewInput {
        handoff_report: &handoff_report,
        delivery_report: &delivery_report,
        acknowledgement_report: &acknowledgement_report,
        drift_report: &drift_report,
        route_owner_profile: &route_owner_profile(),
        now_unix_ms: NOW + 90_000,
    })
    .unwrap();
    let assurance_package = generate_relay_alert_assurance_package(RelayAlertAssuranceInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        handoff_report: &handoff_report,
        normalization_report: &normalization_report,
        delivery_report: &delivery_report,
        acknowledgement_report: &acknowledgement_report,
        drift_report: &drift_report,
        review_packet: &review_packet,
        now_unix_ms: NOW + 90_000,
    })
    .unwrap();
    GeneratedAssuranceChain {
        alert_report,
        trend_report,
        handoff_report,
        normalization_report,
        delivery_report,
        acknowledgement_report,
        drift_report,
        review_packet,
        assurance_package,
    }
}

pub(super) fn retention_profile_for_export() -> RelayAlertAssuranceRetentionProfileDocument {
    RelayAlertAssuranceRetentionProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        warning_window_ms: 30_000,
        rules: vec![
            RelayAlertAssuranceRetentionRule {
                artifact_role: "assurance_package".to_string(),
                retain_for_ms: 900_000,
                legal_hold: true,
            },
            RelayAlertAssuranceRetentionRule {
                artifact_role: "normalized_delivery_evidence".to_string(),
                retain_for_ms: 900_000,
                legal_hold: false,
            },
        ],
    }
}

pub(super) fn trusted_exporters(
    public_key: chio_core_types::PublicKey,
) -> RelayAlertAssuranceTrustedExportersDocument {
    RelayAlertAssuranceTrustedExportersDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        min_exported_at_unix_ms: NOW,
        exporters: vec![RelayAlertAssuranceTrustedExporter {
            exporter_id: "relay-exporter".to_string(),
            key_id: "relay-export-key-1".to_string(),
            public_key,
            valid_from_unix_ms: NOW - 1_000,
            valid_until_unix_ms: NOW + 900_000,
            status: "active".to_string(),
        }],
    }
}

pub(super) fn archive_profile_for_export() -> RelayAlertAssuranceArchiveProfileDocument {
    RelayAlertAssuranceArchiveProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        require_replay_match: true,
        require_recovery_drill: true,
    }
}

pub(super) fn closeout_profile_for_export() -> RelayAlertAssuranceCloseoutProfileDocument {
    RelayAlertAssuranceCloseoutProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        require_replay_match: true,
        require_recovery_drill: true,
        block_legal_hold: true,
        block_eligible_for_delete: false,
    }
}

pub(super) fn relay_alert_assurance_export_bundle(
    seed: u8,
    bundle_id: &str,
) -> (
    chio_pheromone_relay::RelayAlertAssuranceExportBundle,
    Keypair,
) {
    let chain = generated_assurance_chain();
    let exporter = key(seed);
    let bundle = sign_relay_alert_assurance_export_bundle(RelayAlertAssuranceExportBuildInput {
        bundle_id,
        exporter_id: "relay-exporter",
        exporter_key_id: "relay-export-key-1",
        signing_key: &exporter,
        retention_profile: &retention_profile_for_export(),
        alert_report: &chain.alert_report,
        trend_report: &chain.trend_report,
        handoff_report: &chain.handoff_report,
        normalization_report: &chain.normalization_report,
        delivery_report: &chain.delivery_report,
        acknowledgement_report: &chain.acknowledgement_report,
        drift_report: &chain.drift_report,
        review_packet: &chain.review_packet,
        assurance_package: &chain.assurance_package,
        normalized_delivery_evidence: &chain.normalization_report.evidence,
        exported_at_unix_ms: NOW + 100_000,
    })
    .unwrap();
    (bundle, exporter)
}

pub(super) struct AcceptingReceiver;

#[async_trait]
impl RelayBatchReceiver for AcceptingReceiver {
    async fn receive_batch(
        &self,
        batch: PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
        assert_eq!(authenticated_sender_kernel_id, "did:chio:llamaworks");
        Ok(PheromoneReceiveReport {
            schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
            accepted: true,
            batch_outcome: PheromoneBatchOutcome::Accepted,
            accepted_frame_count: 1,
            rejected_frame_count: 0,
            batch_sha256: chio_core_types::crypto::sha256_hex(
                &chio_core_types::canonical::canonical_json_bytes(&batch).unwrap(),
            ),
            recipient_kernel_id: batch.recipient_kernel_id,
            authenticated_sender_kernel_id,
            received_at_unix_ms,
            frames: vec![PheromoneFrameReport {
                frame_index: 0,
                accepted: true,
                code: "accepted".to_string(),
                detail: "accepted".to_string(),
                deposit_nonce: Some("nonce-live-relay-001".to_string()),
            }],
        })
    }
}

pub(super) fn accepted_report() -> PheromoneReceiveReport {
    PheromoneReceiveReport {
        schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
        accepted: true,
        batch_outcome: PheromoneBatchOutcome::Accepted,
        accepted_frame_count: 1,
        rejected_frame_count: 0,
        batch_sha256: "b".repeat(64),
        recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
        authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        received_at_unix_ms: NOW,
        frames: vec![PheromoneFrameReport {
            frame_index: 0,
            accepted: true,
            code: "accepted".to_string(),
            detail: "accepted".to_string(),
            deposit_nonce: Some("nonce-live-relay-001".to_string()),
        }],
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExternalRetentionNegativeCorpus {
    pub(super) cases: Vec<ExternalRetentionNegativeCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExternalRetentionNegativeCase {
    pub(super) case_id: String,
    pub(super) expected_code: String,
}

const EXTERNAL_RETENTION_KERNEL_ID: &str = "did:chio:buyer-kernel";
const EXTERNAL_RETENTION_PACKAGE_ID: &str = "relay-archive-package-1";
const EXTERNAL_RETENTION_SINCE_UNIX_MS: u64 = NOW - 10_000;
const EXTERNAL_RETENTION_UNTIL_UNIX_MS: u64 = NOW + 10_000;

fn external_retention_profile() -> RelayAlertAssuranceExternalRetentionProfileDocument {
    RelayAlertAssuranceExternalRetentionProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA.to_string(),
        local_kernel_id: EXTERNAL_RETENTION_KERNEL_ID.to_string(),
        allowed_retention_system_aliases: vec![
            "retention-vault".to_string(),
            "retention-vault-b".to_string(),
        ],
        max_package_count: 8,
        max_evidence_age_ms: 120_000,
        require_generation_continuity: true,
        require_restore_accepted: true,
        require_physical_readback: true,
        require_retention_handoff_ready: true,
        min_sampled_members: 1,
        min_sample_coverage_basis_points: 1_000,
        recommendation_codes: vec!["operator_external_retention_review".to_string()],
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
    }
}

fn external_retention_package_report(
    generation: u64,
    previous_package_manifest_sha256: Option<String>,
) -> RelayAlertAssuranceArchivePackageReport {
    RelayAlertAssuranceArchivePackageReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: EXTERNAL_RETENTION_KERNEL_ID.to_string(),
        generated_at_unix_ms: NOW,
        package_id: EXTERNAL_RETENTION_PACKAGE_ID.to_string(),
        package_generation: generation,
        previous_package_manifest_sha256,
        package_manifest_sha256: format!("{:064x}", generation),
        source_archive_report_sha256: "b".repeat(64),
        source_closeout_report_sha256: "c".repeat(64),
        package_member_count: 4,
        package_total_byte_count: 128,
        bundle_count: 1,
        trusted_packager_verified: true,
        nested_exporter_verified: true,
        source_reports_matched: true,
        closeout_ready_verified: true,
        total_byte_count_matched: true,
        extractable: true,
        checks: vec![RelayAlertCheck {
            code: "accepted".to_string(),
            accepted: true,
            detail: "package report verified".to_string(),
        }],
    }
}

fn external_retention_package_report_sha256(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> String {
    sha256_hex(&canonical_json_bytes(report).unwrap())
}

fn external_retention_restore_drill(
    report: &RelayAlertAssuranceArchivePackageReport,
    accepted: bool,
) -> RelayAlertAssuranceArchiveRestoreDrillReport {
    let package_code = if accepted {
        "accepted".to_string()
    } else {
        "package_report_rejected".to_string()
    };
    RelayAlertAssuranceArchiveRestoreDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "restore_blocked".to_string()
        },
        local_kernel_id: EXTERNAL_RETENTION_KERNEL_ID.to_string(),
        generated_at_unix_ms: NOW,
        package_count: 1,
        verified_generation_count: if accepted { 1 } else { 0 },
        latest_package_generation: report.package_generation,
        quarantine_count: if accepted { 0 } else { 1 },
        blocked_count: if accepted { 0 } else { 1 },
        packages: vec![RelayAlertAssuranceArchiveRestorePackageReview {
            package_id: report.package_id.clone(),
            package_generation: report.package_generation,
            package_manifest_sha256: report.package_manifest_sha256.clone(),
            previous_package_manifest_sha256: report.previous_package_manifest_sha256.clone(),
            accepted,
            code: package_code,
        }],
        checks: vec![RelayAlertCheck {
            code: if accepted {
                "accepted".to_string()
            } else {
                "restore_blocked".to_string()
            },
            accepted,
            detail: "restore drill review".to_string(),
        }],
    }
}

fn external_retention_physical_drill(
    report_hash: &str,
    sampled_member_count: u64,
) -> RelayAlertAssurancePhysicalArchiveDrillReport {
    RelayAlertAssurancePhysicalArchiveDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: EXTERNAL_RETENTION_KERNEL_ID.to_string(),
        generated_at_unix_ms: NOW,
        evidence_id: "physical-readback-001".to_string(),
        package_id: EXTERNAL_RETENTION_PACKAGE_ID.to_string(),
        package_report_sha256: report_hash.to_string(),
        sampled_member_count,
        checks: vec![RelayAlertCheck {
            code: "accepted".to_string(),
            accepted: true,
            detail: "physical readback".to_string(),
        }],
    }
}

fn external_retention_handoff(
    report_hash: &str,
    target_system_alias: &str,
) -> RelayAlertAssuranceRetentionHandoffReport {
    RelayAlertAssuranceRetentionHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: EXTERNAL_RETENTION_KERNEL_ID.to_string(),
        generated_at_unix_ms: NOW,
        evidence_id: "handoff-001".to_string(),
        package_id: EXTERNAL_RETENTION_PACKAGE_ID.to_string(),
        package_report_sha256: report_hash.to_string(),
        target_system_alias: target_system_alias.to_string(),
        ready_for_operator_handoff: true,
        checks: vec![RelayAlertCheck {
            code: "accepted".to_string(),
            accepted: true,
            detail: "retention handoff".to_string(),
        }],
    }
}

fn external_retention_review_code(
    profile: &RelayAlertAssuranceExternalRetentionProfileDocument,
    package_reports: &[RelayAlertAssuranceArchivePackageReport],
    restore_drill_reports: &[RelayAlertAssuranceArchiveRestoreDrillReport],
    physical_drill_reports: &[RelayAlertAssurancePhysicalArchiveDrillReport],
    retention_handoff_reports: &[RelayAlertAssuranceRetentionHandoffReport],
) -> String {
    generate_relay_alert_assurance_external_retention_review_report(
        RelayAlertAssuranceExternalRetentionReviewInput {
            package_reports,
            restore_drill_reports,
            physical_drill_reports,
            retention_handoff_reports,
            profile,
            since_unix_ms: EXTERNAL_RETENTION_SINCE_UNIX_MS,
            until_unix_ms: EXTERNAL_RETENTION_UNTIL_UNIX_MS,
            now_unix_ms: NOW,
        },
    )
    .map(|report| report.code)
    .unwrap_or_else(|error| error.code().to_string())
}

pub(super) fn external_retention_negative_code(case_id: &str) -> String {
    if case_id == "stale_profile" {
        let stale_profile = serde_json::json!({
            "schema": PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
            "localKernelId": EXTERNAL_RETENTION_KERNEL_ID,
            "allowedRetentionSystemAliases": ["retention-vault"],
            "maxPackageCount": 8,
            "maxEvidenceAgeMs": 120000,
            "requireGenerationContinuity": true,
            "requireRestoreAccepted": true,
            "requirePhysicalReadback": true,
            "requireRetentionHandoffReady": true,
            "minSampledMembers": 1,
            "minSampleCoverageBasisPoints": 1000,
            "recommendationCodes": ["operator_external_retention_review"],
            "issuedAtUnixMs": NOW - 1_000_000,
            "expiresAtUnixMs": NOW - 500_000,
        });
        return relay_alert_assurance_external_retention_profile_from_json(
            &stale_profile.to_string(),
            NOW,
        )
        .unwrap_err()
        .code()
        .to_string();
    }

    let profile = external_retention_profile();
    let mut package_report = external_retention_package_report(1, None);
    let report_hash = external_retention_package_report_sha256(&package_report);
    let mut restore_drill_reports =
        vec![external_retention_restore_drill(&package_report, true)];
    let mut physical_drill_reports = vec![external_retention_physical_drill(&report_hash, 1)];
    let mut retention_handoff_reports =
        vec![external_retention_handoff(&report_hash, "retention-vault")];
    let mut package_reports = vec![package_report.clone()];

    match case_id {
        "untrusted_packager" => package_report.trusted_packager_verified = false,
        "untrusted_exporter" => package_report.nested_exporter_verified = false,
        "source_report_mismatch" => package_report.source_reports_matched = false,
        "stale_evidence" => package_report.generated_at_unix_ms = NOW - 200_000,
        "local_kernel_mismatch" => package_report.local_kernel_id = "did:chio:other-kernel".to_string(),
        "generation_gap" => {
            let first = external_retention_package_report(1, None);
            let second = external_retention_package_report(
                3,
                Some("0000000000000000000000000000000000000000000000000000000000000002".to_string()),
            );
            let first_hash = external_retention_package_report_sha256(&first);
            let second_hash = external_retention_package_report_sha256(&second);
            package_reports = vec![first, second];
            restore_drill_reports = vec![
                external_retention_restore_drill(&package_reports[0], true),
                external_retention_restore_drill(&package_reports[1], true),
            ];
            physical_drill_reports = vec![
                external_retention_physical_drill(&first_hash, 1),
                external_retention_physical_drill(&second_hash, 1),
            ];
            retention_handoff_reports = vec![
                external_retention_handoff(&first_hash, "retention-vault"),
                external_retention_handoff(&second_hash, "retention-vault"),
            ];
            return external_retention_review_code(
                &profile,
                &package_reports,
                &restore_drill_reports,
                &physical_drill_reports,
                &retention_handoff_reports,
            );
        }
        "previous_manifest_mismatch" => {
            package_reports = vec![
                external_retention_package_report(1, None),
                external_retention_package_report(
                    2,
                    Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()),
                ),
            ];
            let second_hash = external_retention_package_report_sha256(&package_reports[1]);
            restore_drill_reports = vec![
                external_retention_restore_drill(&package_reports[0], true),
                external_retention_restore_drill(&package_reports[1], true),
            ];
            physical_drill_reports = vec![
                external_retention_physical_drill(
                    &external_retention_package_report_sha256(&package_reports[0]),
                    1,
                ),
                external_retention_physical_drill(&second_hash, 1),
            ];
            retention_handoff_reports = vec![
                external_retention_handoff(
                    &external_retention_package_report_sha256(&package_reports[0]),
                    "retention-vault",
                ),
                external_retention_handoff(&second_hash, "retention-vault"),
            ];
            return external_retention_review_code(
                &profile,
                &package_reports,
                &restore_drill_reports,
                &physical_drill_reports,
                &retention_handoff_reports,
            );
        }
        "missing_restore_drill" => restore_drill_reports.clear(),
        "rejected_restore_drill" => {
            restore_drill_reports = vec![external_retention_restore_drill(&package_report, false)]
        }
        "missing_physical_readback" => physical_drill_reports.clear(),
        "insufficient_sample" => {
            physical_drill_reports = vec![external_retention_physical_drill(&report_hash, 0)]
        }
        "missing_retention_handoff" => retention_handoff_reports.clear(),
        "unknown_retention_alias" => {
            retention_handoff_reports =
                vec![external_retention_handoff(&report_hash, "unknown-vault")]
        }
        "alias_drift" => {
            let first = external_retention_package_report(1, None);
            let second = external_retention_package_report(
                2,
                Some(first.package_manifest_sha256.clone()),
            );
            let first_hash = external_retention_package_report_sha256(&first);
            let second_hash = external_retention_package_report_sha256(&second);
            package_reports = vec![first, second];
            restore_drill_reports = vec![
                external_retention_restore_drill(&package_reports[0], true),
                external_retention_restore_drill(&package_reports[1], true),
            ];
            physical_drill_reports = vec![
                external_retention_physical_drill(&first_hash, 1),
                external_retention_physical_drill(&second_hash, 1),
            ];
            retention_handoff_reports = vec![
                external_retention_handoff(&first_hash, "retention-vault"),
                external_retention_handoff(&second_hash, "retention-vault-b"),
            ];
            return external_retention_review_code(
                &profile,
                &package_reports,
                &restore_drill_reports,
                &physical_drill_reports,
                &retention_handoff_reports,
            );
        }
        other => panic!("unsupported external retention negative case {other}"),
    }

    package_reports = vec![package_report];
    external_retention_review_code(
        &profile,
        &package_reports,
        &restore_drill_reports,
        &physical_drill_reports,
        &retention_handoff_reports,
    )
}
