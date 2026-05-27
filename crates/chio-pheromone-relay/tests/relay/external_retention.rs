use super::common::NOW;
use chio_pheromone_relay::{
    generate_relay_alert_assurance_external_retention_review_report,
    relay_alert_assurance_external_retention_profile_from_json,
    RelayAlertAssuranceArchivePackageReport, RelayAlertAssuranceExternalRetentionProfileDocument,
    RelayAlertAssuranceExternalRetentionReviewInput, PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA,
};

fn external_retention_profile() -> RelayAlertAssuranceExternalRetentionProfileDocument {
    RelayAlertAssuranceExternalRetentionProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        allowed_retention_system_aliases: vec!["vault-1".to_string()],
        max_package_count: 10,
        max_evidence_age_ms: 100_000,
        require_generation_continuity: false,
        require_restore_accepted: false,
        require_physical_readback: false,
        require_retention_handoff_ready: false,
        min_sampled_members: 1,
        min_sample_coverage_basis_points: 1,
        recommendation_codes: Vec::new(),
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 60_000,
    }
}

fn archive_package_report() -> RelayAlertAssuranceArchivePackageReport {
    RelayAlertAssuranceArchivePackageReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW + 10_000,
        package_id: "relay-alert-archive-package-001".to_string(),
        package_generation: 1,
        previous_package_manifest_sha256: None,
        package_manifest_sha256: "a".repeat(64),
        source_archive_report_sha256: "b".repeat(64),
        source_closeout_report_sha256: "c".repeat(64),
        package_member_count: 1,
        package_total_byte_count: 128,
        bundle_count: 1,
        trusted_packager_verified: true,
        nested_exporter_verified: true,
        source_reports_matched: true,
        closeout_ready_verified: true,
        total_byte_count_matched: true,
        extractable: true,
        checks: vec![chio_pheromone_relay::RelayAlertCheck {
            code: "accepted".to_string(),
            accepted: true,
            detail: "package report verified".to_string(),
        }],
    }
}

#[test]
fn external_retention_profile_rejects_invalid_alias_token() {
    let mut profile = external_retention_profile();
    profile.allowed_retention_system_aliases = vec!["bad alias".to_string()];

    let err = relay_alert_assurance_external_retention_profile_from_json(
        &serde_json::to_string(&profile).unwrap(),
        NOW + 1_000,
    )
    .unwrap_err();

    assert!(err.to_string().contains("invalid"));
}

#[test]
fn external_retention_profile_rejects_expired_profile() {
    let mut profile = external_retention_profile();
    profile.expires_at_unix_ms = NOW + 500;

    let err = relay_alert_assurance_external_retention_profile_from_json(
        &serde_json::to_string(&profile).unwrap(),
        NOW + 10_000,
    )
    .unwrap_err();

    assert!(err.to_string().contains("not fresh"));
}

#[test]
fn external_retention_profile_rejects_sample_coverage_above_full_percent() {
    let mut profile = external_retention_profile();
    profile.min_sample_coverage_basis_points = 10_001;

    let err = relay_alert_assurance_external_retention_profile_from_json(
        &serde_json::to_string(&profile).unwrap(),
        NOW + 1_000,
    )
    .unwrap_err();

    assert!(err.to_string().contains("100 percent"));
}

#[test]
fn external_retention_review_accepts_valid_package_report() {
    let profile = external_retention_profile();
    let package = archive_package_report();
    let report = generate_relay_alert_assurance_external_retention_review_report(
        RelayAlertAssuranceExternalRetentionReviewInput {
            package_reports: std::slice::from_ref(&package),
            restore_drill_reports: &[],
            physical_drill_reports: &[],
            retention_handoff_reports: &[],
            profile: &profile,
            since_unix_ms: NOW,
            until_unix_ms: NOW + 50_000,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap();

    assert_eq!(
        report.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA
    );
    assert!(report.accepted);
    assert_eq!(report.package_count, 1);
    assert_eq!(report.quarantine_count, 0);
    assert!(report.reviews[0].accepted);
}

#[test]
fn external_retention_review_quarantines_local_kernel_mismatch() {
    let profile = external_retention_profile();
    let mut package = archive_package_report();
    package.local_kernel_id = "did:chio:other-kernel".to_string();

    let report = generate_relay_alert_assurance_external_retention_review_report(
        RelayAlertAssuranceExternalRetentionReviewInput {
            package_reports: std::slice::from_ref(&package),
            restore_drill_reports: &[],
            physical_drill_reports: &[],
            retention_handoff_reports: &[],
            profile: &profile,
            since_unix_ms: NOW,
            until_unix_ms: NOW + 50_000,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap();

    assert!(!report.accepted);
    assert_eq!(report.code, "external_retention_blocked");
    assert_eq!(report.quarantine_count, 1);
    assert!(!report.reviews[0].accepted);
}

#[test]
fn external_retention_review_rejects_empty_package_reports() {
    let profile = external_retention_profile();

    let err = generate_relay_alert_assurance_external_retention_review_report(
        RelayAlertAssuranceExternalRetentionReviewInput {
            package_reports: &[],
            restore_drill_reports: &[],
            physical_drill_reports: &[],
            retention_handoff_reports: &[],
            profile: &profile,
            since_unix_ms: NOW,
            until_unix_ms: NOW + 50_000,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap_err();

    assert!(err
        .to_string()
        .contains("requires at least one package report"));
}

#[test]
fn external_retention_review_rejects_invalid_review_window() {
    let profile = external_retention_profile();
    let package = archive_package_report();

    let err = generate_relay_alert_assurance_external_retention_review_report(
        RelayAlertAssuranceExternalRetentionReviewInput {
            package_reports: std::slice::from_ref(&package),
            restore_drill_reports: &[],
            physical_drill_reports: &[],
            retention_handoff_reports: &[],
            profile: &profile,
            since_unix_ms: NOW + 50_000,
            until_unix_ms: NOW,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap_err();

    assert!(err.to_string().contains("review window is invalid"));
}
