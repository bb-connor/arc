use super::common::NOW;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_pheromone_relay::{
    generate_relay_alert_assurance_external_retention_review_report,
    relay_alert_assurance_external_retention_profile_from_json,
    RelayAlertAssuranceArchivePackageReport, RelayAlertAssuranceArchiveRestoreDrillReport,
    RelayAlertAssuranceArchiveRestorePackageReview,
    RelayAlertAssuranceExternalRetentionProfileDocument,
    RelayAlertAssuranceExternalRetentionReviewInput, RelayAlertAssurancePhysicalArchiveDrillReport,
    RelayAlertAssuranceRetentionHandoffReport, RelayAlertCheck,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
};
use std::fs;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NegativeCorpus {
    cases: Vec<NegativeCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NegativeCase {
    #[serde(rename = "caseId")]
    id: String,
    expected_code: String,
}

struct ExternalRetentionFixture {
    profile: RelayAlertAssuranceExternalRetentionProfileDocument,
    package_report: RelayAlertAssuranceArchivePackageReport,
    restore_drill: RelayAlertAssuranceArchiveRestoreDrillReport,
    physical_drill: RelayAlertAssurancePhysicalArchiveDrillReport,
    handoff: RelayAlertAssuranceRetentionHandoffReport,
    since_unix_ms: u64,
    until_unix_ms: u64,
    now_unix_ms: u64,
}

#[test]
fn external_retention_review_accepts_well_formed_chain() {
    let fixture = external_retention_fixture();
    let review = generate_relay_alert_assurance_external_retention_review_report(
        external_retention_input(&fixture),
    )
    .unwrap();

    assert!(review.accepted);
    assert_eq!(review.code, "accepted");
    assert_eq!(review.package_count, 1);
    assert_eq!(review.quarantine_count, 0);
    assert_eq!(review.reviews[0].restore_status, "accepted");
    assert_eq!(review.reviews[0].physical_readback_status, "accepted");
    assert_eq!(review.reviews[0].retention_handoff_status, "accepted");
    assert_eq!(
        review.reviews[0].target_system_alias.as_deref(),
        Some("retention-vault")
    );
}

#[test]
fn external_retention_review_negative_corpus_cases_are_executable() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance/",
        "relay-alert-assurance-external-retention-negative-cases.json"
    );
    let corpus: NegativeCorpus = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for case in &corpus.cases {
        assert!(seen.insert(case.id.as_str()), "duplicate case {}", case.id);
        if case.id == "wrong_expected_code" {
            let observed = external_retention_negative_code("untrusted_packager");
            assert_ne!(observed, "archive_package_invalid");
            assert_eq!(case.expected_code, "negative_corpus_mismatch");
            continue;
        }
        let observed = external_retention_negative_code(&case.id);
        assert_eq!(
            observed, case.expected_code,
            "negative case {} expected {} but observed {}",
            case.id, case.expected_code, observed
        );
    }
    for required in [
        "untrusted_packager",
        "untrusted_exporter",
        "source_report_mismatch",
        "stale_profile",
        "stale_evidence",
        "local_kernel_mismatch",
        "generation_gap",
        "previous_manifest_mismatch",
        "missing_restore_drill",
        "rejected_restore_drill",
        "missing_physical_readback",
        "insufficient_sample",
        "missing_retention_handoff",
        "unknown_retention_alias",
        "alias_drift",
        "wrong_expected_code",
    ] {
        assert!(seen.contains(required), "missing negative case {required}");
    }
}

fn external_retention_negative_code(case_id: &str) -> String {
    match case_id {
        "stale_profile" => {
            let mut fixture = external_retention_fixture();
            fixture.profile.issued_at_unix_ms = NOW + 10_000;
            fixture.profile.expires_at_unix_ms = NOW + 20_000;
            relay_alert_assurance_external_retention_profile_from_json(
                &serde_json::to_string(&fixture.profile).unwrap(),
                NOW,
            )
            .unwrap_err()
            .code()
            .to_string()
        }
        "generation_gap" | "previous_manifest_mismatch" | "alias_drift" => {
            let mut fixture = external_retention_fixture();
            let mut second = second_generation_package_report(&fixture.package_report);
            let second_sha256 = package_report_sha256(&second);
            let mut restore = fixture.restore_drill.clone();
            restore
                .packages
                .push(RelayAlertAssuranceArchiveRestorePackageReview {
                    package_id: second.package_id.clone(),
                    package_generation: second.package_generation,
                    package_manifest_sha256: second.package_manifest_sha256.clone(),
                    previous_package_manifest_sha256: Some(
                        fixture.package_report.package_manifest_sha256.clone(),
                    ),
                    accepted: true,
                    code: "accepted".to_string(),
                });
            let mut physical = fixture.physical_drill.clone();
            physical.package_id = second.package_id.clone();
            physical.package_report_sha256 = second_sha256.clone();
            physical.generated_at_unix_ms = second.generated_at_unix_ms;
            let mut second_handoff = fixture.handoff.clone();
            second_handoff.package_id = second.package_id.clone();
            second_handoff.package_report_sha256 = second_sha256;
            second_handoff.generated_at_unix_ms = second.generated_at_unix_ms;
            match case_id {
                "generation_gap" => {
                    second.package_generation = 3;
                    restore.packages[1].package_generation = 3;
                }
                "previous_manifest_mismatch" => {
                    second.previous_package_manifest_sha256 = Some("f".repeat(64));
                    restore.packages[1].previous_package_manifest_sha256 = Some("f".repeat(64));
                }
                "alias_drift" => {
                    second_handoff.target_system_alias = "other-vault".to_string();
                    fixture
                        .profile
                        .allowed_retention_system_aliases
                        .push("other-vault".to_string());
                }
                _ => {}
            }
            external_retention_review_code(
                &fixture.profile,
                &[fixture.package_report, second],
                &[restore],
                &[fixture.physical_drill, physical],
                &[fixture.handoff, second_handoff],
                fixture.since_unix_ms,
                fixture.until_unix_ms,
                fixture.now_unix_ms,
            )
        }
        other => {
            let mut fixture = external_retention_fixture();
            match other {
                "untrusted_packager" => fixture.package_report.trusted_packager_verified = false,
                "untrusted_exporter" => fixture.package_report.nested_exporter_verified = false,
                "source_report_mismatch" => fixture.package_report.source_reports_matched = false,
                "stale_evidence" => fixture.package_report.generated_at_unix_ms = NOW - 600_000,
                "local_kernel_mismatch" => {
                    fixture.package_report.local_kernel_id = "did:chio:other-kernel".to_string();
                }
                "missing_restore_drill" => {
                    return external_retention_review_code(
                        &fixture.profile,
                        std::slice::from_ref(&fixture.package_report),
                        &[],
                        std::slice::from_ref(&fixture.physical_drill),
                        std::slice::from_ref(&fixture.handoff),
                        fixture.since_unix_ms,
                        fixture.until_unix_ms,
                        fixture.now_unix_ms,
                    );
                }
                "rejected_restore_drill" => fixture.restore_drill.accepted = false,
                "missing_physical_readback" => {
                    return external_retention_review_code(
                        &fixture.profile,
                        std::slice::from_ref(&fixture.package_report),
                        std::slice::from_ref(&fixture.restore_drill),
                        &[],
                        std::slice::from_ref(&fixture.handoff),
                        fixture.since_unix_ms,
                        fixture.until_unix_ms,
                        fixture.now_unix_ms,
                    );
                }
                "insufficient_sample" => {
                    fixture.package_report.package_member_count = 100;
                    fixture.physical_drill.sampled_member_count = 1;
                }
                "missing_retention_handoff" => {
                    return external_retention_review_code(
                        &fixture.profile,
                        std::slice::from_ref(&fixture.package_report),
                        std::slice::from_ref(&fixture.restore_drill),
                        std::slice::from_ref(&fixture.physical_drill),
                        &[],
                        fixture.since_unix_ms,
                        fixture.until_unix_ms,
                        fixture.now_unix_ms,
                    );
                }
                "unknown_retention_alias" => {
                    fixture.handoff.target_system_alias = "unknown-vault".to_string();
                }
                unsupported => panic!("unsupported external retention negative case {unsupported}"),
            }
            external_retention_review_code(
                &fixture.profile,
                std::slice::from_ref(&fixture.package_report),
                std::slice::from_ref(&fixture.restore_drill),
                std::slice::from_ref(&fixture.physical_drill),
                std::slice::from_ref(&fixture.handoff),
                fixture.since_unix_ms,
                fixture.until_unix_ms,
                fixture.now_unix_ms,
            )
        }
    }
}

fn external_retention_review_code(
    profile: &RelayAlertAssuranceExternalRetentionProfileDocument,
    package_reports: &[RelayAlertAssuranceArchivePackageReport],
    restore_drill_reports: &[RelayAlertAssuranceArchiveRestoreDrillReport],
    physical_drill_reports: &[RelayAlertAssurancePhysicalArchiveDrillReport],
    retention_handoff_reports: &[RelayAlertAssuranceRetentionHandoffReport],
    since_unix_ms: u64,
    until_unix_ms: u64,
    now_unix_ms: u64,
) -> String {
    generate_relay_alert_assurance_external_retention_review_report(
        RelayAlertAssuranceExternalRetentionReviewInput {
            package_reports,
            restore_drill_reports,
            physical_drill_reports,
            retention_handoff_reports,
            profile,
            since_unix_ms,
            until_unix_ms,
            now_unix_ms,
        },
    )
    .map(|report| report.code)
    .unwrap_or_else(|error| error.code().to_string())
}

fn external_retention_input(
    fixture: &ExternalRetentionFixture,
) -> RelayAlertAssuranceExternalRetentionReviewInput<'_> {
    RelayAlertAssuranceExternalRetentionReviewInput {
        package_reports: std::slice::from_ref(&fixture.package_report),
        restore_drill_reports: std::slice::from_ref(&fixture.restore_drill),
        physical_drill_reports: std::slice::from_ref(&fixture.physical_drill),
        retention_handoff_reports: std::slice::from_ref(&fixture.handoff),
        profile: &fixture.profile,
        since_unix_ms: fixture.since_unix_ms,
        until_unix_ms: fixture.until_unix_ms,
        now_unix_ms: fixture.now_unix_ms,
    }
}

fn external_retention_fixture() -> ExternalRetentionFixture {
    let profile = external_retention_profile();
    let package_report = baseline_package_report();
    let package_report_sha256 = package_report_sha256(&package_report);
    let restore_drill =
        baseline_restore_drill(&package_report, package_report.generated_at_unix_ms);
    let physical_drill = baseline_physical_drill(
        &package_report,
        &package_report_sha256,
        package_report.generated_at_unix_ms,
    );
    let handoff = baseline_handoff(&package_report, &package_report_sha256);
    ExternalRetentionFixture {
        profile,
        package_report,
        restore_drill,
        physical_drill,
        handoff,
        since_unix_ms: NOW,
        until_unix_ms: NOW + 12_000,
        now_unix_ms: NOW + 4_000,
    }
}

fn external_retention_profile() -> RelayAlertAssuranceExternalRetentionProfileDocument {
    RelayAlertAssuranceExternalRetentionProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        allowed_retention_system_aliases: vec!["retention-vault".to_string()],
        max_package_count: 8,
        max_evidence_age_ms: 120_000,
        require_generation_continuity: true,
        require_restore_accepted: true,
        require_physical_readback: true,
        require_retention_handoff_ready: true,
        min_sampled_members: 1,
        min_sample_coverage_basis_points: 1_000,
        recommendation_codes: vec!["operator_external_retention_review".to_string()],
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 90_000,
    }
}

fn baseline_package_report() -> RelayAlertAssuranceArchivePackageReport {
    RelayAlertAssuranceArchivePackageReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW + 2_000,
        package_id: "relay-archive-package-1".to_string(),
        package_generation: 1,
        previous_package_manifest_sha256: None,
        package_manifest_sha256: "0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
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
        checks: vec![accepted_check("package report verified")],
    }
}

fn second_generation_package_report(
    first: &RelayAlertAssuranceArchivePackageReport,
) -> RelayAlertAssuranceArchivePackageReport {
    RelayAlertAssuranceArchivePackageReport {
        package_id: first.package_id.clone(),
        package_generation: 2,
        previous_package_manifest_sha256: Some(first.package_manifest_sha256.clone()),
        package_manifest_sha256: "0000000000000000000000000000000000000000000000000000000000000002"
            .to_string(),
        generated_at_unix_ms: first.generated_at_unix_ms + 1_000,
        ..first.clone()
    }
}

fn baseline_restore_drill(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    generated_at_unix_ms: u64,
) -> RelayAlertAssuranceArchiveRestoreDrillReport {
    RelayAlertAssuranceArchiveRestoreDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: package_report.local_kernel_id.clone(),
        generated_at_unix_ms,
        package_count: 1,
        verified_generation_count: 1,
        latest_package_generation: package_report.package_generation,
        quarantine_count: 0,
        blocked_count: 0,
        packages: vec![RelayAlertAssuranceArchiveRestorePackageReview {
            package_id: package_report.package_id.clone(),
            package_generation: package_report.package_generation,
            package_manifest_sha256: package_report.package_manifest_sha256.clone(),
            previous_package_manifest_sha256: package_report
                .previous_package_manifest_sha256
                .clone(),
            accepted: true,
            code: "accepted".to_string(),
        }],
        checks: vec![accepted_check("restore drill accepted")],
    }
}

fn baseline_physical_drill(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    package_report_sha256: &str,
    generated_at_unix_ms: u64,
) -> RelayAlertAssurancePhysicalArchiveDrillReport {
    RelayAlertAssurancePhysicalArchiveDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: package_report.local_kernel_id.clone(),
        generated_at_unix_ms,
        evidence_id: "physical-readback-001".to_string(),
        package_id: package_report.package_id.clone(),
        package_report_sha256: package_report_sha256.to_string(),
        sampled_member_count: 1,
        checks: vec![accepted_check("physical readback accepted")],
    }
}

fn baseline_handoff(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    package_report_sha256: &str,
) -> RelayAlertAssuranceRetentionHandoffReport {
    RelayAlertAssuranceRetentionHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: package_report.local_kernel_id.clone(),
        generated_at_unix_ms: package_report.generated_at_unix_ms,
        evidence_id: "handoff-001".to_string(),
        package_id: package_report.package_id.clone(),
        package_report_sha256: package_report_sha256.to_string(),
        target_system_alias: "retention-vault".to_string(),
        ready_for_operator_handoff: true,
        checks: vec![accepted_check("retention handoff ready")],
    }
}

fn package_report_sha256(report: &RelayAlertAssuranceArchivePackageReport) -> String {
    sha256_hex(&canonical_json_bytes(report).unwrap())
}

fn accepted_check(detail: &str) -> RelayAlertCheck {
    RelayAlertCheck {
        code: "accepted".to_string(),
        accepted: true,
        detail: detail.to_string(),
    }
}
