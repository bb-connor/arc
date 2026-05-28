use super::common::{
    archive_profile_for_export, closeout_profile_for_export,
    generate_relay_alert_assurance_archive_report, generate_relay_alert_assurance_closeout_report,
    generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    generated_assurance_chain, key, relay_alert_assurance_export_bundle,
    retention_profile_for_export, sign_relay_alert_assurance_export_bundle, trusted_exporters,
    verify_relay_alert_assurance_export_bundle,
    RelayAlertAssuranceArchiveBundleCandidate,
    RelayAlertAssuranceArchiveInput, RelayAlertAssuranceCloseoutInput,
    RelayAlertAssuranceExportBuildInput, RelayAlertAssuranceRecoveryDrillInput,
    RelayAlertAssuranceReplayInput, RelayAlertAssuranceRetentionInput, NOW,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::PublicKey;
use std::{collections::BTreeSet, fs};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveRestoreNegativeCase {
    case_id: String,
    expected_code: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveRestoreNegativeCorpus {
    cases: Vec<ArchiveRestoreNegativeCase>,
}
use chio_pheromone_relay::{
    build_relay_alert_assurance_archive_extraction_report,
    generate_relay_alert_assurance_archive_restore_drill_report,
    generate_relay_alert_assurance_physical_archive_drill_report,
    generate_relay_alert_assurance_retention_handoff_report,
    sign_relay_alert_assurance_archive_package, verify_relay_alert_assurance_archive_package,
    RelayAlertAssuranceArchivePackageBuildInput, RelayAlertAssuranceArchivePackageReport,
    RelayAlertAssuranceArchivePackageVerifyInput, RelayAlertAssuranceArchiveRestoreDrillInput,
    RelayAlertAssuranceArchiveRestoreProfileDocument,
    RelayAlertAssurancePhysicalArchiveDrillInput, RelayAlertAssurancePhysicalArchiveEvidence,
    RelayAlertAssuranceRetentionHandoffEvidence, RelayAlertAssuranceRetentionHandoffInput,
    RelayAlertAssuranceRetentionHandoffProfileDocument,
    RelayAlertAssuranceRetentionHandoffReport, RelayAlertAssuranceTrustedArchivePackager,
    RelayAlertAssuranceTrustedArchivePackagersDocument, RelayAlertCheck,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA,
};

#[test]
fn relay_alert_assurance_archive_verifies_before_closeout_review() {
    let (bundle, exporter) =
        relay_alert_assurance_export_bundle(93, "relay-alert-assurance-export-archive-001");
    let candidate = RelayAlertAssuranceArchiveBundleCandidate {
        bundle_path: "exports/relay-alert-assurance-export-archive-001".to_string(),
        bundle: Some(bundle),
        error_code: None,
        error_detail: None,
    };
    let trusted = trusted_exporters(exporter.public_key());
    let archive = generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
        bundles: std::slice::from_ref(&candidate),
        trusted_exporters: &trusted,
        archive_profile: &archive_profile_for_export(),
        retention_profile: &retention_profile_for_export(),
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();

    assert_eq!(
        archive.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA
    );
    assert!(archive.accepted);
    assert_eq!(archive.archive_ready_count, 1);
    assert_eq!(archive.quarantine_count, 0);
    assert_eq!(archive.legal_hold_count, 1);
    assert_eq!(archive.reviews[0].state, "archive_ready");
    assert!(archive.reviews[0].trusted_exporter_verified);
    assert!(archive.reviews[0].replay_matched);
    assert!(archive.reviews[0].recovery_drill_accepted);

    let closeout =
        generate_relay_alert_assurance_closeout_report(RelayAlertAssuranceCloseoutInput {
            bundles: &[candidate],
            trusted_exporters: &trusted,
            closeout_profile: &closeout_profile_for_export(),
            retention_profile: &retention_profile_for_export(),
            now_unix_ms: NOW + 100_000,
        })
        .unwrap();
    assert_eq!(
        closeout.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA
    );
    assert!(!closeout.accepted);
    assert_eq!(closeout.closeout_blocked_count, 1);
    assert_eq!(closeout.reviews[0].state, "closeout_blocked");
    assert_eq!(closeout.reviews[0].code, "legal_hold_blocked");
}

#[test]
fn relay_alert_assurance_archive_quarantines_bad_bundle_without_aborting_batch() {
    let (bundle, _exporter) =
        relay_alert_assurance_export_bundle(94, "relay-alert-assurance-export-archive-002");
    let candidate = RelayAlertAssuranceArchiveBundleCandidate {
        bundle_path: "exports/relay-alert-assurance-export-archive-002".to_string(),
        bundle: Some(bundle),
        error_code: None,
        error_detail: None,
    };
    let untrusted = trusted_exporters(key(95).public_key());

    let archive = generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
        bundles: &[candidate],
        trusted_exporters: &untrusted,
        archive_profile: &archive_profile_for_export(),
        retention_profile: &retention_profile_for_export(),
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();

    assert!(!archive.accepted);
    assert_eq!(archive.archive_ready_count, 0);
    assert_eq!(archive.quarantine_count, 1);
    assert_eq!(archive.reviews[0].state, "quarantine");
    assert_eq!(archive.reviews[0].code, "signature_invalid");
    assert!(!archive.reviews[0].trusted_exporter_verified);
}

#[test]
fn relay_alert_assurance_export_signs_verifies_replays_and_plans_retention() {
    let chain = generated_assurance_chain();
    let exporter = key(91);
    let bundle = sign_relay_alert_assurance_export_bundle(RelayAlertAssuranceExportBuildInput {
        bundle_id: "relay-alert-assurance-export-001",
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

    assert_eq!(
        bundle.manifest.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA
    );
    assert_eq!(
        bundle.report.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA
    );
    assert!(bundle.report.accepted);
    assert!(bundle
        .manifest
        .body
        .artifacts
        .iter()
        .any(|artifact| artifact.role == "assurance_package"));
    assert!(bundle
        .manifest
        .body
        .artifacts
        .iter()
        .all(|artifact| !artifact.path.starts_with('/')));

    let trusted = trusted_exporters(exporter.public_key());
    let verify =
        verify_relay_alert_assurance_export_bundle(&bundle, &trusted, NOW + 100_000).unwrap();
    assert!(verify.accepted);

    let replay = generate_relay_alert_assurance_replay_report(RelayAlertAssuranceReplayInput {
        bundle: &bundle,
        trusted_exporters: &trusted,
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();
    assert_eq!(
        replay.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA
    );
    assert!(replay.accepted);
    assert_eq!(replay.replayed_package_sha256, replay.source_package_sha256);

    let retention =
        generate_relay_alert_assurance_retention_report(RelayAlertAssuranceRetentionInput {
            bundles: std::slice::from_ref(&bundle),
            retention_profile: &retention_profile_for_export(),
            now_unix_ms: NOW + 100_000,
        })
        .unwrap();
    assert_eq!(
        retention.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA
    );
    assert!(retention.accepted);
    assert!(retention
        .entries
        .iter()
        .any(|entry| entry.state == "blocked" && entry.artifact_role == "assurance_package"));

    let drill = generate_relay_alert_assurance_recovery_drill_report(
        RelayAlertAssuranceRecoveryDrillInput {
            bundle: &bundle,
            trusted_exporters: &trusted,
            case_id: "all",
            now_unix_ms: NOW + 100_000,
        },
    )
    .unwrap();
    assert_eq!(
        drill.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA
    );
    assert!(drill.accepted);
    assert!(drill
        .drills
        .iter()
        .any(|entry| entry.case_id == "bad_export_signature"));
}

#[test]
fn relay_alert_assurance_export_rejects_unsafe_or_untrusted_bundles() {
    let chain = generated_assurance_chain();
    let exporter = key(92);
    let bundle = sign_relay_alert_assurance_export_bundle(RelayAlertAssuranceExportBuildInput {
        bundle_id: "relay-alert-assurance-export-002",
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

    let unknown = trusted_exporters(key(99).public_key());
    let err =
        verify_relay_alert_assurance_export_bundle(&bundle, &unknown, NOW + 100_000).unwrap_err();
    assert_eq!(err.code(), "signature_invalid");

    let mut tampered = bundle.clone();
    tampered.files[0].bytes.push(b'\n');
    let err = verify_relay_alert_assurance_export_bundle(
        &tampered,
        &trusted_exporters(exporter.public_key()),
        NOW + 100_000,
    )
    .unwrap_err();
    assert_eq!(err.code(), "body_hash_mismatch");

    let mut unsafe_path = bundle.clone();
    unsafe_path.files[0].path = "../escape.json".to_string();
    let err = verify_relay_alert_assurance_export_bundle(
        &unsafe_path,
        &trusted_exporters(exporter.public_key()),
        NOW + 100_000,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");
}

#[test]
fn relay_alert_assurance_archive_package_binds_source_reports_and_members() {
    let (bundle, exporter) =
        relay_alert_assurance_export_bundle(96, "relay-alert-assurance-export-package-001");
    let candidate = RelayAlertAssuranceArchiveBundleCandidate {
        bundle_path: "exports/relay-alert-assurance-export-package-001".to_string(),
        bundle: Some(bundle),
        error_code: None,
        error_detail: None,
    };
    let trusted = trusted_exporters(exporter.public_key());
    let archive = generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
        bundles: std::slice::from_ref(&candidate),
        trusted_exporters: &trusted,
        archive_profile: &archive_profile_for_export(),
        retention_profile: &retention_profile_for_export(),
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();
    let mut closeout_profile = closeout_profile_for_export();
    closeout_profile.block_legal_hold = false;
    let closeout =
        generate_relay_alert_assurance_closeout_report(RelayAlertAssuranceCloseoutInput {
            bundles: std::slice::from_ref(&candidate),
            trusted_exporters: &trusted,
            closeout_profile: &closeout_profile,
            retention_profile: &retention_profile_for_export(),
            now_unix_ms: NOW + 100_000,
        })
        .unwrap();
    assert!(closeout.accepted);

    let packager = key(97);
    let package =
        sign_relay_alert_assurance_archive_package(RelayAlertAssuranceArchivePackageBuildInput {
            package_id: "relay-alert-archive-package-001",
            packager_id: "relay-archive-packager",
            packager_key_id: "relay-archive-key-1",
            package_generation: 1,
            previous_package_report: None,
            signing_key: &packager,
            bundles: std::slice::from_ref(&candidate),
            trusted_exporters: &trusted,
            archive_report: &archive,
            closeout_report: &closeout,
            created_at_unix_ms: NOW + 110_000,
        })
        .unwrap();
    let manifest_json = serde_json::to_value(&package.manifest).unwrap();
    assert_eq!(manifest_json["body"]["packageGeneration"], 1);

    let report = verify_relay_alert_assurance_archive_package(
        RelayAlertAssuranceArchivePackageVerifyInput {
            package: &package,
            trusted_packagers: &trusted_archive_packagers(packager.public_key()),
            trusted_exporters: &trusted,
            archive_report: &archive,
            closeout_report: &closeout,
            now_unix_ms: NOW + 120_000,
        },
    )
    .unwrap();
    assert!(report.accepted);
    assert!(report.source_reports_matched);
    assert!(report.closeout_ready_verified);
    assert!(report.total_byte_count_matched);
    assert_eq!(
        report.package_total_byte_count,
        package_file_bytes(&package)
    );

    let extraction = build_relay_alert_assurance_archive_extraction_report(
        &report,
        package.files.len() as u64,
        NOW + 130_000,
    )
    .unwrap();
    assert!(extraction.accepted);

    let mut mismatched_bundle_package = package.clone();
    mismatched_bundle_package.manifest.body.bundles[0].artifact_count += 1;
    let (signature, _) = packager
        .sign_canonical(&mismatched_bundle_package.manifest.body)
        .unwrap();
    mismatched_bundle_package.manifest.signature = signature;
    let err = verify_relay_alert_assurance_archive_package(
        RelayAlertAssuranceArchivePackageVerifyInput {
            package: &mismatched_bundle_package,
            trusted_packagers: &trusted_archive_packagers(packager.public_key()),
            trusted_exporters: &trusted,
            archive_report: &archive,
            closeout_report: &closeout,
            now_unix_ms: NOW + 120_000,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("archive report review"));

    let mut outside_package = package.clone();
    outside_package.manifest.body.members[0].path =
        format!("outside/{}", outside_package.manifest.body.members[0].path);
    outside_package.files[0].path = outside_package.manifest.body.members[0].path.clone();
    let (signature, _) = packager
        .sign_canonical(&outside_package.manifest.body)
        .unwrap();
    outside_package.manifest.signature = signature;
    let err = verify_relay_alert_assurance_archive_package(
        RelayAlertAssuranceArchivePackageVerifyInput {
            package: &outside_package,
            trusted_packagers: &trusted_archive_packagers(packager.public_key()),
            trusted_exporters: &trusted,
            archive_report: &archive,
            closeout_report: &closeout,
            now_unix_ms: NOW + 120_000,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("outside verified bundle"));
}

#[test]
fn relay_alert_assurance_archive_drill_evidence_binds_package_report_identity() {
    let report = archive_package_report_for_evidence();
    let report_sha256 = sha256_hex(&canonical_json_bytes(&report).unwrap());
    let physical = RelayAlertAssurancePhysicalArchiveEvidence {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA.to_string(),
        local_kernel_id: report.local_kernel_id.clone(),
        evidence_id: "physical-readback-001".to_string(),
        package_id: report.package_id.clone(),
        package_report_sha256: report_sha256.clone(),
        package_manifest_sha256: report.package_manifest_sha256.clone(),
        observed_at_unix_ms: NOW + 10_000,
        sampled_member_count: 1,
        media_alias: "offline-vault-1".to_string(),
        claims: vec!["local_archive_package_only".to_string()],
    };
    let drill = generate_relay_alert_assurance_physical_archive_drill_report(
        RelayAlertAssurancePhysicalArchiveDrillInput {
            evidence: &physical,
            expected_package_id: &report.package_id,
            expected_package_report_sha256: &report_sha256,
            expected_package_manifest_sha256: &report.package_manifest_sha256,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap();
    assert!(drill.accepted);

    let mut forged_physical = physical.clone();
    forged_physical.package_manifest_sha256 = "f".repeat(64);
    let err = generate_relay_alert_assurance_physical_archive_drill_report(
        RelayAlertAssurancePhysicalArchiveDrillInput {
            evidence: &forged_physical,
            expected_package_id: &report.package_id,
            expected_package_report_sha256: &report_sha256,
            expected_package_manifest_sha256: &report.package_manifest_sha256,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("package manifest hash mismatch"));

    let handoff_profile = RelayAlertAssuranceRetentionHandoffProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA.to_string(),
        local_kernel_id: report.local_kernel_id.clone(),
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 60_000,
        allowed_system_aliases: vec!["external-retention-1".to_string()],
    };
    let handoff = RelayAlertAssuranceRetentionHandoffEvidence {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA.to_string(),
        local_kernel_id: report.local_kernel_id.clone(),
        evidence_id: "handoff-001".to_string(),
        package_id: report.package_id.clone(),
        package_report_sha256: report_sha256.clone(),
        target_system_alias: "external-retention-1".to_string(),
        observed_at_unix_ms: NOW + 10_000,
        claims: vec!["operator_managed_handoff".to_string()],
    };
    let handoff_report = generate_relay_alert_assurance_retention_handoff_report(
        RelayAlertAssuranceRetentionHandoffInput {
            evidence: &handoff,
            profile: &handoff_profile,
            expected_package_id: &report.package_id,
            expected_package_report_sha256: &report_sha256,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap();
    assert!(handoff_report.ready_for_operator_handoff);

    let mut forged_handoff = handoff;
    forged_handoff.package_id = "other-package".to_string();
    let err = generate_relay_alert_assurance_retention_handoff_report(
        RelayAlertAssuranceRetentionHandoffInput {
            evidence: &forged_handoff,
            profile: &handoff_profile,
            expected_package_id: &report.package_id,
            expected_package_report_sha256: &report_sha256,
            now_unix_ms: NOW + 20_000,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("package id mismatch"));
}

fn trusted_archive_packagers(
    public_key: PublicKey,
) -> RelayAlertAssuranceTrustedArchivePackagersDocument {
    RelayAlertAssuranceTrustedArchivePackagersDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        min_created_at_unix_ms: NOW,
        packagers: vec![RelayAlertAssuranceTrustedArchivePackager {
            packager_id: "relay-archive-packager".to_string(),
            key_id: "relay-archive-key-1".to_string(),
            public_key,
            valid_from_unix_ms: NOW,
            valid_until_unix_ms: NOW + 900_000,
            status: "active".to_string(),
        }],
    }
}

fn package_file_bytes(package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage) -> u64 {
    package
        .files
        .iter()
        .map(|file| file.bytes.len() as u64)
        .sum()
}

fn archive_package_report_for_evidence() -> RelayAlertAssuranceArchivePackageReport {
    RelayAlertAssuranceArchivePackageReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA
            .to_string(),
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
fn relay_alert_assurance_archive_restore_drill_accepts_continuous_generation() {
    let profile = restore_profile_for_drill();
    let gen1 = valid_restore_package_report(
        "relay-alert-archive-package-001",
        1,
        "1111111111111111111111111111111111111111111111111111111111111111",
        None,
    );
    let gen1_manifest = gen1.package_manifest_sha256.clone();
    let gen2 = valid_restore_package_report(
        "relay-alert-archive-package-002",
        2,
        "2222222222222222222222222222222222222222222222222222222222222222",
        Some(gen1_manifest),
    );
    let physical = [
        matching_physical_drill(&gen1),
        matching_physical_drill(&gen2),
    ];
    let handoff = [
        matching_retention_handoff(&gen1),
        matching_retention_handoff(&gen2),
    ];
    let report = generate_relay_alert_assurance_archive_restore_drill_report(
        RelayAlertAssuranceArchiveRestoreDrillInput {
            package_reports: &[gen1, gen2],
            physical_drill_reports: &physical,
            retention_handoff_reports: &handoff,
            restore_profile: &profile,
            now_unix_ms: NOW + 100_000,
        },
    )
    .unwrap();

    assert_eq!(
        report.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA
    );
    assert!(report.accepted);
    assert_eq!(report.code, "accepted");
    assert_eq!(report.package_count, 2);
    assert_eq!(report.latest_package_generation, 2);
}

#[test]
fn relay_alert_assurance_archive_restore_negative_corpus_cases_are_executable() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance/",
        "relay-alert-assurance-archive-restore-negative-cases.json"
    );
    let corpus: ArchiveRestoreNegativeCorpus =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let mut seen = BTreeSet::new();
    for case in &corpus.cases {
        assert!(seen.insert(case.case_id.as_str()), "duplicate case {}", case.case_id);
        if case.case_id == "wrong_expected_code" {
            let observed = restore_drill_code("generation_gap");
            assert_eq!(observed, "restore_blocked");
            assert_eq!(case.expected_code, "negative_corpus_mismatch");
            continue;
        }
        let observed = restore_drill_code(&case.case_id);
        assert_eq!(
            observed, case.expected_code,
            "negative case {} expected {} but observed {}",
            case.case_id, case.expected_code, observed
        );
    }
    for required in [
        "generation_gap",
        "duplicate_generation",
        "previous_hash_mismatch",
        "missing_readback",
        "retention_handoff_not_ready",
        "wrong_expected_code",
    ] {
        assert!(seen.contains(required), "missing negative case {required}");
    }
}

fn restore_drill_code(case_id: &str) -> String {
    let profile = restore_profile_for_drill();
    let gen1_manifest = "1111111111111111111111111111111111111111111111111111111111111111";
    let gen1 = valid_restore_package_report(
        "relay-alert-archive-package-001",
        1,
        gen1_manifest,
        None,
    );
    let gen1_physical = matching_physical_drill(&gen1);
    let gen1_handoff = matching_retention_handoff(&gen1);

    let (package_reports, physical, handoff) = match case_id {
        "generation_gap" => {
            let gen3 = valid_restore_package_report(
                "relay-alert-archive-package-003",
                3,
                "3333333333333333333333333333333333333333333333333333333333333333",
                Some("2222222222222222222222222222222222222222222222222222222222222222".to_string()),
            );
            let gen3_physical = matching_physical_drill(&gen3);
            let gen3_handoff = matching_retention_handoff(&gen3);
            (
                vec![gen1, gen3],
                vec![gen1_physical, gen3_physical],
                vec![gen1_handoff, gen3_handoff],
            )
        }
        "duplicate_generation" => {
            let duplicate = valid_restore_package_report(
                "relay-alert-archive-package-001b",
                1,
                "4444444444444444444444444444444444444444444444444444444444444444",
                None,
            );
            let duplicate_physical = matching_physical_drill(&duplicate);
            let duplicate_handoff = matching_retention_handoff(&duplicate);
            (
                vec![gen1, duplicate],
                vec![gen1_physical, duplicate_physical],
                vec![gen1_handoff, duplicate_handoff],
            )
        }
        "previous_hash_mismatch" => {
            let gen2 = valid_restore_package_report(
                "relay-alert-archive-package-002",
                2,
                "2222222222222222222222222222222222222222222222222222222222222222",
                Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            );
            let gen2_physical = matching_physical_drill(&gen2);
            let gen2_handoff = matching_retention_handoff(&gen2);
            (
                vec![gen1, gen2],
                vec![gen1_physical, gen2_physical],
                vec![gen1_handoff, gen2_handoff],
            )
        }
        "missing_readback" => (vec![gen1], Vec::new(), vec![gen1_handoff]),
        "retention_handoff_not_ready" => {
            (vec![gen1], vec![gen1_physical], Vec::new())
        }
        other => panic!("unsupported archive restore negative case {other}"),
    };

    generate_relay_alert_assurance_archive_restore_drill_report(
        RelayAlertAssuranceArchiveRestoreDrillInput {
            package_reports: &package_reports,
            physical_drill_reports: &physical,
            retention_handoff_reports: &handoff,
            restore_profile: &profile,
            now_unix_ms: NOW + 100_000,
        },
    )
    .expect("restore drill negative corpus cases should produce a report")
    .code
}

fn restore_profile_for_drill() -> RelayAlertAssuranceArchiveRestoreProfileDocument {
    RelayAlertAssuranceArchiveRestoreProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        profile_id: "relay-archive-restore-profile".to_string(),
        max_package_count: 8,
        require_generation_continuity: true,
        require_physical_readback: true,
        require_retention_handoff_ready: true,
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 900_000,
    }
}

fn valid_restore_package_report(
    package_id: &str,
    generation: u64,
    manifest_sha256: &str,
    previous_manifest_sha256: Option<String>,
) -> RelayAlertAssuranceArchivePackageReport {
    RelayAlertAssuranceArchivePackageReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW + 10_000,
        package_id: package_id.to_string(),
        package_generation: generation,
        previous_package_manifest_sha256: previous_manifest_sha256,
        package_manifest_sha256: manifest_sha256.to_string(),
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
        checks: vec![RelayAlertCheck {
            code: "accepted".to_string(),
            accepted: true,
            detail: "package report verified".to_string(),
        }],
    }
}

fn matching_physical_drill(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveDrillReport {
    let report_sha256 = sha256_hex(&canonical_json_bytes(report).unwrap());
    chio_pheromone_relay::RelayAlertAssurancePhysicalArchiveDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: report.local_kernel_id.clone(),
        generated_at_unix_ms: NOW + 20_000,
        evidence_id: format!("physical-readback-{}", report.package_id),
        package_id: report.package_id.clone(),
        package_report_sha256: report_sha256,
        sampled_member_count: 1,
        checks: vec![RelayAlertCheck {
            code: "local_readback_evidence".to_string(),
            accepted: true,
            detail: "operator-provided local readback evidence is hash-bound to package report"
                .to_string(),
        }],
    }
}

fn matching_retention_handoff(
    report: &RelayAlertAssuranceArchivePackageReport,
) -> RelayAlertAssuranceRetentionHandoffReport {
    let report_sha256 = sha256_hex(&canonical_json_bytes(report).unwrap());
    RelayAlertAssuranceRetentionHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: report.local_kernel_id.clone(),
        generated_at_unix_ms: NOW + 20_000,
        evidence_id: format!("handoff-{}", report.package_id),
        package_id: report.package_id.clone(),
        package_report_sha256: report_sha256,
        target_system_alias: "external-retention-1".to_string(),
        ready_for_operator_handoff: true,
        checks: vec![RelayAlertCheck {
            code: "accepted".to_string(),
            accepted: true,
            detail: "retention handoff evidence is hash-bound to package report".to_string(),
        }],
    }
}
