use super::*;
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn authority_fixture() -> TestResult<(tempfile::TempDir, crate::SqliteAuthorityStore)> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("authority.db");
    let locks = directory.path().join("locks");
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&locks)?;
    crate::SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = crate::SqliteAuthorityStore::open_serving(&database, &locks)?;
    Ok((directory, authority))
}

fn capture_root() -> TestResult<Option<std::path::PathBuf>> {
    let Some(path) = std::env::var_os("CHIO_RECOVERY_PRODUCT_VIEW_CAPTURE_ROOT") else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() {
        return Err("product capture requires an absolute target path".into());
    }
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target")
        .canonicalize()?;
    let parent = path
        .parent()
        .ok_or("product capture parent")?
        .canonicalize()?;
    if !parent.starts_with(&target) {
        return Err("product capture must remain in the workspace target directory".into());
    }
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("product capture requires a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("product capture directory must be owner-only".into());
        }
    }
    let path = path.canonicalize()?;
    if !path.starts_with(target) {
        return Err("product capture target escaped".into());
    }
    Ok(Some(path))
}

fn capture_file(root: &std::path::Path, name: &str, bytes: &[u8]) -> TestResult {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn scope() -> TestResult<RecoveryScopeV1> {
    Ok(RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new("projection-authority")?,
        tenant_id: RecoveryTenantId::new("projection-tenant")?,
        process_id: ProcessId::new("projection-process")?,
    })
}

fn label(owners: usize) -> TestResult<InformationLabel> {
    let shared = (0..255)
        .map(|index| PrincipalId::new(format!("reader-{index:03}-{:\"<245}", "")))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut policies = BTreeMap::new();
    for index in 0..owners {
        let owner = PrincipalId::new(format!("owner-{index:03}"))?;
        let mut readers = shared.clone();
        readers.insert(owner.clone());
        policies.insert(owner, readers);
    }
    Ok(InformationLabel::try_known(policies, BTreeSet::new())?)
}

fn report(label: InformationLabel) -> TestResult<StoredDecisionReportV1> {
    let report = DecisionReportV1 {
        domain_version: VersionV1,
        scope: scope()?,
        workflow_id: WorkflowId::new("projection-workflow")?,
        expected_revision: SafeInteger::new(1)?,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("bounded report")?,
        desired_outcome: ProtectedText::new("review the retained decision")?,
        attachments: BoundedList::new(vec![])?,
    };
    let digest = CommandDigest::from_bytes(hash(RecoveryDigestDomain::DecisionReport, &report)?);
    Ok(StoredDecisionReportV1 {
        id: EvidenceRef::new("projection-report")?,
        digest,
        report,
        reporter: PrincipalId::new("projection-reporter")?,
        reporter_subject: chio_core::Keypair::from_seed(&[91; 32]).public_key(),
        label,
        influence: ArtifactInfluenceV1 {
            commitment: CanonicalPayloadDigest::from_bytes(*digest.as_bytes()),
            externally_influenced: true,
            unknown: true,
        },
        submitted_at_unix_ms: SafeInteger::new(1_000)?,
    })
}

fn proposal(label: InformationLabel) -> TestResult<StoredPolicyMaintenanceProposalV1> {
    let trajectory = PolicyTrajectoryRefV1 {
        artifact: ArtifactVersionRefV1 {
            scope: scope()?,
            artifact: ArtifactId::new("projection-trajectory")?,
            version: ArtifactRevisionId::new("projection-trajectory-version")?,
            provenance: ProvenanceDigest::from_bytes([1; 32]),
        },
        case_id: EvidenceRef::new("projection-benign")?,
    };
    let proposal = PolicyMaintenanceProposalV1 {
        domain_version: VersionV1,
        scope: scope()?,
        proposal_id: ReviewId::new("projection-proposal")?,
        report_id: EvidenceRef::new("projection-report")?,
        base_deployment: DeploymentDigest::from_bytes([2; 32]),
        base_policy: PolicyDigest::from_bytes([3; 32]),
        target_policy: PolicyDigest::from_bytes([4; 32]),
        rationale: ProtectedText::new("independent review")?,
        affected_contracts: NonEmptyBoundedList::new(vec![SemanticPackageDigest::from_bytes(
            [5; 32],
        )])?,
        benign_trajectories: NonEmptyBoundedList::new(vec![trajectory.clone()])?,
        adversarial_trajectories: NonEmptyBoundedList::new(vec![PolicyTrajectoryRefV1 {
            case_id: EvidenceRef::new("projection-adversarial")?,
            ..trajectory
        }])?,
        expected_effects: ProtectedText::new("bounded policy change")?,
        rollback_policy: PolicyDigest::from_bytes([3; 32]),
        rollback_plan: ProtectedText::new("independent subsequent review")?,
    };
    let digest = CanonicalPayloadDigest::from_bytes(hash(
        RecoveryDigestDomain::PolicyMaintenanceProposal,
        &proposal,
    )?);
    Ok(StoredPolicyMaintenanceProposalV1 {
        proposal,
        digest,
        maintainer: PrincipalId::new("projection-maintainer")?,
        maintainer_subject: chio_core::Keypair::from_seed(&[92; 32]).public_key(),
        label,
        influence: ArtifactInfluenceV1 {
            commitment: digest,
            externally_influenced: true,
            unknown: true,
        },
        submitted_at_unix_ms: SafeInteger::new(1_000)?,
    })
}

#[test]
fn product_public_views_fit_whenever_native_record_encoding_succeeds() -> TestResult {
    let capture = capture_root()?;
    let mut captured = Vec::new();
    for owners in [0, 1, 2, 3, 4, 16, 64] {
        let label = label(owners)?;
        let report = report(label.clone())?;
        let proposal = proposal(label)?;
        let report_view = DecisionReportViewV1 {
            domain_version: VersionV1,
            id: report.id.clone(),
            digest: report.digest,
            report: report.report.clone(),
            label: report.label.clone(),
            influence: report.influence.clone(),
        };
        let proposal_view = PolicyMaintenanceViewV1 {
            domain_version: VersionV1,
            digest: proposal.digest,
            proposal: proposal.proposal.clone(),
            label: proposal.label.clone(),
            influence: proposal.influence.clone(),
        };
        let report_size = canonical_json_bytes(&report)?.len();
        let proposal_size = canonical_json_bytes(&proposal)?.len();
        let report_wire = canonical_json_bytes(&report_view)?;
        let proposal_wire = canonical_json_bytes(&proposal_view)?;
        assert!(report_wire.len() < report_size);
        assert!(proposal_wire.len() < proposal_size);
        assert_eq!(protected::encode(&report).is_ok(), report_size <= 262_144);
        assert_eq!(
            protected::encode(&proposal).is_ok(),
            proposal_size <= 262_144
        );
        if let Some(root) = &capture {
            for (kind, native_size, wire) in [
                ("report", report_size, report_wire),
                ("proposal", proposal_size, proposal_wire),
            ] {
                if native_size <= 262_144 {
                    let name = format!("{kind}-owners-{owners}.json");
                    capture_file(root, &name, &wire)?;
                    captured.push(serde_json::json!({
                        "kind": kind,
                        "owners": owners,
                        "file": name,
                        "size_bytes": wire.len(),
                        "sha256": sha256_hex(&wire),
                        "native_record_size_bytes": native_size,
                        "native_record_encoding_succeeded": true,
                    }));
                }
            }
        }
    }
    if let Some(root) = capture {
        capture_file(
            &root,
            "manifest.json",
            &canonical_json_bytes(&serde_json::json!({
                "version": 1,
                "source": "product/projection_tests.rs",
                "source_sha256": sha256_hex(include_bytes!("projection_tests.rs")),
                "artifacts": captured,
                "scope": "actual Rust canonical serialization and native record encoding; no live product intake or qualification claim",
            }))?,
        )?;
    }
    Ok(())
}

type RecoveryAccounting = (Vec<(String, String, String, i64, Vec<u8>)>, i64, i64);

/// Every retained recovery record, with the event and global-commit counts
/// that custody them.
fn recovery_accounting(connection: &rusqlite::Connection) -> TestResult<RecoveryAccounting> {
    let mut statement = connection.prepare(
        "SELECT record_key, scope_key, kind, version, payload
         FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    let records = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let (events, commits) = connection.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events),
                (SELECT count(*) FROM authority_global_commits WHERE projection_kind = 'recovery')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((records, events, commits))
}

#[test]
fn product_oversized_record_rolls_back_its_intake_reservation() -> TestResult {
    let (_directory, authority) = authority_fixture()?;
    let store: SqliteAdmissionOperationStore = authority.admission_operation_store();
    let value = report(label(4)?)?;
    assert!(canonical_json_bytes(&value)?.len() > 262_144);
    let mut connection = store.connection()?;
    let baseline = recovery_accounting(&connection)?;
    let (quota_key, _) =
        lifecycle::quota_key(&value.report.scope, lifecycle::ProductWorkKind::Report)?;
    assert!(
        !baseline.0.iter().any(|record| record.0 == quota_key),
        "the quota counter starts absent"
    );
    let tx = store.begin_write(&mut connection, None)?;
    reserve_quota(
        &tx,
        &store.serving_owner,
        &value.report.scope,
        lifecycle::ProductWorkKind::Report,
    )?;
    let reserved: i64 = tx.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key = ?1",
        [&quota_key],
        |row| row.get(0),
    )?;
    assert_eq!(
        reserved, 1,
        "the intake reservation is held before the refusal"
    );
    assert!(save(
        &tx,
        &store.serving_owner,
        &value.report.scope,
        "product-report:oversized",
        &value
    )
    .is_err());
    drop(tx);
    assert_eq!(
        recovery_accounting(&connection)?,
        baseline,
        "oversized feedback cannot commit a report, quota row, event or global commit"
    );
    Ok(())
}
