//! A transient original journal failure remains retryable at the setup boundary.
use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RetainedSetupRecord {
    key: String,
    scope_key: String,
    kind: String,
    version: i64,
    payload: Vec<u8>,
    native_namespace: Option<String>,
    native_request: Option<String>,
}

pub(super) fn retained_setup_records(f: &KnowledgeFixture) -> TestResult<Vec<RetainedSetupRecord>> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut statement = connection.prepare(
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request \
         FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RetainedSetupRecord {
            key: row.get(0)?,
            scope_key: row.get(1)?,
            kind: row.get(2)?,
            version: row.get(3)?,
            payload: row.get(4)?,
            native_namespace: row.get(5)?,
            native_request: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

#[tokio::test]
async fn setup_original_journal_unavailability_is_retryable_without_a_selection_or_charge(
) -> TestResult {
    use chio_kernel::admission_operation::AdmissionOperationStoreError;
    use chio_kernel::recovery::{RecoveryOriginalRequestError, RecoveryProcessOriginPort};

    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let original = Box::pin(f.f.denied_seed_named("setup-journal-original")).await?;
    require_eligible_original(&f, &original)?;
    let selected = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    f.runtime
        .validate_setup_binding(f.f.runtime.scope(), &selected.native_authority)?;
    f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Create,
    )?;
    let create = f.f.command(
        "setup-journal-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("setup-journal-original")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&original)?,
        },
    )?;
    let before = retained_setup_records(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let original_path = f.f.path.join("process.db");
    let unavailable_path = f.f.path.join("temporarily-unavailable-process.db");
    let original_bytes = std::fs::read(&original_path)?;
    #[cfg(unix)]
    let original_identity = {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&original_path)?;
        (metadata.dev(), metadata.ino())
    };
    std::fs::rename(&original_path, &unavailable_path)?;
    // Check the exact owning failure before the public facade. Existing broker
    // bindings are still current; no grant, native row or process byte changes.
    let raw = f.f.process.original_request_scope(
        f.f.runtime.scope(),
        &original,
        selected.security_context.as_v1().session_id().as_str(),
    );
    let mediator = f
        .runtime
        .validate_setup_binding(f.f.runtime.scope(), &selected.native_authority);
    // The broker and origin selector share this physical journal. Losing the
    // path is an operational failure for both; the public facade must still
    // project that real failure without calling it an authority denial.
    let result = RecoverySetupService::for_creation(
        RecoverySetupHost {
            runtime: f.f.runtime.clone(),
            store: Arc::new(f.f.authority.admission_operation_store()),
            fence: f.f.authority.mutation_fence(),
            knowledge: Some(Arc::new(f.runtime.clone())),
            operator: Keypair::from_seed(&[211; 32]),
        },
        &f.f.control,
        &create,
    )
    .await;
    // Restore the same file before any assertion or retry. The independently
    // opened journal keeps its inode and cannot be replaced with a donor.
    std::fs::rename(&unavailable_path, &original_path)?;
    assert!(
        matches!(mediator, Err(chio_kernel::KernelError::DurableAdmission(_))),
        "the actual broker must observe the same unavailable journal",
    );
    assert!(matches!(
        raw,
        Err(RecoveryOriginalRequestError::Store(
            AdmissionOperationStoreError::Unavailable(_)
        ))
    ));
    assert_eq!(std::fs::read(&original_path)?, original_bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&original_path)?;
        assert_eq!((metadata.dev(), metadata.ino()), original_identity);
    }
    assert_eq!(retained_setup_records(&f)?, before);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(
        result.err(),
        Some(crate::recovery::RecoveryRuntimeError::Unavailable),
        "original journal infrastructure must not be projected as a permanent authority denial"
    );
    require_eligible_original(&f, &original)?;
    f.runtime
        .validate_setup_binding(f.f.runtime.scope(), &selected.native_authority)?;
    let service = RecoverySetupService::for_creation(
        RecoverySetupHost {
            runtime: f.f.runtime.clone(),
            store: Arc::new(f.f.authority.admission_operation_store()),
            fence: f.f.authority.mutation_fence(),
            knowledge: Some(Arc::new(f.runtime.clone())),
            operator: Keypair::from_seed(&[211; 32]),
        },
        &f.f.control,
        &create,
    )
    .await?;
    let retained = f.f.record(service.workflow())?;
    assert!(retained.origin.is_some() && retained.process_reservation.is_some());
    assert!(!retained.captured && retained.native_link.is_none());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls + 1);
    Ok(())
}
