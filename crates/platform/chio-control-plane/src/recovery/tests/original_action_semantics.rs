//! Real native original closure feeds the public action materializer.
use super::*;
use chio_core_types::recovery::RecoveryDigestDomain;
use chio_kernel::tool_outcome::ToolOutcomeStore;

#[tokio::test]
async fn recovery_materialized_original_action_separates_its_semantic_request_domain() -> TestResult
{
    let fixture = RecoveryFixture::new(false)?;
    let key = "semantic-domain-original";
    let seed = fixture.process.tool_request(
        fixture.runtime.scope().process_id.as_str(),
        key,
        &fixture.seed.server_id,
        &fixture.seed.tool_name,
        fixture.seed.arguments.clone(),
    )?;
    let denial = Box::pin(fixture.process.invoke_known_only(
        fixture.runtime.scope().process_id.as_str(),
        key,
        &seed,
    ))
    .await?;
    assert_eq!(denial.verdict, Verdict::Deny);
    assert!(denial.receipt.verify_signature()?);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &seed.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("actual denied original request absent")?;
    original.validate_request_material(&seed)?;
    let deployment = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    original.validate_native_security_authority(&deployment.native_authority)?;
    original.validate_native_security_context(&deployment.security_context)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(fixture
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .is_none());
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    let original_bytes = chio_core::canonical_json_bytes(&operation.to_persisted())?;

    let created = fixture
        .execute(
            "create-semantic-domain-original",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new(key)?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )
        .await?;
    let record = fixture.record(&created.status.workflow_id)?;
    let action = record
        .action
        .as_ref()
        .ok_or("actual materialized action absent")?;
    let origin = record
        .origin
        .as_ref()
        .ok_or("actual original closure absent")?;
    assert_eq!(action.origin.as_ref(), Some(origin));
    assert_eq!(
        origin.operation.operation_id().as_str(),
        operation.binding().operation_id().as_str()
    );
    let mut continuation_request = record.seed.clone();
    continuation_request.request_id = fixture.process.request_id(
        fixture.runtime.scope().process_id.as_str(),
        &crate::recovery::materialize::operation_key(&record.continuation_id),
    )?;
    assert_eq!(action.request_id.as_str(), continuation_request.request_id);
    assert_eq!(
        action.capability_id.as_str(),
        continuation_request.capability.id
    );
    let canonical = continuation_request
        .recovery_review_projection()
        .canonical_semantics()?;
    let expected = RecoveryDigestDomain::SemanticNativeRequestSemantics.digest(&canonical);
    let other_contract = RecoveryDigestDomain::SemanticContent.digest(&canonical);
    let undomained = chio_core::sha256(canonical.as_bytes());
    assert_ne!(expected, other_contract);
    assert_ne!(expected.as_bytes(), undomained.as_bytes());

    let current = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("original operation disappeared during materialization")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&current.to_persisted())?,
        original_bytes
    );
    assert!(record.native_link.is_none());
    assert!(!record.captured);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    eprintln!(
        "RECOVERY_ORIGINAL_ACTION_SEMANTIC_DOMAIN {}",
        serde_json::json!({
            "original_operation": operation.binding().operation_id().as_str(),
            "original_version": operation.version(),
            "workflow": record.workflow_id.as_str(),
            "action_wire_version": serde_json::to_value(action)?["version"],
            "source_generation": action.source_generation.get(),
            "actual_semantic_request": action.semantic_request,
            "actual_matches_undomained_sha": action.semantic_request.as_bytes() == undomained.as_bytes(),
            "canonical_semantics_sha256": chio_core::sha256_hex(canonical.as_bytes()),
            "canonical_semantics_bytes": canonical.as_bytes().len(),
            "expected_registered_domain": RecoveryDigestDomain::SemanticNativeRequestSemantics.name(),
            "original_unchanged": true,
            "provider_effects": 0,
        })
    );
    assert_eq!(
        action.semantic_request.as_bytes(),
        expected.as_bytes(),
        "the actual fresh original-action producer omitted its registered semantic domain"
    );
    Ok(())
}
