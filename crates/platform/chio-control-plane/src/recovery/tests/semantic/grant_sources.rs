//! Native disclosure authority must cover every verified semantic restriction.
use super::*;
use chio_core_types::SignedDeclassificationGrant;
use chio_flow::{canonical_request_hash, information_label_hash};
use chio_security_types::ports::{CanonicalBody, DestinationId, GrantId};
use chio_security_types::{DeclassificationGrantBody, DeclassificationGrantClaims};

async fn exercise_native_semantic_source_grant(additional_restriction: bool) -> TestResult {
    let f = native_fixture("annotated-disclosure")?;
    let (runtime, mut request, mut p) = prepare(
        &f,
        "native-semantic-source-grant",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    assert_eq!(
        p.invocation.audience.body().audience,
        InformationLabel::bottom()
    );
    assert_eq!(p.invocation.endorsements.as_slice().len(), 0);
    let restriction = if additional_restriction {
        InformationLabel::try_known(
            Default::default(),
            std::iter::once(
                "semantic-only-private".parse::<chio_security_types::flow::Compartment>()?,
            )
            .collect(),
        )?
    } else {
        InformationLabel::bottom()
    };
    let answer = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: p.plan.scope.clone(),
            input: p.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: restriction.clone(),
            externally_influenced: false,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10_000)?,
            issued_at_unix_ms: p.invocation.action.issued_at_unix_ms,
            valid_until_unix_ms: p.invocation.action.valid_until_unix_ms,
        },
        &p.annotator,
    )?;
    f.authority
        .admission_operation_store()
        .install_semantic_annotation(&answer)?;
    p.invocation.action.source_label = p
        .invocation
        .action
        .source_label
        .join_restrictions(&restriction)?;
    p.invocation.action.influence = chio_semantic_contracts::semantic_annotated_influence(
        p.invocation.action.influence,
        std::slice::from_ref(&answer),
    )?;
    p.invocation.annotations = BoundedList::new(vec![answer])?;
    request.arguments = serde_json::to_value(&p.invocation)?;
    let context = f.process.recovery_security_context("root")?;
    let key = context.as_v1();
    let now = now_ms()? / 1000;
    let authority = super::super::authority_history::fixture_aggregate_key(&f.path);
    let grant = SignedDeclassificationGrant::sign(
        DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("native-semantic-source-grant")?,
            capability_id: RecordId::new(&request.capability.id)?,
            tenant_id: key.tenant_id().clone(),
            subject_id: key.principal_id().clone(),
            agent_id: RecordId::new(&request.agent_id)?,
            session_id: key.session_id().clone(),
            source_label_hash: information_label_hash(&restricted_label())?,
            target_label: InformationLabel::bottom(),
            destination_id: DestinationId::new(&request.server_id)?,
            tool_name: RecordId::new(&request.tool_name)?,
            purpose: DeclassificationPurpose::new("approved-disclosure")?,
            request_hash: canonical_request_hash(&CanonicalBody::new(
                chio_core::canonical_json_bytes(&request.arguments)?,
            )?)?,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now.checked_add(300).ok_or("grant expiry overflow")?,
            authority_key_id: RecordId::new("aggregate")?,
        })?,
        &authority,
    )?;
    assert!(grant.verify_signature()?);
    request.declassification_grant = Some(grant.into());
    let result = runtime
        .execute_step(&f.process, "root", "native-semantic-source-grant", &request)
        .await;
    if additional_restriction {
        assert!(
            result.is_err() || result.as_ref().is_ok_and(|response| response.verdict == Verdict::Deny),
            "native disclosure of the base source cannot waive an additional selected semantic restriction: {result:?}"
        );
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    } else {
        let response = result?;
        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(f.effects.load(Ordering::SeqCst), 1);
        let store = f.authority.admission_operation_store();
        let (operation, original) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &request.request_id)?,
                &f.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("native semantic grant control original absent")?;
        original.validate_request_material(&request)?;
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert!(operation.native_dispatch_ledger_digest().is_some());
        let (_, egress) = store
            .load_native_security_egress(
                operation.binding().operation_id(),
                &f.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("native semantic grant control egress absent")?;
        assert!(egress
            .ok_or("native semantic grant control egress")?
            .commitment
            .ok_or("native semantic grant control commitment")?
            .declassification
            .is_some());
    }
    Ok(())
}

#[tokio::test]
async fn native_disclosure_grant_preserves_a_coherent_semantic_source_control() -> TestResult {
    exercise_native_semantic_source_grant(false).await
}

#[tokio::test]
async fn native_disclosure_grant_cannot_waive_a_stronger_selected_semantic_source() -> TestResult {
    exercise_native_semantic_source_grant(true).await
}
