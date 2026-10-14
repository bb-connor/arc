//! Real immutable product sources own artifact retention independently.
use super::*;

#[tokio::test]
async fn policy_report_evidence_owner_is_anchored_to_its_real_immutable_source() -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let artifact = f.publish("report-owner-evidence", b"immutable report evidence")?;
    let input = report(&f, &workflow, artifact.clone())?;
    let service = maintenance(&f)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        0,
        "an artifact publication alone is not a product evidence owner"
    );
    let stored = service
        .submit_report(
            &f.f.control,
            &CommandId::new("report-owner-submit")?,
            &input,
        )
        .map_err(|error| format!("report owner phase=real native report submission: {error}"))?;
    assert_eq!(stored.report, input);
    assert_eq!(service.read_report(&f.f.control, &stored.id)?, stored);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    assert!(f.runtime.collect(&f.f.control, &artifact).is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
        "the submitted immutable report needs its exact scoped product owner before retirement can be safe"
    );
    assert_eq!(
        service.submit_report(
            &f.f.control,
            &CommandId::new("report-owner-submit")?,
            &input
        )?,
        stored
    );
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn policy_proposal_evidence_owner_is_anchored_to_its_real_scoped_immutable_source(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let artifact = f.publish("proposal-owner-evidence", b"immutable policy trajectory")?;
    let input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&f, &workflow, artifact.clone())?
    };
    let service = maintenance(&f)?;
    let report = service.submit_report(
        &f.f.control,
        &CommandId::new("proposal-owner-report")?,
        &input,
    )?;
    assert_eq!(service.read_report(&f.f.control, &report.id)?, report);
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        0,
        "an attachment-free report cannot own an unrelated trajectory artifact"
    );
    let proposal = super::lifecycle::proposal(&f, &service, &report, &artifact)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let stored = service
        .propose(&f.f.control, &proposal)
        .map_err(|error| format!("proposal owner phase=real native scoped proposal: {error}"))?;
    assert_eq!(stored.proposal, proposal);
    assert_eq!(service.propose(&f.f.control, &proposal)?, stored);
    assert_eq!(active_product_quota(&f, "proposals")?, 1);
    assert!(f.runtime.collect(&f.f.control, &artifact).is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
        "the same artifact in benign and adversarial trajectories has one exact scoped proposal owner"
    );
    assert_eq!(service.propose(&f.f.control, &proposal)?, stored);
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}
