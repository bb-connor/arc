use super::*;

#[test]
fn fanin_requires_the_exact_join_reference_before_consumption() -> TestResult {
    let mut swarm = join_bundle()?;
    swarm.terminal_receipts.clear();
    let fixture = BindingFixture::with_capability(
        swarm,
        swarm_fixtures::runtime_swarm_capability("task-root")?,
    )?;
    let mut request = fixture.request.clone();
    request
        .governed_intent
        .as_mut()
        .and_then(|intent| intent.context.as_mut())
        .and_then(|context| context.get_mut("chioSwarm"))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("missing swarm context")?
        .remove("joinReceipt");
    fixture.assert_denied_without_consuming(&request, "chio_swarm_authority_ref_mismatch")
}

#[test]
fn supplied_malformed_join_reference_is_not_treated_as_absent() -> TestResult {
    for field in ["joinReceipt", "joinReceiptId", "joinReceiptSha256"] {
        let fixture = BindingFixture::new()?;
        let mut request = fixture.request.clone();
        let context = request
            .governed_intent
            .as_mut()
            .and_then(|intent| intent.context.as_mut())
            .and_then(|context| context.get_mut("chioSwarm"))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("missing swarm context")?;
        context.remove("joinReceipt");
        context.insert(field.into(), serde_json::Value::Null);
        fixture.assert_denied_without_consuming(
            &request,
            if field == "joinReceipt" {
                "invalid_chio_swarm_evidence_ref"
            } else {
                "missing_chio_swarm_evidence_ref"
            },
        )?;
    }
    Ok(())
}
