use super::*;

#[test]
fn dense_semantic_plan_at_the_step_ceiling_fits_its_declared_budget() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut steps = Vec::new();
    for index in 0..8 {
        let mut step = f.plan.steps.as_slice()[0].clone();
        step.step = StepId::new(&format!("step-{index:02}"))?;
        step.dependencies = BoundedList::new(
            (0..index)
                .map(|prior| StepId::new(&format!("step-{prior:02}")))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        steps.push(step);
    }
    steps.reverse();
    let plan = SemanticPlanV1 {
        steps: NonEmptyBoundedList::new(steps)?,
        ..f.plan
    };
    let ordered = validate_semantic_plan(
        &plan,
        &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
    )?;
    assert_eq!(ordered.len(), 8);
    assert_eq!(ordered[0].as_str(), "step-00");
    assert_eq!(ordered[7].as_str(), "step-07");
    Ok(())
}

#[test]
fn fresh_semantic_plan_refuses_more_than_eight_top_level_steps() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut steps = Vec::new();
    for index in 0..9 {
        let mut step = f.plan.steps.as_slice()[0].clone();
        step.step = StepId::new(&format!("step-{index:02}"))?;
        steps.push(step);
    }
    let mut wire = serde_json::to_value(&f.plan)?;
    wire["steps"] = serde_json::to_value(&steps)?;
    assert_eq!(
        (decode_contract::<SemanticPlanV1>(&chio_core_types::canonical_json_bytes(&wire)?)).err(),
        Some(ContractError::Malformed)
    );
    assert_eq!(
        (NonEmptyBoundedList::<SemanticPlanStepV1, 8>::new(steps)).err(),
        Some(ContractError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn prerequisite_dags_refuse_cycles_duplicates_missing_and_undeclared_future_inputs() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert_eq!(
        validate_semantic_plan(
            &f.plan,
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
        )?,
        vec![StepId::new("remedy")?]
    );
    for (dependency, expected) in [
        ("remedy", ContractError::DependencyCycle),
        ("missing", ContractError::MissingDependency),
    ] {
        let mut plan = f.plan.clone();
        let mut step = plan.steps.as_slice()[0].clone();
        step.dependencies = BoundedList::new(vec![StepId::new(dependency)?])?;
        plan.steps = NonEmptyBoundedList::new(vec![step])?;
        assert_eq!(
            (validate_semantic_plan(
                &plan,
                &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
            ))
            .err(),
            Some(expected)
        );
    }
    let mut plan = f.plan.clone();
    plan.steps = NonEmptyBoundedList::new(vec![
        plan.steps.as_slice()[0].clone(),
        plan.steps.as_slice()[0].clone(),
    ])?;
    assert_eq!(
        (validate_semantic_plan(
            &plan,
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
        ))
        .err(),
        Some(ContractError::DuplicateIdentity)
    );
    assert_eq!(
        (verify_semantic_invocation(
            &compiled(&f)?,
            &f.invocation,
            &SemanticInvocationExpectationV1 {
                server: "server-a",
                tool: "send",
                request_id: "request-a",
                request_namespace: f.invocation.action.request_namespace,
                capability: f.invocation.action.capability,
                request_semantics: f.invocation.action.request_semantics,
                source_label: &InformationLabel::bottom(),
                externally_influenced: false,
                influence: f.invocation.action.influence,
                native_disclosure_target: None,
                now_unix_ms: 1001
            },
            &mut VerificationBudget::new(1, MAX_RECOVERY_VERIFICATION_WORK)?
        ))
        .err(),
        Some(ContractError::WorkBudgetExceeded)
    );
    Ok(())
}

#[test]
fn future_inputs_require_declared_prerequisites() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let mut plan = f.plan.clone();
    let mut step = plan.steps.as_slice()[0].clone();
    step.inputs = NonEmptyBoundedList::new(vec![SemanticPlanInputV1::FutureOutput {
        step: StepId::new("unaccepted-producer")?,
    }])?;
    plan.steps = NonEmptyBoundedList::new(vec![step])?;
    assert_eq!(
        (validate_semantic_plan(
            &plan,
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
        ))
        .err(),
        Some(ContractError::MissingDependency)
    );
    Ok(())
}
