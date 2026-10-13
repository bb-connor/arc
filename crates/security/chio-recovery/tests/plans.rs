//! Symbolic plans remain bounded, deterministic advice with no live owner.
use chio_recovery::*;
use chio_security_types::{recovery::*, InformationLabel};
use chio_semantic_contracts::{DependencyGraphSchema, DependencyGraphV1, DependencyNodeV1};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    snapshot: RecoverySnapshotV1,
    registry: RecoveryRemedyRegistryV1,
}
impl Fixture {
    fn new() -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../spec/vectors/recovery/v1/explanation-inputs.json"
        ))?;
        Ok(Self {
            snapshot: serde_json::from_value(value["snapshot"].clone())?,
            registry: serde_json::from_value(value["registry"].clone())?,
        })
    }
}

fn registry(f: &Fixture, nodes: usize) -> Result<RecoveryPlanningRegistryV1> {
    let template = &f.registry.templates.as_slice()[0];
    let mut steps = Vec::new();
    for index in 0..nodes {
        steps.push(DependencyNodeV1 {
            step_id: StepId::new(&format!("step:{index:02}"))?,
            template_id: template.template_id.clone(),
            dependencies: BoundedList::new(if index == 0 {
                vec![]
            } else {
                vec![StepId::new(&format!("step:{:02}", index - 1))?]
            })?,
            estimated_cost_units: template.cost.budget_units,
        });
    }
    Ok(RecoveryPlanningRegistryV1 {
        scope: f.snapshot.scope.clone(),
        workflow_id: WorkflowId::new("workflow:planning")?,
        intent_digest: f.snapshot.intent_digest,
        classification: f.snapshot.context_label.clone(),
        plans: BoundedList::new(vec![RegisteredCandidatePlanV1 {
            plan_id: PlanId::new("plan:chain")?,
            top_level_steps: NonEmptyBoundedList::new(vec![StepId::new(&format!(
                "step:{:02}",
                nodes - 1
            ))?])?,
            graph: DependencyGraphV1 {
                schema: DependencyGraphSchema::V1,
                version: VersionV1,
                nodes: NonEmptyBoundedList::new(steps)?,
            },
        }])?,
    })
}

#[test]
fn planning_produces_a_bounded_multistep_candidate_in_canonical_order() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 3)?;
    let limits = PlannerLimitsV1::new(16, 8, 32, 8, 4096)?;
    let planned = plan(&f.snapshot, &f.registry, &graph, limits)?;
    let PlanDecision::Candidates {
        plans,
        classification,
    } = &planned
    else {
        return Err("valid registered steps must produce advisory candidates".into());
    };
    assert_eq!(classification, &f.snapshot.context_label);
    assert_eq!(plans.as_slice().len(), 1);
    let candidate = &plans.as_slice()[0];
    assert_eq!(
        candidate.ordered_steps(),
        &[
            StepId::new("step:00")?,
            StepId::new("step:01")?,
            StepId::new("step:02")?,
        ]
    );
    assert_eq!(
        candidate.assessment(),
        ExplanationAssessmentV1::FeasibleUnderSnapshot
    );
    let mut candidates = graph.plans.as_slice().to_vec();
    let mut nodes = candidates[0].graph.nodes.as_slice().to_vec();
    nodes.reverse();
    candidates[0].graph.nodes = NonEmptyBoundedList::new(nodes)?;
    graph.plans = BoundedList::new(candidates)?;
    assert_eq!(planned, plan(&f.snapshot, &f.registry, &graph, limits)?);
    Ok(())
}

#[test]
fn planning_names_the_exact_step_node_depth_or_work_bound() -> Result {
    let f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    for (limits, expected) in [
        (
            PlannerLimitsV1::new(16, 8, 2, 8, 4096)?,
            PlannerSearchLimit::Nodes,
        ),
        (
            PlannerLimitsV1::new(16, 8, 32, 2, 4096)?,
            PlannerSearchLimit::Depth,
        ),
        (
            PlannerLimitsV1::new(16, 8, 32, 8, 1)?,
            PlannerSearchLimit::Work,
        ),
    ] {
        assert_eq!(
            plan(&f.snapshot, &f.registry, &graph, limits)?,
            PlanDecision::SearchBoundReached {
                limit: expected,
                classification: InformationLabel::Top
            }
        );
    }
    let mut multiple_roots = graph.clone();
    let mut candidates = multiple_roots.plans.as_slice().to_vec();
    candidates[0].top_level_steps =
        NonEmptyBoundedList::new(vec![StepId::new("step:01")?, StepId::new("step:02")?])?;
    multiple_roots.plans = BoundedList::new(candidates)?;
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            &multiple_roots,
            PlannerLimitsV1::new(16, 1, 32, 8, 4096)?
        )?,
        PlanDecision::SearchBoundReached {
            limit: PlannerSearchLimit::Steps,
            classification: InformationLabel::Top
        },
    );
    for values in [
        (17, 8, 32, 8, 4096),
        (16, 9, 32, 8, 4096),
        (16, 8, 33, 8, 4096),
        (16, 8, 32, 9, 4096),
        (16, 8, 32, 8, 4097),
    ] {
        assert!(PlannerLimitsV1::new(values.0, values.1, values.2, values.3, values.4).is_err());
    }
    Ok(())
}

#[test]
fn planning_refuses_foreign_intents_cycles_and_missing_templates() -> Result {
    let f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    let limits = PlannerLimitsV1::new(16, 8, 32, 8, 4096)?;
    for mutation in 0..3 {
        let mut changed = graph.clone();
        if mutation == 0 {
            changed.intent_digest = IntentDigest::from_bytes([91; 32]);
        } else {
            let mut candidates = changed.plans.as_slice().to_vec();
            let mut nodes = candidates[0].graph.nodes.as_slice().to_vec();
            if mutation == 1 {
                nodes[0].dependencies = BoundedList::new(vec![StepId::new("step:02")?])?;
            } else {
                nodes[0].template_id = TemplateId::new("unregistered")?;
            }
            candidates[0].graph.nodes = NonEmptyBoundedList::new(nodes)?;
            changed.plans = BoundedList::new(candidates)?;
        }
        assert!(plan(&f.snapshot, &f.registry, &changed, limits).is_err());
    }
    Ok(())
}

#[test]
fn symbolic_steps_never_establish_future_evidence_or_disclose_through_debug() -> Result {
    let mut f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    let mut facts = f.snapshot.observations.as_slice().to_vec();
    for fact in &mut facts {
        if fact.fact == ExplanationFactKind::AuthorityCoverage {
            fact.state = ExplanationFactStateV1::Gap {
                reason: ExplanationGap::NotConsulted,
            };
        }
    }
    f.snapshot.observations = BoundedList::new(facts)?;
    let decision = plan(
        &f.snapshot,
        &f.registry,
        &graph,
        PlannerLimitsV1::new(16, 8, 32, 8, 4096)?,
    )?;
    assert_eq!(format!("{decision:?}"), "PlanDecision([redacted])");
    let PlanDecision::Candidates { plans, .. } = decision else {
        return Err("bounded plans must preserve the explicit evidence gap".into());
    };
    let candidate = &plans.as_slice()[0];
    assert_eq!(
        candidate.assessment(),
        ExplanationAssessmentV1::NeedsFreshEvidence
    );
    assert_eq!(candidate.scope(), &graph.scope);
    assert_eq!(candidate.workflow_id(), &graph.workflow_id);
    assert_eq!(candidate.intent_digest(), graph.intent_digest);
    assert_eq!(candidate.plan_id(), &graph.plans.as_slice()[0].plan_id);
    assert_eq!(
        candidate.total_cost_units().get(),
        f.registry.templates.as_slice()[0].cost.budget_units.get() * 3
    );
    assert_eq!(format!("{candidate:?}"), "CandidatePlanV1([redacted])");
    Ok(())
}
