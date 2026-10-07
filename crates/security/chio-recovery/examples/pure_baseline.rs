//! Explicit hosted measurement harness, excluded from the pure library call graph.
use chio_core_types::{
    canonical::CanonicalBytes,
    recovery::{decode_contract, RecoveryDigestDomain},
};
use chio_recovery::advise_workflow;
use chio_security_types::recovery::{
    BoundedList, NonEmptyBoundedList, RecoveryObservationV1, SafeInteger, StepId, TemplateId,
};
use chio_semantic_contracts::{validate_dependency_graph, DependencyNodeV1, VerificationBudget};
use serde_json::{json, Value};
use std::{hint::black_box, time::Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn measure(name: &str, mut operation: impl FnMut() -> Result, ceiling_ns: u128) -> Result<Value> {
    for _ in 0..100 {
        operation()?;
    }
    let start = Instant::now();
    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let sample = Instant::now();
        operation()?;
        samples.push(sample.elapsed().as_nanos());
    }
    let elapsed = start.elapsed().as_nanos();
    let samples_ns = samples.clone();
    samples.sort_unstable();
    let measurement = json!({"operation":name,"samples":1000,"warmups":100,
        "samples_ns":samples_ns,"sample_unit":"nanoseconds","percentile_method":"nearest_rank",
        "p50_ns":samples[499],"p95_ns":samples[949],"p99_ns":samples[989],"max_ns":samples[999],
        "elapsed_ns":elapsed,"p95_ceiling_ns":ceiling_ns});
    // Retain the observed vector even when the fixed ceiling refuses the run.
    println!("PURE_RECOVERY_MEASUREMENT {measurement}");
    if samples[949] > ceiling_ns {
        return Err("predeclared p95 ceiling exceeded".into());
    }
    Ok(measurement)
}
fn main() -> Result {
    let bytes = include_str!("../../../../spec/vectors/recovery/v1/observation.json")
        .trim_end()
        .as_bytes();
    let observation: RecoveryObservationV1 = decode_contract(bytes)?;
    let body = CanonicalBytes::new(&observation)?;
    let mut nodes = Vec::new();
    for index in 0..16 {
        let dependencies = if index == 0 {
            vec![]
        } else {
            vec![StepId::new(&format!("step-{:02}", index - 1))?]
        };
        nodes.push(DependencyNodeV1 {
            step_id: StepId::new(&format!("step-{index:02}"))?,
            template_id: TemplateId::new("registered-template")?,
            dependencies: BoundedList::new(dependencies)?,
            estimated_cost_units: SafeInteger::new(1)?,
        });
    }
    let nodes = NonEmptyBoundedList::new(nodes)?;
    let intake = measure(
        "intake",
        || {
            black_box(decode_contract::<RecoveryObservationV1>(black_box(bytes))?);
            Ok(())
        },
        5_000_000,
    )?;
    let digest = measure(
        "digest",
        || {
            black_box(RecoveryDigestDomain::Basis.digest(black_box(&body)));
            Ok(())
        },
        250_000,
    )?;
    let reduction = measure(
        "reduction",
        || {
            black_box(advise_workflow(black_box(&observation)));
            Ok(())
        },
        250_000,
    )?;
    let graph = measure(
        "graph_16_steps",
        || {
            black_box(validate_dependency_graph(
                black_box(&nodes),
                &mut VerificationBudget::new(4096)?,
            )?);
            Ok(())
        },
        1_000_000,
    )?;
    println!(
        "PURE_RECOVERY_BASELINE {}",
        json!({"profile":if cfg!(debug_assertions) { "debug" } else { "release" },
        "errors":0,"intake":intake,
        "digest":digest,"reduction":reduction,"graph_16_steps":graph})
    );
    Ok(())
}
