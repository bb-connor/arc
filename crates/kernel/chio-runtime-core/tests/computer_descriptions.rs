use chio_runtime_core::computer::ComputerDescription;
use chio_runtime_core::program::{compile_program, CompiledDescription, ProgramExpr};
use serde::Deserialize;
use serde_json::Value;

#[path = "computer_descriptions/refusals.rs"]
mod refusals;
#[path = "computer_descriptions/vectors.rs"]
mod vectors;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
    refusals: Vec<Refusal>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    id: String,
    computer: Value,
    request_id: String,
    expression: Value,
    expected: CompiledDescription,
    canonical: String,
}

#[derive(Deserialize)]
struct Refusal {
    id: String,
    section: String,
    path: Vec<Value>,
    value: Value,
    error: String,
}

fn fixture() -> Result<Fixture, serde_json::Error> {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/computer/v1.json"
    )))
}

fn base() -> Result<(ComputerDescription, String, ProgramExpr), Box<dyn std::error::Error>> {
    let case = fixture()?
        .cases
        .into_iter()
        .next()
        .ok_or("missing vector")?;
    Ok((
        ComputerDescription::from_json(&serde_json::to_vec(&case.computer)?)?,
        case.request_id,
        ProgramExpr::from_json(&serde_json::to_vec(&case.expression)?)?,
    ))
}
