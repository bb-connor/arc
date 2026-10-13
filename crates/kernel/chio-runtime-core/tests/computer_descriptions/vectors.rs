use chio_runtime_core::program::validate_compiled_program;

use super::*;

#[test]
fn shared_canonical_vectors() -> TestResult {
    for case in fixture()?.cases {
        let computer = ComputerDescription::from_json(&serde_json::to_vec(&case.computer)?)?;
        let expression = ProgramExpr::from_json(&serde_json::to_vec(&case.expression)?)?;
        let result = compile_program(&computer, &case.request_id, &expression)?;
        assert_eq!(result.description(), &case.expected, "{}", case.id);
        assert_eq!(
            chio_core_types::crypto::canonical_json_bytes(result.description())?,
            case.canonical.as_bytes(),
            "{}",
            case.id
        );
        assert_eq!(
            validate_compiled_program(&computer, &case.request_id, &expression, &case.expected)?,
            result
        );
    }
    Ok(())
}

#[test]
fn operator_precedence_matches_canonical_chain() -> TestResult {
    let case = fixture()?
        .cases
        .into_iter()
        .find(|case| case.id == "operator_precedence")
        .ok_or("missing vector")?;
    let computer = ComputerDescription::from_json(&serde_json::to_vec(&case.computer)?)?;
    let mut leaves = case
        .expected
        .occurrences
        .iter()
        .map(|item| ProgramExpr::Leaf {
            leaf: Box::new(item.leaf.clone()),
        });
    let a = leaves.next().ok_or("missing a")?;
    let b = leaves.next().ok_or("missing b")?;
    let c = leaves.next().ok_or("missing c")?;
    let d = leaves.next().ok_or("missing d")?;
    let e = leaves.next().ok_or("missing e")?;
    let canonical = ProgramExpr::Parallel {
        items: vec![a.clone(), b.clone(), c.clone()],
    }
    .pipe(d.clone())
    .pipe(e.clone());
    let operators = a & b & c | d | e;
    assert_eq!(
        compile_program(&computer, &case.request_id, &operators)?.description(),
        &case.expected
    );
    assert_eq!(
        compile_program(&computer, &case.request_id, &canonical)?.description(),
        &case.expected
    );
    Ok(())
}

#[test]
fn repeated_leaves_retry_and_new_request_have_distinct_identities() -> TestResult {
    for case in fixture()?
        .cases
        .into_iter()
        .filter(|case| case.id.starts_with("repeated_"))
    {
        let computer = ComputerDescription::from_json(&serde_json::to_vec(&case.computer)?)?;
        let expression = ProgramExpr::from_json(&serde_json::to_vec(&case.expression)?)?;
        let first = compile_program(&computer, &case.request_id, &expression)?;
        let retry = compile_program(&computer, &case.request_id, &expression)?;
        assert_eq!(first, retry);
        let ids = first
            .description()
            .occurrences
            .iter()
            .map(|item| &item.occurrence_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 2);
        let other = compile_program(&computer, "new-request", &expression)?;
        assert!(other
            .description()
            .occurrences
            .iter()
            .all(|item| !ids.contains(&item.occurrence_id)));
    }
    Ok(())
}
