use super::super::super::StructuredBudgetProjectionKindView;

#[test]
fn standalone_hold_projection_kind_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let kind: StructuredBudgetProjectionKindView =
        serde_json::from_str("\"standalone_hold\"")?;
    assert_eq!(serde_json::to_string(&kind)?, "\"standalone_hold\"");
    Ok(())
}

#[test]
fn retired_hold_projection_kind_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let result = serde_json::from_str::<StructuredBudgetProjectionKindView>(
        "\"legacy_hold\"",
    );
    let Err(error) = result else {
        return Err("retired projection kind was accepted".into());
    };
    assert_eq!(
        error.to_string(),
        "unknown variant `legacy_hold`, expected `standalone_hold` or `admission_operation` at line 1 column 13"
    );
    Ok(())
}

#[test]
fn admission_operation_projection_kind_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let kind: StructuredBudgetProjectionKindView =
        serde_json::from_str("\"admission_operation\"")?;
    assert_eq!(serde_json::to_string(&kind)?, "\"admission_operation\"");
    Ok(())
}
