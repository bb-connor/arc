use super::*;

pub(in crate::clearing) fn validate_round_core(
    core: &NettingRoundCoreV1,
) -> Result<(), ClearingError> {
    if core.schema != CLEARING_ROUND_CORE_SCHEMA {
        return Err(ClearingError::InvalidField("round_core_schema"));
    }
    validate_text("round_id", &core.round_id)?;
    validate_positive("epoch", core.epoch)?;
    validate_text("governance_scope_id", &core.governance_scope_id)?;
    validate_text("clearing_authority_id", &core.clearing_authority_id)?;
    validate_positive(
        "clearing_authority_key_epoch",
        core.clearing_authority_key_epoch,
    )?;
    validate_currency(&core.currency)?;
    if core.algorithm_version != CLEARING_ALGORITHM_V1 {
        return Err(ClearingError::InvalidField("algorithm_version"));
    }
    validate_digest(
        "participant_snapshot_digest",
        &core.participant_snapshot_digest,
    )?;
    validate_digest("input_manifest_digest", &core.input_manifest_digest)?;
    validate_positive("input_count", core.input_count)?;
    if usize::try_from(core.input_count).map_err(|_| ClearingError::ArithmeticOverflow)? + 1
        > MAX_ECONOMIC_TRANSITIONS
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    validate_digest("reservation_root", &core.reservation_root)?;
    validate_positive(
        "dispute_window_ends_at_unix_ms",
        core.dispute_window_ends_at_unix_ms,
    )?;
    validate_positive("generated_at_unix_ms", core.generated_at_unix_ms)?;
    if core.dispute_window_ends_at_unix_ms <= core.generated_at_unix_ms {
        return Err(ClearingError::InvalidField("dispute_window"));
    }
    Ok(())
}

pub(in crate::clearing) fn validate_round_head(
    head: &EconomicResourceHeadV1,
    record: &ClearingRoundLifecycleRecordV1,
) -> Result<(), ClearingError> {
    let expected_state = serde_json::to_value(record)
        .map_err(|error| ClearingError::Canonicalization(error.to_string()))?;
    if head.resource_key.resource_family != CLEARING_ROUND_RESOURCE_FAMILY
        || head.resource_key.scope_id != record.governance_scope_id
        || head.resource_key.resource_id != record.round_id
        || head.resource_version != record.row_version
        || head.lifecycle_fence != record.fence
        || head.lifecycle_state != record.state.as_str()
        || !matches!(&head.state, EconomicContentV1::Inline { value } if value == &expected_state)
        || head.operation_id.is_some()
        || head.effect_idempotency_key.is_some()
        || head.terminal_result.is_some()
    {
        return Err(ClearingError::InvalidField("current_round_head"));
    }
    Ok(())
}
