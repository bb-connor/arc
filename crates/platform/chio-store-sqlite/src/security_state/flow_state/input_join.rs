//! Resolve complete input taint in the admission writer's existing transaction.
use super::*;
use chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1;

/// No writer is created here. The admission owner first validates the original
/// operation and intent, calls this under its write transaction, then enables
/// the ordinary closed monotone-join owner for the resolved command.
pub(crate) fn resolve_native_input_join(
    transaction: &rusqlite::Transaction<'_>,
    authority: &str,
    input: &NativeSecurityInputJoinRequestV1,
) -> PortResult<FlowJoinRequest> {
    resolve_native_label_join(
        transaction,
        authority,
        input.key(),
        input.input_label(),
        input.transition_id(),
    )
}

pub(crate) fn resolve_native_label_join(
    transaction: &rusqlite::Transaction<'_>,
    authority: &str,
    key: &FlowStateKey,
    label: &InformationLabel,
    transition_id: &RecordId,
) -> PortResult<FlowJoinRequest> {
    let reader = FlowReader::native(transaction, authority);
    // Read each real row even before an exact isolation epoch exists. In
    // particular, an absent epoch does not erase a shared lineage or a
    // principal's already established epoch under a different lineage.
    let labels = [
        load_principal_label(reader, key)?,
        load_lineage_label(reader, key)?,
        load_session_label(reader, key)?,
    ];
    let mut source = label.clone();
    for (label, _) in labels.into_iter().flatten() {
        source = source
            .join_restrictions(&label)
            .map_err(|_| PortError::invalid_data())?;
    }
    Ok(FlowJoinRequest {
        key: key.clone(),
        transition_id: transition_id.clone(),
        principal_join: source.clone(),
        lineage_join: source.clone(),
        session_join: source,
    })
}
