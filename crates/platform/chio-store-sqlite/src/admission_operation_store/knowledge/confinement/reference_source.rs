//! Original confined inputs remain held independently of stop or exit state.
use super::*;

pub(in crate::admission_operation_store::knowledge) struct ConfinedInputReferenceSource {
    boundary: IsolationBoundaryV1,
    source: protected::ProtectedSourceReference,
    references: Vec<ArtifactVersionRefV1>,
    pins: Vec<protected::ProtectedSourceReference>,
}

impl ConfinedInputReferenceSource {
    pub(in crate::admission_operation_store::knowledge) fn boundary(&self) -> &IsolationBoundaryV1 {
        &self.boundary
    }

    pub(in crate::admission_operation_store::knowledge) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }

    pub(in crate::admission_operation_store::knowledge) fn references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        &self.references
    }

    pub(in crate::admission_operation_store::knowledge) fn pins(
        &self,
    ) -> &[protected::ProtectedSourceReference] {
        &self.pins
    }
}

/// Data-only source proof inside the caller's authenticated authority snapshot.
/// The current head may record Stop; original input ownership cannot retire.
pub(in crate::admission_operation_store::knowledge) fn input_reference_source(
    tx: &Connection,
    record_key: &str,
) -> Result<Option<ConfinedInputReferenceSource>, AdmissionOperationStoreError> {
    if !record_key.starts_with("confined-boundary:") {
        return Ok(None);
    }
    let Some(row) = protected::raw_checked(tx, record_key)? else {
        return Ok(None);
    };
    let mut initial: BoundaryRecord = protected::decode(&row.payload)?;
    let boundary = initial.reservation.boundary.clone();
    boundary.validate().map_err(refused)?;
    let scope = scope_key(&boundary.scope)?;
    if record_key != key(&boundary.scope, &boundary.request)?
        || row.scope != scope
        || row.kind != "command"
        || row.version == 0
        || initial.installation.scope != boundary.scope
        || initial.installation.contract.parent != boundary.parent
    {
        return Err(refused("confined input source identity"));
    }
    let source = protected::source_reference(tx, record_key)?;
    if source.scope_key() != scope || source.kind() != "command" || source.version() != row.version
    {
        return Err(refused("confined input source head"));
    }

    // All remaining fields are immutable reservation identity. Compare the
    // complete reconstructed preimage with its original authenticated event.
    initial.stop_requested = false;
    initial.reservation.state = IsolationStateV1::Reserved;
    initial.prepared = None;
    initial.prepared_profile = None;
    initial.launch = None;
    initial.enforcement = None;
    initial.terminal = None;
    initial.input_packet = None;
    initial.expected_return = None;
    initial.observation_release = None;
    initial.return_seal = None;
    initial.return_artifact = None;
    initial.return_metadata = None;
    initial.return_admission = None;
    initial.return_authority = None;
    initial.return_origin = None;
    if !protected::matches_historical_source_command_payload(
        tx,
        &source,
        1,
        &protected::encode(&initial)?,
    )? {
        return Err(refused("confined original input source"));
    }
    let boundary_commit = protected::historical_record_commit(tx, record_key, 1)?;
    let mut references = Vec::new();
    let mut pins = Vec::new();
    for (ordinal, reference) in boundary
        .seed_artifacts
        .as_slice()
        .iter()
        .chain(core::iter::once(&boundary.observation))
        .enumerate()
    {
        if reference.scope != boundary.scope {
            return Err(refused("confined input reference scope"));
        }
        let pin_key = format!(
            "knowledge-pin:{scope}:confined:{}:{ordinal}",
            boundary.boundary.as_str()
        );
        let pin_row = protected::raw_checked(tx, &pin_key)?
            .ok_or_else(|| refused("confined input pin absent"))?;
        let pinned: Option<ArtifactVersionRefV1> = protected::decode(&pin_row.payload)?;
        if pin_row.scope != scope
            || pin_row.kind != "command"
            || pin_row.version != 1
            || pinned.as_ref() != Some(reference)
        {
            return Err(refused("confined original input pin"));
        }
        let pin = protected::source_reference(tx, &pin_key)?;
        if pin.scope_key() != scope
            || pin.kind() != "command"
            || pin.version() != 1
            || pin.global_commit_sequence() >= boundary_commit
        {
            return Err(refused("confined input pin ordering"));
        }
        if !references.contains(reference) {
            references.push(reference.clone());
        }
        pins.push(pin);
    }
    Ok(Some(ConfinedInputReferenceSource {
        boundary,
        source,
        references,
        pins,
    }))
}
