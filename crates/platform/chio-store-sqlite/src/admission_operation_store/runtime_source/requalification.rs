use super::*;

pub struct RuntimeSourceRequalificationInput<'a> {
    pub prior: &'a RuntimeSourceRecordV1,
    pub source_id: &'a AdmissionIdentifier,
    pub runtime_authority_id: &'a AdmissionIdentifier,
    pub source: &'a dyn RuntimeSourcePort,
}

impl SqliteAdmissionOperationStore {
    pub fn requalify_runtime_source(
        &self,
        input: RuntimeSourceRequalificationInput<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeSourceRecordV1, AdmissionOperationStoreError> {
        let _installation = self
            .serving_owner
            .begin_source_installation()
            .map_err(map_owner_error)?;
        let previous = {
            let mut connection = self.connection()?;
            let transaction = self.begin_read(&mut connection)?;
            verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
            source_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
            checked_replacement(&transaction, &input)?
        };
        if let Some(existing) = previous {
            require_binding(
                &existing.qualification,
                input.source_id,
                input.runtime_authority_id,
                fence,
            )?;
            input.source.verify_exact(&existing.qualification)?;
            return self
                .load_runtime_source(input.runtime_authority_id, fence, trusted_now_unix_ms)?
                .filter(|current| current == &existing)
                .ok_or_else(|| invariant("runtime source requalification readback mismatch"));
        }
        let destination =
            AdmissionIdentifier::try_new("destination_store_uuid", &fence.store_uuid)?;
        let qualification =
            input
                .source
                .qualify(input.source_id, input.runtime_authority_id, &destination)?;
        require_binding(
            &qualification,
            input.source_id,
            input.runtime_authority_id,
            fence,
        )?;
        input.source.verify_exact(&qualification)?;
        let candidate;
        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = source_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
            if checked_replacement(&transaction, &input)?.is_some() {
                return Err(invariant("runtime source changed during requalification"));
            }
            candidate = records::new_record(qualification, observed, fence.clone())?;
            records::insert(&transaction, &candidate)?;
            supersession::Supersession::new(input.prior, &candidate).insert(&transaction)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    supersession::MUTATION,
                    PROJECTION_KIND,
                    input.prior.qualification.runtime_authority_id(),
                    2,
                )
                .map_err(map_owner_error)?;
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    INSTALL_MUTATION,
                    PROJECTION_KIND,
                    input.runtime_authority_id.as_str(),
                    1,
                )
                .map_err(map_owner_error)?;
            verify_runtime_source_projection_coverage(&transaction).map_err(map_owner_error)?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        self.load_runtime_source(input.runtime_authority_id, fence, trusted_now_unix_ms)?
            .filter(|current| current == &candidate)
            .ok_or_else(|| invariant("runtime source requalification readback mismatch"))
    }
}

fn checked_replacement(
    connection: &Connection,
    input: &RuntimeSourceRequalificationInput<'_>,
) -> Result<Option<RuntimeSourceRecordV1>, AdmissionOperationStoreError> {
    verify_runtime_source_projection_coverage(connection).map_err(map_owner_error)?;
    let records = verify_all_records(connection).map_err(integrity_error)?;
    let prior = records
        .iter()
        .find(|record| {
            record.qualification.runtime_authority_id()
                == input.prior.qualification.runtime_authority_id()
        })
        .ok_or_else(|| invariant("runtime source requalification prior record is absent"))?;
    if prior != input.prior {
        return Err(invariant(
            "runtime source requalification prior record mismatch",
        ));
    }
    if prior.qualification.source_id() == input.source_id.as_str()
        || prior.qualification.runtime_authority_id() == input.runtime_authority_id.as_str()
    {
        return Err(invariant(
            "runtime source requalification requires fresh identities",
        ));
    }
    let supersessions = supersession::load_all(connection, &records).map_err(integrity_error)?;
    if let Some(supersession) = supersessions
        .iter()
        .find(|record| record.prior_runtime == prior.qualification.runtime_authority_id())
    {
        if supersession.replacement_runtime != input.runtime_authority_id.as_str() {
            return Err(invariant(
                "runtime source requalification replacement conflict",
            ));
        }
        let replacement = records
            .iter()
            .find(|record| {
                record.qualification.runtime_authority_id() == supersession.replacement_runtime
            })
            .ok_or_else(|| invariant("runtime source requalification replacement is absent"))?;
        if replacement.qualification.source_id() != input.source_id.as_str() {
            return Err(invariant(
                "runtime source requalification replacement conflict",
            ));
        }
        supersession::require_active(connection, input.runtime_authority_id.as_str())?;
        return Ok(Some(replacement.clone()));
    }
    if records.iter().any(|record| {
        record.qualification.source_id() == input.source_id.as_str()
            || record.qualification.runtime_authority_id() == input.runtime_authority_id.as_str()
    }) {
        return Err(invariant(
            "runtime source requalification identity already exists",
        ));
    }
    if supersessions.len() >= MAX_SUPERSEDED {
        return Err(invariant(
            "runtime source supersession history capacity exhausted",
        ));
    }
    Ok(None)
}
