//! Bindings from governed fee schedules to the signed fee-schedule envelopes
//! issued for them.
use super::*;

impl SqliteFiscalStore {
    pub fn bind_fee_schedule(
        &self,
        envelope: &SignedOpenMarketFeeSchedule,
        schedule: &VerifiedFiscalSchedule,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        match self.bind_fee_schedule_admitted(envelope, schedule, fence, || {
            Ok::<(), std::convert::Infallible>(())
        })? {
            Ok(()) => Ok(()),
            Err(never) => match never {},
        }
    }

    /// Binds `envelope` only if `admit` accepts it inside the binding
    /// write transaction, immediately before that transaction commits. A
    /// refusal is returned as `Ok(Err(_))` after the transaction rolls back,
    /// so neither the binding nor its projection commit is persisted. Store
    /// failures stay `Err(_)`. Nothing after a successful commit refuses it.
    pub fn bind_fee_schedule_admitted<E>(
        &self,
        envelope: &SignedOpenMarketFeeSchedule,
        schedule: &VerifiedFiscalSchedule,
        fence: &StoreMutationFence,
        admit: impl FnOnce() -> Result<(), E>,
    ) -> Result<Result<(), E>, FiscalStoreError> {
        envelope
            .body
            .validate()
            .map_err(|error| invariant(format!("fee schedule envelope is invalid: {error}")))?;
        if !envelope
            .verify_signature(&envelope.signer_key)
            .map_err(|error| {
                invariant(format!("fee schedule envelope signature failed: {error}"))
            })?
        {
            return Err(invariant("fee schedule envelope signature is invalid"));
        }
        let FiscalParams::OpenMarketFeeAndBondSchedule { fee_schedule } = &schedule.body().params
        else {
            return Err(FiscalStoreError::Conflict);
        };
        if fee_schedule.as_ref() != &envelope.body {
            return Err(FiscalStoreError::Conflict);
        }
        let fee_schedule_id = &envelope.body.fee_schedule_id;
        let envelope_json = canonical_json_bytes(envelope).map_err(canonical_error)?;
        let envelope_digest = sha256_hex(&envelope_json);
        let schedule_json = schedule.canonical_bytes()?;
        let schedule_digest = sha256_hex(&schedule_json);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let retained = transaction
            .query_row(
                "SELECT fiscal_schedule_id, fiscal_schedule_digest, envelope_digest FROM fiscal_fee_schedule_bindings WHERE fee_schedule_id = ?1",
                [fee_schedule_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some((schedule_id, digest, retained_envelope_digest)) = retained {
            if schedule_id != schedule.body().schedule_id
                || digest != schedule_digest
                || retained_envelope_digest != envelope_digest
            {
                return Err(FiscalStoreError::Conflict);
            }
            if let Err(refusal) = admit() {
                return Ok(Err(refusal));
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(Ok(()));
        }
        let exact_schedule = transaction
            .query_row(
                "SELECT schedule_digest = ?1 AND signed_json = ?2 FROM fiscal_schedules WHERE schedule_id = ?3",
                params![&schedule_digest, &schedule_json, &schedule.body().schedule_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .unwrap_or(false);
        if !exact_schedule {
            return Err(FiscalStoreError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO fiscal_fee_schedule_bindings (fee_schedule_id, fiscal_schedule_id, fiscal_schedule_digest, envelope_digest) VALUES (?1, ?2, ?3, ?4)",
                params![
                    fee_schedule_id,
                    &schedule.body().schedule_id,
                    &schedule_digest,
                    &envelope_digest,
                ],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("fee-schedule:{fee_schedule_id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "bind_fee_schedule",
            &schedule_digest,
        )?;
        if let Err(refusal) = admit() {
            return Ok(Err(refusal));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(Ok(()))
    }

    pub fn load_fee_schedule_binding(
        &self,
        fiscal_schedule_id: &str,
    ) -> Result<FiscalFeeScheduleBindingRecord, FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let record = transaction
            .query_row(
                "SELECT fee_schedule_id, fiscal_schedule_id, fiscal_schedule_digest, envelope_digest FROM fiscal_fee_schedule_bindings WHERE fiscal_schedule_id = ?1",
                [fiscal_schedule_id],
                |row| {
                    Ok(FiscalFeeScheduleBindingRecord {
                        fee_schedule_id: row.get(0)?,
                        fiscal_schedule_id: row.get(1)?,
                        fiscal_schedule_digest: row.get(2)?,
                        envelope_digest: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(FiscalStoreError::NotFound)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }
}
