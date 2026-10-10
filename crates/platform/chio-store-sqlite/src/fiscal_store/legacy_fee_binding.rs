//! Bindings from governed fee schedules to the legacy fee-schedule envelopes
//! issued for them.
use super::*;

impl SqliteFiscalStore {
    pub fn bind_legacy_fee_schedule(
        &self,
        legacy_schedule: &SignedOpenMarketFeeSchedule,
        schedule: &VerifiedFiscalSchedule,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        match self.bind_legacy_fee_schedule_admitted(legacy_schedule, schedule, fence, || {
            Ok::<(), std::convert::Infallible>(())
        })? {
            Ok(()) => Ok(()),
            Err(never) => match never {},
        }
    }

    /// Binds `legacy_schedule` only if `admit` accepts it inside the binding
    /// write transaction, immediately before that transaction commits. A
    /// refusal is returned as `Ok(Err(_))` after the transaction rolls back,
    /// so neither the binding nor its projection commit is persisted. Store
    /// failures stay `Err(_)`. Nothing after a successful commit refuses it.
    pub fn bind_legacy_fee_schedule_admitted<E>(
        &self,
        legacy_schedule: &SignedOpenMarketFeeSchedule,
        schedule: &VerifiedFiscalSchedule,
        fence: &StoreMutationFence,
        admit: impl FnOnce() -> Result<(), E>,
    ) -> Result<Result<(), E>, FiscalStoreError> {
        legacy_schedule
            .body
            .validate()
            .map_err(|error| invariant(format!("legacy fee schedule is invalid: {error}")))?;
        if !legacy_schedule
            .verify_signature()
            .map_err(|error| invariant(format!("legacy fee schedule signature failed: {error}")))?
        {
            return Err(invariant("legacy fee schedule signature is invalid"));
        }
        let FiscalParams::OpenMarketFeeAndBondSchedule { legacy_body } = &schedule.body().params
        else {
            return Err(FiscalStoreError::Conflict);
        };
        if legacy_body.as_ref() != &legacy_schedule.body {
            return Err(FiscalStoreError::Conflict);
        }
        let legacy_schedule_id = &legacy_schedule.body.fee_schedule_id;
        let legacy_envelope_json =
            canonical_json_bytes(legacy_schedule).map_err(canonical_error)?;
        let legacy_envelope_digest = sha256_hex(&legacy_envelope_json);
        let schedule_json = schedule.canonical_bytes()?;
        let schedule_digest = sha256_hex(&schedule_json);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let retained = transaction
            .query_row(
                "SELECT fiscal_schedule_id, fiscal_schedule_digest, legacy_envelope_digest FROM fiscal_legacy_fee_schedule_bindings WHERE legacy_schedule_id = ?1",
                [legacy_schedule_id],
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
        if let Some((schedule_id, digest, envelope_digest)) = retained {
            if schedule_id != schedule.body().schedule_id
                || digest != schedule_digest
                || envelope_digest != legacy_envelope_digest
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
                "INSERT INTO fiscal_legacy_fee_schedule_bindings (legacy_schedule_id, fiscal_schedule_id, fiscal_schedule_digest, legacy_envelope_digest) VALUES (?1, ?2, ?3, ?4)",
                params![
                    legacy_schedule_id,
                    &schedule.body().schedule_id,
                    &schedule_digest,
                    &legacy_envelope_digest,
                ],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("legacy-fee:{legacy_schedule_id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "bind_legacy_fee_schedule",
            &schedule_digest,
        )?;
        if let Err(refusal) = admit() {
            return Ok(Err(refusal));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(Ok(()))
    }

    pub fn load_legacy_fee_schedule_binding(
        &self,
        fiscal_schedule_id: &str,
    ) -> Result<FiscalLegacyFeeScheduleBindingRecord, FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let record = transaction
            .query_row(
                "SELECT legacy_schedule_id, fiscal_schedule_id, fiscal_schedule_digest, legacy_envelope_digest FROM fiscal_legacy_fee_schedule_bindings WHERE fiscal_schedule_id = ?1",
                [fiscal_schedule_id],
                |row| {
                    Ok(FiscalLegacyFeeScheduleBindingRecord {
                        legacy_schedule_id: row.get(0)?,
                        fiscal_schedule_id: row.get(1)?,
                        fiscal_schedule_digest: row.get(2)?,
                        legacy_envelope_digest: row.get(3)?,
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
