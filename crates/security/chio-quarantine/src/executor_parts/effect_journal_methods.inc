impl<
        S: ResponseSchedulerStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > ResponseExecutor<S, E, R, A>
{
    fn ensure_apply_intent(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        let key = ResponseEffectKey {
            tenant_id: plan.tenant_id.clone(),
            effect_id: effect.effect_id.clone(),
        };
        if let Some(existing) = self.store.load_effect(&key).map_err(ExecutorError::Store)? {
            let journal = self.decode_journal(plan, effect, &existing)?;
            if !matches!(journal.phase, EffectJournalPhase::ApplyRequested) {
                return Err(ExecutorError::InvalidEffectJournal);
            }
            return Ok(existing);
        }
        let journal = EffectJournal {
            schema_version: EFFECT_JOURNAL_SCHEMA_VERSION,
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
            effect_id: effect.effect_id.clone(),
            plan_hash: plan.plan_hash,
            canonical_contribution: effect.canonical_contribution.clone(),
            contribution_hash: effect.contribution_hash,
            observed_base_version_hash: effect.observed_base_version_hash,
            apply_idempotency_key: effect_command_id(
                plan,
                &effect.effect_id,
                EffectOperation::Apply,
                0,
            )?,
            occurred_at_unix_ms: now_unix_ms,
            receipt_prior_id: None,
            phase: EffectJournalPhase::ApplyRequested,
        };
        let record = encode_effect_record(
            &journal,
            0,
            work.lease_owner_id.clone(),
            work.fencing_token,
            None,
        )?;
        match self
            .store
            .persist_effect(&record)
            .map_err(ExecutorError::Store)?
        {
            chio_security_types::ports::CreateOutcome::Created
            | chio_security_types::ports::CreateOutcome::Existing => Ok(record),
        }
    }

    fn load_effect_record(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        self.store
            .load_effect(&ResponseEffectKey {
                tenant_id: plan.tenant_id.clone(),
                effect_id: effect.effect_id.clone(),
            })
            .map_err(ExecutorError::Store)?
            .ok_or(ExecutorError::InvalidEffectJournal)
    }

    fn decode_journal(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
        record: &ResponseEffectRecord,
    ) -> Result<EffectJournal, ExecutorError> {
        let journal: EffectJournal = serde_json::from_slice(record.canonical_body.as_bytes())
            .map_err(|_| ExecutorError::InvalidEffectJournal)?;
        let canonical =
            canonical_json_bytes(&journal).map_err(|_| ExecutorError::InvalidEffectJournal)?;
        if canonical.as_slice() != record.canonical_body.as_bytes()
            || Digest32::new(*sha256(&canonical).as_bytes()) != record.body_hash
            || record.tenant_id != plan.tenant_id
            || record.action_id != plan.action_id
            || record.effect_id != effect.effect_id
            || record.state.as_str() != journal.phase.state_name()
            || journal.schema_version != EFFECT_JOURNAL_SCHEMA_VERSION
            || journal.tenant_id != plan.tenant_id
            || journal.action_id != plan.action_id
            || journal.effect_id != effect.effect_id
            || journal.plan_hash != plan.plan_hash
            || journal.canonical_contribution != effect.canonical_contribution
            || journal.contribution_hash != effect.contribution_hash
            || journal.observed_base_version_hash != effect.observed_base_version_hash
            || record.scheduler_fencing_token == 0
            || (record.generation == 0) != journal.receipt_prior_id.is_none()
            || (record.generation == 0
                && !matches!(journal.phase, EffectJournalPhase::ApplyRequested))
        {
            return Err(ExecutorError::InvalidEffectJournal);
        }
        Ok(journal)
    }

    fn update_effect_record(
        &self,
        plan_record: &ResponsePlanRecord,
        current: &ResponseEffectRecord,
        mut journal: EffectJournal,
        work: &ScheduledWork,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        journal.receipt_prior_id = Some(self.require_receipt_head(plan_record)?);
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(ExecutorError::GenerationOverflow)?;
        let record = encode_effect_record(
            &journal,
            generation,
            work.lease_owner_id.clone(),
            work.fencing_token,
            current.encrypted_rollback_ref.clone(),
        )?;
        let transition_id = effect_transition_id(current.generation, &record)?;
        self.store
            .compare_and_swap_effect(&ResponseEffectCasRequest {
                record,
                expected_generation: current.generation,
                transition_id,
            })
            .map_err(ExecutorError::Store)
    }

    fn rebind_pending_effect_command(
        &self,
        plan_record: &ResponsePlanRecord,
        current: &ResponseEffectRecord,
        journal: EffectJournal,
        work: &ScheduledWork,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        if current.scheduler_lease_owner_id == work.lease_owner_id
            && current.scheduler_fencing_token == work.fencing_token
        {
            return Ok(current.clone());
        }
        if work.fencing_token <= current.scheduler_fencing_token {
            return Err(ExecutorError::StaleLease);
        }
        self.store
            .validate_lease(work)
            .map_err(ExecutorError::Store)?;
        self.update_effect_record(plan_record, current, journal, work)
    }

    fn record_effect_mutation(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        effect_record: &ResponseEffectRecord,
        mutation: EffectMutation,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let snapshot = decode_response_record(current)?;
        let effect = snapshot
            .plan
            .effect(&effect_record.effect_id)
            .ok_or(ExecutorError::InvalidEffectJournal)?;
        let mut effect_record = effect_record.clone();
        let mut journal = self.decode_journal(&snapshot.plan, effect, &effect_record)?;
        if effect_record.scheduler_lease_owner_id != work.lease_owner_id
            || effect_record.scheduler_fencing_token != work.fencing_token
        {
            effect_record =
                self.rebind_pending_effect_command(current, &effect_record, journal, work)?;
            self.append_receipt(current, Some(&effect_record))?;
            journal = self.decode_journal(&snapshot.plan, effect, &effect_record)?;
        }
        if mutation_for_journal_phase(&journal.phase) != mutation {
            return Err(ExecutorError::InvalidEffectJournal);
        }
        let effect_transition_id = if effect_record.generation == 0 {
            if journal.receipt_prior_id.is_some()
                || !matches!(journal.phase, EffectJournalPhase::ApplyRequested)
            {
                return Err(ExecutorError::InvalidEffectJournal);
            }
            None
        } else {
            if journal.receipt_prior_id.is_none() {
                return Err(ExecutorError::InvalidEffectJournal);
            }
            Some(effect_transition_id(
                effect_record
                    .generation
                    .checked_sub(1)
                    .ok_or(ExecutorError::GenerationOverflow)?,
                &effect_record,
            )?)
        };
        // Effect CAS records are zero-based; signed transition receipts use a
        // positive, one-based generation as required by their wire schema.
        let receipt_effect_generation = effect_record
            .generation
            .checked_add(1)
            .ok_or(ExecutorError::GenerationOverflow)?;
        self.state_machine()
            .record_effect_with_receipt_scheduled(
                current,
                work,
                &EffectMutationRequest {
                    expected_generation: current.generation,
                    effect_id: effect_record.effect_id.clone(),
                    occurred_at_unix_ms: journal.occurred_at_unix_ms,
                    mutation,
                },
                &EffectReceiptContext {
                    effect_generation: receipt_effect_generation,
                    scheduler_lease_owner_id: Some(effect_record.scheduler_lease_owner_id.clone()),
                    scheduler_fencing_token: effect_record.scheduler_fencing_token,
                    effect_transition_id,
                    prior_receipt_id: journal.receipt_prior_id,
                },
            )
            .map_err(ExecutorError::StateMachine)
    }

    fn require_receipt_head(
        &self,
        plan_record: &ResponsePlanRecord,
    ) -> Result<OpaqueReceiptRef, ExecutorError> {
        self.reconcile_receipts(plan_record)?;
        let snapshot = decode_response_record(plan_record)?;
        let expected = latest_response_receipt(&snapshot)
            .and_then(|body| body.evidence_id())
            .map_err(|_| ExecutorError::Canonical)?;
        let cursor = self
            .store
            .load_receipt_cursor(&ResponsePlanKey {
                tenant_id: snapshot.plan.tenant_id.clone(),
                action_id: snapshot.plan.action_id.clone(),
            })
            .map_err(ExecutorError::Store)?
            .ok_or(ExecutorError::ReceiptLineageMismatch)?;
        validate_receipt_cursor(
            &cursor,
            &ResponseReceiptCursor {
                tenant_id: snapshot.plan.tenant_id.clone(),
                action_id: snapshot.plan.action_id.clone(),
                plan_hash: snapshot.plan.plan_hash,
                generation: 0,
                current_evidence_id: snapshot.plan.trigger_finding_receipt_id.clone(),
            },
            &snapshot,
        )?;
        if cursor.generation
            != u64::try_from(snapshot.mutations.len())
                .map_err(|_| ExecutorError::GenerationOverflow)?
            || cursor.current_evidence_id != expected
        {
            return Err(ExecutorError::ReceiptLineageMismatch);
        }
        Ok(cursor.current_evidence_id)
    }

    fn append_receipt(
        &self,
        plan_record: &ResponsePlanRecord,
        _effect_record: Option<&ResponseEffectRecord>,
    ) -> Result<(), ExecutorError> {
        let snapshot = decode_response_record(plan_record)?;
        self.reconcile_snapshot_receipts(&snapshot)
    }

    fn reconcile_receipts(&self, plan_record: &ResponsePlanRecord) -> Result<(), ExecutorError> {
        let snapshot = decode_response_record(plan_record)?;
        self.reconcile_snapshot_receipts(&snapshot)
    }

    fn reconcile_snapshot_receipts(
        &self,
        snapshot: &ResponseSnapshot,
    ) -> Result<(), ExecutorError> {
        let key = ResponsePlanKey {
            tenant_id: snapshot.plan.tenant_id.clone(),
            action_id: snapshot.plan.action_id.clone(),
        };
        let initial = ResponseReceiptCursor {
            tenant_id: snapshot.plan.tenant_id.clone(),
            action_id: snapshot.plan.action_id.clone(),
            plan_hash: snapshot.plan.plan_hash,
            generation: 0,
            current_evidence_id: snapshot.plan.trigger_finding_receipt_id.clone(),
        };
        if self
            .store
            .load_receipt_cursor(&key)
            .map_err(ExecutorError::Store)?
            .is_none()
        {
            self.store
                .initialize_receipt_cursor(&initial)
                .map_err(ExecutorError::Store)?;
        }
        let mut cursor = self
            .store
            .load_receipt_cursor(&key)
            .map_err(ExecutorError::Store)?
            .ok_or_else(|| ExecutorError::Store(PortError::integrity_failure()))?;
        validate_receipt_cursor(&cursor, &initial, snapshot)?;

        loop {
            let mutation_index = usize::try_from(cursor.generation)
                .map_err(|_| ExecutorError::GenerationOverflow)?;
            if mutation_index == snapshot.mutations.len() {
                return Ok(());
            }
            let body = response_receipt_for_mutation(snapshot, mutation_index)
                .map_err(|_| ExecutorError::Canonical)?;
            if body.header().prior_receipt_ids.as_slice() != [cursor.current_evidence_id.clone()] {
                return Err(ExecutorError::ReceiptLineageMismatch);
            }
            let request = receipt_append_request(&body).map_err(|_| ExecutorError::Canonical)?;
            let appended = self
                .receipts
                .sign_and_append(&request)
                .map_err(ExecutorError::Receipt)?;
            if appended != request.evidence_id {
                return Err(ExecutorError::Receipt(PortError::integrity_failure()));
            }
            let next_generation = cursor
                .generation
                .checked_add(1)
                .ok_or(ExecutorError::GenerationOverflow)?;
            let next = ResponseReceiptCursor {
                tenant_id: cursor.tenant_id.clone(),
                action_id: cursor.action_id.clone(),
                plan_hash: cursor.plan_hash,
                generation: next_generation,
                current_evidence_id: request.evidence_id,
            };
            let cas = ResponseReceiptCursorCasRequest {
                cursor: next.clone(),
                expected_generation: cursor.generation,
                expected_evidence_id: cursor.current_evidence_id.clone(),
                transition_id: receipt_cursor_transition_id(&cursor, &next)?,
            };
            cursor = match self.store.compare_and_swap_receipt_cursor(&cas) {
                Ok(updated) if updated == next => updated,
                Ok(_) => {
                    return Err(ExecutorError::Store(PortError::integrity_failure()));
                }
                Err(error) => {
                    let reloaded = self
                        .store
                        .load_receipt_cursor(&key)
                        .map_err(ExecutorError::Store)?;
                    if reloaded.as_ref() == Some(&next) {
                        next
                    } else {
                        return Err(ExecutorError::Store(error));
                    }
                }
            };
        }
    }

    fn page_rollback_failure(
        &self,
        snapshot: &ResponseSnapshot,
        record: &ResponsePlanRecord,
    ) -> Result<(), ExecutorError> {
        let mutation = snapshot
            .mutations
            .as_slice()
            .last()
            .ok_or(ExecutorError::InvalidEffectJournal)?;
        let event_id = domain_record_id(
            "response_alert_event",
            ALERT_EVENT_ID_DOMAIN,
            &(
                &snapshot.plan.tenant_id,
                &snapshot.plan.action_id,
                &snapshot.plan.trigger_finding_id,
                mutation.transition_id(),
                mutation.occurred_at_unix_ms(),
                record.body_hash,
            ),
        )?;
        let idempotency_key = domain_record_id(
            "response_alert_command",
            ALERT_IDEMPOTENCY_KEY_DOMAIN,
            &event_id,
        )?;
        let alert = SecurityAlert {
            tenant_id: snapshot.plan.tenant_id.clone(),
            event_id,
            idempotency_key,
            occurred_at_unix_ms: mutation.occurred_at_unix_ms(),
            alert_type: record_id("response_rollback_partial")?,
            finding_id_hash: domain_hash(ALERT_HASH_DOMAIN, &snapshot.plan.trigger_finding_id)?,
            action_id_hash: Some(domain_hash(ALERT_HASH_DOMAIN, &snapshot.plan.action_id)?),
            evidence_hash: record.body_hash,
        };
        let status = self.alerts.page(&alert).map_err(ExecutorError::Alert)?;
        let persisted = self
            .alerts
            .load_delivery(&AlertDeliveryQuery { alert })
            .map_err(ExecutorError::Alert)?;
        if persisted != Some(status) {
            return Err(ExecutorError::Alert(PortError::integrity_failure()));
        }
        Ok(())
    }

    fn load_effect_execution_status(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
        lookup: EffectResultLookup<'_>,
        work: &ScheduledWork,
    ) -> Result<EffectExecutionStatus, ExecutorError> {
        if lookup.command_fencing_token == 0 {
            return Err(ExecutorError::InvalidEffectJournal);
        }
        let query = EffectResultQuery {
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
            plan_hash: plan.plan_hash,
            effect_id: effect.effect_id.clone(),
            effect_kind: effect.kind,
            target: effect.target.clone(),
            plan_expires_at_unix_ms: plan.expires_at_unix_ms,
            operation: lookup.operation,
            idempotency_key: lookup.idempotency_key.clone(),
            expected_version_hash: lookup.expected_version_hash,
            contribution_hash: effect.contribution_hash,
            // Result lookup is bound to the authority identity used for the
            // original external command. A takeover lease may have a newer
            // scheduler token, but rebinding the lookup to that token would
            // hide an already-completed mutation and execute it twice.
            scheduler_lease_owner_id: lookup.command_lease_owner_id.clone(),
            scheduler_fencing_token: lookup.command_fencing_token,
        };
        self.store
            .validate_lease(work)
            .map_err(ExecutorError::Store)?;
        self.effects
            .load_result(&query)
            .map_err(ExecutorError::EffectQuery)
    }

    fn validate_work(
        &self,
        snapshot: &ResponseSnapshot,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<(), ExecutorError> {
        if work.tenant_id != snapshot.plan.tenant_id || work.action_id != snapshot.plan.action_id {
            return Err(ExecutorError::WorkMismatch);
        }
        if work.lease_expires_at_unix_ms <= now_unix_ms {
            return Err(ExecutorError::StaleLease);
        }
        Ok(())
    }

    fn state_machine(&self) -> ResponseStateMachine<S> {
        ResponseStateMachine::new(Arc::clone(&self.store))
    }
}
