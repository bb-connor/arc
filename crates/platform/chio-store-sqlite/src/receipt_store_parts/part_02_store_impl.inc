impl SqliteReceiptStore {
    /// Reader-pool connection. READS ONLY: every write transaction must go
    /// through `writer_handle().run_write` (single-writer discipline). The
    /// reader pool is asserted read-only by
    /// `reader_pool_never_begins_a_write_transaction` in tests.
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.database_identity_file.validate()?;
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn reader_connection_for_test(
        &self,
    ) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.connection()
    }

    pub(crate) fn writer_handle(&self) -> WriterHandle {
        WriterHandle {
            sender: self.receipt_commit_actor.sender.clone(),
            health: Arc::clone(&self.receipt_commit_actor.health),
            database_identity_file: Some(Arc::clone(&self.database_identity_file)),
        }
    }

    /// Highest tool-receipt replication seq, or 0 on an empty store. Single
    /// indexed MAX read; does not materialize the store.
    pub fn max_tool_receipt_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Highest child-receipt replication seq, or 0 on an empty store.
    pub fn max_child_receipt_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_child_receipts",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Multi-tenant receipt isolation: toggle strict-isolation
    /// mode on tenant-scoped queries.
    ///
    /// When `strict = true`, a `tenant_filter = Some(id)` query returns
    /// ONLY rows whose `tenant_id = id`. Pre-multitenant receipts with
    /// `tenant_id IS NULL` are excluded.
    ///
    /// When `strict = false`, the same query also includes rows where
    /// `tenant_id IS NULL` -- the pre-multitenant "public" fallback
    /// set -- so pre-multitenant (NULL-tagged) receipts remain visible during
    /// an explicit compatibility window.
    ///
    /// A `tenant_filter = None` admin / compat query always returns
    /// every row regardless of this setting.
    pub fn with_strict_tenant_isolation(&self, strict: bool) {
        self.strict_tenant_isolation
            .store(strict, std::sync::atomic::Ordering::SeqCst);
    }

    /// Read the current strict-tenant-isolation setting.
    #[must_use]
    pub fn strict_tenant_isolation_enabled(&self) -> bool {
        self.strict_tenant_isolation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Read-only after open (staged-rollout flag).
    #[must_use]
    pub fn incremental_verification_enabled(&self) -> bool {
        self.incremental_verification
    }

    fn writer_checkpoint_snapshot(&self) -> WriterCheckpointSnapshot {
        let health = &self.receipt_commit_actor.health;
        WriterCheckpointSnapshot {
            checkpoint_seq: health.head_checkpoint_seq.load(Ordering::SeqCst),
            checkpointed_entry_seq: health.head_checkpointed_entry_seq.load(Ordering::SeqCst),
        }
    }

    #[cfg(test)]
    pub(crate) fn writer_head_snapshot(&self) -> WriterHeadSnapshot {
        let health = &self.receipt_commit_actor.health;
        WriterHeadSnapshot {
            checkpoint_seq: health.head_checkpoint_seq.load(Ordering::SeqCst),
            checkpointed_entry_seq: health.head_checkpointed_entry_seq.load(Ordering::SeqCst),
            claim_log_count: health.head_claim_log_count.load(Ordering::SeqCst),
            claim_log_max_seq: health.head_claim_log_max_seq.load(Ordering::SeqCst),
        }
    }

    pub fn append_chio_receipt_canonical(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
            .map(|_| ())
    }

    pub fn append_chio_receipt_canonical_bytes(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical(canonical)
    }

    pub fn append_chio_receipt_canonical_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        let receipt = decode_canonical_chio_receipt(canonical.as_ref())?;
        let raw_json = canonical_receipt_json(canonical.as_ref())?;
        self.append_verified_chio_receipt_record(&receipt, raw_json, false)
    }

    pub fn append_chio_receipt_canonical_bytes_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
    }

    fn append_verified_chio_receipt_record(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor
            .append(receipt.clone(), raw_json.to_string(), ensure_lineage)
    }

    fn append_verified_chio_receipt_record_with_timeout(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
        ensure_lineage: bool,
        timeout: Duration,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor.append_with_timeout(
            receipt.clone(),
            raw_json.to_string(),
            ensure_lineage,
            timeout,
        )
    }

    pub fn append_chio_receipt_with_settlement_observer_outbox_with_timeout(
        &self,
        receipt: &ChioReceipt,
        budget: Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.writer_handle().run_write_receipt_with_timeout(
            self.settlement_observer_append_job(receipt)?,
            budget,
        )
    }

    fn settlement_observer_append_job(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<
        impl FnOnce(&mut SqliteStoreConnection) -> Result<Option<u64>, ReceiptStoreError>
            + Send
            + 'static,
        ReceiptStoreError,
    > {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        let raw_json = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let raw_json = std::str::from_utf8(raw_json.as_slice())
            .map_err(|error| {
                ReceiptStoreError::Canonical(format!(
                    "canonical receipt bytes are not UTF-8: {error}"
                ))
            })?
            .to_string();
        let receipt = receipt.clone();
        Ok(move |connection: &mut SqliteStoreConnection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let seq = append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            enqueue_settlement_observer_outbox_tx(&tx, &receipt)?;
            tx.commit()?;
            Ok(Some(seq))
        })
    }

    /// Best-effort writer liveness derived from the commit-actor counters,
    /// assessed against the operator-configured `stall_threshold`. See
    /// [`classify_writer_liveness`] for the transition rules.
    pub fn writer_liveness(&self, stall_threshold: Duration) -> chio_kernel::ReceiptWriterLiveness {
        classify_writer_liveness(
            &self.receipt_commit_actor.writer_counters(),
            u64::try_from(stall_threshold.as_millis()).unwrap_or(u64::MAX),
            RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64,
            self.receipt_commit_actor.backlog_started_unix_ms(),
            current_unix_ms(),
        )
    }

    pub fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        if receipt.id != consumption.consumer_receipt_id {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption consumer receipt id does not match appended receipt"
                    .to_string(),
            ));
        }
        if receipt.tenant_id.as_deref() != consumption.tenant_id.as_deref() {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption tenant id does not match appended receipt".to_string(),
            ));
        }
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        let raw_json = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let raw_json = std::str::from_utf8(raw_json.as_slice()).map_err(|error| {
            ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
        })?;
        let raw_json = raw_json.to_string();
        let receipt = receipt.clone();
        let consumption = consumption.clone();
        self.writer_handle().run_write_receipt(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            consume_authorization_receipt_tx(&tx, &consumption)?;
            append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Durably write a dispatch intent as a metadata-only single-writer job.
    /// The response is sent only after `tx.commit()` returns, so the caller
    /// observes a durable (WAL-fsynced) commit before it proceeds to dispatch.
    pub fn record_dispatch_intent(
        &self,
        intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<(), ReceiptStoreError> {
        self.writer_handle().run_write(dispatch_intent_insert_job(
            intent,
            self.instance_token.clone(),
        ))
    }

    /// Bounded variant of [`Self::record_dispatch_intent`]: identical up to
    /// the response wait, which is capped at `budget` so a writer that wedges
    /// after the pre-dispatch liveness check fails this caller closed instead
    /// of hanging the evaluation inside the intent write. A timed-out write
    /// is also ABANDONED: the caller denies before dispatch on timeout, so
    /// the job still queued on a slow-but-alive writer must not land a stale
    /// row that would dead-letter at the next boot as a false orphan for a
    /// call that never executed. Because the marker cannot stop an insert
    /// that has already passed its final check and is inside its commit when
    /// the deadline expires, the timeout path also enqueues a sweep behind
    /// the insert, keyed to this attempt's own commit, so a commit that
    /// outruns the marker leaves no row behind while a pre-existing intent
    /// for the same request is never touched.
    pub fn record_dispatch_intent_with_timeout(
        &self,
        intent: &chio_kernel::receipt_store::DispatchIntentRecord,
        budget: Duration,
    ) -> Result<(), ReceiptStoreError> {
        let abandoned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let landed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let job = dispatch_intent_insert_job_unless_abandoned(
            intent,
            self.instance_token.clone(),
            Arc::clone(&abandoned),
            Arc::clone(&landed),
        );
        let result = self
            .writer_handle()
            .run_write_abandoning_on_timeout(job, budget, abandoned);
        if matches!(result, Err(ReceiptStoreError::Timeout { .. })) {
            // The caller is about to deny before dispatch, yet an insert that
            // was inside its commit when the marker landed may still have
            // committed. Enqueue a sweep on the same single-writer queue:
            // FIFO order runs it strictly after the insert job, so it deletes
            // the row when the straddling commit recorded itself in the
            // `landed` slot and reports NotFound when the insert refused.
            // The slot keys the sweep to THIS attempt: a timed-out retry or
            // concurrent duplicate whose insert collided with a request's
            // pre-existing open intent must not delete that earlier
            // invocation's crash marker out from under its in-flight call.
            // The sweep is enqueued detached: the denial this caller is
            // about to return does not depend on the sweep's outcome, and a
            // bounded wait here would stack a second budget on top of the
            // one the insert already consumed, doubling the pre-dispatch
            // wall-clock cap on the same stalled writer. The queued sweep
            // still drains with the writer, so a slow-but-alive writer
            // cannot leave a row that would dead-letter as a false orphan
            // for a call that never dispatched. NotFound is the common
            // outcome (the insert refused via the marker); a refused
            // enqueue leaves the row for boot reconciliation, which at
            // worst surfaces an extra operator-visible dead letter rather
            // than losing a real orphan.
            let key = chio_kernel::receipt_store::DispatchIntentKey {
                request_id: intent.request_id.clone(),
                parameter_hash: intent.parameter_hash.clone(),
                tenant_id: intent.tenant_id.clone(),
            };
            let _ = self
                .writer_handle()
                .run_write_detached(dispatch_intent_sweep_landed_job(&key, landed));
        }
        result
    }

    /// Append a receipt and, in the SAME immediate transaction, consume the
    /// matching dispatch intent: a crash before commit leaves the intent open
    /// and the receipt absent, and a successful commit removes the intent and
    /// persists the receipt, so exactly one of the two states survives.
    pub fn append_chio_receipt_consuming_intent(
        &self,
        receipt: &ChioReceipt,
        key: &chio_kernel::receipt_store::DispatchIntentKey,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.writer_handle()
            .run_write_receipt(self.dispatch_intent_consuming_append_job(receipt, key, false)?)
    }

    /// Bounded variant of [`Self::append_chio_receipt_consuming_intent`]: the
    /// response wait is capped at `budget` so a wedged writer cannot pin the
    /// kernel-wide receipt write lock through the consuming append.
    pub fn append_chio_receipt_consuming_intent_with_timeout(
        &self,
        receipt: &ChioReceipt,
        key: &chio_kernel::receipt_store::DispatchIntentKey,
        budget: Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.writer_handle().run_write_receipt_with_timeout(
            self.dispatch_intent_consuming_append_job(receipt, key, false)?,
            budget,
        )
    }

    pub fn append_chio_receipt_consuming_intent_with_settlement_observer_outbox_with_timeout(
        &self,
        receipt: &ChioReceipt,
        key: &chio_kernel::receipt_store::DispatchIntentKey,
        budget: Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.writer_handle().run_write_receipt_with_timeout(
            self.dispatch_intent_consuming_append_job(receipt, key, true)?,
            budget,
        )
    }

    /// Validate the receipt/key binding and build the writer job that deletes
    /// the intent and inserts the receipt inside one immediate transaction.
    fn dispatch_intent_consuming_append_job(
        &self,
        receipt: &ChioReceipt,
        key: &chio_kernel::receipt_store::DispatchIntentKey,
        enqueue_settlement_observer: bool,
    ) -> Result<
        impl FnOnce(&mut SqliteStoreConnection) -> Result<Option<u64>, ReceiptStoreError>
            + Send
            + 'static,
        ReceiptStoreError,
    > {
        ensure_chio_receipt_verified(receipt)?;
        if receipt.action.parameter_hash != key.parameter_hash {
            return Err(ReceiptStoreError::Conflict(
                "dispatch intent key parameter_hash does not match appended receipt".to_string(),
            ));
        }
        if receipt.tenant_id.as_deref() != key.tenant_id.as_deref() {
            return Err(ReceiptStoreError::Conflict(
                "dispatch intent key tenant id does not match appended receipt".to_string(),
            ));
        }
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        let raw_json = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let raw_json = std::str::from_utf8(raw_json.as_slice())
            .map_err(|error| {
                ReceiptStoreError::Canonical(format!(
                    "canonical receipt bytes are not UTF-8: {error}"
                ))
            })?
            .to_string();
        let receipt = receipt.clone();
        let key = key.clone();
        Ok(move |connection: &mut SqliteStoreConnection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            finalize_dispatch_intent_tx(&tx, &key)?;
            let seq = append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            if enqueue_settlement_observer {
                enqueue_settlement_observer_outbox_tx(&tx, &receipt)?;
            }
            tx.commit()?;
            Ok(Some(seq))
        })
    }

    pub fn supports_durable_settlement_observer_outbox(&self) -> bool {
        true
    }

    pub fn list_settlement_observer_outbox_receipt_ids(
        &self,
        now_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<String>, ReceiptStoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now_unix_ms = sqlite_i64(now_unix_ms, "settlement-observer inventory time")?;
        let limit = i64::try_from(limit).map_err(|_| {
            ReceiptStoreError::Conflict(
                "settlement-observer inventory limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT receipt_id
            FROM chio_settlement_observer_outbox AS candidate
            WHERE candidate.state != 'completed'
              AND (
                  candidate.state = 'pending'
                  OR (
                      candidate.state IN ('claimed', 'routing')
                      AND candidate.claim_deadline_unix_ms <= ?1
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM chio_settlement_observer_outbox AS earlier
                  WHERE earlier.state != 'completed'
                    AND (
                        earlier.finalized_at < candidate.finalized_at
                        OR (
                            earlier.finalized_at = candidate.finalized_at
                            AND earlier.receipt_id < candidate.receipt_id
                        )
                    )
              )
            ORDER BY finalized_at ASC, receipt_id ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![now_unix_ms, limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut receipt_ids = Vec::new();
        for row in rows {
            receipt_ids.push(row?);
        }
        Ok(receipt_ids)
    }

    pub fn count_unfinished_settlement_observer_outbox(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let count = connection.query_row(
            "SELECT COUNT(*) FROM chio_settlement_observer_outbox WHERE state != 'completed'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        sqlite_u64(count, "unfinished settlement-observer outbox count")
    }

    pub fn claim_settlement_observer_outbox(
        &self,
        receipt_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<chio_kernel::SettlementObserverOutboxClaimOutcome, ReceiptStoreError> {
        validate_settlement_observer_outbox_text(
            receipt_id,
            "receipt id",
            SETTLEMENT_OBSERVER_OUTBOX_RECEIPT_ID_MAX_BYTES,
        )?;
        validate_settlement_observer_outbox_text(
            claim_token,
            "claim token",
            SETTLEMENT_OBSERVER_OUTBOX_CLAIM_TOKEN_MAX_BYTES,
        )?;
        if claim_deadline_unix_ms <= now_unix_ms {
            return Err(ReceiptStoreError::Conflict(
                "settlement-observer claim deadline must be after claim time".to_string(),
            ));
        }
        let receipt_id = receipt_id.to_string();
        let claim_token = claim_token.to_string();
        self.writer_handle().run_write(move |connection| {
            let now_unix_ms = sqlite_i64(now_unix_ms, "settlement-observer claim time")?;
            let claim_deadline_unix_ms = sqlite_i64(
                claim_deadline_unix_ms,
                "settlement-observer claim deadline",
            )?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let claimed_version = tx
                .query_row(
                    r#"
                    UPDATE chio_settlement_observer_outbox
                    SET state = CASE
                            WHEN state = 'routing' THEN 'routing'
                            ELSE 'claimed'
                        END,
                        claim_token = ?2,
                        claim_deadline_unix_ms = ?3,
                        version = version + 1,
                        last_error = NULL
                    WHERE receipt_id = ?1
                      AND (
                          state = 'pending'
                          OR (
                              state IN ('claimed', 'routing')
                              AND claim_deadline_unix_ms <= ?4
                          )
                      )
                    RETURNING version, finalized_at, staged_status_json
                    "#,
                    params![
                        receipt_id.as_str(),
                        claim_token.as_str(),
                        claim_deadline_unix_ms,
                        now_unix_ms,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .optional()?;
            let outcome = if let Some((version, finalized_at, staged_status_json)) = claimed_version
            {
                chio_kernel::SettlementObserverOutboxClaimOutcome::Claimed(
                    chio_kernel::SettlementObserverOutboxLease {
                        receipt_id: receipt_id.clone(),
                        finalized_at: sqlite_u64(
                            finalized_at,
                            "settlement-observer finalized_at",
                        )?,
                        claim_token: claim_token.clone(),
                        claim_deadline_unix_ms: sqlite_u64(
                            claim_deadline_unix_ms,
                            "settlement-observer claim deadline",
                        )?,
                        version: sqlite_u64(version, "settlement-observer outbox version")?,
                        staged_status_json,
                    },
                )
            } else {
                match tx
                    .query_row(
                        "SELECT state FROM chio_settlement_observer_outbox WHERE receipt_id = ?1",
                        params![receipt_id.as_str()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .as_deref()
                {
                    Some("completed") => {
                        chio_kernel::SettlementObserverOutboxClaimOutcome::Completed
                    }
                    Some("pending" | "claimed" | "routing") => {
                        chio_kernel::SettlementObserverOutboxClaimOutcome::Busy
                    }
                    Some(other) => {
                        return Err(ReceiptStoreError::Conflict(format!(
                            "settlement-observer outbox has unknown state `{other}`"
                        )))
                    }
                    None => chio_kernel::SettlementObserverOutboxClaimOutcome::Missing,
                }
            };
            tx.commit()?;
            Ok(outcome)
        })
    }

    pub fn stage_settlement_observer_outbox_status(
        &self,
        receipt_id: &str,
        expected_version: u64,
        claim_token: &str,
        status_json: &str,
    ) -> Result<Option<chio_kernel::SettlementObserverOutboxLease>, ReceiptStoreError> {
        validate_settlement_observer_outbox_text(
            receipt_id,
            "receipt id",
            SETTLEMENT_OBSERVER_OUTBOX_RECEIPT_ID_MAX_BYTES,
        )?;
        validate_settlement_observer_outbox_text(
            claim_token,
            "claim token",
            SETTLEMENT_OBSERVER_OUTBOX_CLAIM_TOKEN_MAX_BYTES,
        )?;
        validate_settlement_observer_outbox_text(
            status_json,
            "staged status",
            SETTLEMENT_OBSERVER_OUTBOX_STAGED_STATUS_MAX_BYTES,
        )?;
        let receipt_id = receipt_id.to_string();
        let claim_token = claim_token.to_string();
        let status_json = status_json.to_string();
        self.writer_handle().run_write(move |connection| {
            let expected_version =
                sqlite_i64(expected_version, "settlement-observer staging version")?;
            let staged = connection
                .query_row(
                    r#"
                    UPDATE chio_settlement_observer_outbox
                    SET state = 'routing',
                        version = version + 1,
                        staged_status_json = ?4,
                        last_error = NULL
                    WHERE receipt_id = ?1
                      AND state = 'claimed'
                      AND version = ?2
                      AND claim_token = ?3
                    RETURNING version, finalized_at, claim_deadline_unix_ms
                    "#,
                    params![
                        receipt_id.as_str(),
                        expected_version,
                        claim_token.as_str(),
                        status_json.as_str(),
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            staged
                .map(|(version, finalized_at, claim_deadline_unix_ms)| {
                    Ok(chio_kernel::SettlementObserverOutboxLease {
                        receipt_id,
                        finalized_at: sqlite_u64(
                            finalized_at,
                            "settlement-observer finalized_at",
                        )?,
                        claim_token,
                        claim_deadline_unix_ms: sqlite_u64(
                            claim_deadline_unix_ms,
                            "settlement-observer claim deadline",
                        )?,
                        version: sqlite_u64(version, "settlement-observer outbox version")?,
                        staged_status_json: Some(status_json),
                    })
                })
                .transpose()
        })
    }

    pub fn acknowledge_settlement_observer_outbox(
        &self,
        receipt_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<bool, ReceiptStoreError> {
        validate_settlement_observer_outbox_text(
            receipt_id,
            "receipt id",
            SETTLEMENT_OBSERVER_OUTBOX_RECEIPT_ID_MAX_BYTES,
        )?;
        validate_settlement_observer_outbox_text(
            claim_token,
            "claim token",
            SETTLEMENT_OBSERVER_OUTBOX_CLAIM_TOKEN_MAX_BYTES,
        )?;
        let receipt_id = receipt_id.to_string();
        let claim_token = claim_token.to_string();
        self.writer_handle().run_write(move |connection| {
            let expected_version = sqlite_i64(
                expected_version,
                "settlement-observer acknowledgement version",
            )?;
            let changed = connection.execute(
                r#"
                UPDATE chio_settlement_observer_outbox
                SET state = 'completed',
                    claim_token = NULL,
                    claim_deadline_unix_ms = NULL,
                    version = version + 1,
                    staged_status_json = NULL,
                    last_error = NULL
                WHERE receipt_id = ?1
                  AND state = 'routing'
                  AND version = ?2
                  AND claim_token = ?3
                "#,
                params![receipt_id.as_str(), expected_version, claim_token.as_str()],
            )?;
            if changed == 1 {
                connection.execute(
                    r#"
                    DELETE FROM chio_settlement_observer_outbox
                    WHERE receipt_id = ?1
                      AND state = 'completed'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM chio_tool_receipts
                          WHERE receipt_id = ?1
                      )
                    "#,
                    params![receipt_id.as_str()],
                )?;
            }
            Ok(changed == 1)
        })
    }

    pub fn abandon_settlement_observer_outbox(
        &self,
        receipt_id: &str,
        expected_version: u64,
        claim_token: &str,
        last_error: &str,
    ) -> Result<bool, ReceiptStoreError> {
        validate_settlement_observer_outbox_text(
            receipt_id,
            "receipt id",
            SETTLEMENT_OBSERVER_OUTBOX_RECEIPT_ID_MAX_BYTES,
        )?;
        validate_settlement_observer_outbox_text(
            claim_token,
            "claim token",
            SETTLEMENT_OBSERVER_OUTBOX_CLAIM_TOKEN_MAX_BYTES,
        )?;
        let receipt_id = receipt_id.to_string();
        let claim_token = claim_token.to_string();
        let last_error = truncate_settlement_observer_outbox_error(last_error);
        self.writer_handle().run_write(move |connection| {
            let expected_version =
                sqlite_i64(expected_version, "settlement-observer abandon version")?;
            let changed = connection.execute(
                r#"
                UPDATE chio_settlement_observer_outbox
                SET state = CASE
                        WHEN state = 'routing' THEN 'routing'
                        ELSE 'pending'
                    END,
                    claim_token = CASE
                        WHEN state = 'routing' THEN claim_token
                        ELSE NULL
                    END,
                    claim_deadline_unix_ms = CASE
                        WHEN state = 'routing' THEN 0
                        ELSE NULL
                    END,
                    version = version + 1,
                    last_error = ?4
                WHERE receipt_id = ?1
                  AND state IN ('claimed', 'routing')
                  AND version = ?2
                  AND claim_token = ?3
                "#,
                params![
                    receipt_id.as_str(),
                    expected_version,
                    claim_token.as_str(),
                    last_error,
                ],
            )?;
            Ok(changed == 1)
        })
    }

    /// Attach a rail authorization id to the open monetary intent for
    /// `(tenant_id, request_id)`. Best-effort from the caller's perspective
    /// (`NotFound` when the intent was already consumed or never written),
    /// but the update itself commits durably on the single writer.
    pub fn attach_dispatch_intent_rail_ref(
        &self,
        request_id: &str,
        tenant_id: Option<&str>,
        rail_authorization_id: &str,
    ) -> Result<(), ReceiptStoreError> {
        self.writer_handle().run_write(dispatch_intent_rail_ref_job(
            request_id,
            tenant_id,
            rail_authorization_id,
        ))
    }

    /// Bounded variant of [`Self::attach_dispatch_intent_rail_ref`], so the
    /// best-effort post-authorize attach fails closed within budget instead
    /// of hanging its caller on a wedged writer.
    pub fn attach_dispatch_intent_rail_ref_with_timeout(
        &self,
        request_id: &str,
        tenant_id: Option<&str>,
        rail_authorization_id: &str,
        budget: Duration,
    ) -> Result<(), ReceiptStoreError> {
        self.writer_handle().run_write_with_timeout(
            dispatch_intent_rail_ref_job(request_id, tenant_id, rail_authorization_id),
            budget,
        )
    }

    /// Delete the open intent for a call that returned to its caller without
    /// dispatching (no effect, no terminal receipt): the row must not
    /// survive to dead-letter as a false orphan at the next boot.
    pub fn clear_dispatch_intent(
        &self,
        key: &chio_kernel::receipt_store::DispatchIntentKey,
    ) -> Result<(), ReceiptStoreError> {
        self.writer_handle()
            .run_write(dispatch_intent_clear_job(key))
    }

    /// Bounded variant of [`Self::clear_dispatch_intent`]: the response wait
    /// is capped at `budget` so the non-dispatch exit cannot hang its caller
    /// on a wedged writer.
    pub fn clear_dispatch_intent_with_timeout(
        &self,
        key: &chio_kernel::receipt_store::DispatchIntentKey,
        budget: Duration,
    ) -> Result<(), ReceiptStoreError> {
        self.writer_handle()
            .run_write_with_timeout(dispatch_intent_clear_job(key), budget)
    }

    /// List the open dispatch intents, oldest first: the operator view of
    /// work that is either in flight or awaiting boot reconciliation.
    pub fn open_dispatch_intents(
        &self,
    ) -> Result<Vec<chio_kernel::receipt_store::DispatchIntentRecord>, ReceiptStoreError> {
        let connection = self.connection()?;
        select_open_dispatch_intents(&connection)
    }

    /// True when [`Self::reconcile_dispatch_intents`] is worth re-running
    /// while the store serves: an on-disk database can gain and lose
    /// sibling writer instances at any time, so a crashed sibling's orphans
    /// only surface if some survivor re-reconciles. An in-memory database
    /// can have no siblings; its attach-time pass is complete.
    pub fn supports_dispatch_intent_recovery(&self) -> bool {
        self.writer_lifetime_lock.is_some()
    }

    /// True when a journaled dispatch intent survives a process crash: the
    /// database is file-backed, so a committed row (WAL, synchronous FULL)
    /// outlives the process. An in-memory database loses the journal with
    /// the process and can never honor the crash-marker guarantee the
    /// journal exists to provide.
    pub fn supports_durable_dispatch_intent_journal(&self) -> bool {
        self.writer_lifetime_lock.is_some()
    }

    /// Resolve every open intent journaled by another store instance (a
    /// crashed prior incarnation, or a sibling on a shared database file).
    /// Reads run on the reader pool and the reconciler runs on the calling
    /// thread (so a rail-querying reconciler never blocks the single
    /// writer); the resulting annotations are applied in one writer
    /// transaction.
    ///
    /// Safe to run at any time, not only at attach: rows carrying this
    /// instance's own owner token are its live in-flight work and are never
    /// candidates, so a serving store can re-run the pass to pick up a
    /// sibling that crashed after this instance attached.
    ///
    /// Claiming an open row asserts its writer is gone, but the database
    /// file may be shared with live sibling instances whose in-flight calls
    /// own some of these rows. Liveness is therefore judged per owner,
    /// serialized under a sidecar probe mutex: every instance holds its own
    /// owner mark for its open's lifetime, and a foreign row is claimed
    /// only when a non-blocking probe acquires ITS owner's mark, proving
    /// that owner gone. A crashed writer's orphans thus surface even while
    /// other siblings stay live, and a live writer's rows always defer to
    /// it (reported, never silent). A row naming no probeable owner
    /// (journaled before owner tokens existed) is claimed only after
    /// converting this instance's shared lifetime mark to exclusive,
    /// proving no sibling at all, so a single-instance restart still
    /// reconciles everything foreign.
    pub fn reconcile_dispatch_intents(
        &self,
        reconciler: &dyn chio_kernel::receipt_store::DispatchIntentReconciler,
    ) -> Result<chio_kernel::receipt_store::DispatchIntentReconcileReport, ReceiptStoreError> {
        use chio_kernel::receipt_store::{DispatchIntentReconcileReport, DispatchIntentResolution};
        // First read without any sidecar traffic: the recovery worker calls
        // this on a cadence, and an idle store should answer with one
        // indexed query. The authoritative candidate set is re-read under
        // the probe mutex below.
        let foreign_open = {
            let connection = self.connection()?;
            select_open_dispatch_intents_excluding_owner(&connection, &self.instance_token)?
        };
        let mut report = DispatchIntentReconcileReport {
            open: foreign_open.len() as u64,
            ..DispatchIntentReconcileReport::default()
        };
        if foreign_open.is_empty() {
            return Ok(report);
        }
        // Declaration order is load-bearing: on an unwind the downgrade
        // guard and the held owner marks (declared later) drop first, while
        // the probe mutex is still held, and the probe releases after them.
        let mut reconcile_probe: Option<std::fs::File> = None;
        let mut exclusive_mark = MarkDowngradeGuard { mark: None };
        // Marks of owners proven gone, held (with their paths) until their
        // rows are claimed and the stale files removed.
        let mut claimed_owner_marks: Vec<(std::fs::File, std::path::PathBuf)> = Vec::new();
        let claimable = match &self.writer_lifetime_lock {
            // An in-memory database cannot be shared with sibling
            // instances, so every foreign row (a prior open within this
            // process) is an orphan.
            None => foreign_open
                .into_iter()
                .map(|row| row.record)
                .collect::<Vec<_>>(),
            Some(lock) => {
                // Serialize sibling reconcile passes on a separate sidecar
                // mutex BEFORE touching any mark. flock conversions are not
                // atomic: upgrading drops this instance's shared mark for
                // an instant while the exclusive attempt resolves, so two
                // instances converting concurrently could each observe the
                // other markless, win exclusivity in turn, and dead-letter
                // each other's LIVE in-flight intents. With the probe mutex
                // held, every sibling's marks are continuously present
                // (siblings only convert or clean up under this same
                // mutex). A refused probe means a live sibling is
                // mid-reconcile: defer to it without disturbing this
                // instance's own marks.
                let probe = open_sidecar_lock_file(&lock.probe_path)?;
                match probe.try_lock() {
                    Ok(()) => reconcile_probe = Some(probe),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        report.deferred_to_live_writer = report.open;
                        return Ok(report);
                    }
                    // An errored probe must neither claim possibly live
                    // rows nor silently skip: fail closed, refusing the
                    // pass.
                    Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
                }
                // Re-read the candidates now that no sibling pass can be
                // mid-claim: the first read may have seen rows a since-
                // finished pass already resolved, and resolving works from
                // a set no serialized pass can be mutating.
                let foreign_open = {
                    let connection = self.connection()?;
                    select_open_dispatch_intents_excluding_owner(&connection, &self.instance_token)?
                };
                report.open = foreign_open.len() as u64;
                if foreign_open.is_empty() {
                    return Ok(report);
                }
                // Judge liveness per owner: a row whose token can name a
                // mark file probes THAT owner's mark, so a crashed owner's
                // rows surface even while other siblings stay live, and no
                // pass ever converts a lock it holds itself. Rows naming no
                // probeable owner (journaled before owner tokens existed,
                // or carrying a token this code never generated) fall back
                // to whole-file exclusivity.
                let mut per_owner = std::collections::BTreeMap::<String, Vec<_>>::new();
                let mut unattributed = Vec::new();
                for row in foreign_open {
                    match row
                        .owner_token
                        .filter(|token| crate::is_owner_token_shaped(token))
                    {
                        Some(token) => per_owner.entry(token).or_default().push(row.record),
                        None => unattributed.push(row.record),
                    }
                }
                let mut rows = Vec::new();
                let mut deferred = 0u64;
                for (token, group) in per_owner {
                    match probe_foreign_owner_liveness(&lock.database_path, &token)? {
                        OwnerLiveness::Gone { mark, path } => {
                            claimed_owner_marks.push((mark, path));
                            rows.extend(group);
                        }
                        OwnerLiveness::Live => deferred += group.len() as u64,
                    }
                }
                if !unattributed.is_empty() {
                    match lock.mark.try_lock() {
                        Ok(()) => {
                            exclusive_mark.mark = Some(&lock.mark);
                            rows.extend(unattributed);
                        }
                        Err(std::fs::TryLockError::WouldBlock) => {
                            // The refused conversion may have dropped the
                            // shared mark; restore it before deferring so
                            // this instance stays visible as a live writer.
                            // Only the probe holder converts, so no sibling
                            // can misread this instance as gone during the
                            // gap.
                            lock.mark.lock_shared()?;
                            deferred += unattributed.len() as u64;
                        }
                        // An errored exclusivity check must neither claim
                        // possibly live rows nor silently skip: fail
                        // closed, refusing the pass.
                        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
                    }
                }
                report.deferred_to_live_writer = deferred;
                if rows.is_empty() {
                    // Every candidate deferred: the downgrade guard is
                    // unarmed (the conversion only happens when it yields
                    // rows) and the probe releases on return.
                    return Ok(report);
                }
                rows
            }
        };
        let claim = (|| {
            let mut dead_letters: Vec<(String, Option<String>, String)> = Vec::new();
            let mut reconciled: Vec<(String, Option<String>, String)> = Vec::new();
            let mut deferred_to_admission_operations: Vec<(
                String,
                Option<String>,
                String,
                String,
            )> = Vec::new();
            let mut replayable: Vec<(String, Option<String>)> = Vec::new();
            for intent in &claimable {
                match reconciler.resolve(intent)? {
                    DispatchIntentResolution::DeadLetter { detail } => {
                        report.dead_lettered += 1;
                        dead_letters.push((
                            intent.request_id.clone(),
                            intent.tenant_id.clone(),
                            detail,
                        ));
                    }
                    DispatchIntentResolution::MonetaryReconciled { rail_reference } => {
                        // A rail-proven outcome gets its own terminal state:
                        // it is resolved work, not an outcome-unknown
                        // incident, so it must not dead-letter (which flips
                        // health until an operator intervenes).
                        report.monetary_reconciled += 1;
                        reconciled.push((
                            intent.request_id.clone(),
                            intent.tenant_id.clone(),
                            format!("monetary reconciled; rail_reference={rail_reference}"),
                        ));
                    }
                    DispatchIntentResolution::SafeToReplay => {
                        // The reconciler proved the effect never ran, so the
                        // resolution is to run the request again. The replay
                        // journals its own intent under the same (tenant,
                        // request id) identity, so the row must be released
                        // outright: any survivor would refuse the replay's
                        // pre-dispatch insert and fail the request before
                        // the tool runs.
                        report.replayed += 1;
                        replayable.push((intent.request_id.clone(), intent.tenant_id.clone()));
                    }
                    DispatchIntentResolution::DeferredToAdmissionOperation { operation_id } => {
                        report.deferred_to_admission_operation += 1;
                        deferred_to_admission_operations.push((
                            intent.request_id.clone(),
                            intent.tenant_id.clone(),
                            intent.parameter_hash.clone(),
                            operation_id,
                        ));
                    }
                }
            }
            // Every resolution write is keyed on the claimed row's (tenant,
            // request id) identity so a live tenant's intent sharing the
            // request id is never resolved alongside the orphan. Bounded and
            // abandon-checked (see `dispatch_intent_resolution_batch_job`):
            // a wedged-but-alive writer must not hang this pass indefinitely
            // while it holds the reconcile probe mutex (and, when the batch
            // claimed unattributed rows, the exclusive writer-lifetime mark).
            // A timeout here releases cleanly through the same cleanup below
            // and leaves every claimed row untouched for the next recovery
            // pass to re-claim.
            let abandoned = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let job = dispatch_intent_resolution_batch_job(
                dead_letters,
                reconciled,
                deferred_to_admission_operations,
                replayable,
                Arc::clone(&abandoned),
            );
            self.writer_handle().run_write_abandoning_on_timeout(
                job,
                DISPATCH_INTENT_RECONCILE_RESOLUTION_BUDGET,
                abandoned,
            )
        })();
        // Return to the shared mark even when the claim failed: holding the
        // exclusive lock past this pass would block sibling opens for the
        // store's whole lifetime. The claim error outranks a downgrade error
        // (both refuse the pass); a reconciler panic unwinding through the
        // claim downgrades through the guard's drop instead.
        let downgrade = exclusive_mark.downgrade().map_err(ReceiptStoreError::from);
        if claim.is_ok() {
            // The claimed owners' rows are terminal, so their mark files
            // are stale: remove them while still holding both their locks
            // and the probe mutex, so no concurrent pass can be probing
            // them. Best-effort, because a leftover file is inert (liveness
            // is the lock, and a dead owner's lock stays acquirable). A
            // failed claim keeps the files for the retrying pass instead.
            for (_mark, path) in &claimed_owner_marks {
                let _ = std::fs::remove_file(path);
            }
        }
        drop(claimed_owner_marks);
        // Release the probe mutex only after the mark is shared again, so no
        // sibling's probe can ever overlap this pass's conversion gaps.
        drop(reconcile_probe);
        claim?;
        downgrade?;
        Ok(report)
    }

    pub fn append_indexed_security_evidence(
        &self,
        evidence_id: &OpaqueReceiptRef,
        receipt: &ChioReceipt,
    ) -> Result<ChioReceipt, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        validate_indexed_security_receipt(evidence_id, receipt)?;
        let raw_json = serde_json::to_string(receipt)?;
        let evidence_id = evidence_id.as_str().to_string();
        let receipt = receipt.clone();
        self.writer_handle().run_write_receipt(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some(existing_raw_json) = tx
                .query_row(
                    r#"
                    SELECT receipt.raw_json
                    FROM chio_security_evidence_index AS evidence
                    JOIN chio_tool_receipts AS receipt
                      ON receipt.receipt_id = evidence.receipt_id
                    WHERE evidence.evidence_id = ?1
                    "#,
                    params![evidence_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                let existing = decode_verified_chio_receipt(
                    &existing_raw_json,
                    "indexed active-defense receipt",
                    None,
                )?;
                if !same_unsigned_receipt_and_bbs_binding(&existing, &receipt)? {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "active-defense evidence `{evidence_id}` is already mapped to a different receipt"
                    )));
                }
                tx.commit()?;
                return Ok(existing);
            }

            let existing_for_receipt = tx
                .query_row(
                    "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                    params![receipt.id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|existing_raw_json| {
                    decode_verified_chio_receipt(
                        &existing_raw_json,
                        "preexisting active-defense receipt",
                        None,
                    )
                })
                .transpose()?;
            let persisted = match existing_for_receipt {
                Some(existing) => {
                    if !same_unsigned_receipt_and_bbs_binding(&existing, &receipt)? {
                        return Err(ReceiptStoreError::Conflict(format!(
                            "active-defense receipt `{}` already exists with different unsigned content",
                            receipt.id
                        )));
                    }
                    existing
                }
                None => {
                    append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
                    ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
                    receipt
                }
            };
            if let Some(existing_evidence_id) = tx
                .query_row(
                    "SELECT evidence_id FROM chio_security_evidence_index WHERE receipt_id = ?1",
                    params![persisted.id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "active-defense receipt `{}` is already mapped to evidence `{existing_evidence_id}`",
                    persisted.id
                )));
            }
            tx.execute(
                "INSERT INTO chio_security_evidence_index (evidence_id, receipt_id) VALUES (?1, ?2)",
                params![evidence_id.as_str(), persisted.id.as_str()],
            )?;
            tx.commit()?;
            Ok(persisted)
        })
    }

    pub fn load_indexed_security_evidence(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        connection
            .query_row(
                r#"
                SELECT receipt.seq, receipt.raw_json
                FROM chio_security_evidence_index AS evidence
                JOIN chio_tool_receipts AS receipt
                  ON receipt.receipt_id = evidence.receipt_id
                WHERE evidence.evidence_id = ?1
                "#,
                params![evidence_id.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(seq, raw_json)| {
                let receipt = decode_verified_chio_receipt(
                    &raw_json,
                    "indexed active-defense receipt",
                    Some(seq.max(0) as u64),
                )?;
                validate_indexed_security_receipt(evidence_id, &receipt)?;
                Ok(receipt)
            })
            .transpose()
    }

    pub fn ensure_indexed_security_evidence_ready(&self) -> Result<(), ReceiptStoreError> {
        let health = self.receipt_store_health()?;
        if !health.healthy {
            return Err(ReceiptStoreError::Conflict(
                "indexed security evidence store is not healthy".to_string(),
            ));
        }
        let connection = self.connection()?;
        bootstrap::open::validate_indexed_security_evidence_schema(&connection)
    }

    pub fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush()?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    /// Flush every accepted receipt write, stop and join the writer actor, and
    /// release all SQLite handles before returning.
    pub fn close(self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        let flush = self
            .receipt_commit_actor
            .flush_for_shutdown()
            .and_then(|()| {
                let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
                self.flush_report(wal_checkpoint)
            });
        let shutdown = self.receipt_commit_actor.shutdown();
        match flush {
            Err(error) => Err(error),
            Ok(report) => shutdown.map(|()| report),
        }
    }

    /// Recover a store whose claim-log projection rows survived a source-row
    /// delete. Fail-closed: only removes claim-log `extra` rows (absent from
    /// both source tables) that are (a) present in the named archive and (b) at
    /// or below the smallest checkpoint batch_end_seq that covers them, so the
    /// uncheckpointed suffix is never touched. Returns the number of rows
    /// removed.
    ///
    /// Dispatched as its own writer-actor command (`RetentionRepair`), not
    /// `writer_handle().run_write`: a `Write` job is rejected outright while
    /// the head is `Poisoned` (see `handle_non_append_command`'s `Write`
    /// arm), which is exactly the state a bricked store's writer actor is in
    /// on open, so `run_write` can never reach the store this method exists
    /// to repair. `RetentionRepair` runs unconditionally on the single writer
    /// connection (still fully serialized with every other writer command,
    /// same single-writer discipline as `run_write`), like `ReseedHead` and
    /// `Rotate`, and reseeds the head on success so the same store instance
    /// is appendable again without requiring a fresh open.
    pub fn retention_repair(&self, archive_path: &str) -> Result<u64, ReceiptStoreError> {
        self.database_identity_file.validate()?;
        let (response, result) = mpsc::sync_channel(1);
        let health = &self.receipt_commit_actor.health;
        // In-flight writer, same accounting discipline as a rotation
        // (`dispatch_rotate`): increment before handing the command to the
        // actor so a concurrent `receipt_store_health` cannot observe a
        // dequeued-but-uncounted repair. The `RetentionRepair` arm adopts the
        // increment until repair and head reseeding have finished; a rejected
        // send is released here before returning.
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(health);
        health.note_channel_send();
        if let Err(error) =
            self.receipt_commit_actor
                .sender
                .try_send(ReceiptCommitCommand::RetentionRepair {
                    archive_path: archive_path.to_string(),
                    response,
                    inflight,
                })
        {
            inflight_release.release();
            health.note_channel_send_rejected();
            return Err(match error {
                mpsc::TrySendError::Full(_) => {
                    health.saturated_total.fetch_add(1, Ordering::SeqCst);
                    receipt_actor_saturated_error()
                }
                mpsc::TrySendError::Disconnected(_) => {
                    health.note_writer_unavailable();
                    receipt_actor_unavailable_error()
                }
            });
        }
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                inflight_release.release();
                health.note_writer_unavailable();
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    /// Rerun the one-time full verification on the writer connection and
    /// adopt the resulting head. This is the `chio receipt audit --repair`
    /// entry point; it is also safe to call on a healthy store.
    pub fn reseed_verified_head(&self) -> Result<(), ReceiptStoreError> {
        self.database_identity_file.validate()?;
        let (response, result) = mpsc::sync_channel(1);
        let health = &self.receipt_commit_actor.health;
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(health);
        health.note_channel_send();
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::ReseedHead { response, inflight })
        {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                inflight_release.release();
                health.note_channel_send_rejected();
                health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                inflight_release.release();
                health.note_channel_send_rejected();
                // A disconnected admin send is the first observation that the
                // writer is gone. Record the unavailable marker so the next
                // liveness sample reports the writer Dead immediately, rather
                // than staying Healthy until a later append also disconnects.
                health.note_writer_unavailable();
                return Err(receipt_actor_unavailable_error());
            }
        }
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                inflight_release.release();
                health.note_writer_unavailable();
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    /// Install the background checkpoint signer. Idempotent per store (a
    /// second call replaces the signer). Until called, the store appends
    /// without producing checkpoints.
    pub fn enable_background_checkpoints(
        &self,
        signer: BackgroundCheckpointSigner,
    ) -> Result<(), ReceiptStoreError> {
        self.database_identity_file.validate()?;
        let health = &self.receipt_commit_actor.health;
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(health);
        health.note_channel_send();
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::InstallSigner { signer, inflight })
        {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                inflight_release.release();
                health.note_channel_send_rejected();
                health.saturated_total.fetch_add(1, Ordering::SeqCst);
                Err(receipt_actor_saturated_error())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                inflight_release.release();
                health.note_channel_send_rejected();
                // See `reseed_verified_head`: a disconnected admin send must
                // flip liveness to Dead now, not on a later append.
                health.note_writer_unavailable();
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    pub fn flush_receipt_writes_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush_with_timeout(timeout)?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    /// Record the outcome of a background retention rotation into health.
    /// `None` clears a prior failure after a successful rotation; `Some(message)`
    /// records a rotation error or panic so a persistently failing background
    /// maintenance task surfaces as unhealthy in `receipt_store_health` instead
    /// of the failure living only in the worker's logs. Called by the kernel
    /// maintenance worker on the store handle it holds; the health snapshot is
    /// shared across all handles of this store, so the failure is visible to any
    /// other handle sampling health.
    pub fn record_retention_rotation_outcome(&self, failure: Option<&str>) {
        if let Ok(mut retention_error) = self.receipt_commit_actor.health.retention_error.lock() {
            *retention_error = failure.map(ToString::to_string);
        }
    }

    pub fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let status = self.receipt_checkpoint_status(Some(1))?;
        // A checkpoint-chain error already produced an unhealthy status: the
        // checkpointed boundary drops to 0, so the committed floor (which folds
        // in a retention watermark whose live prefix rows were archived and
        // deleted) reads as a whole-log backlog. Re-probing that range would
        // decode rows retention intentionally removed and turn the prepared
        // unhealthy report (carrying the checkpoint_error operators need) into a
        // hard error. Only decode-probe the uncheckpointed suffix when the
        // checkpoint status itself is clean.
        if status.checkpoint_error.is_none()
            && status.latest_committed_entry_seq > status.latest_checkpointed_entry_seq
        {
            let connection = self.connection()?;
            let start_seq = status.latest_checkpointed_entry_seq + 1;
            load_claim_tree_canonical_bytes_range(
                &connection,
                start_seq,
                status.latest_committed_entry_seq,
            )?;
        }
        let writer_counters = self.receipt_commit_actor.writer_counters();
        let (writer_level, writer_restart_total) =
            self.receipt_commit_actor.writer_health_summary();
        // The authoritative pre-dispatch gate reads the watchdog verdict against
        // the operator-configured stall threshold; this report has no config in
        // scope, so it both labels and folds health against the shipped default.
        let writer_liveness = self.writer_liveness(std::time::Duration::from_millis(
            chio_kernel::DEFAULT_RECEIPT_WRITER_STALL_MS,
        ));
        let retention_error = self
            .receipt_commit_actor
            .health
            .retention_error
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        // A writer that cannot be trusted to persist can never read green. This is
        // the same predicate the pre-dispatch gate denies on, so readiness and the
        // gate never disagree: it covers a wedged, saturated, or dead writer by
        // liveness, a dead or degraded supervised thread by level, and a poisoned
        // verified head via `writer_serving_closed`, where the thread is still
        // Healthy and no batch recorded a `last_error` yet every append is already
        // rejected. A persistently failing background retention rotation also
        // forces unhealthy so a silently unenforced retention policy is not masked.
        let (open_dispatch_intents, dead_letter_dispatch_intents) = {
            let connection = self.connection()?;
            (
                open_dispatch_intent_count_query(&connection)?,
                dead_letter_dispatch_intent_count_query(&connection)?,
            )
        };
        // A dead-letter intent means an effect may have occurred with no
        // receipt: the store must read loudly unhealthy until an operator
        // resolves the incident. Open intents alone are in-flight work, not
        // incidents, and do not affect health.
        let healthy = receipt_store_healthy(
            status.healthy,
            writer_counters.last_error.as_deref(),
            writer_liveness,
        ) && !self.receipt_commit_actor.writer_serving_closed()
            && matches!(writer_level, HealthLevel::Healthy)
            && retention_error.is_none()
            && dead_letter_dispatch_intents == 0;
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) = uncheckpointed_range(
            status.latest_checkpointed_entry_seq,
            status.latest_committed_entry_seq,
        );
        Ok(ReceiptStoreHealthReport {
            healthy,
            writer: writer_counters,
            writer_liveness: writer_liveness.as_label().to_string(),
            latest_committed_entry_seq: status.latest_committed_entry_seq,
            latest_checkpoint_seq: status.latest_checkpoint_seq,
            latest_checkpointed_entry_seq: status.latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            checkpoint_error: status.checkpoint_error,
            db_size_bytes: self.db_size_bytes().ok(),
            retention_watermark_entry_seq: status.retention_watermark_entry_seq,
            retention_error,
            writer_level,
            writer_restart_total,
            open_dispatch_intents,
            dead_letter_dispatch_intents,
        })
    }

    /// Count of open (in-flight or unreconciled) dispatch intents.
    pub fn open_dispatch_intent_count(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        open_dispatch_intent_count_query(&connection)
    }

    /// Count of dead-letter (orphaned, outcome-unknown) dispatch intents.
    pub fn dead_letter_dispatch_intent_count(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        dead_letter_dispatch_intent_count_query(&connection)
    }

    /// Resolve a specific dead-letter dispatch intent: the sanctioned
    /// operator remediation for the incident a nonzero
    /// `dead_letter_dispatch_intents` count flags in health. See
    /// [`resolve_dead_letter_dispatch_intent_tx`] for the fail-closed
    /// state check and the auditable append-only note.
    pub fn resolve_dead_letter_dispatch_intent(
        &self,
        request_id: &str,
        tenant_id: Option<&str>,
        note: &str,
    ) -> Result<(), ReceiptStoreError> {
        let request_id = request_id.to_string();
        let tenant_id = tenant_id.map(str::to_string);
        let note = note.to_string();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            resolve_dead_letter_dispatch_intent_tx(&tx, &request_id, tenant_id.as_deref(), &note)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Whether the commit writer can no longer be trusted to persist receipts, so
    /// the kernel pre-dispatch gate must deny before a tool executes. True when the
    /// supervised writer thread has left the healthy state, and also when the
    /// writer's verified head is poisoned: the thread is alive but every append is
    /// rejected until an operator reseeds.
    pub fn writer_serving_closed(&self) -> bool {
        self.receipt_commit_actor.writer_serving_closed()
    }

    /// Sample receipt-store health from a READ-ONLY connection.
    ///
    /// The SIEM serve-mode watchdog observes a receipt DB the kernel owns; it
    /// must not create it, switch it to WAL, or spin a writer pool on it,
    /// matching the read-only receipt-polling contract. `open` does all three, so
    /// it cannot be used on a read-only mount and would create an empty DB on a
    /// mistyped path. This opens a single READ_ONLY connection instead: a missing
    /// file reports `NotFound` rather than being created, and a read-only mount
    /// is sampled without any write attempt.
    ///
    /// A read-only observer cannot see the owning writer's in-memory counters, so
    /// `writer` is defaulted; the checkpoint-progress fields the watchdog gauges
    /// consume (committed/checkpointed seqs and the uncheckpointed range) are
    /// computed from the read connection with the same helpers as
    /// `receipt_store_health`.
    pub fn receipt_store_health_read_only(
        path: &Path,
    ) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::CannotOpen) {
                ReceiptStoreError::NotFound(format!(
                    "receipt database {} does not exist",
                    path.display()
                ))
            } else {
                ReceiptStoreError::Sqlite(error)
            }
        })?;
        let live_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        let retention_watermark_entry_seq = support::retention_watermark(&connection)?;
        // A full rotation deletes every live claim-log row, so the live
        // MAX(entry_seq) drops to 0 while the latest checkpoint still sits at the
        // archived watermark. Committed progress must fold in the archived prefix,
        // otherwise this read-only watchdog reports a healthy, fully-archived
        // store as behind its checkpoints (committed 0 < checkpointed W). Floor
        // the committed seq at the watermark.
        let latest_committed_entry_seq =
            live_committed_entry_seq.max(retention_watermark_entry_seq.unwrap_or(0));
        // Catch a checkpoint-chain-integrity failure into a report with the
        // checkpoint_error set rather than propagating Err. The watchdog samples
        // this on a fixed interval; if corruption made this return Err, the
        // sampler would log-and-skip with NO gauge update, so a corrupt store
        // would look silent instead of alarming. Mirror the
        // fail-open shape of `receipt_checkpoint_status` so the watchdog still
        // emits a large-backlog gauge (checkpointed defaults to 0 -> the
        // uncheckpointed range spans the whole committed log) with the
        // checkpoint_error attached.
        //
        // Dead-letter intents are durable rows, so this read-only observer
        // sees them and folds them into health exactly like the owning store.
        let open_dispatch_intents = open_dispatch_intent_count_query(&connection)?;
        let dead_letter_dispatch_intents = dead_letter_dispatch_intent_count_query(&connection)?;
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
                    uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
                Ok(ReceiptStoreHealthReport {
                    healthy: latest_committed_entry_seq >= latest_checkpointed_entry_seq
                        && dead_letter_dispatch_intents == 0,
                    writer: ReceiptWriterCounters::default(),
                    // A read-only observer cannot see the owning writer's
                    // in-memory liveness, so it is reported as unknown.
                    writer_liveness: chio_kernel::ReceiptWriterLiveness::Unknown
                        .as_label()
                        .to_string(),
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    uncheckpointed_start_seq,
                    uncheckpointed_end_seq,
                    checkpoint_error: None,
                    db_size_bytes: None,
                    retention_watermark_entry_seq,
                    // A read-only observer cannot see the owning writer's
                    // in-memory background-retention state, so it is defaulted
                    // like the writer counters above.
                    retention_error: None,
                    // A read-only observer cannot see the owning writer's supervisor.
                    writer_level: HealthLevel::default(),
                    writer_restart_total: 0,
                    open_dispatch_intents,
                    dead_letter_dispatch_intents,
                })
            }
            Err(error) => {
                let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
                    uncheckpointed_range(0, latest_committed_entry_seq);
                Ok(ReceiptStoreHealthReport {
                    healthy: false,
                    writer: ReceiptWriterCounters::default(),
                    writer_liveness: chio_kernel::ReceiptWriterLiveness::Unknown
                        .as_label()
                        .to_string(),
                    latest_committed_entry_seq,
                    latest_checkpoint_seq: None,
                    latest_checkpointed_entry_seq: 0,
                    uncheckpointed_start_seq,
                    uncheckpointed_end_seq,
                    checkpoint_error: Some(error.to_string()),
                    db_size_bytes: None,
                    retention_watermark_entry_seq,
                    retention_error: None,
                    writer_level: HealthLevel::default(),
                    writer_restart_total: 0,
                    open_dispatch_intents,
                    dead_letter_dispatch_intents,
                })
            }
        }
    }

    pub fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        // After a full-prefix rotation the live claim-log table is empty, so
        // MAX(entry_seq) drops to 0 while the latest checkpoint and the
        // retention watermark still sit at the archived boundary W. Committed
        // progress must fold in the archived prefix; floor the live committed
        // seq at the watermark so a direct trait caller does not see committed
        // regress to 0 behind its checkpoints. Mirrors receipt_checkpoint_status,
        // receipt_store_health_read_only, and flush_report.
        let live = latest_claim_log_entry_seq(&connection)?;
        let watermark = support::retention_watermark(&connection)?.unwrap_or(0);
        Ok(live.max(watermark))
    }

    pub fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_checkpointed_entry_seq(&connection)
    }

    pub fn next_checkpoint_range(
        &self,
        max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        let connection = self.connection()?;
        next_checkpoint_range_for_connection(&connection, max_batch)
    }

    pub fn receipt_checkpoint_status(
        &self,
        max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let connection = self.connection()?;
        // Read once and reuse across every branch below: the watermark is
        // reported even on an error/unhealthy status so retention visibility
        // does not depend on checkpoint health.
        let retention_watermark_entry_seq = support::retention_watermark(&connection)?;
        // After a full-prefix rotation the live claim-log table is empty, so
        // MAX(entry_seq) drops to 0 while the latest checkpoint and the
        // retention watermark still sit at the archived boundary W. Committed
        // progress must fold in the archived prefix; floor the live committed
        // seq at the watermark so a fully-archived store does not report
        // committed regressing to 0 behind its checkpoints. Mirrors
        // receipt_store_health_read_only.
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?
            .max(retention_watermark_entry_seq.unwrap_or(0));
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                if latest_committed_entry_seq > latest_checkpointed_entry_seq {
                    let start_seq = latest_checkpointed_entry_seq + 1;
                    if let Err(error) = ensure_claim_log_range_contiguous(
                        &connection,
                        start_seq,
                        latest_committed_entry_seq,
                        "uncheckpointed range",
                    ) {
                        return Ok(ReceiptCheckpointStatusReport {
                            healthy: false,
                            latest_committed_entry_seq,
                            latest_checkpoint_seq,
                            latest_checkpointed_entry_seq,
                            next_range: None,
                            checkpoint_error: Some(error.to_string()),
                            retention_watermark_entry_seq,
                        });
                    }
                }
                let next_range = match max_batch {
                    Some(max_batch) => {
                        next_checkpoint_range_for_connection(&connection, max_batch)?
                    }
                    None => None,
                };
                Ok(ReceiptCheckpointStatusReport {
                    healthy: true,
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    next_range,
                    checkpoint_error: None,
                    retention_watermark_entry_seq,
                })
            }
            Err(error) => Ok(ReceiptCheckpointStatusReport {
                healthy: false,
                latest_committed_entry_seq,
                latest_checkpoint_seq: None,
                latest_checkpointed_entry_seq: 0,
                next_range: None,
                checkpoint_error: Some(error.to_string()),
                retention_watermark_entry_seq,
            }),
        }
    }

    pub fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        let keypair = keypair.clone();
        self.writer_handle().run_write(move |connection| {
            validate_claim_receipt_log_entries(connection)?;
            create_next_receipt_checkpoint_atomic(connection, max_batch, &keypair)
        })
    }

    fn flush_report(
        &self,
        wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        let head = self.writer_checkpoint_snapshot();
        let connection = self.connection()?;
        // After a full-prefix rotation the live claim-log table is empty, so
        // MAX(entry_seq) drops to 0 while the latest checkpoint and the retention
        // watermark still sit at the archived boundary W. Committed progress must
        // fold in the archived prefix; floor the live committed seq at the
        // watermark so a fully-archived store does not report committed
        // regressing to 0 behind its checkpoints and corrupt operators' flush
        // metrics. Mirrors receipt_checkpoint_status and
        // receipt_store_health_read_only.
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?
            .max(support::retention_watermark(&connection)?.unwrap_or(0));
        // The writer head snapshot is only refreshed by this handle's own
        // appends/writes. When another store instance or the operator CLI
        // extends the checkpoint chain and this handle has had no intervening
        // local write, the head atomics are stale and would overstate the
        // uncheckpointed range. Read the persisted checkpoint head from the DB
        // (read-only reader-pool query, not a writer-head mutation) and take
        // the higher of the two so the report reflects the current chain.
        // Only trust the persisted latest checkpoint if its signed body
        // VERIFIES: `parse_persisted_checkpoint_row` checks
        // column/body agreement AND the signature, so a tampered or out-of-band
        // row with an inflated `batch_end_seq` cannot make the flush report a
        // false `checkpointed_entry_seq` and hide the uncheckpointed range. On a
        // verification failure fall back to ONLY the actor's verified head (via
        // the `.max` below). Reader-pool READ, no write; single latest-row
        // body verification, not a full chain verify.
        //
        // Chain-connectivity guard: a single-row parse
        // does NOT catch a latest checkpoint that individually verifies yet is
        // DISCONNECTED from the chain (skipped `checkpoint_seq` or wrong
        // predecessor), which a full `verify_checkpoint_chain_integrity`
        // catches. Additionally require
        // the latest checkpoint to link to its immediate predecessor before
        // trusting its `batch_end_seq`; a disconnected latest is dropped (fall
        // back to the actor's verified head). This is a bounded O(1) predecessor
        // read on the operator/health surface, NOT a full O(N) chain walk on the
        // per-append hot path.
        //
        // Claim-log content guard: a separate process
        // advancing `kernel_checkpoints` on a shared DB can persist a latest row
        // that parses (columns match its signed body) AND links to its predecessor
        // yet whose `merkle_root`/`tree_size`/`batch_end_seq` describe a batch this
        // database's `claim_receipt_log_entries` never actually contained (an
        // imported/foreign checkpoint). A full `verify_checkpoint_chain_integrity`
        // rebuilds the checkpoint Merkle range from the local claim log; without
        // that content check here an
        // inflated `batch_end_seq` would make this report advertise a false
        // `checkpointed_entry_seq` and hide the uncheckpointed range. Rebuild the
        // latest checkpoint's Merkle range from the LOCAL claim log and drop it on
        // mismatch (fall back to the actor's verified head). Bounded O(b) over the
        // single latest checkpoint's own batch on the operator/health surface, NOT
        // a full O(N) chain walk on the per-append hot path.
        //
        // Watermark exemption: a checkpoint fully covered by a TRUSTED archival
        // watermark has had its claim-log rows co-archived and deleted, so a live
        // Merkle rebuild would fail for a perfectly valid checkpoint. Mirror the
        // full chain verification (`verify_checkpoint_chain_integrity`): skip only
        // the live rebuild for a watermark-covered checkpoint and trust the archive
        // to serve that deep verification; its signature, column agreement, and
        // chain connectivity above still run. Without this, a fully-archived latest
        // checkpoint is discarded and flush reports a stale `checkpointed_entry_seq`
        // and a spurious uncheckpointed range until a later write catches the head
        // up. `trusted_retention_watermark` is fail-closed (0 unless the boundary,
        // the absent live prefix, and the backing archive all check out), so a
        // forged watermark cannot suppress the rebuild for an unarchived range.
        let trusted_watermark = trusted_retention_watermark(&connection)?;
        let verified_persisted = load_latest_persisted_checkpoint_row(&connection)?
            .and_then(|row| parse_persisted_checkpoint_row(row).ok())
            .filter(|checkpoint| {
                latest_checkpoint_is_chain_connected(&connection, checkpoint).is_ok()
                    && (checkpoint.body.batch_end_seq <= trusted_watermark
                        || validate_checkpoint_against_claim_log(&connection, checkpoint).is_ok())
            });
        let persisted_checkpoint_seq = verified_persisted
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.checkpoint_seq);
        let persisted_checkpointed_entry_seq = verified_persisted
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        let checkpoint_seq = head.checkpoint_seq.max(persisted_checkpoint_seq);
        let latest_checkpointed_entry_seq = head
            .checkpointed_entry_seq
            .max(persisted_checkpointed_entry_seq);
        let latest_checkpoint_seq = (checkpoint_seq > 0).then_some(checkpoint_seq);
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
            uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
        Ok(ReceiptFlushReport {
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq,
            latest_checkpoint_seq,
            latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            wal_checkpoint,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    fn validate_claim_receipt_log_projection_current(&self) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        validate_claim_receipt_log_entries(&connection)
    }

    fn wal_checkpoint_passive(&self) -> Result<ReceiptWalCheckpointReport, ReceiptStoreError> {
        let connection = self.connection()?;
        let (busy, log_frames, checkpointed_frames) =
            connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
        Ok(ReceiptWalCheckpointReport {
            busy: sqlite_u64(busy, "wal checkpoint busy")?,
            log_frames: wal_checkpoint_frame_count(log_frames, "wal checkpoint log frames")?,
            checkpointed_frames: wal_checkpoint_frame_count(
                checkpointed_frames,
                "wal checkpointed frames",
            )?,
        })
    }
}
