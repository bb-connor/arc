impl ApprovalStore for SqliteApprovalStore {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        self.authority_profile
    }

    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        let payload = serialize_payload(request)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let returned_payload = conn
            .query_row(
                r#"
            INSERT INTO chio_hitl_pending (approval_id, policy_id, subject_id, tool_server, tool_name, parameter_hash, expires_at, created_at, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(approval_id) DO UPDATE SET payload = excluded.payload WHERE chio_hitl_pending.payload = excluded.payload RETURNING payload
            "#,
                params![
                    request.approval_id,
                    request.policy_id,
                    request.subject_id,
                    request.tool_server,
                    request.tool_name,
                    request.parameter_hash,
                    request.expires_at as i64,
                    request.created_at as i64,
                    payload,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("insert pending: {e}")))?;
        if returned_payload.is_none() {
            return Err(ApprovalStoreError::Backend(format!(
                "approval_id {} already exists with different payload",
                request.approval_id
            )));
        }
        Ok(())
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<String> = conn
            .query_row(
                "SELECT payload FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select pending: {e}")))?;
        match row {
            Some(raw) => Ok(Some(deserialize_payload(&raw)?)),
            None => Ok(None),
        }
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let not_expired_at = filter
            .not_expired_at
            .map(|value| {
                i64::try_from(value).map_err(|_| {
                    ApprovalStoreError::Invalid(
                        "not_expired_at exceeds SQLite INTEGER range".to_string(),
                    )
                })
            })
            .transpose()?;
        let limit = filter
            .limit
            .map(|value| {
                i64::try_from(value).map_err(|_| {
                    ApprovalStoreError::Invalid("limit exceeds SQLite INTEGER range".to_string())
                })
            })
            .transpose()?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let mut sql = String::from("SELECT payload FROM chio_hitl_pending WHERE 1=1");
        if filter.subject_id.is_some() {
            sql.push_str(" AND subject_id = :subject_id");
        }
        if filter.tool_server.is_some() {
            sql.push_str(" AND tool_server = :tool_server");
        }
        if filter.tool_name.is_some() {
            sql.push_str(" AND tool_name = :tool_name");
        }
        if not_expired_at.is_some() {
            sql.push_str(" AND expires_at > :not_expired_at");
        }
        sql.push_str(" ORDER BY created_at ASC");
        if limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| ApprovalStoreError::Backend(format!("prepare list: {e}")))?;

        let mut params_vec: Vec<(&str, Box<dyn rusqlite::ToSql>)> = Vec::new();
        if let Some(s) = &filter.subject_id {
            params_vec.push((":subject_id", Box::new(s.clone())));
        }
        if let Some(s) = &filter.tool_server {
            params_vec.push((":tool_server", Box::new(s.clone())));
        }
        if let Some(s) = &filter.tool_name {
            params_vec.push((":tool_name", Box::new(s.clone())));
        }
        if let Some(t) = not_expired_at {
            params_vec.push((":not_expired_at", Box::new(t)));
        }
        if let Some(limit) = limit {
            params_vec.push((":limit", Box::new(limit)));
        }

        let refs: Vec<(&str, &dyn rusqlite::ToSql)> = params_vec
            .iter()
            .map(|(name, value)| (*name, value.as_ref()))
            .collect();

        let rows = stmt
            .query_map(refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| ApprovalStoreError::Backend(format!("query list: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| ApprovalStoreError::Backend(format!("row: {e}")))?;
            out.push(deserialize_payload(&raw)?);
        }
        Ok(out)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin tx: {e}")))?;
        let token_digest = decision
            .token
            .token_digest()
            .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?;

        // Pull pending record inside the tx to avoid TOCTOU races.
        let pending: Option<(String, String)> = tx
            .query_row(
                "SELECT policy_id, parameter_hash FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select: {e}")))?;
        let (policy_id, parameter_hash) = match pending {
            Some(p) => p,
            None => return Err(ApprovalStoreError::NotFound(id.to_string())),
        };

        let reservation_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1 OR token_digest = ?2
                "#,
                params![decision.token.id, token_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("reservation replay check: {e}")))?;
        if let Some(owner) = reservation_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by operation `{owner}`"
            )));
        }
        let threshold_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT proposal_id
                FROM chio_hitl_threshold_votes
                WHERE token_id = ?1 OR canonical_token_digest = ?2
                "#,
                params![decision.token.id, token_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("threshold replay check: {e}")))?;
        if let Some(owner) = threshold_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by threshold proposal `{owner}`"
            )));
        }

        // Replay guard: the bound token must not already be consumed.
        let already: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 OR token_digest = ?2 LIMIT 1",
                params![decision.token.id, token_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("replay check: {e}")))?;
        if already.is_some() {
            return Err(ApprovalStoreError::Replay(id.to_string()));
        }

        // Idempotency: if already resolved, treat as AlreadyResolved.
        let already_resolved: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_resolved WHERE approval_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("resolved check: {e}")))?;
        if already_resolved.is_some() {
            return Err(ApprovalStoreError::AlreadyResolved(id.to_string()));
        }

        let outcome = match decision.outcome {
            ApprovalOutcome::Approved => "approved",
            ApprovalOutcome::Denied => "denied",
        };

        tx.execute(
            r#"INSERT INTO chio_hitl_resolved (
                approval_id, policy_id, subject_id, outcome, resolved_at,
                approver_hex, token_id
            ) SELECT approval_id, policy_id, subject_id, ?2, ?3, ?4, ?5
            FROM chio_hitl_pending WHERE approval_id = ?1"#,
            params![
                id,
                outcome,
                decision.received_at as i64,
                decision.approver.to_hex(),
                decision.token.id,
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert resolved: {e}")))?;

        tx.execute(
            "INSERT INTO chio_hitl_consumed_tokens (token_id, parameter_hash, token_digest, consumed_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                decision.token.id,
                parameter_hash,
                token_digest,
                decision.received_at as i64
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;

        tx.execute(
            "DELETE FROM chio_hitl_pending WHERE approval_id = ?1",
            params![id],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("delete pending: {e}")))?;

        tx.commit()
            .map_err(|e| ApprovalStoreError::Backend(format!("commit: {e}")))?;

        // policy_id is part of the trait signature but unused on this path.
        let _ = policy_id;
        Ok(())
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_hitl_resolved WHERE subject_id = ?1 AND policy_id = ?2 AND outcome = 'approved'",
                params![subject_id, policy_id],
                |row| row.get(0),
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("count: {e}")))?;
        Ok(count.max(0) as u64)
    }

    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin consumed tx: {e}")))?;
        let reservation_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1
                "#,
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("reservation replay check: {e}")))?;
        if let Some(owner) = reservation_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by operation `{owner}`"
            )));
        }
        let threshold_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT proposal_id
                FROM chio_hitl_threshold_votes
                WHERE token_id = ?1
                "#,
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("threshold replay check: {e}")))?;
        if let Some(owner) = threshold_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by threshold proposal `{owner}`"
            )));
        }
        let already_consumed: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 LIMIT 1",
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("legacy replay check: {e}")))?;
        if already_consumed.is_some() {
            return Err(ApprovalStoreError::Replay(format!(
                "token {token_id} already consumed"
            )));
        }
        tx.execute(
            "INSERT INTO chio_hitl_consumed_tokens (token_id, parameter_hash, consumed_at) VALUES (?1, ?2, ?3)",
            params![token_id, parameter_hash, now as i64],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;
        tx.commit()
            .map_err(|e| ApprovalStoreError::Backend(format!("commit consumed tx: {e}")))?;
        Ok(())
    }

    fn is_consumed(
        &self,
        token_id: &str,
        _parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<i64> = conn
            .query_row(
                r#"
                SELECT 1
                FROM chio_hitl_consumed_tokens
                WHERE token_id = ?1
                UNION ALL
                SELECT 1
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1
                UNION ALL
                SELECT 1
                FROM chio_hitl_threshold_votes
                WHERE token_id = ?1
                LIMIT 1
                "#,
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("is_consumed: {e}")))?;
        Ok(row.is_some())
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<(String, String, i64, String, String)> = conn
            .query_row(
                r#"SELECT approval_id, outcome, resolved_at, approver_hex, token_id
                   FROM chio_hitl_resolved WHERE approval_id = ?1"#,
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("get_resolution: {e}")))?;
        match row {
            Some((approval_id, outcome_str, resolved_at, approver_hex, token_id)) => {
                let outcome = match outcome_str.as_str() {
                    "approved" => ApprovalOutcome::Approved,
                    "denied" => ApprovalOutcome::Denied,
                    other => {
                        return Err(ApprovalStoreError::Serialization(format!(
                            "unknown outcome: {other}"
                        )))
                    }
                };
                Ok(Some(ResolvedApproval {
                    approval_id,
                    outcome,
                    resolved_at: resolved_at.max(0) as u64,
                    approver_hex,
                    token_id,
                }))
            }
            None => Ok(None),
        }
    }

    fn reserve_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        let requested = ApprovalReservation::new(operation_id.to_string(), approval_set.clone())?;
        let members_json = serialize_reservation_members(requested.approval_set().members())?;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin reservation tx: {e}")))?;

        if let Some(existing) = load_approval_reservation(&tx, operation_id)? {
            if existing.approval_set() == requested.approval_set() {
                tx.rollback().map_err(|e| {
                    ApprovalStoreError::Backend(format!("rollback reservation retry: {e}"))
                })?;
                return Ok(existing);
            }
            return Err(ApprovalStoreError::Replay(format!(
                "operation `{operation_id}` is already bound to a different approval-token set"
            )));
        }

        let hash_owner = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservations
                WHERE approval_set_hash = ?1
                LIMIT 1
                "#,
                params![requested.approval_set().approval_set_hash()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("query approval set owner: {e}")))?;
        if let Some(owner) = hash_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval set hash is already owned by operation `{owner}`"
            )));
        }

        let transfer_proposal = threshold_transfer_proposal(&tx, requested.approval_set())?;
        if let Some(proposal_id) = transfer_proposal.as_deref() {
            let existing_transfer = tx
                .query_row(
                    r#"
                    SELECT operation_id
                    FROM chio_hitl_threshold_operation_transfers
                    WHERE proposal_id = ?1
                    "#,
                    params![proposal_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| {
                    ApprovalStoreError::Backend(format!(
                        "query threshold ownership transfer: {error}"
                    ))
                })?;
            if let Some(owner) = existing_transfer {
                return Err(ApprovalStoreError::Replay(format!(
                    "threshold proposal is already transferred to operation `{owner}`"
                )));
            }
        }

        for member in requested.approval_set().members() {
            let legacy_consumed = tx
                .query_row(
                    r#"
                    SELECT 1
                    FROM chio_hitl_consumed_tokens
                    WHERE token_id = ?1 OR token_digest = ?2
                    LIMIT 1
                    "#,
                    params![member.token_id(), member.token_digest()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|e| {
                    ApprovalStoreError::Backend(format!("query legacy token replay: {e}"))
                })?;
            if legacy_consumed.is_some() {
                return Err(ApprovalStoreError::Replay(format!(
                    "approval token `{}` was already consumed",
                    member.token_id()
                )));
            }

            let owner = tx
                .query_row(
                    r#"
                    SELECT operation_id
                    FROM chio_hitl_operation_reservation_tokens
                    WHERE token_id = ?1 OR token_digest = ?2
                    LIMIT 1
                    "#,
                    params![member.token_id(), member.token_digest()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| ApprovalStoreError::Backend(format!("query token owner: {e}")))?;
            if let Some(owner) = owner {
                return Err(ApprovalStoreError::Replay(format!(
                    "approval token is already owned by operation `{owner}`"
                )));
            }
        }

        tx.execute(
            r#"
            INSERT INTO chio_hitl_operation_reservations (
                operation_id, approval_set_hash, members_json, proposal_deadline, state
            ) VALUES (?1, ?2, ?3, ?4, 'reserved')
            "#,
            params![
                operation_id,
                requested.approval_set().approval_set_hash(),
                members_json,
                i64::try_from(requested.approval_set().proposal_deadline()).map_err(|_| {
                    ApprovalStoreError::Backend(
                        "approval reservation proposal deadline exceeds SQLite INTEGER".to_string(),
                    )
                })?
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert reservation: {e}")))?;
        if let Some(proposal_id) = transfer_proposal.as_deref() {
            tx.execute(
                r#"
                INSERT INTO chio_hitl_threshold_operation_transfers (operation_id, proposal_id)
                VALUES (?1, ?2)
                "#,
                params![operation_id, proposal_id],
            )
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("insert threshold ownership transfer: {error}"))
            })?;
        }
        for (position, member) in requested.approval_set().members().iter().enumerate() {
            tx.execute(
                r#"
                INSERT INTO chio_hitl_operation_reservation_tokens (
                    token_id, token_digest, operation_id, position
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    member.token_id(),
                    member.token_digest(),
                    operation_id,
                    position as i64
                ],
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("insert reservation token: {e}")))?;
        }
        tx.commit().map_err(|e| {
            ApprovalStoreError::Backend(format!("commit approval reservation: {e}"))
        })?;
        Ok(requested)
    }

    fn commit_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition_approval_reservation(operation_id, ReplayReservationState::Committed)
    }

    fn cancel_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition_approval_reservation(operation_id, ReplayReservationState::Cancelled)
    }

    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        validate_reservation_operation_id(operation_id)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        load_approval_reservation(&conn, operation_id)
    }

    fn create_threshold_approval_proposal(
        &self,
        registration: &ThresholdApprovalProposalRegistration,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApprovalStoreError::Backend(format!("pool get: {error}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("begin threshold create tx: {error}"))
            })?;
        registration.validate_for_creation(current_context, trusted_policy_authorities, now)?;
        let body = registration.proposal().body();
        if let Some(existing) = load_threshold_proposal(&tx, body.proposal_id())? {
            if existing.registration() == registration {
                tx.rollback().map_err(|error| {
                    ApprovalStoreError::Backend(format!("rollback threshold create retry: {error}"))
                })?;
                return Ok(existing);
            }
            return Err(ApprovalStoreError::Conflict(format!(
                "proposal_id `{}` already has different immutable bindings",
                body.proposal_id()
            )));
        }
        let request_owner = tx
            .query_row(
                r#"
                SELECT proposal_id
                FROM chio_hitl_threshold_proposals
                WHERE request_id = ?1
                "#,
                params![body.request_id()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("query threshold request owner: {error}"))
            })?;
        if let Some(owner) = request_owner {
            return Err(ApprovalStoreError::Conflict(format!(
                "canonical request ID already belongs to threshold proposal `{owner}`"
            )));
        }
        let canonical_proposal_json =
            canonical_artifact_json(registration.proposal(), "threshold proposal")?;
        let canonical_eligible_approvers_json = canonical_artifact_json(
            registration.eligible_approvers(),
            "threshold eligible approvers",
        )?;
        tx.execute(
            r#"
            INSERT INTO chio_hitl_threshold_proposals (
                proposal_id, request_id, server_id, tool_name,
                governed_intent_hash, subject_key,
                authorization_capability_hash, policy_hash, required,
                eligible_set_digest, proposal_created_at, proposal_deadline,
                policy_authority_key, canonical_proposal_json,
                canonical_eligible_approvers_json, submitter_fingerprint,
                separation_of_duties, status, satisfied_at, delivered_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, 'collecting', NULL, NULL
            )
            "#,
            params![
                body.proposal_id(),
                body.request_id(),
                registration.server_id(),
                registration.tool_name(),
                body.governed_intent_hash(),
                body.subject().to_hex(),
                body.authorization_capability_hash(),
                body.policy_hash(),
                i64::from(body.required()),
                body.eligible_set_digest(),
                sqlite_i64(body.proposal_created_at(), "proposal_created_at")?,
                sqlite_i64(body.proposal_deadline(), "proposal_deadline")?,
                registration.proposal().policy_authority().to_hex(),
                canonical_proposal_json,
                canonical_eligible_approvers_json,
                registration.submitter_fingerprint(),
                if registration.separation_of_duties() {
                    1_i64
                } else {
                    0_i64
                },
            ],
        )
        .map_err(|error| {
            ApprovalStoreError::Backend(format!("insert threshold proposal: {error}"))
        })?;
        let record = load_threshold_proposal(&tx, body.proposal_id())?.ok_or_else(|| {
            ApprovalStoreError::Backend(
                "inserted threshold proposal could not be reloaded".to_string(),
            )
        })?;
        tx.commit().map_err(|error| {
            ApprovalStoreError::Backend(format!("commit threshold create tx: {error}"))
        })?;
        Ok(record)
    }

    fn get_threshold_approval_proposal_request_id(
        &self,
        proposal_id: &str,
        current_policy_hash: &str,
        trusted_policy_authorities: &[PublicKey],
    ) -> Result<Option<String>, ApprovalStoreError> {
        validate_threshold_proposal_id(proposal_id)?;
        let conn = self
            .pool
            .get()
            .map_err(|error| ApprovalStoreError::Backend(format!("pool get: {error}")))?;
        configure_reservation_connection(&conn)?;
        let Some(record) = load_threshold_proposal(&conn, proposal_id)? else {
            return Ok(None);
        };
        record
            .registration()
            .validate_current_authority(current_policy_hash, trusted_policy_authorities)?;
        Ok(Some(record.proposal().body().request_id().to_string()))
    }

    fn get_threshold_approval_proposal(
        &self,
        proposal_id: &str,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<Option<ThresholdApprovalProposalRecord>, ApprovalStoreError> {
        validate_threshold_proposal_id(proposal_id)?;
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApprovalStoreError::Backend(format!("pool get: {error}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("begin threshold get tx: {error}"))
            })?;
        let Some(mut record) = load_threshold_proposal(&tx, proposal_id)? else {
            tx.rollback().map_err(|error| {
                ApprovalStoreError::Backend(format!("rollback threshold miss: {error}"))
            })?;
            return Ok(None);
        };
        record
            .registration()
            .validate_current_context(current_context, trusted_policy_authorities)?;
        if persist_threshold_expiry(
            &tx,
            proposal_id,
            record.status(),
            now,
            record.proposal().body().proposal_deadline(),
        )? {
            record = load_threshold_proposal(&tx, proposal_id)?.ok_or_else(|| {
                ApprovalStoreError::Serialization(
                    "expired threshold proposal disappeared".to_string(),
                )
            })?;
        }
        tx.commit().map_err(|error| {
            ApprovalStoreError::Backend(format!("commit threshold get tx: {error}"))
        })?;
        Ok(Some(record))
    }

    fn append_threshold_approval_vote(
        &self,
        proposal_id: &str,
        token: &GovernedApprovalToken,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        validate_threshold_proposal_id(proposal_id)?;
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApprovalStoreError::Backend(format!("pool get: {error}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("begin threshold vote tx: {error}"))
            })?;
        let record = load_threshold_proposal(&tx, proposal_id)?
            .ok_or_else(|| ApprovalStoreError::NotFound(proposal_id.to_string()))?;
        record.validate_current_bindings(current_context, trusted_policy_authorities)?;
        if persist_threshold_expiry(
            &tx,
            proposal_id,
            record.status(),
            now,
            record.proposal().body().proposal_deadline(),
        )? {
            tx.commit().map_err(|error| {
                ApprovalStoreError::Backend(format!("commit threshold expiry: {error}"))
            })?;
            return Err(ApprovalStoreError::AlreadyResolved(format!(
                "threshold proposal `{proposal_id}` has expired"
            )));
        }
        if record.existing_vote_for(token)?.is_some() {
            tx.rollback().map_err(|error| {
                ApprovalStoreError::Backend(format!("rollback threshold vote retry: {error}"))
            })?;
            return Ok(record);
        }
        if record.status() != ThresholdApprovalCollectorStatus::Collecting {
            return Err(ApprovalStoreError::AlreadyResolved(format!(
                "threshold proposal `{proposal_id}` is {}",
                record.status().as_str()
            )));
        }
        let vote = ThresholdApprovalVoteRecord::validate_new(
            record.registration(),
            token.clone(),
            now,
            false,
        )?;
        let legacy_owner = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 OR token_digest = ?2 LIMIT 1",
                params![token.id, vote.token_digest()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("query threshold legacy owner: {error}"))
            })?;
        if legacy_owner.is_some() {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token `{}` was already consumed",
                token.id
            )));
        }
        let operation_owner = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1 OR token_digest = ?2
                LIMIT 1
                "#,
                params![token.id, vote.token_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("query threshold operation owner: {error}"))
            })?;
        if let Some(owner) = operation_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by operation `{owner}`"
            )));
        }
        let collector_owner = tx
            .query_row(
                r#"
                SELECT proposal_id
                FROM chio_hitl_threshold_votes
                WHERE token_id = ?1 OR canonical_token_digest = ?2
                LIMIT 1
                "#,
                params![token.id, vote.token_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("query threshold collector owner: {error}"))
            })?;
        if let Some(owner) = collector_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by threshold proposal `{owner}`"
            )));
        }
        let canonical_token_json = canonical_artifact_json(token, "threshold approval token")?;
        let position = i64::try_from(record.votes().len()).map_err(|_| {
            ApprovalStoreError::Invalid(
                "threshold vote position does not fit SQLite INTEGER".to_string(),
            )
        })?;
        tx.execute(
            r#"
            INSERT INTO chio_hitl_threshold_votes (
                proposal_id, position, token_id, approver_fingerprint,
                canonical_token_digest, canonical_token_json, received_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                proposal_id,
                position,
                token.id,
                vote.approver_fingerprint(),
                vote.token_digest(),
                canonical_token_json,
                sqlite_i64(now, "vote_received_at")?,
            ],
        )
        .map_err(|error| ApprovalStoreError::Backend(format!("insert threshold vote: {error}")))?;
        let required = usize::try_from(record.proposal().body().required()).map_err(|_| {
            ApprovalStoreError::Invalid(
                "threshold requirement does not fit this platform".to_string(),
            )
        })?;
        if record.votes().len() + 1 >= required {
            let updated = tx
                .execute(
                    r#"
                    UPDATE chio_hitl_threshold_proposals
                    SET status = 'satisfied', satisfied_at = ?2
                    WHERE proposal_id = ?1 AND status = 'collecting'
                    "#,
                    params![proposal_id, sqlite_i64(now, "satisfied_at")?],
                )
                .map_err(|error| {
                    ApprovalStoreError::Backend(format!("persist threshold satisfaction: {error}"))
                })?;
            if updated != 1 {
                return Err(ApprovalStoreError::Conflict(
                    "threshold proposal state changed concurrently".to_string(),
                ));
            }
        }
        let updated = load_threshold_proposal(&tx, proposal_id)?.ok_or_else(|| {
            ApprovalStoreError::Serialization(
                "threshold proposal disappeared after vote insertion".to_string(),
            )
        })?;
        tx.commit().map_err(|error| {
            ApprovalStoreError::Backend(format!("commit threshold vote tx: {error}"))
        })?;
        Ok(updated)
    }

    fn mark_threshold_approval_response_delivered(
        &self,
        proposal_id: &str,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        validate_threshold_proposal_id(proposal_id)?;
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApprovalStoreError::Backend(format!("pool get: {error}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("begin threshold delivery tx: {error}"))
            })?;
        let record = load_threshold_proposal(&tx, proposal_id)?
            .ok_or_else(|| ApprovalStoreError::NotFound(proposal_id.to_string()))?;
        record.validate_current_bindings(current_context, trusted_policy_authorities)?;
        if record.status() == ThresholdApprovalCollectorStatus::Delivered {
            tx.rollback().map_err(|error| {
                ApprovalStoreError::Backend(format!("rollback threshold delivery retry: {error}"))
            })?;
            return Ok(record);
        }
        if persist_threshold_expiry(
            &tx,
            proposal_id,
            record.status(),
            now,
            record.proposal().body().proposal_deadline(),
        )? {
            tx.commit().map_err(|error| {
                ApprovalStoreError::Backend(format!("commit threshold expiry: {error}"))
            })?;
            return Err(ApprovalStoreError::AlreadyResolved(format!(
                "threshold proposal `{proposal_id}` has expired"
            )));
        }
        if record.status() != ThresholdApprovalCollectorStatus::Satisfied {
            return Err(ApprovalStoreError::Conflict(format!(
                "threshold proposal `{proposal_id}` is not satisfied"
            )));
        }
        let updated = tx
            .execute(
                r#"
                UPDATE chio_hitl_threshold_proposals
                SET status = 'delivered', delivered_at = ?2
                WHERE proposal_id = ?1 AND status = 'satisfied'
                "#,
                params![proposal_id, sqlite_i64(now, "delivered_at")?],
            )
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("persist threshold delivery: {error}"))
            })?;
        if updated != 1 {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal state changed concurrently".to_string(),
            ));
        }
        let delivered = load_threshold_proposal(&tx, proposal_id)?.ok_or_else(|| {
            ApprovalStoreError::Serialization(
                "threshold proposal disappeared after response delivery".to_string(),
            )
        })?;
        tx.commit().map_err(|error| {
            ApprovalStoreError::Backend(format!("commit threshold delivery tx: {error}"))
        })?;
        Ok(delivered)
    }
}

fn validate_threshold_proposal_id(proposal_id: &str) -> Result<(), ApprovalStoreError> {
    if proposal_id.is_empty() || proposal_id.len() > 512 || proposal_id.contains('\0') {
        return Err(ApprovalStoreError::Invalid(
            "proposal_id is empty, oversized, or contains NUL".to_string(),
        ));
    }
    Ok(())
}

fn reject_volatile_database_path(path: &Path) -> Result<(), ApprovalStoreError> {
    let path = path.to_string_lossy();
    let lower = path.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path.is_empty() || path == ":memory:" || memory_uri || lower.starts_with("file::memory:") {
        return Err(ApprovalStoreError::Invalid(
            "volatile SQLite approval-store paths are not durable; use open_in_memory for an explicitly ephemeral store"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_test_support::prelude::*;

    #[test]
    fn open_colocated_creates_parent_dirs_for_a_file_uri_with_query() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("chio-approval-uri-{nonce}"));
        let db = base.join("nested").join("receipts.db");
        let parent = db.parent().expect("db path has a parent");
        assert!(!parent.exists());

        let uri = format!("file:{}?mode=rwc", db.display());
        let store = SqliteApprovalStore::open_colocated_with_receipt_store(uri.as_str())
            .expect("open colocated approval store from a file URI");
        store
            .store_pending(&sample_request("uri-1", "hash-uri"))
            .expect("store a pending approval");

        assert!(parent.exists());
        let _ = fs::remove_dir_all(&base);
    }

    fn operation_id(hex_pair: &str) -> String {
        hex_pair.repeat(32)
    }

    fn sample_request(id: &str, hash: &str) -> ApprovalRequest {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        ApprovalRequest {
            approval_id: id.into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "tool".into(),
            action: "invoke".into(),
            parameter_hash: hash.into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 42,
            summary: "unit".into(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        }
    }

    fn approval_set(hash_hex_pair: &str, members: &[(&str, &str)]) -> ApprovalSetReservationInput {
        ApprovalSetReservationInput::new(
            hash_hex_pair.repeat(32),
            members
                .iter()
                .map(|(token_id, digest_hex_pair)| {
                    ApprovalReservationMember::new(
                        (*token_id).to_string(),
                        digest_hex_pair.repeat(32),
                    )
                    .unwrap()
                })
                .collect(),
            10_000,
        )
        .unwrap()
    }

    #[test]
    fn store_and_list_round_trip() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let r1 = sample_request("a-1", "h-1");
        let r2 = sample_request("a-2", "h-2");
        store.store_pending(&r1).unwrap();
        store.store_pending(&r2).unwrap();

        let all = store.list_pending(&ApprovalFilter::default()).unwrap();
        assert_eq!(all.len(), 2);

        let fetched = store.get_pending("a-1").unwrap().unwrap();
        assert_eq!(fetched.approval_id, "a-1");
        assert_eq!(fetched.parameter_hash, "h-1");
    }

    #[test]
    fn duplicate_pending_insert_is_idempotent_only_when_payload_matches() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let original = sample_request("dup-1", "hash-a");
        let identical = original.clone();
        let mut mismatched = original.clone();
        mismatched.parameter_hash = "hash-b".into();

        store.store_pending(&original).unwrap();
        store.store_pending(&identical).unwrap();

        let err = store.store_pending(&mismatched).unwrap_err();
        match err {
            ApprovalStoreError::Backend(message) => {
                assert!(message.contains("already exists with different payload"));
            }
            other => panic!("expected Backend mismatch error, got {other:?}"),
        }

        let fetched = store.get_pending("dup-1").unwrap().unwrap();
        assert_eq!(fetched.parameter_hash, "hash-a");
    }

    #[test]
    fn standalone_open_refuses_a_receipt_sidecar_that_colocated_open_adopts() {
        // `chio api protect` keeps the approval store in the same file as its
        // receipt and revocation sidecar tables, and opens the receipt store
        // first so it owns the shared file's provenance anchor; the approval store
        // then co-locates onto it. A database carrying only receipt (and
        // revocation) tables and no approval anchor therefore belongs to the
        // receipt store. The standalone approval open must refuse it rather than
        // write HITL tables into a receipt store's file, while the dedicated
        // co-located open adopts it as its sibling.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sidecar.sqlite3");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE http_receipts (id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);
                 CREATE TABLE tool_receipts (id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);
                 CREATE TABLE revoked_capabilities (capability_id TEXT PRIMARY KEY);",
            )
            .unwrap();
            let app_id: i32 = conn
                .query_row("PRAGMA application_id", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                app_id, 0,
                "fixture must be unstamped like a legacy database"
            );
        }

        assert!(
            SqliteApprovalStore::open(&path).is_err(),
            "standalone approval open must refuse a receipt-only sidecar file"
        );

        let store = SqliteApprovalStore::open_colocated_with_receipt_store(&path)
            .expect("co-located open must adopt the receipt sidecar file");
        store
            .store_pending(&sample_request("adopt-1", "hash-adopt"))
            .unwrap();
        assert!(store.get_pending("adopt-1").unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn receipt_colocated_approval_pool_rejects_post_open_path_rebinding() {
        use std::os::unix::fs::OpenOptionsExt;

        let directory =
            chio_test_support::private_fs::private_tempdir("receipt-colocated-approval-rebind")
                .test_expect("create private receipt approval directory");
        let directory = fs::canonicalize(directory.path()).unwrap();
        let path = directory.join("receipt-approval.sqlite3");
        let displaced = directory.join("receipt-approval-displaced.sqlite3");
        let replacement = directory.join("receipt-approval-replacement.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let approval_store =
            SqliteApprovalStore::open_colocated_with_receipt_store_handle(&receipt_store).unwrap();
        match &approval_store.pool {
            ApprovalConnectionPool::ReceiptBound(pool) => assert!(pool.try_get().is_some()),
            ApprovalConnectionPool::Standalone(_) => {
                panic!("co-located approval authority must retain the receipt-bound pool")
            }
        }
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&replacement)
            .unwrap();

        fs::rename(&path, &displaced).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let rejected = match &approval_store.pool {
            ApprovalConnectionPool::ReceiptBound(pool) => pool.try_get().is_none(),
            ApprovalConnectionPool::Standalone(_) => false,
        };
        assert!(
            rejected,
            "the approval authority must check the receipt descriptor on pool checkout"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            0,
            "a rejected replacement must not receive approval schema mutations"
        );

        fs::rename(&path, &replacement).unwrap();
        fs::rename(&displaced, &path).unwrap();
        drop(approval_store);
        drop(receipt_store);
    }

    #[test]
    fn standalone_open_reopens_a_genuine_approval_database() {
        // A real approval database carries the approval anchor, so the standalone
        // open reopens it across restarts without co-location.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sqlite3");
        {
            let store = SqliteApprovalStore::open(&path).unwrap();
            store
                .store_pending(&sample_request("reopen-1", "hash-reopen"))
                .unwrap();
        }
        let store = SqliteApprovalStore::open(&path)
            .expect("a genuine approval database must reopen standalone");
        assert!(store.get_pending("reopen-1").unwrap().is_some());
    }

    #[test]
    fn operation_reservation_schema_bounds_member_payloads() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let connection = store.pool.get().unwrap();
        let oversized_members = "x".repeat(262_145);
        assert!(connection
            .execute(
                r#"
                INSERT INTO chio_hitl_operation_reservations (
                    operation_id, approval_set_hash, members_json, proposal_deadline, state
                ) VALUES (?1, ?2, ?3, ?4, 'reserved')
                "#,
                params![
                    operation_id("20"),
                    "aa".repeat(32),
                    oversized_members,
                    10_000
                ],
            )
            .is_err());
    }

    #[test]
    fn operation_approval_reservations_survive_restart_and_reject_rebinding() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-reservation-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first_set = approval_set(
            "aa",
            &[("approval-token-2", "22"), ("approval-token-1", "11")],
        );
        let committed = {
            let store = SqliteApprovalStore::open(&path).unwrap();
            let reserved = store
                .reserve_approval_set(operation_id("01").as_str(), &first_set)
                .unwrap();
            assert_eq!(reserved.state(), ReplayReservationState::Reserved);
            assert_eq!(reserved.approval_set().proposal_deadline(), 10_000);
            assert_eq!(
                reserved
                    .approval_set()
                    .members()
                    .iter()
                    .map(ApprovalReservationMember::token_id)
                    .collect::<Vec<_>>(),
                vec!["approval-token-1", "approval-token-2"]
            );
            assert_eq!(
                store
                    .reserve_approval_set(operation_id("01").as_str(), &first_set)
                    .unwrap(),
                reserved
            );
            let changed_deadline = ApprovalSetReservationInput::new(
                first_set.approval_set_hash().to_string(),
                first_set.members().to_vec(),
                10_001,
            )
            .unwrap();
            assert!(matches!(
                store.reserve_approval_set(operation_id("01").as_str(), &changed_deadline),
                Err(ApprovalStoreError::Replay(_))
            ));
            let overlapping = approval_set("bb", &[("approval-token-3", "11")]);
            assert!(matches!(
                store.reserve_approval_set(operation_id("02").as_str(), &overlapping),
                Err(ApprovalStoreError::Replay(_))
            ));
            let duplicate_hash = approval_set("aa", &[("approval-token-hash", "55")]);
            assert!(matches!(
                store.reserve_approval_set(operation_id("05").as_str(), &duplicate_hash),
                Err(ApprovalStoreError::Replay(_))
            ));
            store
                .commit_approval_reservation(operation_id("01").as_str())
                .unwrap()
        };
        let reopened = SqliteApprovalStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_approval_reservation(operation_id("01").as_str())
                .unwrap(),
            Some(committed.clone())
        );
        assert_eq!(
            reopened
                .commit_approval_reservation(operation_id("01").as_str())
                .unwrap(),
            committed
        );
        assert!(matches!(
            reopened.cancel_approval_reservation(operation_id("01").as_str()),
            Err(ApprovalStoreError::Replay(_))
        ));
        let cancellation_set = approval_set("cc", &[("approval-token-4", "33")]);
        let cancelled = reopened
            .reserve_approval_set(operation_id("03").as_str(), &cancellation_set)
            .and_then(|_| reopened.cancel_approval_reservation(operation_id("03").as_str()))
            .unwrap();
        drop(reopened);
        let reopened = SqliteApprovalStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .reserve_approval_set(operation_id("03").as_str(), &cancellation_set)
                .unwrap(),
            cancelled
        );
        assert_eq!(
            reopened
                .cancel_approval_reservation(operation_id("03").as_str())
                .unwrap(),
            cancelled
        );
        assert!(matches!(
            reopened.reserve_approval_set(operation_id("04").as_str(), &cancellation_set),
            Err(ApprovalStoreError::Replay(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_and_operation_approval_replay_paths_interlock_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-interlock-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let legacy_member_set = approval_set("aa", &[("legacy-token", "11")]);
        let operation_member_set = approval_set("bb", &[("operation-token", "22")]);
        {
            let store = SqliteApprovalStore::open(&path).unwrap();
            store
                .record_consumed("legacy-token", "parameter-a", 1)
                .unwrap();
            assert!(matches!(
                store.record_consumed("legacy-token", "parameter-b", 2),
                Err(ApprovalStoreError::Replay(_))
            ));
            assert!(store.is_consumed("legacy-token", "parameter-b").unwrap());
            assert!(matches!(
                store.reserve_approval_set(operation_id("06").as_str(), &legacy_member_set),
                Err(ApprovalStoreError::Replay(_))
            ));
            store
                .reserve_approval_set(operation_id("07").as_str(), &operation_member_set)
                .unwrap();
        }
        let reopened = SqliteApprovalStore::open(&path).unwrap();
        assert!(matches!(
            reopened.record_consumed("operation-token", "parameter-b", 2),
            Err(ApprovalStoreError::Replay(_))
        ));
        assert!(reopened
            .is_consumed("operation-token", "parameter-b")
            .unwrap());
        assert!(matches!(
            reopened.reserve_approval_set(operation_id("06").as_str(), &legacy_member_set),
            Err(ApprovalStoreError::Replay(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_approval_reservations_have_one_token_owner() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-reservation-race-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let second = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let shared_set = approval_set("aa", &[("race-token", "44")]);
        let spawn = |store: std::sync::Arc<SqliteApprovalStore>, operation_id: String| {
            let barrier = std::sync::Arc::clone(&barrier);
            let shared_set = shared_set.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.reserve_approval_set(&operation_id, &shared_set)
            })
        };
        let first_thread = spawn(std::sync::Arc::clone(&first), operation_id("08"));
        let second_thread = spawn(std::sync::Arc::clone(&second), operation_id("09"));
        barrier.wait();
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ApprovalStoreError::Replay(_))))
                .count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_legacy_and_operation_paths_have_one_token_owner() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-cross-path-race-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let reservation_store = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let legacy_store = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let set = approval_set("aa", &[("cross-path-token", "55")]);
        let reservation_thread = {
            let store = std::sync::Arc::clone(&reservation_store);
            let barrier = std::sync::Arc::clone(&barrier);
            let reservation_operation_id = operation_id("10");
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .reserve_approval_set(&reservation_operation_id, &set)
                    .map(|_| ())
            })
        };
        let legacy_thread = {
            let store = std::sync::Arc::clone(&legacy_store);
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.record_consumed("cross-path-token", "parameter", 1)
            })
        };
        barrier.wait();
        let results = [
            reservation_thread.join().unwrap(),
            legacy_thread.join().unwrap(),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ApprovalStoreError::Replay(_))))
                .count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }
}
