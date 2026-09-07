impl SessionThrottleStore for SqliteSecurityStateStore {
    fn ensure_session_throttles_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        let orphaned: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_session_throttle_effects AS effects
                    LEFT JOIN security_session_throttle_state AS state
                      ON state.tenant_id = effects.tenant_id
                     AND state.session_id = effects.session_id
                    WHERE state.tenant_id IS NULL
                    UNION ALL
                    SELECT 1
                    FROM security_session_throttle_windows AS windows
                    LEFT JOIN security_session_throttle_effects AS effects
                      ON effects.tenant_id = windows.tenant_id
                     AND effects.session_id = windows.session_id
                     AND effects.effect_id = windows.effect_id
                    WHERE effects.tenant_id IS NULL
                    UNION ALL
                    SELECT 1
                    FROM security_session_throttle_invocations AS invocations
                    LEFT JOIN security_session_throttle_windows AS windows
                      ON windows.tenant_id = invocations.tenant_id
                     AND windows.session_id = invocations.session_id
                     AND windows.effect_id = invocations.effect_id
                     AND windows.window_start = invocations.window_start
                    WHERE windows.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if orphaned {
            return Err(PortError::integrity_failure());
        }

        let mut state_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, session_id
                FROM security_session_throttle_state
                ORDER BY tenant_id, session_id
                "#,
            )
            .map_err(sqlite_error)?;
        let state_rows = state_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut keys = Vec::new();
        for row in state_rows {
            let (tenant_id, session_id) = row.map_err(sqlite_error)?;
            keys.push(SessionThrottleKey {
                tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                    .map_err(|_| PortError::integrity_failure())?,
                session_id: chio_security_types::ports::SessionId::new(session_id)
                    .map_err(|_| PortError::integrity_failure())?,
            });
        }
        drop(state_statement);
        for key in &keys {
            load_session_throttle_snapshot(&connection, key)?;
        }

        let mut window_statement = connection
            .prepare(
                r#"
                SELECT windows.tenant_id, windows.session_id, windows.effect_id,
                       windows.window_start, windows.window_end, windows.window_id,
                       windows.consumed, effects.window_ms, effects.max_invocations
                FROM security_session_throttle_windows AS windows
                JOIN security_session_throttle_effects AS effects
                  ON effects.tenant_id = windows.tenant_id
                 AND effects.session_id = windows.session_id
                 AND effects.effect_id = windows.effect_id
                ORDER BY windows.tenant_id, windows.session_id,
                         windows.effect_id, windows.window_start
                "#,
            )
            .map_err(sqlite_error)?;
        let window_rows = window_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })
            .map_err(sqlite_error)?;
        for row in window_rows {
            let (
                tenant_id,
                session_id,
                effect_id,
                window_start,
                window_end,
                window_id,
                consumed,
                window_ms,
                max_invocations,
            ) = row.map_err(sqlite_error)?;
            let key = SessionThrottleKey {
                tenant_id: chio_security_types::ports::TenantId::new(tenant_id.clone())
                    .map_err(|_| PortError::integrity_failure())?,
                session_id: chio_security_types::ports::SessionId::new(session_id.clone())
                    .map_err(|_| PortError::integrity_failure())?,
            };
            let effect_id =
                EffectId::new(effect_id.clone()).map_err(|_| PortError::integrity_failure())?;
            let limits = SessionThrottleLimits {
                window_ms: from_i64(window_ms)?,
                max_invocations: u32::try_from(max_invocations)
                    .map_err(|_| PortError::integrity_failure())?,
            };
            limits
                .validate()
                .map_err(|_| PortError::integrity_failure())?;
            let identity =
                session_throttle_window_identity(&key, &effect_id, limits, from_i64(window_start)?)
                    .map_err(|_| PortError::integrity_failure())?;
            let consumed = u32::try_from(consumed).map_err(|_| PortError::integrity_failure())?;
            let invocation_count: i64 = connection
                .query_row(
                    r#"
                    SELECT COUNT(*) FROM security_session_throttle_invocations
                    WHERE tenant_id = ?1 AND session_id = ?2
                      AND effect_id = ?3 AND window_start = ?4
                    "#,
                    params![tenant_id, session_id, effect_id.as_str(), window_start],
                    |count_row| count_row.get(0),
                )
                .map_err(sqlite_error)?;
            if identity.window_start_unix_ms != from_i64(window_start)?
                || identity.window_id.as_str() != window_id
                || identity.window_end_unix_ms != from_i64(window_end)?
                || consumed > limits.max_invocations
                || u32::try_from(invocation_count).map_err(|_| PortError::integrity_failure())?
                    != consumed
            {
                return Err(PortError::integrity_failure());
            }
        }
        drop(window_statement);

        let mut command_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, idempotency_key
                FROM security_session_throttle_commands
                ORDER BY tenant_id, idempotency_key
                "#,
            )
            .map_err(sqlite_error)?;
        let command_rows = command_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        for row in command_rows {
            let (tenant_id, idempotency_key) = row.map_err(sqlite_error)?;
            let command = load_session_throttle_command(
                &connection,
                tenant_id.as_str(),
                idempotency_key.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            validate_stored_session_throttle_command(&command)?;
        }
        Ok(())
    }

    fn apply_session_throttle(
        &self,
        request: &SessionThrottleApplyRequest,
    ) -> PortResult<SessionThrottleSnapshot> {
        validate_session_throttle_apply_command(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_fence(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_session_throttle_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing.resulting_snapshot);
        }
        let binding = load_session_throttle_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.contribution.effect_id.as_str(),
        )?;
        if let Some((session_id, action_id)) = binding.as_ref() {
            if session_id != request.key.session_id.as_str()
                || action_id != request.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        let current = load_session_throttle_snapshot(&transaction, &request.key)?;
        let predicted = predict_session_throttle_apply(
            &current,
            &request.contribution,
            request.scheduler_fencing_token,
        )?;
        if request.command.resulting_snapshot != predicted {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            if existing != &request.contribution {
                return Err(PortError::conflict());
            }
            persist_session_throttle_state(
                &transaction,
                &request.key,
                current.generation,
                current
                    .highest_fencing_token
                    .max(request.scheduler_fencing_token),
            )?;
            let stored = load_session_throttle_snapshot(&transaction, &request.key)?;
            if stored != predicted {
                return Err(PortError::integrity_failure());
            }
            persist_session_throttle_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        if binding.is_some()
            || current.generation != request.expected_generation
            || session_throttle_version_hash(&current)?
                != request.command.request.expected_version_hash
            || request.contribution.expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::conflict());
        }
        persist_session_throttle_state(
            &transaction,
            &request.key,
            current.generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        transaction
            .execute(
                r#"
                INSERT INTO security_session_throttle_effects (
                    tenant_id, session_id, effect_id, action_id, window_ms,
                    max_invocations, contribution_hash, expires_at,
                    installed_fencing_token
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.session_id.as_str(),
                    request.contribution.effect_id.as_str(),
                    request.action_id.as_str(),
                    to_i64(request.contribution.limits.window_ms)?,
                    i64::from(request.contribution.limits.max_invocations),
                    request.contribution.contribution_hash.as_bytes().as_slice(),
                    to_i64(request.contribution.expires_at_unix_ms)?,
                    to_i64(request.scheduler_fencing_token)?
                ],
            )
            .map_err(sqlite_error)?;
        persist_session_throttle_state(
            &transaction,
            &request.key,
            predicted.generation,
            predicted.highest_fencing_token,
        )?;
        let stored = load_session_throttle_snapshot(&transaction, &request.key)?;
        if stored != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_session_throttle_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn remove_session_throttle(
        &self,
        request: &SessionThrottleRemoveRequest,
    ) -> PortResult<SessionThrottleSnapshot> {
        validate_session_throttle_remove_command(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_fence(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_session_throttle_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing.resulting_snapshot);
        }
        let binding = load_session_throttle_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.effect_id.as_str(),
        )?;
        if let Some((session_id, action_id)) = binding.as_ref() {
            if session_id != request.key.session_id.as_str()
                || action_id != request.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        let current = load_session_throttle_snapshot(&transaction, &request.key)?;
        let predicted = predict_session_throttle_remove(
            &current,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        if request.command.resulting_snapshot != predicted {
            return Err(PortError::conflict());
        }
        let Some(stored_contribution) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        else {
            if binding.is_some() {
                return Err(PortError::integrity_failure());
            }
            persist_session_throttle_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        };
        let limits = decode_session_throttle_limits(&request.command.request)?;
        if stored_contribution.limits != limits
            || stored_contribution.contribution_hash != request.command.request.contribution_hash
            || stored_contribution.expires_at_unix_ms
                != request.command.request.plan_expires_at_unix_ms
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let deleted = transaction
            .execute(
                r#"
                DELETE FROM security_session_throttle_effects
                WHERE tenant_id = ?1 AND session_id = ?2
                  AND effect_id = ?3 AND action_id = ?4
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.session_id.as_str(),
                    request.effect_id.as_str(),
                    request.action_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        persist_session_throttle_state(
            &transaction,
            &request.key,
            predicted.generation,
            predicted.highest_fencing_token,
        )?;
        let stored = load_session_throttle_snapshot(&transaction, &request.key)?;
        if stored != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_session_throttle_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn load_session_throttles(
        &self,
        key: &SessionThrottleKey,
    ) -> PortResult<Option<SessionThrottleSnapshot>> {
        let connection = self.connection()?;
        let exists: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM security_session_throttle_state
                    WHERE tenant_id = ?1 AND session_id = ?2
                )
                "#,
                params![key.tenant_id.as_str(), key.session_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !exists {
            return Ok(None);
        }
        Ok(Some(load_session_throttle_snapshot(&connection, key)?))
    }

    fn consume_session_invocation(
        &self,
        request: &SessionThrottleConsumeRequest,
    ) -> PortResult<SessionThrottleDecision> {
        if request.observed_at_unix_ms == 0 {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let snapshot = load_session_throttle_snapshot(&transaction, &request.key)?;
        let current_version_hash = session_throttle_version_hash(&snapshot)?;
        let mut windows = Vec::with_capacity(snapshot.contributions.len());
        let mut allowed = true;
        for contribution in snapshot.contributions.as_slice() {
            let identity = session_throttle_window_identity(
                &request.key,
                &contribution.effect_id,
                contribution.limits,
                request.observed_at_unix_ms,
            )?;
            let stored: Option<(i64, i64, String, i64)> = transaction
                .query_row(
                    r#"
                    SELECT window_start, window_end, window_id, consumed
                    FROM security_session_throttle_windows
                    WHERE tenant_id = ?1 AND session_id = ?2
                      AND effect_id = ?3 AND window_start = ?4
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.session_id.as_str(),
                        contribution.effect_id.as_str(),
                        to_i64(identity.window_start_unix_ms)?
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(sqlite_error)?;
            let consumed = if let Some((window_start, window_end, window_id, consumed)) = stored {
                let consumed =
                    u32::try_from(consumed).map_err(|_| PortError::integrity_failure())?;
                let invocation_count: i64 = transaction
                    .query_row(
                        r#"
                        SELECT COUNT(*) FROM security_session_throttle_invocations
                        WHERE tenant_id = ?1 AND session_id = ?2
                          AND effect_id = ?3 AND window_start = ?4
                        "#,
                        params![
                            request.key.tenant_id.as_str(),
                            request.key.session_id.as_str(),
                            contribution.effect_id.as_str(),
                            window_start
                        ],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_error)?;
                if from_i64(window_start)? != identity.window_start_unix_ms
                    || from_i64(window_end)? != identity.window_end_unix_ms
                    || window_id != identity.window_id.as_str()
                    || consumed > contribution.limits.max_invocations
                    || u32::try_from(invocation_count)
                        .map_err(|_| PortError::integrity_failure())?
                        != consumed
                {
                    return Err(PortError::integrity_failure());
                }
                consumed
            } else {
                0
            };
            let replay: bool = transaction
                .query_row(
                    r#"
                    SELECT EXISTS(
                        SELECT 1 FROM security_session_throttle_invocations
                        WHERE tenant_id = ?1 AND session_id = ?2
                          AND effect_id = ?3 AND window_start = ?4
                          AND invocation_id = ?5
                    )
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.session_id.as_str(),
                        contribution.effect_id.as_str(),
                        to_i64(identity.window_start_unix_ms)?,
                        request.invocation_id.as_str()
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if !replay && consumed >= contribution.limits.max_invocations {
                allowed = false;
            }
            windows.push((contribution, identity, consumed, replay));
        }

        let mut usages = Vec::with_capacity(windows.len());
        for (contribution, identity, consumed, replay) in windows {
            let resulting_consumed = if allowed && !replay {
                transaction
                    .execute(
                        r#"
                        INSERT INTO security_session_throttle_windows (
                            tenant_id, session_id, effect_id, window_start,
                            window_end, window_id, consumed
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
                        ON CONFLICT (tenant_id, session_id, effect_id, window_start)
                        DO NOTHING
                        "#,
                        params![
                            request.key.tenant_id.as_str(),
                            request.key.session_id.as_str(),
                            contribution.effect_id.as_str(),
                            to_i64(identity.window_start_unix_ms)?,
                            to_i64(identity.window_end_unix_ms)?,
                            identity.window_id.as_str()
                        ],
                    )
                    .map_err(sqlite_error)?;
                let inserted = transaction
                    .execute(
                        r#"
                        INSERT INTO security_session_throttle_invocations (
                            tenant_id, session_id, effect_id, window_start, invocation_id
                        ) VALUES (?1, ?2, ?3, ?4, ?5)
                        "#,
                        params![
                            request.key.tenant_id.as_str(),
                            request.key.session_id.as_str(),
                            contribution.effect_id.as_str(),
                            to_i64(identity.window_start_unix_ms)?,
                            request.invocation_id.as_str()
                        ],
                    )
                    .map_err(sqlite_error)?;
                if inserted != 1 {
                    return Err(PortError::integrity_failure());
                }
                let updated = transaction
                    .execute(
                        r#"
                        UPDATE security_session_throttle_windows
                        SET consumed = consumed + 1
                        WHERE tenant_id = ?1 AND session_id = ?2
                          AND effect_id = ?3 AND window_start = ?4
                          AND consumed = ?5 AND consumed < ?6
                        "#,
                        params![
                            request.key.tenant_id.as_str(),
                            request.key.session_id.as_str(),
                            contribution.effect_id.as_str(),
                            to_i64(identity.window_start_unix_ms)?,
                            i64::from(consumed),
                            i64::from(contribution.limits.max_invocations)
                        ],
                    )
                    .map_err(sqlite_error)?;
                if updated != 1 {
                    return Err(PortError::integrity_failure());
                }
                consumed
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?
            } else {
                consumed
            };
            if allowed {
                transaction
                    .execute(
                        r#"
                        DELETE FROM security_session_throttle_windows
                        WHERE tenant_id = ?1 AND session_id = ?2
                          AND effect_id = ?3 AND window_start < ?4
                        "#,
                        params![
                            request.key.tenant_id.as_str(),
                            request.key.session_id.as_str(),
                            contribution.effect_id.as_str(),
                            to_i64(identity.window_start_unix_ms)?
                        ],
                    )
                    .map_err(sqlite_error)?;
            }
            usages.push(SessionThrottleWindowUsage {
                effect_id: contribution.effect_id.clone(),
                identity,
                consumed_before: consumed,
                consumed_after: resulting_consumed,
                max_invocations: contribution.limits.max_invocations,
                replayed: replay,
            });
        }
        let windows =
            SessionThrottleWindowUsages::new(usages).map_err(|_| PortError::integrity_failure())?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(SessionThrottleDecision {
            key: request.key.clone(),
            allowed,
            generation: snapshot.generation,
            current_version_hash,
            windows,
        })
    }

    fn load_session_throttle_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let connection = self.connection()?;
        let Some(command) = load_session_throttle_command(
            &connection,
            query.tenant_id.as_str(),
            query.idempotency_key.as_str(),
        )?
        else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        validate_stored_session_throttle_command(&command)?;
        if !effect_request_matches_query(&command.request, query) {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result,
        })
    }
}

impl EgressRestrictionStore for SqliteSecurityStateStore {
    fn ensure_egress_restrictions_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        let orphan_effect: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_egress_restriction_effects AS effects
                    LEFT JOIN security_egress_restriction_state AS state
                      ON state.tenant_id = effects.tenant_id
                     AND state.session_id = effects.session_id
                    WHERE state.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let orphan_destination: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_egress_restriction_destinations AS destinations
                    LEFT JOIN security_egress_restriction_effects AS effects
                      ON effects.tenant_id = destinations.tenant_id
                     AND effects.session_id = destinations.session_id
                     AND effects.effect_id = destinations.effect_id
                    WHERE effects.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if orphan_effect || orphan_destination {
            return Err(PortError::integrity_failure());
        }

        let mut statement = connection
            .prepare(
                r#"
                SELECT tenant_id, session_id
                FROM security_egress_restriction_state
                ORDER BY tenant_id, session_id
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut keys = Vec::new();
        for row in rows {
            let (tenant_id, session_id) = row.map_err(sqlite_error)?;
            keys.push(EgressRestrictionSessionKey {
                tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                    .map_err(|_| PortError::integrity_failure())?,
                session_id: chio_security_types::ports::SessionId::new(session_id)
                    .map_err(|_| PortError::integrity_failure())?,
            });
        }
        drop(statement);
        for key in keys {
            if load_egress_restriction_snapshot(&connection, &key)?.is_none() {
                return Err(PortError::integrity_failure());
            }
        }
        let mut command_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, idempotency_key
                FROM security_egress_restriction_commands
                ORDER BY tenant_id, idempotency_key
                "#,
            )
            .map_err(sqlite_error)?;
        let command_rows = command_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut command_keys = Vec::new();
        for row in command_rows {
            command_keys.push(row.map_err(sqlite_error)?);
        }
        drop(command_statement);
        for (tenant_id, idempotency_key) in command_keys {
            let command = load_egress_restriction_command(
                &connection,
                tenant_id.as_str(),
                idempotency_key.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            validate_stored_egress_restriction_command(&command)?;
        }
        Ok(())
    }

    fn apply_egress_restriction(
        &self,
        request: &EgressRestrictionApplyRequest,
    ) -> PortResult<EgressRestrictionSnapshot> {
        validate_egress_apply_command(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let binding = load_egress_restriction_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.contribution.effect_id.as_str(),
        )?;
        if let Some((session_id, action_id)) = binding.as_ref() {
            if session_id != request.key.session_id.as_str()
                || action_id != request.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        validate_scheduler_fence(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_egress_restriction_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            let current = load_egress_restriction_snapshot(&transaction, &request.key)?
                .unwrap_or(empty_egress_restriction_snapshot(&request.key)?);
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        }
        let current = load_egress_restriction_snapshot(&transaction, &request.key)?
            .unwrap_or(empty_egress_restriction_snapshot(&request.key)?);
        if let Some(existing) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            if binding.is_none() {
                return Err(PortError::integrity_failure());
            }
            if existing != &request.contribution {
                return Err(PortError::conflict());
            }
            persist_egress_restriction_state(
                &transaction,
                &request.key,
                current.generation,
                current
                    .highest_fencing_token
                    .max(request.scheduler_fencing_token),
            )?;
            let snapshot = load_egress_restriction_snapshot(&transaction, &request.key)?
                .ok_or_else(PortError::integrity_failure)?;
            persist_egress_restriction_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(snapshot);
        }
        if binding.is_some() {
            return Err(PortError::integrity_failure());
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        if request.contribution.expires_at_unix_ms <= trusted_now {
            return Err(PortError::invalid_data());
        }

        persist_egress_restriction_state(
            &transaction,
            &request.key,
            current.generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        transaction
            .execute(
                r#"
                INSERT INTO security_egress_restriction_effects (
                    tenant_id, session_id, effect_id, action_id, contribution_hash,
                    expires_at, installed_fencing_token
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.session_id.as_str(),
                    request.contribution.effect_id.as_str(),
                    request.action_id.as_str(),
                    request.contribution.contribution_hash.as_bytes().as_slice(),
                    to_i64(request.contribution.expires_at_unix_ms)?,
                    to_i64(request.scheduler_fencing_token)?
                ],
            )
            .map_err(sqlite_error)?;
        for destination in request.contribution.destinations.as_slice() {
            transaction
                .execute(
                    r#"
                    INSERT INTO security_egress_restriction_destinations (
                        tenant_id, session_id, effect_id, destination_id
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.session_id.as_str(),
                        request.contribution.effect_id.as_str(),
                        destination.as_str()
                    ],
                )
                .map_err(sqlite_error)?;
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        persist_egress_restriction_state(
            &transaction,
            &request.key,
            generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        let snapshot = load_egress_restriction_snapshot(&transaction, &request.key)?
            .ok_or_else(PortError::integrity_failure)?;
        persist_egress_restriction_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn remove_egress_restriction(
        &self,
        request: &EgressRestrictionRemoveRequest,
    ) -> PortResult<EgressRestrictionSnapshot> {
        validate_egress_remove_command(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let binding = load_egress_restriction_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.effect_id.as_str(),
        )?;
        if let Some((session_id, action_id)) = binding.as_ref() {
            if session_id != request.key.session_id.as_str()
                || action_id != request.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        validate_scheduler_fence(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_egress_restriction_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            let current = load_egress_restriction_snapshot(&transaction, &request.key)?
                .unwrap_or(empty_egress_restriction_snapshot(&request.key)?);
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        }
        let current = load_egress_restriction_snapshot(&transaction, &request.key)?
            .unwrap_or(empty_egress_restriction_snapshot(&request.key)?);
        let existing_contribution = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id);
        let Some(existing_contribution) = existing_contribution else {
            if binding.is_some() {
                return Err(PortError::integrity_failure());
            }
            persist_egress_restriction_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        };
        if binding.is_none() {
            return Err(PortError::integrity_failure());
        }
        let command_contribution = decode_egress_command_contribution(&request.command.request)?;
        if command_contribution.destinations != existing_contribution.destinations
            || request.command.request.contribution_hash != existing_contribution.contribution_hash
            || request.command.request.plan_expires_at_unix_ms
                != existing_contribution.expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        let deleted = transaction
            .execute(
                r#"
                DELETE FROM security_egress_restriction_effects
                WHERE tenant_id = ?1 AND session_id = ?2
                  AND effect_id = ?3 AND action_id = ?4
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.session_id.as_str(),
                    request.effect_id.as_str(),
                    request.action_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        persist_egress_restriction_state(
            &transaction,
            &request.key,
            generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        let snapshot = load_egress_restriction_snapshot(&transaction, &request.key)?
            .ok_or_else(PortError::integrity_failure)?;
        persist_egress_restriction_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn load_egress_restrictions(
        &self,
        key: &EgressRestrictionSessionKey,
    ) -> PortResult<Option<EgressRestrictionSnapshot>> {
        let connection = self.connection()?;
        load_egress_restriction_snapshot(&connection, key)
    }

    fn evaluate_destination(
        &self,
        query: &EgressDestinationQuery,
    ) -> PortResult<EgressRestrictionDecision> {
        let connection = self.connection()?;
        let snapshot = load_egress_restriction_snapshot(&connection, &query.key)?;
        let Some(snapshot) = snapshot else {
            return Ok(EgressRestrictionDecision {
                key: query.key.clone(),
                destination_id: query.destination_id.clone(),
                denied: false,
                active_effect_ids: EgressRestrictionEffectIds::new(Vec::new())
                    .map_err(|_| PortError::integrity_failure())?,
                generation: 0,
            });
        };
        let effect_ids = snapshot
            .contributions
            .as_slice()
            .iter()
            .filter(|contribution| {
                contribution
                    .destinations
                    .as_slice()
                    .binary_search(&query.destination_id)
                    .is_ok()
            })
            .map(|contribution| contribution.effect_id.clone())
            .collect();
        let active_effect_ids = EgressRestrictionEffectIds::new(effect_ids)
            .map_err(|_| PortError::integrity_failure())?;
        Ok(EgressRestrictionDecision {
            key: query.key.clone(),
            destination_id: query.destination_id.clone(),
            denied: !active_effect_ids.is_empty(),
            active_effect_ids,
            generation: snapshot.generation,
        })
    }

    fn load_egress_restriction_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let connection = self.connection()?;
        let Some(command) = load_egress_restriction_command(
            &connection,
            query.tenant_id.as_str(),
            query.idempotency_key.as_str(),
        )?
        else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        validate_stored_egress_restriction_command(&command)?;
        if !effect_request_matches_query(&command.request, query) {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EgressCommandContributionBody {
    destinations: EgressDestinationSet,
}

fn validate_stored_egress_restriction_command(
    command: &EgressRestrictionCommand,
) -> PortResult<()> {
    validate_egress_command_common(command).map_err(|_| PortError::integrity_failure())?;
    Ok(())
}

fn validate_egress_apply_command(request: &EgressRestrictionApplyRequest) -> PortResult<()> {
    validate_egress_command_common(&request.command)?;
    let command = &request.command.request;
    let ResponseTarget::Session { session_id } = &command.target else {
        return Err(PortError::invalid_data());
    };
    let contribution = decode_egress_command_contribution(command)?;
    if command.tenant_id != request.key.tenant_id
        || session_id != &request.key.session_id
        || command.action_id != request.action_id
        || command.effect_id != request.contribution.effect_id
        || command.operation != EffectOperation::Apply
        || command.plan_expires_at_unix_ms != request.contribution.expires_at_unix_ms
        || command.contribution_hash != request.contribution.contribution_hash
        || command.scheduler_fencing_token != request.scheduler_fencing_token
        || contribution.destinations != request.contribution.destinations
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_egress_remove_command(request: &EgressRestrictionRemoveRequest) -> PortResult<()> {
    validate_egress_command_common(&request.command)?;
    let command = &request.command.request;
    let ResponseTarget::Session { session_id } = &command.target else {
        return Err(PortError::invalid_data());
    };
    if command.tenant_id != request.key.tenant_id
        || session_id != &request.key.session_id
        || command.action_id != request.action_id
        || command.effect_id != request.effect_id
        || command.operation != EffectOperation::Remove
        || command.scheduler_fencing_token != request.scheduler_fencing_token
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_egress_command_common(command: &EgressRestrictionCommand) -> PortResult<()> {
    let request = &command.request;
    if request.effect_kind != ResponseEffectKind::RestrictEgress
        || !matches!(&request.target, ResponseTarget::Session { .. })
        || request.plan_expires_at_unix_ms == 0
        || request.scheduler_fencing_token == 0
        || !request
            .idempotency_key
            .as_str()
            .starts_with("response_effect_command:")
        || command.result.effect_id != request.effect_id
        || command.result.applied != matches!(request.operation, EffectOperation::Apply)
    {
        return Err(PortError::invalid_data());
    }
    decode_egress_command_contribution(request)?;
    Ok(())
}

fn decode_egress_command_contribution(
    request: &EffectRequest,
) -> PortResult<EgressCommandContributionBody> {
    validate_canonical_json_body(&request.canonical_contribution, &request.contribution_hash)?;
    let contribution: EgressCommandContributionBody =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    let canonical =
        canonical_json_bytes(&contribution).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(contribution)
}

fn effect_request_matches_query(request: &EffectRequest, query: &EffectResultQuery) -> bool {
    request.tenant_id == query.tenant_id
        && request.action_id == query.action_id
        && request.plan_hash == query.plan_hash
        && request.effect_id == query.effect_id
        && request.effect_kind == query.effect_kind
        && request.target == query.target
        && request.plan_expires_at_unix_ms == query.plan_expires_at_unix_ms
        && request.operation == query.operation
        && request.idempotency_key == query.idempotency_key
        && request.expected_version_hash == query.expected_version_hash
        && request.scheduler_lease_owner_id == query.scheduler_lease_owner_id
        && request.scheduler_fencing_token == query.scheduler_fencing_token
        && request.contribution_hash == query.contribution_hash
}

type StoredEgressRestrictionCommand = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn load_egress_restriction_command(
    connection: &Connection,
    tenant_id: &str,
    idempotency_key: &str,
) -> PortResult<Option<EgressRestrictionCommand>> {
    let stored: Option<StoredEgressRestrictionCommand> = connection
        .query_row(
            r#"
            SELECT request_body, request_body_hash, result_body, result_body_hash
            FROM security_egress_restriction_commands
            WHERE tenant_id = ?1 AND idempotency_key = ?2
            "#,
            params![tenant_id, idempotency_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(request_body, request_hash, result_body, result_hash)| {
            let request_hash = decode_digest(request_hash)?;
            if body_hash(&request_body).as_slice() != request_hash.as_bytes() {
                return Err(PortError::integrity_failure());
            }
            let request: EffectRequest = serde_json::from_slice(&request_body)
                .map_err(|_| PortError::integrity_failure())?;
            let canonical_request =
                canonical_json_bytes(&request).map_err(|_| PortError::integrity_failure())?;
            if canonical_request.as_slice() != request_body.as_slice() {
                return Err(PortError::integrity_failure());
            }
            let result_hash = decode_digest(result_hash)?;
            if body_hash(&result_body).as_slice() != result_hash.as_bytes() {
                return Err(PortError::integrity_failure());
            }
            let result: EffectResult =
                serde_json::from_slice(&result_body).map_err(|_| PortError::integrity_failure())?;
            let canonical_result =
                canonical_json_bytes(&result).map_err(|_| PortError::integrity_failure())?;
            if canonical_result.as_slice() != result_body.as_slice()
                || request.tenant_id.as_str() != tenant_id
                || request.idempotency_key.as_str() != idempotency_key
            {
                return Err(PortError::integrity_failure());
            }
            Ok(EgressRestrictionCommand { request, result })
        })
        .transpose()
}

fn persist_egress_restriction_command(
    transaction: &Transaction<'_>,
    command: &EgressRestrictionCommand,
) -> PortResult<()> {
    if let Some(existing) = load_egress_restriction_command(
        transaction,
        command.request.tenant_id.as_str(),
        command.request.idempotency_key.as_str(),
    )? {
        return if &existing == command {
            Ok(())
        } else {
            Err(PortError::conflict())
        };
    }
    let request_body =
        canonical_json_bytes(&command.request).map_err(|_| PortError::invalid_data())?;
    let request_hash = body_hash(&request_body);
    let result_body =
        canonical_json_bytes(&command.result).map_err(|_| PortError::invalid_data())?;
    let result_hash = body_hash(&result_body);
    transaction
        .execute(
            r#"
            INSERT INTO security_egress_restriction_commands (
                tenant_id, idempotency_key, request_body, request_body_hash,
                result_body, result_body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                command.request.tenant_id.as_str(),
                command.request.idempotency_key.as_str(),
                request_body,
                request_hash.as_slice(),
                result_body,
                result_hash.as_slice()
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn empty_egress_restriction_snapshot(
    key: &EgressRestrictionSessionKey,
) -> PortResult<EgressRestrictionSnapshot> {
    Ok(EgressRestrictionSnapshot {
        key: key.clone(),
        generation: 0,
        contributions: EgressRestrictionContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        denied_destinations: EgressDeniedDestinations::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    })
}

fn load_egress_restriction_binding(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<(String, String)>> {
    connection
        .query_row(
            r#"
            SELECT session_id, action_id
            FROM security_egress_restriction_effects
            WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn load_egress_restriction_snapshot(
    connection: &Connection,
    key: &EgressRestrictionSessionKey,
) -> PortResult<Option<EgressRestrictionSnapshot>> {
    let state: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT generation, highest_fencing_token
            FROM security_egress_restriction_state
            WHERE tenant_id = ?1 AND session_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.session_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((generation, highest_fencing_token)) = state else {
        let dangling_effect: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM security_egress_restriction_effects
                    WHERE tenant_id = ?1 AND session_id = ?2
                )
                "#,
                params![key.tenant_id.as_str(), key.session_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if dangling_effect {
            return Err(PortError::integrity_failure());
        }
        return Ok(None);
    };
    let generation = from_i64(generation)?;
    let highest_fencing_token = from_i64(highest_fencing_token)?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT effect_id, action_id, contribution_hash, expires_at,
                   installed_fencing_token
            FROM security_egress_restriction_effects
            WHERE tenant_id = ?1 AND session_id = ?2
            ORDER BY effect_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![key.tenant_id.as_str(), key.session_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut stored_effects = Vec::new();
    for row in rows {
        stored_effects.push(row.map_err(sqlite_error)?);
    }
    drop(statement);

    let mut contributions = Vec::with_capacity(stored_effects.len());
    let mut denied_destinations = BTreeSet::new();
    let mut maximum_installed_fencing_token = 0_u64;
    for (effect_id, action_id, contribution_hash, expires_at, installed_fencing_token) in
        stored_effects
    {
        let effect_id = EffectId::new(effect_id).map_err(|_| PortError::integrity_failure())?;
        ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?;
        let installed_fencing_token = from_i64(installed_fencing_token)?;
        if installed_fencing_token == 0 {
            return Err(PortError::integrity_failure());
        }
        maximum_installed_fencing_token =
            maximum_installed_fencing_token.max(installed_fencing_token);
        let mut destination_statement = connection
            .prepare(
                r#"
                SELECT destination_id
                FROM security_egress_restriction_destinations
                WHERE tenant_id = ?1 AND session_id = ?2 AND effect_id = ?3
                ORDER BY destination_id
                "#,
            )
            .map_err(sqlite_error)?;
        let destination_rows = destination_statement
            .query_map(
                params![
                    key.tenant_id.as_str(),
                    key.session_id.as_str(),
                    effect_id.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut destinations = Vec::new();
        for destination in destination_rows {
            let destination = DestinationId::new(destination.map_err(sqlite_error)?)
                .map_err(|_| PortError::integrity_failure())?;
            denied_destinations.insert(destination.clone());
            destinations.push(destination);
        }
        contributions.push(EgressRestrictionContribution {
            effect_id,
            destinations: EgressDestinationSet::new(destinations)
                .map_err(|_| PortError::integrity_failure())?,
            contribution_hash: decode_digest(contribution_hash)?,
            expires_at_unix_ms: from_i64(expires_at)?,
        });
    }
    if contributions
        .windows(2)
        .any(|pair| pair[0].effect_id >= pair[1].effect_id)
        || generation
            < u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?
        || highest_fencing_token < maximum_installed_fencing_token
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(EgressRestrictionSnapshot {
        key: key.clone(),
        generation,
        contributions: EgressRestrictionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        denied_destinations: EgressDeniedDestinations::new(
            denied_destinations.into_iter().collect(),
        )
        .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token,
    }))
}

fn persist_egress_restriction_state(
    transaction: &Transaction<'_>,
    key: &EgressRestrictionSessionKey,
    generation: u64,
    highest_fencing_token: u64,
) -> PortResult<()> {
    transaction
        .execute(
            r#"
            INSERT INTO security_egress_restriction_state (
                tenant_id, session_id, generation, highest_fencing_token
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, session_id) DO UPDATE SET
                generation = excluded.generation,
                highest_fencing_token = excluded.highest_fencing_token
            "#,
            params![
                key.tenant_id.as_str(),
                key.session_id.as_str(),
                to_i64(generation)?,
                to_i64(highest_fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
