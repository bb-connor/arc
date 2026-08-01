fn validate_partition_escrow_projection_integrity(
    connection: &Connection,
) -> Result<(), AdmissionConsensusError> {
    let mut statement = connection.prepare(
        r#"
        SELECT evidence.hold_id, evidence.evidence_digest, evidence.canonical_evidence
        FROM budget_composite_partition_escrow_evidence AS evidence
        WHERE NOT EXISTS (
            SELECT 1 FROM budget_composite_authorizations AS authorization
            WHERE authorization.hold_id = evidence.hold_id
        ) OR NOT EXISTS (
            SELECT 1 FROM budget_composite_authorization_artifacts AS artifact
            WHERE artifact.hold_id = evidence.hold_id
              AND artifact.artifact_digest = evidence.evidence_digest
        )
        ORDER BY evidence.hold_id ASC
        "#,
    )?;
    if statement.query([])?.next()?.is_some() {
        return Err(AdmissionConsensusError::Protocol(
            "admission partition escrow projection contains unbound evidence".to_string(),
        ));
    }
    drop(statement);

    let mut statement = connection.prepare(
        r#"
        SELECT hold_id, evidence_digest, canonical_evidence
        FROM budget_composite_partition_escrow_evidence
        ORDER BY hold_id ASC
        "#,
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let hold_id = row.get::<_, String>(0)?;
        let evidence_digest = row.get::<_, String>(1)?;
        let canonical_evidence = row.get::<_, Vec<u8>>(2)?;
        if hold_id.is_empty() || !is_lower_sha256(&evidence_digest) {
            return Err(AdmissionConsensusError::Protocol(
                "admission partition escrow projection identity is invalid".to_string(),
            ));
        }
        let canonical_evidence = String::from_utf8(canonical_evidence).map_err(|_| {
            AdmissionConsensusError::Protocol(
                "admission partition escrow projection is not UTF-8 JSON".to_string(),
            )
        })?;
        chio_kernel::budget_store::PartitionEscrowCommitEvidence::from_canonical_json(
            canonical_evidence,
            evidence_digest,
        )
        .map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "admission partition escrow projection failed canonical digest validation: {error}"
            ))
        })?;
    }
    Ok(())
}

fn validate_admission_genesis_table_schema(
    connection: &Connection,
    spec: &AdmissionGenesisTableSpec,
) -> Result<(), AdmissionConsensusError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info(\"{}\")", spec.name))?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != spec.columns.len() {
        return Err(AdmissionConsensusError::Protocol(format!(
            "admission genesis table `{}` has extra or missing columns",
            spec.name
        )));
    }
    for (expected_name, expected_type) in spec.columns {
        let Some((_, declared_type)) = actual.iter().find(|(name, _)| name == expected_name) else {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis table `{}` is missing column `{expected_name}`",
                spec.name
            )));
        };
        if sqlite_logical_value_type(declared_type).as_ref() != Some(expected_type) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis column `{}.{expected_name}` has an incompatible logical type",
                spec.name
            )));
        }
    }
    Ok(())
}

fn sqlite_logical_value_type(declared_type: &str) -> Option<AdmissionGenesisValueType> {
    let declared = declared_type.trim().to_ascii_uppercase();
    if declared.contains("INT") {
        Some(AdmissionGenesisValueType::Integer)
    } else if declared.contains("CHAR") || declared.contains("CLOB") || declared.contains("TEXT") {
        Some(AdmissionGenesisValueType::Text)
    } else if declared.contains("REAL") || declared.contains("FLOA") || declared.contains("DOUB") {
        Some(AdmissionGenesisValueType::Real)
    } else if declared.is_empty() || declared.contains("BLOB") {
        Some(AdmissionGenesisValueType::Blob)
    } else {
        None
    }
}

fn admission_genesis_value_matches_type(
    value: &AdmissionGenesisValue,
    expected: AdmissionGenesisValueType,
) -> bool {
    matches!(value, AdmissionGenesisValue::Null)
        || matches!(
            (value, expected),
            (
                AdmissionGenesisValue::Integer(_),
                AdmissionGenesisValueType::Integer
            ) | (
                AdmissionGenesisValue::RealBits(_),
                AdmissionGenesisValueType::Real
            ) | (
                AdmissionGenesisValue::Text(_),
                AdmissionGenesisValueType::Text
            ) | (
                AdmissionGenesisValue::BlobHex(_),
                AdmissionGenesisValueType::Blob
            )
        )
}

fn validate_admission_genesis_projection(
    projection: &AdmissionGenesisProjection,
) -> Result<(), AdmissionConsensusError> {
    if projection.tables.len() != ADMISSION_GENESIS_TABLES.len() {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection has extra or missing tables".to_string(),
        ));
    }
    let mut row_count = 0usize;
    let mut cell_count = 0usize;
    for (table, spec) in projection.tables.iter().zip(ADMISSION_GENESIS_TABLES) {
        if table.name != spec.name || table.columns.len() != spec.columns.len() {
            return Err(AdmissionConsensusError::Protocol(
                "admission genesis projection table schema is noncanonical".to_string(),
            ));
        }
        for (column, (expected_name, expected_type)) in table.columns.iter().zip(spec.columns) {
            if column.name != *expected_name || column.value_type != *expected_type {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission genesis projection column `{}.{}` is noncanonical",
                    table.name, column.name
                )));
            }
        }
        row_count = row_count.checked_add(table.rows.len()).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission genesis row count overflow".to_string())
        })?;
        for row in &table.rows {
            if row.len() != table.columns.len() {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission genesis table `{}` contains a partial row",
                    table.name
                )));
            }
            cell_count = cell_count.checked_add(row.len()).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission genesis cell count overflow".to_string(),
                )
            })?;
            for (value, column) in row.iter().zip(&table.columns) {
                if !admission_genesis_value_matches_type(value, column.value_type)
                    || admission_genesis_value_bytes(value) > MAX_ADMISSION_GENESIS_CELL_BYTES
                    || !admission_genesis_value_is_canonical(value)
                {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission genesis table `{}` contains an invalid typed value",
                        table.name
                    )));
                }
            }
        }
        let row_keys = table
            .rows
            .iter()
            .map(canonical_json_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "admission genesis row canonicalization failed: {error}"
                ))
            })?;
        if row_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis table `{}` rows are unsorted or duplicated",
                table.name
            )));
        }
    }
    if row_count > MAX_ADMISSION_GENESIS_ROWS || cell_count > MAX_ADMISSION_GENESIS_CELLS {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection exceeds row or cell bounds".to_string(),
        ));
    }
    let canonical = canonical_json_bytes(projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission genesis projection canonicalization failed: {error}"
        ))
    })?;
    if canonical.len() > MAX_ADMISSION_GENESIS_BYTES {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection exceeds the encoded size bound".to_string(),
        ));
    }
    Ok(())
}

fn admission_genesis_value_bytes(value: &AdmissionGenesisValue) -> usize {
    match value {
        AdmissionGenesisValue::Null | AdmissionGenesisValue::Integer(_) => 0,
        AdmissionGenesisValue::RealBits(value)
        | AdmissionGenesisValue::Text(value)
        | AdmissionGenesisValue::BlobHex(value) => value.len(),
    }
}

fn admission_genesis_value_is_canonical(value: &AdmissionGenesisValue) -> bool {
    match value {
        AdmissionGenesisValue::RealBits(value) => value.len() == 16 && is_lower_hex(value),
        AdmissionGenesisValue::BlobHex(value) => value.len() % 2 == 0 && is_lower_hex(value),
        AdmissionGenesisValue::Null
        | AdmissionGenesisValue::Integer(_)
        | AdmissionGenesisValue::Text(_) => true,
    }
}

fn admission_genesis_projection_digest(
    projection: &AdmissionGenesisProjection,
) -> Result<String, AdmissionConsensusError> {
    validate_admission_genesis_projection(projection)?;
    let canonical = canonical_json_bytes(projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission genesis projection canonicalization failed: {error}"
        ))
    })?;
    let mut preimage =
        Vec::with_capacity(ADMISSION_PROJECTION_BASELINE_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ADMISSION_PROJECTION_BASELINE_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn capture_admission_security_projection_digest_from_connection(
    connection: &Connection,
) -> Result<String, AdmissionConsensusError> {
    let projection = capture_admission_genesis_projection_from_connection(connection, |_| Ok(()))?;
    admission_security_projection_digest(&projection)
}

fn admission_security_projection_digest(
    projection: &AdmissionGenesisProjection,
) -> Result<String, AdmissionConsensusError> {
    validate_admission_genesis_projection(projection)?;
    let mut tables = Vec::with_capacity(projection.tables.len());
    for table in &projection.tables {
        let included = table
            .columns
            .iter()
            .enumerate()
            .filter(|(_, column)| !admission_security_projection_ignores(&table.name, &column.name))
            .collect::<Vec<_>>();
        let columns = included
            .iter()
            .map(|(_, column)| (*column).clone())
            .collect::<Vec<_>>();
        let mut rows = table
            .rows
            .iter()
            .map(|row| {
                included
                    .iter()
                    .map(|(index, _)| row[*index].clone())
                    .collect::<Vec<_>>()
            })
            .map(|row| {
                canonical_json_bytes(&row)
                    .map(|key| (key, row))
                    .map_err(|error| {
                        AdmissionConsensusError::Protocol(format!(
                            "admission security projection row canonicalization failed: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        tables.push(AdmissionSecurityTable {
            name: table.name.clone(),
            columns,
            rows: rows.into_iter().map(|(_, row)| row).collect(),
        });
    }
    let projection = AdmissionSecurityProjection { tables };
    let canonical = canonical_json_bytes(&projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission security projection canonicalization failed: {error}"
        ))
    })?;
    let mut preimage =
        Vec::with_capacity(ADMISSION_SECURITY_PROJECTION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ADMISSION_SECURITY_PROJECTION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn admission_security_projection_ignores(table: &str, column: &str) -> bool {
    ADMISSION_SECURITY_PROJECTION_EXCLUSIONS.contains(&(table, column))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn admission_genesis_projection_is_empty(projection: &AdmissionGenesisProjection) -> bool {
    projection.tables.iter().all(|table| {
        if table.name == "admission_authority_meta" {
            table.rows
                == vec![vec![
                    AdmissionGenesisValue::Integer(1),
                    AdmissionGenesisValue::Text("combined-admission-capture-v1".to_string()),
                    AdmissionGenesisValue::Integer(0),
                    AdmissionGenesisValue::Integer(0),
                ]]
        } else {
            table.rows.is_empty()
        }
    })
}

fn install_admission_genesis_projection(
    transaction: &Transaction<'_>,
    projection: &AdmissionGenesisProjection,
) -> Result<(), AdmissionConsensusError> {
    validate_admission_genesis_projection(projection)?;
    transaction.execute_batch(
        r#"
        PRAGMA defer_foreign_keys = ON;
        DROP TRIGGER IF EXISTS admission_revocation_insert_requires_authority;
        "#,
    )?;
    for table in projection.tables.iter().rev() {
        transaction.execute(&format!("DELETE FROM \"{}\"", table.name), [])?;
    }
    for table in &projection.tables {
        if table.rows.is_empty() {
            continue;
        }
        let columns = table
            .columns
            .iter()
            .map(|column| format!("\"{}\"", column.name))
            .collect::<Vec<_>>()
            .join(", ");
        let bind_markers = (1..=table.columns.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT INTO \"{}\" ({columns}) VALUES ({bind_markers})",
            table.name
        );
        for row in &table.rows {
            let values = row
                .iter()
                .map(admission_genesis_sql_value)
                .collect::<Result<Vec<_>, _>>()?;
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
    }
    transaction.execute_batch(
        r#"
        CREATE TRIGGER IF NOT EXISTS admission_revocation_insert_requires_authority
        BEFORE INSERT ON revoked_capabilities
        BEGIN
            SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
        END;
        "#,
    )?;
    normalize_admission_transport_cache(transaction)?;
    let foreign_key_violation = transaction
        .query_row("PRAGMA foreign_key_check", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    if foreign_key_violation.is_some() {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection violates relational integrity".to_string(),
        ));
    }
    let installed = capture_admission_genesis_projection_from_connection(transaction, |_| Ok(()))?;
    if installed != *projection {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection was only partially installed".to_string(),
        ));
    }
    Ok(())
}

fn admission_genesis_sql_value(
    value: &AdmissionGenesisValue,
) -> Result<rusqlite::types::Value, AdmissionConsensusError> {
    Ok(match value {
        AdmissionGenesisValue::Null => rusqlite::types::Value::Null,
        AdmissionGenesisValue::Integer(value) => rusqlite::types::Value::Integer(*value),
        AdmissionGenesisValue::RealBits(value) => {
            let bits = u64::from_str_radix(value, 16).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "admission genesis real value has invalid bits".to_string(),
                )
            })?;
            rusqlite::types::Value::Real(f64::from_bits(bits))
        }
        AdmissionGenesisValue::Text(value) => rusqlite::types::Value::Text(value.clone()),
        AdmissionGenesisValue::BlobHex(value) => {
            rusqlite::types::Value::Blob(decode_lower_hex(value)?)
        }
    })
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, AdmissionConsensusError> {
    if !value.len().is_multiple_of(2) || !is_lower_hex(value) {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis blob is not canonical lowercase hex".to_string(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "admission genesis blob contains invalid hex".to_string(),
                )
            })?;
            u8::from_str_radix(text, 16).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "admission genesis blob contains invalid hex".to_string(),
                )
            })
        })
        .collect()
}

fn normalize_admission_transport_cache(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionConsensusError> {
    transaction.execute("DELETE FROM budget_import_floors", [])?;
    transaction.execute("DELETE FROM budget_origin_ack_heads", [])?;
    transaction.execute("DELETE FROM budget_abandoned_event_seqs", [])?;
    transaction.execute("DELETE FROM budget_abandoned_event_ranges", [])?;
    transaction.execute(
        "UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1",
        [],
    )?;
    transaction.execute(
        r#"
        UPDATE budget_replication_meta
        SET next_seq = MAX(
            COALESCE((SELECT MAX(seq) FROM capability_grant_budgets), 0),
            COALESCE((SELECT MAX(event_seq) FROM budget_mutation_events), 0)
        )
        WHERE singleton = 1
        "#,
        [],
    )?;
    Ok(())
}

fn apply_admission_log_entry(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    if proof.index != entry.index || proof.leader_epoch < entry.leader_epoch {
        return Err("admission commit proof does not match the applied entry".to_string());
    }
    validate_partition_escrow_authority_for_mutation(config, transaction)?;
    match entry.command_kind {
        AdmissionCommandKind::LeadershipBarrier => canonical_result(&json!({"committed": true})),
        AdmissionCommandKind::IncrementInvocation => {
            apply_increment_invocation(config, transaction, entry, proof)
        }
        AdmissionCommandKind::CompositeAuthorize => {
            apply_composite_authorize(config, transaction, entry, proof)
        }
        AdmissionCommandKind::CaptureInvocations => {
            apply_invocation_capture(config, transaction, entry, proof)
        }
        AdmissionCommandKind::ReverseExposure => {
            apply_reverse_exposure(config, transaction, entry, proof)
        }
        AdmissionCommandKind::ReleaseExposure => apply_reduce_exposure(
            config,
            transaction,
            entry,
            proof,
            AdmissionCommandKind::ReleaseExposure,
        ),
        AdmissionCommandKind::ReconcileSpend => apply_reduce_exposure(
            config,
            transaction,
            entry,
            proof,
            AdmissionCommandKind::ReconcileSpend,
        ),
        AdmissionCommandKind::CaptureExposure => apply_reduce_exposure(
            config,
            transaction,
            entry,
            proof,
            AdmissionCommandKind::CaptureExposure,
        ),
        AdmissionCommandKind::Revoke => apply_revocation(transaction, entry),
        AdmissionCommandKind::CombinedCapture => {
            apply_combined_capture(config, transaction, entry, proof)
        }
    }
}

fn apply_increment_invocation(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    if config.partition_escrow_authority.is_some() {
        return Err(
            "sealed partition escrow authority rejects legacy unbound invocation increments"
                .to_string(),
        );
    }
    let command: ConsensusIncrementInvocationCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = budget_authority_from_view(&command.authority)?;
    let outcome = match SqliteBudgetStore::increment_invocation_in_transaction(
        transaction,
        &command.request.capability_id,
        command.request.grant_index,
        command.request.max_invocations,
        &entry.operation_id,
        &authority,
    ) {
        Ok(outcome) => outcome,
        Err(error) => return frozen_budget_rejection(error),
    };
    let (metadata, commit) =
        consensus_budget_evidence(proof, &authority, outcome.event_seq, None);
    canonical_result(&TryIncrementBudgetResponse {
        capability_id: command.request.capability_id,
        grant_index: command.request.grant_index,
        allowed: outcome.allowed,
        invocation_count: Some(outcome.invocation_count),
        budget_authority: Some(metadata),
        budget_commit: Some(commit),
    })
}

fn apply_composite_authorize(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let command: ConsensusCompositeAuthorizeCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    if command.request.existing_only {
        return Err(
            "existingOnly composite authorization commands cannot be applied".to_string(),
        );
    }
    let authority = budget_authority_from_view(&command.authority)?;
    let prepared = super::super::budget_handlers::sqlite_composite_authorize_input(
        &command.request,
        authority.clone(),
        config.partition_escrow_authority.as_deref(),
    )
    .map_err(|error| error.to_string())?;
    let decision = match prepared.authorize_in_transaction(transaction, false) {
        Ok(decision) => decision,
        Err(error) => return frozen_budget_rejection(error),
    };
    let budget_seq = load_consensus_budget_event(transaction, &command.request.event_id)?.event_seq;
    let partition_escrow_evidence = validated_partition_escrow_hold_evidence(
        config,
        transaction,
        &command.request.hold_id,
    )?;
    let (metadata, commit) = consensus_budget_evidence(
        proof,
        &authority,
        budget_seq,
        partition_escrow_evidence.as_ref(),
    );
    let response = super::super::budget_handlers::composite_authorize_response_view(
        &command.request,
        decision,
        metadata,
        commit,
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&response)
}

fn apply_invocation_capture(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let request: CaptureInvocationReservationsRequest =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "invocation capture omitted its persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let partition_escrow_evidence =
        validated_partition_escrow_hold_evidence(config, transaction, &request.hold_id)?;
    let decision = match SqliteBudgetStore::capture_invocation_reservations_in_transaction(
        transaction,
        &BudgetCaptureInvocationRequest {
            admission_operation: Some(
                BudgetAdmissionOperationBinding::new(
                    request.operation_id.clone(),
                    request.request_binding_hash.clone(),
                )
                .map_err(|error| error.to_string())?,
            ),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: Some(request.hold_id.clone()),
            event_id: Some(request.event_id.clone()),
            authority: Some(authority.clone()),
        },
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_budget_rejection(error),
    };
    if decision.invocation_state != BudgetInvocationReservationState::Captured {
        return Err("invocation capture did not reach captured state".to_string());
    }
    let budget_seq = load_consensus_budget_event(transaction, &request.event_id)?.event_seq;
    let (metadata, commit) = consensus_budget_evidence(
        proof,
        &authority,
        budget_seq,
        partition_escrow_evidence.as_ref(),
    );
    let response = super::super::budget_handlers::invocation_capture_response_view(
        &request, decision, metadata, commit,
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&response)
}

fn apply_reverse_exposure(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let request: ReverseChargeCostRequest =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let hold_id = request
        .hold_id
        .as_deref()
        .ok_or_else(|| "reverse exposure command omitted hold_id".to_string())?;
    let event_id = request
        .event_id
        .as_deref()
        .ok_or_else(|| "reverse exposure command omitted event_id".to_string())?;
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "reverse exposure command omitted persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let partition_escrow_evidence =
        validated_partition_escrow_hold_evidence(config, transaction, hold_id)?;
    let decision = match SqliteBudgetStore::reverse_composite_budget_hold_in_transaction(
        transaction,
        BudgetReverseHoldRequest {
            admission_operation: super::super::budget_handlers::budget_admission_operation_binding(
                request.operation_id.as_deref(),
                request.request_binding_hash.as_deref(),
            )
            .map_err(|error| error.to_string())?,
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            reversed_exposure_units: request.cost_units,
            hold_id: Some(hold_id.to_string()),
            event_id: Some(event_id.to_string()),
            authority: Some(authority.clone()),
        },
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_budget_rejection(error),
    };
    if decision.invocation_state != BudgetInvocationReservationState::Reversed {
        return Err("budget reverse did not reach reversed invocation state".to_string());
    }
    let event = load_consensus_budget_event(transaction, event_id)?;
    validate_consensus_budget_event(
        &event,
        BudgetMutationKind::ReverseInvocations,
        &request.capability_id,
        request.grant_index,
        hold_id,
        request.cost_units,
        0,
        &authority,
    )?;
    let (metadata, commit) = consensus_budget_evidence(
        proof,
        &authority,
        event.event_seq,
        partition_escrow_evidence.as_ref(),
    );
    canonical_result(&ReverseChargeCostResponse {
        capability_id: request.capability_id,
        grant_index: request.grant_index,
        hold_id: event.hold_id.clone(),
        event_id: Some(event.event_id.clone()),
        invocation_count: Some(event.invocation_count_after),
        total_cost_exposed: Some(event.total_cost_exposed_after),
        total_cost_realized_spend: Some(event.total_cost_realized_spend_after),
        budget_authority: Some(metadata),
        budget_commit: Some(commit),
    })
}

fn apply_reduce_exposure(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    command_kind: AdmissionCommandKind,
) -> Result<String, String> {
    let request: ReduceChargeCostRequest =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let hold_id = request
        .hold_id
        .as_deref()
        .ok_or_else(|| "monetary transition command omitted hold_id".to_string())?;
    let event_id = request
        .event_id
        .as_deref()
        .ok_or_else(|| "monetary transition command omitted event_id".to_string())?;
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "monetary transition command omitted persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let partition_escrow_evidence =
        validated_partition_escrow_hold_evidence(config, transaction, hold_id)?;
    let (mutation_kind, exposure_units, realized_spend_units) = match command_kind {
        AdmissionCommandKind::ReleaseExposure => {
            if let Err(error) = SqliteBudgetStore::release_composite_budget_hold_in_transaction(
                transaction,
                BudgetReleaseHoldRequest {
                    admission_operation:
                        super::super::budget_handlers::budget_admission_operation_binding(
                            request.operation_id.as_deref(),
                            request.request_binding_hash.as_deref(),
                        )
                        .map_err(|error| error.to_string())?,
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    released_exposure_units: request.cost_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: Some(authority.clone()),
                },
            ) {
                return frozen_budget_rejection(error);
            }
            (BudgetMutationKind::ReleaseExposure, request.cost_units, 0)
        }
        AdmissionCommandKind::ReconcileSpend => {
            let exposure_units = request
                .exposure_units
                .ok_or_else(|| "reconcile command omitted exposure units".to_string())?;
            let realized_spend_units = request
                .realized_spend_units
                .ok_or_else(|| "reconcile command omitted realized spend".to_string())?;
            if let Err(error) = SqliteBudgetStore::settle_composite_budget_hold_in_transaction(
                transaction,
                BudgetReconcileHoldRequest {
                    admission_operation:
                        super::super::budget_handlers::budget_admission_operation_binding(
                            request.operation_id.as_deref(),
                            request.request_binding_hash.as_deref(),
                        )
                        .map_err(|error| error.to_string())?,
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    exposed_cost_units: exposure_units,
                    realized_spend_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: Some(authority.clone()),
                },
                false,
            ) {
                return frozen_budget_rejection(error);
            }
            (
                BudgetMutationKind::ReconcileSpend,
                exposure_units,
                realized_spend_units,
            )
        }
        AdmissionCommandKind::CaptureExposure => {
            let exposure_units = request
                .exposure_units
                .ok_or_else(|| "capture command omitted exposure units".to_string())?;
            let realized_spend_units = request
                .realized_spend_units
                .ok_or_else(|| "capture command omitted realized spend".to_string())?;
            if exposure_units.checked_sub(realized_spend_units) != Some(request.cost_units) {
                return Err(
                    "capture command reduction does not match exposure minus spend".to_string(),
                );
            }
            let decision = match SqliteBudgetStore::settle_composite_budget_hold_in_transaction(
                transaction,
                BudgetReconcileHoldRequest {
                    admission_operation:
                        super::super::budget_handlers::budget_admission_operation_binding(
                            request.operation_id.as_deref(),
                            request.request_binding_hash.as_deref(),
                        )
                        .map_err(|error| error.to_string())?,
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    exposed_cost_units: exposure_units,
                    realized_spend_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: Some(authority.clone()),
                },
                true,
            ) {
                Ok(decision) => decision,
                Err(error) => return frozen_budget_rejection(error),
            };
            if decision.monetary_state != BudgetMonetaryHoldState::Captured {
                return Err("monetary capture did not reach captured state".to_string());
            }
            (
                BudgetMutationKind::CaptureExposure,
                exposure_units,
                realized_spend_units,
            )
        }
        _ => return Err("unsupported monetary transition command".to_string()),
    };
    let event = load_consensus_budget_event(transaction, event_id)?;
    validate_consensus_budget_event(
        &event,
        mutation_kind,
        &request.capability_id,
        request.grant_index,
        hold_id,
        exposure_units,
        realized_spend_units,
        &authority,
    )?;
    let (metadata, commit) = consensus_budget_evidence(
        proof,
        &authority,
        event.event_seq,
        partition_escrow_evidence.as_ref(),
    );
    canonical_result(&ReduceChargeCostResponse {
        capability_id: request.capability_id,
        grant_index: request.grant_index,
        hold_id: event.hold_id.clone(),
        event_id: Some(event.event_id.clone()),
        invocation_count: Some(event.invocation_count_after),
        total_cost_exposed: Some(event.total_cost_exposed_after),
        total_cost_realized_spend: Some(event.total_cost_realized_spend_after),
        released_exposure_units: Some(request.cost_units),
        budget_authority: Some(metadata),
        budget_commit: Some(commit),
    })
}

fn load_consensus_budget_event(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<BudgetMutationRecord, String> {
    SqliteBudgetStore::mutation_event_for_event_id_in_transaction(transaction, event_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("budget event `{event_id}` is not persisted"))
}

fn validated_partition_escrow_hold_evidence(
    config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<Option<PartitionEscrowCommitEvidence>, String> {
    let persisted = transaction
        .query_row(
            r#"
            SELECT evidence_digest, canonical_evidence
            FROM budget_composite_partition_escrow_evidence
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|(digest, canonical)| {
            let canonical = String::from_utf8(canonical).map_err(|error| {
                format!("persisted partition escrow evidence is not UTF-8 JSON: {error}")
            })?;
            PartitionEscrowCommitEvidence::from_canonical_json(canonical, digest)
                .map_err(|error| error.to_string())
        })
        .transpose()?;

    match (
        config.partition_escrow_authority.as_deref(),
        persisted.as_ref(),
    ) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(
            "ordinary HA authority rejects persisted partition escrow mutation evidence"
                .to_string(),
        ),
        (Some(_), None) => Err(format!(
            "sealed partition escrow mutation for hold `{hold_id}` has no persisted allocation evidence"
        )),
        (Some(authority), Some(evidence)) => {
            authority
                .validate_persisted_commit_evidence(evidence)
                .map_err(|error| error.to_string())?;
            Ok(persisted)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_consensus_budget_event(
    event: &BudgetMutationRecord,
    kind: BudgetMutationKind,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    exposure_units: u64,
    realized_spend_units: u64,
    authority: &BudgetEventAuthority,
) -> Result<(), String> {
    if event.kind != kind
        || event.capability_id != capability_id
        || usize::try_from(event.grant_index).ok() != Some(grant_index)
        || event.hold_id.as_deref() != Some(hold_id)
        || event.exposure_units != exposure_units
        || event.realized_spend_units != realized_spend_units
        || event.authority.as_ref() != Some(authority)
        || event.usage_seq != Some(event.event_seq)
    {
        return Err(format!(
            "budget event `{}` does not match its consensus command",
            event.event_id
        ));
    }
    Ok(())
}

fn apply_revocation(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
) -> Result<String, String> {
    let command: ConsensusRevocationCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let outcome = SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
        transaction,
        &RevocationRecord {
            capability_id: command.capability_id.clone(),
            revoked_at: command.revoked_at,
        },
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&RevokeCapabilityResponse {
        capability_id: command.capability_id,
        revoked: true,
        newly_revoked: !outcome.was_present(),
    })
}
