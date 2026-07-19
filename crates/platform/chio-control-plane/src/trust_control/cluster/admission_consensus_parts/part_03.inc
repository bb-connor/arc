fn synchronize_peer_through(
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    client: &TrustControlClient,
    target_index: u64,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let local = store.meta()?;
    if local.membership_digest.as_deref() != Some(membership.digest())
        || target_index == 0
        || target_index > local.last_log_index
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer synchronization target is outside the local log".to_string(),
        ));
    }
    let probe = send_peer_append_response(
        store,
        election,
        client,
        &AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: election.term,
            leader_id: election.candidate_id.clone(),
            previous_log_index: 0,
            previous_log_term: 0,
            entry: None,
            leader_commit: 0,
            commit_proof: None,
        },
    )?;
    if probe.commit_index > local.commit_index || probe.match_index < probe.commit_index {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer commit index is ahead of the elected leader".to_string(),
        ));
    }
    let follower_commit = probe.commit_index;
    let mut common_index = probe.match_index.min(target_index);
    loop {
        let previous_log_term = if common_index == 0 {
            0
        } else {
            store.entry_at(common_index)?.leader_epoch
        };
        let response = send_peer_append_response(
            store,
            election,
            client,
            &AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index: common_index,
                previous_log_term,
                entry: None,
                leader_commit: follower_commit,
                commit_proof: None,
            },
        )?;
        if response.accepted {
            break;
        }
        if common_index <= follower_commit {
            return Err(AdmissionConsensusError::Protocol(
                "admission peer diverges inside the committed prefix".to_string(),
            ));
        }
        common_index = common_index.checked_sub(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission log backtrack underflow".to_string())
        })?;
    }
    let first_missing_entry = common_index.checked_add(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission log index overflow".to_string())
    })?;
    for index in first_missing_entry..=target_index {
        let entry = store.entry_at(index)?;
        let (previous_log_index, previous_log_term) = previous_store_position(store, entry.index)?;
        send_peer_append(
            store,
            election,
            client,
            AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index,
                previous_log_term,
                entry: Some(entry),
                leader_commit: follower_commit,
                commit_proof: None,
            },
        )?;
    }
    let first_missing_commit = follower_commit.checked_add(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission commit index overflow".to_string())
    })?;
    for index in first_missing_commit..=local.commit_index {
        let entry = store.entry_at(index)?;
        let proof = store.proof_at(index)?;
        send_peer_append(
            store,
            election,
            client,
            AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index: entry.index,
                previous_log_term: entry.leader_epoch,
                entry: None,
                leader_commit: index,
                commit_proof: Some(proof),
            },
        )?;
    }
    let target = store.entry_at(target_index)?;
    send_peer_append(
        store,
        election,
        client,
        AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: election.term,
            leader_id: election.candidate_id.clone(),
            previous_log_index: target.index,
            previous_log_term: target.leader_epoch,
            entry: None,
            leader_commit: local.commit_index,
            commit_proof: None,
        },
    )
}

fn send_peer_append(
    store: &AdmissionConsensusStore,
    election: &AdmissionElection,
    client: &TrustControlClient,
    request: AdmissionAppendEntriesRequest,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let response = send_peer_append_response(store, election, client, &request)?;
    if !response.accepted {
        return Err(AdmissionConsensusError::Protocol(
            response
                .rejection
                .clone()
                .unwrap_or_else(|| "admission peer rejected the append".to_string()),
        ));
    }
    Ok(response)
}

fn send_peer_append_response(
    store: &AdmissionConsensusStore,
    election: &AdmissionElection,
    client: &TrustControlClient,
    request: &AdmissionAppendEntriesRequest,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let response = client.admission_append_entries(request).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission peer append failed before acknowledgement: {error}"
        ))
    })?;
    if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append used an unsupported protocol".to_string(),
        ));
    }
    if response.membership_digest != request.membership_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append membership digest changed".to_string(),
        ));
    }
    if !is_lower_sha256(&response.applied_state_digest) {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append returned an invalid applied-state digest".to_string(),
        ));
    }
    if response.term > election.term {
        store.observe_higher_term(response.term)?;
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append reported a higher term".to_string(),
        ));
    }
    if response.term != election.term {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append returned another election term".to_string(),
        ));
    }
    Ok(response)
}

fn previous_store_position(
    store: &AdmissionConsensusStore,
    index: u64,
) -> Result<(u64, u64), AdmissionConsensusError> {
    let previous = index.checked_sub(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission log index underflow".to_string())
    })?;
    if previous == 0 {
        return Ok((0, 0));
    }
    let entry = store.entry_at(previous)?;
    Ok((entry.index, entry.leader_epoch))
}

fn prepare_command(
    config: &TrustServiceConfig,
    command_kind: AdmissionCommandKind,
    command: Value,
    election: &AdmissionElection,
) -> Result<Value, AdmissionConsensusError> {
    match command_kind {
        AdmissionCommandKind::LeadershipBarrier => Err(AdmissionConsensusError::Protocol(
            "leadership barriers cannot be submitted as external commands".to_string(),
        )),
        AdmissionCommandKind::IncrementInvocation => {
            let request: TryIncrementBudgetRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation increment command is invalid: {error}"
                    ))
                })?;
            if request.capability_id.is_empty()
                || request.capability_id.len() > 512
                || request.capability_id.bytes().any(|byte| byte == 0)
                || request.grant_index > i64::MAX as usize
            {
                return Err(AdmissionConsensusError::Protocol(
                    "invocation increment command fields are invalid".to_string(),
                ));
            }
            let authority = BudgetMutationAuthorityView {
                authority_id: election.candidate_id.clone(),
                lease_id: format!("{}#admission-term-{}", election.candidate_id, election.term),
                lease_epoch: election.term,
            };
            serde_json::to_value(ConsensusIncrementInvocationCommand { request, authority })
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation increment command preparation failed: {error}"
                    ))
                })
        }
        AdmissionCommandKind::CompositeAuthorize => {
            let request: CompositeBudgetAuthorizeRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "composite authorize command is invalid: {error}"
                    ))
                })?;
            let authority = BudgetMutationAuthorityView {
                authority_id: election.candidate_id.clone(),
                lease_id: format!("{}#admission-term-{}", election.candidate_id, election.term),
                lease_epoch: election.term,
            };
            super::super::budget_handlers::sqlite_composite_authorize_input(
                &request,
                budget_authority_from_view(&authority)
                    .map_err(AdmissionConsensusError::Protocol)?,
            )
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            validate_composite_quota_maxima(config, &request)
                .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(ConsensusCompositeAuthorizeCommand { request, authority }).map_err(
                |error| {
                    AdmissionConsensusError::Protocol(format!(
                        "composite authorize command preparation failed: {error}"
                    ))
                },
            )
        }
        AdmissionCommandKind::CaptureInvocations => {
            let request: CaptureInvocationReservationsRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation capture command is invalid: {error}"
                    ))
                })?;
            BudgetAdmissionOperationBinding::new(
                request.operation_id.clone(),
                request.request_binding_hash.clone(),
            )
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                &request.hold_id,
                &request.event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "invocation capture command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::ReverseExposure => {
            let request: ReverseChargeCostRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "reverse exposure command is invalid: {error}"
                    ))
                })?;
            super::super::budget_handlers::budget_admission_operation_binding(
                request.operation_id.as_deref(),
                request.request_binding_hash.as_deref(),
            )
            .and_then(|binding| {
                binding.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "admission reverse command requires operation ownership".to_string(),
                    )
                })
            })
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "reverse exposure command requires hold_id".to_string(),
                )
            })?;
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "reverse exposure command requires event_id".to_string(),
                )
            })?;
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                hold_id,
                event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "reverse exposure command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => {
            let request: ReduceChargeCostRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "monetary transition command is invalid: {error}"
                    ))
                })?;
            super::super::budget_handlers::budget_admission_operation_binding(
                request.operation_id.as_deref(),
                request.request_binding_hash.as_deref(),
            )
            .and_then(|binding| {
                binding.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "admission monetary transition requires operation ownership".to_string(),
                    )
                })
            })
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "monetary transition command requires hold_id".to_string(),
                )
            })?;
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "monetary transition command requires event_id".to_string(),
                )
            })?;
            let shape_matches = match command_kind {
                AdmissionCommandKind::ReleaseExposure => {
                    request.exposure_units.is_none() && request.realized_spend_units.is_none()
                }
                AdmissionCommandKind::ReconcileSpend | AdmissionCommandKind::CaptureExposure => {
                    request
                        .exposure_units
                        .zip(request.realized_spend_units)
                        .is_some_and(|(exposure_units, realized_spend_units)| {
                            exposure_units.checked_sub(realized_spend_units)
                                == Some(request.cost_units)
                        })
                }
                _ => false,
            };
            if !shape_matches {
                return Err(AdmissionConsensusError::Protocol(
                    "monetary transition command fields contradict its kind".to_string(),
                ));
            }
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                hold_id,
                event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "monetary transition command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::Revoke => {
            let request: ConsensusRevocationProposal =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "revocation proposal is invalid: {error}"
                    ))
                })?;
            if request.capability_id.is_empty()
                || request.capability_id.len() > 512
                || request.capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(AdmissionConsensusError::Protocol(
                    "revocation proposal fields are invalid".to_string(),
                ));
            }
            let revoked_at = i64::try_from(unix_timestamp_now()).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "revocation timestamp exceeds the supported range".to_string(),
                )
            })?;
            serde_json::to_value(ConsensusRevocationCommand {
                capability_id: request.capability_id,
                revoked_at,
            })
            .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "revocation command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::CombinedCapture => {
            let request: CombinedAdmissionCaptureRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "combined capture command is invalid: {error}"
                    ))
                })?;
            let prepared = prepare_combined_capture_command(config, request)
                .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(prepared).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "combined capture command preparation failed: {error}"
                ))
            })
        }
    }
}

fn admission_members(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, AdmissionMembership), AdmissionConsensusError> {
    let (self_url, peers, members) = admission_member_urls(state)?;
    let store = configured_admission_consensus_store(&state.config)?;
    let meta = store.meta()?;
    let genesis_projection = if let Some(digest) = meta.baseline_state_digest {
        let projection = store.genesis_projection()?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission consensus baseline has no persisted genesis projection".to_string(),
            )
        })?;
        if admission_genesis_projection_digest(&projection)? != digest {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted genesis projection does not match its baseline digest"
                    .to_string(),
            ));
        }
        projection
    } else if meta.membership_digest.is_none() {
        let path = state.config.budget_db_path.as_deref().ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission consensus requires a budget database".to_string(),
            )
        })?;
        capture_admission_genesis_projection(path)?
    } else {
        return Err(AdmissionConsensusError::Protocol(
            "admission bound membership has no genesis baseline".to_string(),
        ));
    };
    let membership = AdmissionMembership::new_with_genesis(members, genesis_projection)?;
    Ok((self_url, peers, membership))
}

fn admission_member_urls(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, Vec<String>), AdmissionConsensusError> {
    let cluster = state.cluster.as_ref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "HA admission consensus requires configured peers".to_string(),
        )
    })?;
    let guard = match cluster.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut peers = guard.peers.keys().cloned().collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    if peers.is_empty() {
        return Err(AdmissionConsensusError::Protocol(
            "HA admission consensus requires at least two configured nodes".to_string(),
        ));
    }
    let self_url = guard.self_url.clone();
    let mut members = peers.clone();
    members.push(self_url.clone());
    drop(guard);
    Ok((self_url, peers, members))
}

fn configured_admission_consensus_store(
    config: &TrustServiceConfig,
) -> Result<AdmissionConsensusStore, AdmissionConsensusError> {
    let budget_path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus requires a budget database".to_string(),
        )
    })?;
    let revocation_path = config.revocation_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus requires a revocation database".to_string(),
        )
    })?;
    let canonical_budget = std::fs::canonicalize(budget_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission budget database cannot be resolved: {error}"
        ))
    })?;
    let canonical_revocation = std::fs::canonicalize(revocation_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission revocation database cannot be resolved: {error}"
        ))
    })?;
    if canonical_budget != canonical_revocation {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus requires one shared budget and revocation database".to_string(),
        ));
    }
    AdmissionConsensusStore::open_existing(canonical_budget)
}

fn capture_admission_genesis_projection(
    path: &Path,
) -> Result<AdmissionGenesisProjection, AdmissionConsensusError> {
    let mut connection = Connection::open(path)?;
    configure_connection(&connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let projection =
        capture_admission_genesis_projection_from_connection(&transaction, |_| Ok(()))?;
    transaction.commit()?;
    Ok(projection)
}

fn capture_admission_genesis_projection_from_connection<F>(
    connection: &Connection,
    mut after_table: F,
) -> Result<AdmissionGenesisProjection, AdmissionConsensusError>
where
    F: FnMut(&str) -> Result<(), AdmissionConsensusError>,
{
    let existing_tables = {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")?;
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        tables
    };
    for name in &existing_tables {
        let known_authoritative = ADMISSION_GENESIS_TABLES
            .iter()
            .any(|table| table.name == name);
        let known_excluded = name.starts_with("sqlite_")
            || name.starts_with("admission_consensus_")
            || ADMISSION_GENESIS_EXCLUDED_TABLES
                .iter()
                .any(|excluded| excluded == name);
        if !known_authoritative && !known_excluded {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis contains unknown table `{name}`"
            )));
        }
    }

    let mut tables = Vec::with_capacity(ADMISSION_GENESIS_TABLES.len());
    for spec in ADMISSION_GENESIS_TABLES {
        if !existing_tables.iter().any(|name| name == spec.name) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis is missing authoritative table `{}`",
                spec.name
            )));
        }
        validate_admission_genesis_table_schema(connection, spec)?;
        let select_columns = spec
            .columns
            .iter()
            .map(|(name, _)| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement =
            connection.prepare(&format!("SELECT {select_columns} FROM \"{}\"", spec.name))?;
        let mut rows = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = rows.next()? {
            let mut encoded = Vec::with_capacity(spec.columns.len());
            for (index, (_, expected_type)) in spec.columns.iter().enumerate() {
                let value = row.get_ref(index)?;
                let value = match value {
                    rusqlite::types::ValueRef::Null => AdmissionGenesisValue::Null,
                    rusqlite::types::ValueRef::Integer(value) => {
                        AdmissionGenesisValue::Integer(value)
                    }
                    rusqlite::types::ValueRef::Real(value) => {
                        AdmissionGenesisValue::RealBits(format!("{:016x}", value.to_bits()))
                    }
                    rusqlite::types::ValueRef::Text(value) => AdmissionGenesisValue::Text(
                        std::str::from_utf8(value)
                            .map_err(|_| {
                                AdmissionConsensusError::Protocol(format!(
                                    "admission genesis table `{}` contains invalid UTF-8 text",
                                    spec.name
                                ))
                            })?
                            .to_string(),
                    ),
                    rusqlite::types::ValueRef::Blob(value) => {
                        AdmissionGenesisValue::BlobHex(lower_hex(value))
                    }
                };
                if !admission_genesis_value_matches_type(&value, *expected_type) {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission genesis table `{}` contains a value with the wrong logical type",
                        spec.name
                    )));
                }
                encoded.push(value);
            }
            encoded_rows.push(encoded);
        }
        let mut keyed_rows = encoded_rows
            .into_iter()
            .map(|row| {
                canonical_json_bytes(&row)
                    .map(|key| (key, row))
                    .map_err(|error| {
                        AdmissionConsensusError::Protocol(format!(
                            "admission genesis row canonicalization failed: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        keyed_rows.sort_by(|left, right| left.0.cmp(&right.0));
        tables.push(AdmissionGenesisTable {
            name: spec.name.to_string(),
            columns: spec
                .columns
                .iter()
                .map(|(name, value_type)| AdmissionGenesisColumn {
                    name: (*name).to_string(),
                    value_type: *value_type,
                })
                .collect(),
            rows: keyed_rows.into_iter().map(|(_, row)| row).collect(),
        });
        after_table(spec.name)?;
    }
    let projection = AdmissionGenesisProjection { tables };
    validate_admission_genesis_projection(&projection)?;
    Ok(projection)
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
    _config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    if proof.index != entry.index || proof.leader_epoch < entry.leader_epoch {
        return Err("admission commit proof does not match the applied entry".to_string());
    }
    match entry.command_kind {
        AdmissionCommandKind::LeadershipBarrier => canonical_result(&json!({"committed": true})),
        AdmissionCommandKind::IncrementInvocation => {
            apply_increment_invocation(transaction, entry, proof)
        }
        AdmissionCommandKind::CompositeAuthorize => {
            apply_composite_authorize(transaction, entry, proof)
        }
        AdmissionCommandKind::CaptureInvocations => {
            apply_invocation_capture(transaction, entry, proof)
        }
        AdmissionCommandKind::ReverseExposure => apply_reverse_exposure(transaction, entry, proof),
        AdmissionCommandKind::ReleaseExposure => apply_reduce_exposure(
            transaction,
            entry,
            proof,
            AdmissionCommandKind::ReleaseExposure,
        ),
        AdmissionCommandKind::ReconcileSpend => apply_reduce_exposure(
            transaction,
            entry,
            proof,
            AdmissionCommandKind::ReconcileSpend,
        ),
        AdmissionCommandKind::CaptureExposure => apply_reduce_exposure(
            transaction,
            entry,
            proof,
            AdmissionCommandKind::CaptureExposure,
        ),
        AdmissionCommandKind::Revoke => apply_revocation(transaction, entry),
        AdmissionCommandKind::CombinedCapture => apply_combined_capture(transaction, entry, proof),
    }
}

fn apply_increment_invocation(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
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
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, outcome.event_seq);
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
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let command: ConsensusCompositeAuthorizeCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = budget_authority_from_view(&command.authority)?;
    let prepared = super::super::budget_handlers::sqlite_composite_authorize_input(
        &command.request,
        authority.clone(),
    )
    .map_err(|error| error.to_string())?;
    let decision = match prepared.authorize_in_transaction(transaction) {
        Ok(decision) => decision,
        Err(error) => return frozen_budget_rejection(error),
    };
    let budget_seq = load_consensus_budget_event(transaction, &command.request.event_id)?.event_seq;
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, budget_seq);
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
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, budget_seq);
    let response = super::super::budget_handlers::invocation_capture_response_view(
        &request, decision, metadata, commit,
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&response)
}

fn apply_reverse_exposure(
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
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, event.event_seq);
    canonical_result(&ReverseChargeCostResponse {
        capability_id: request.capability_id,
        grant_index: request.grant_index,
        invocation_count: Some(event.invocation_count_after),
        total_cost_exposed: Some(event.total_cost_exposed_after),
        total_cost_realized_spend: Some(event.total_cost_realized_spend_after),
        budget_authority: Some(metadata),
        budget_commit: Some(commit),
    })
}

fn apply_reduce_exposure(
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
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, event.event_seq);
    canonical_result(&ReduceChargeCostResponse {
        capability_id: request.capability_id,
        grant_index: request.grant_index,
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
