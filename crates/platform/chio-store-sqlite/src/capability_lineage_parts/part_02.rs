fn acquire_causal_fence_tx(
    connection: &mut Connection,
    request: &CausalLineageFenceRequest,
    now_unix_ms: u64,
) -> Result<LineageFence, chio_kernel::ReceiptStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let head = transaction
        .query_row(
            r#"
            SELECT source_lineage_version, observed_commit_index,
                   authoritative_commit_index, completeness_watermark
            FROM causal_lineage_heads WHERE tenant_id = ?1
            "#,
            params![request.fence.tenant_id.as_str()],
            |row| {
                Ok((
                    non_negative_u64_from_column(row, 0, "source_lineage_version")?,
                    non_negative_u64_from_column(row, 1, "observed_commit_index")?,
                    non_negative_u64_from_column(row, 2, "authoritative_commit_index")?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage fence requires an authoritative head".to_string(),
            )
        })?;
    let watermark = head
        .3
        .map(|value| receipt_u64(value, "causal completeness watermark"))
        .transpose()?;
    if head.0 == 0
        || head.1 != request.fence.expected_commit_index
        || head.2 != head.1
        || watermark.is_none_or(|value| value < head.1)
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence head is incomplete, lagged, or stale".to_string(),
        ));
    }
    let derived_hash = causal_affected_set_hash(
        &request.fence.tenant_id,
        request.frozen_affected_ids.as_slice(),
    )?;
    if derived_hash != request.fence.expected_affected_set_hash {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence affected set hash mismatch".to_string(),
        ));
    }
    for target in request.frozen_affected_ids.as_slice() {
        let kind = transaction
            .query_row(
                r#"
                SELECT node_kind FROM causal_lineage_nodes
                WHERE tenant_id = ?1 AND node_id = ?2 AND first_commit_index <= ?3
                "#,
                params![
                    request.fence.tenant_id.as_str(),
                    target.as_str(),
                    sqlite_i64(
                        request.fence.expected_commit_index,
                        "causal fence commit index"
                    )?
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if kind.as_deref() != Some("capability") {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage fence target is not a committed capability".to_string(),
            ));
        }
    }

    let existing = load_stored_fence(
        &transaction,
        &request.fence.tenant_id,
        &request.fence.action_id,
    )?;
    if let Some(existing) = existing.as_ref() {
        if existing.state != "active" && existing.state != "released" {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage fence state is corrupt".to_string(),
            ));
        }
        if existing.state == "active" && existing.fence.expires_at_unix_ms > now_unix_ms {
            let targets = load_fence_target_strings(
                &transaction,
                &request.fence.tenant_id,
                &request.fence.action_id,
            )?;
            let expected_targets = request
                .frozen_affected_ids
                .as_slice()
                .iter()
                .map(|target| target.as_str().to_string())
                .collect::<Vec<_>>();
            if existing.fence.commit_index == request.fence.expected_commit_index
                && existing.fence.affected_set_hash == request.fence.expected_affected_set_hash
                && existing.fence.scheduler_lease_owner_id == request.fence.scheduler_lease_owner_id
                && existing.fence.scheduler_fencing_token == request.fence.scheduler_fencing_token
                && existing.fence.expires_at_unix_ms == request.fence.expires_at_unix_ms
                && targets == expected_targets
            {
                return Ok(existing.fence.clone());
            }
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "active causal lineage fence parameters changed".to_string(),
            ));
        }
    }

    transaction.execute(
        r#"
        INSERT INTO causal_lineage_fence_sequences (tenant_id, last_fencing_token)
        VALUES (?1, 0)
        ON CONFLICT(tenant_id) DO NOTHING
        "#,
        params![request.fence.tenant_id.as_str()],
    )?;
    let prior_token: i64 = transaction.query_row(
        "SELECT last_fencing_token FROM causal_lineage_fence_sequences WHERE tenant_id = ?1",
        params![request.fence.tenant_id.as_str()],
        |row| row.get(0),
    )?;
    let fencing_token = receipt_u64(prior_token, "causal fencing token")?
        .checked_add(1)
        .ok_or_else(|| {
            chio_kernel::ReceiptStoreError::Conflict("causal fencing token overflow".to_string())
        })?;
    transaction.execute(
        "UPDATE causal_lineage_fence_sequences SET last_fencing_token = ?2 WHERE tenant_id = ?1",
        params![
            request.fence.tenant_id.as_str(),
            sqlite_i64(fencing_token, "causal fencing token")?
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO causal_lineage_fences (
            tenant_id, action_id, fence_id, commit_index, affected_set_hash,
            fencing_token, scheduler_lease_owner_id, scheduler_fencing_token,
            expires_at_unix_ms, state
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active')
        ON CONFLICT(tenant_id, action_id) DO UPDATE SET
            fence_id = excluded.fence_id,
            commit_index = excluded.commit_index,
            affected_set_hash = excluded.affected_set_hash,
            fencing_token = excluded.fencing_token,
            scheduler_lease_owner_id = excluded.scheduler_lease_owner_id,
            scheduler_fencing_token = excluded.scheduler_fencing_token,
            expires_at_unix_ms = excluded.expires_at_unix_ms,
            state = 'active'
        "#,
        params![
            request.fence.tenant_id.as_str(),
            request.fence.action_id.as_str(),
            deterministic_fence_id(&request.fence.tenant_id, &request.fence.action_id),
            sqlite_i64(
                request.fence.expected_commit_index,
                "causal fence commit index"
            )?,
            request
                .fence
                .expected_affected_set_hash
                .as_bytes()
                .as_slice(),
            sqlite_i64(fencing_token, "causal fencing token")?,
            request.fence.scheduler_lease_owner_id.as_str(),
            sqlite_i64(
                request.fence.scheduler_fencing_token,
                "causal scheduler fencing token"
            )?,
            sqlite_i64(request.fence.expires_at_unix_ms, "causal fence expiry")?,
        ],
    )?;
    transaction.execute(
        "DELETE FROM causal_lineage_fence_targets WHERE tenant_id = ?1 AND action_id = ?2",
        params![
            request.fence.tenant_id.as_str(),
            request.fence.action_id.as_str()
        ],
    )?;
    for target in request.frozen_affected_ids.as_slice() {
        transaction.execute(
            r#"
            INSERT INTO causal_lineage_fence_targets (tenant_id, action_id, target_id)
            VALUES (?1, ?2, ?3)
            "#,
            params![
                request.fence.tenant_id.as_str(),
                request.fence.action_id.as_str(),
                target.as_str()
            ],
        )?;
    }
    let fence = LineageFence {
        tenant_id: request.fence.tenant_id.clone(),
        action_id: request.fence.action_id.clone(),
        commit_index: request.fence.expected_commit_index,
        affected_set_hash: request.fence.expected_affected_set_hash,
        fencing_token,
        scheduler_lease_owner_id: request.fence.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.fence.scheduler_fencing_token,
        expires_at_unix_ms: request.fence.expires_at_unix_ms,
    };
    transaction.commit()?;
    Ok(fence)
}

fn load_live_causal_fence(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
    now_unix_ms: u64,
) -> PortResult<Option<LineageFence>> {
    match load_stored_fence_port(connection, tenant_id, action_id)? {
        Some(stored)
            if stored.state == "active" && stored.fence.expires_at_unix_ms > now_unix_ms =>
        {
            Ok(Some(stored.fence))
        }
        Some(stored) if stored.state == "active" || stored.state == "released" => Ok(None),
        Some(_) => Err(PortError::integrity_failure()),
        None => Ok(None),
    }
}

fn release_causal_fence_tx(
    connection: &mut Connection,
    release: &LineageFenceRelease,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_stored_fence(&transaction, &release.tenant_id, &release.action_id)?
        .ok_or_else(|| {
            chio_kernel::ReceiptStoreError::NotFound(
                "causal lineage fence does not exist".to_string(),
            )
        })?;
    if stored.fence.fencing_token != release.fencing_token
        || stored.fence.scheduler_lease_owner_id != release.scheduler_lease_owner_id
        || stored.fence.scheduler_fencing_token != release.scheduler_fencing_token
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence release binding mismatch".to_string(),
        ));
    }
    if stored.state == "active" {
        transaction.execute(
            r#"
            UPDATE causal_lineage_fences SET state = 'released'
            WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
              AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
            "#,
            params![
                release.tenant_id.as_str(),
                release.action_id.as_str(),
                sqlite_i64(release.fencing_token, "causal fence release token")?,
                release.scheduler_lease_owner_id.as_str(),
                sqlite_i64(
                    release.scheduler_fencing_token,
                    "causal scheduler release token"
                )?
            ],
        )?;
    } else if stored.state != "released" {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence state is corrupt".to_string(),
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn renew_causal_fence_tx(
    connection: &mut Connection,
    renewal: &LineageFenceRenewal,
    now_unix_ms: u64,
) -> Result<LineageFence, chio_kernel::ReceiptStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_stored_fence(&transaction, &renewal.tenant_id, &renewal.action_id)?
        .ok_or_else(|| {
            chio_kernel::ReceiptStoreError::NotFound(
                "causal lineage fence does not exist".to_string(),
            )
        })?;
    if stored.state != "active"
        || stored.fence.expires_at_unix_ms <= now_unix_ms
        || stored.fence.fencing_token != renewal.fencing_token
        || stored.fence.scheduler_lease_owner_id != renewal.scheduler_lease_owner_id
        || stored.fence.scheduler_fencing_token != renewal.scheduler_fencing_token
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence renewal binding mismatch".to_string(),
        ));
    }
    if stored.fence.expires_at_unix_ms == renewal.renewed_expires_at_unix_ms {
        transaction.commit()?;
        return Ok(stored.fence);
    }
    if stored.fence.expires_at_unix_ms != renewal.expected_expires_at_unix_ms
        || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence renewal compare-and-swap failed".to_string(),
        ));
    }
    let updated = transaction.execute(
        r#"
        UPDATE causal_lineage_fences SET expires_at_unix_ms = ?6
        WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
          AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
          AND expires_at_unix_ms = ?7 AND state = 'active'
        "#,
        params![
            renewal.tenant_id.as_str(),
            renewal.action_id.as_str(),
            sqlite_i64(renewal.fencing_token, "causal fence renewal token")?,
            renewal.scheduler_lease_owner_id.as_str(),
            sqlite_i64(
                renewal.scheduler_fencing_token,
                "causal scheduler renewal token"
            )?,
            sqlite_i64(renewal.renewed_expires_at_unix_ms, "causal renewed expiry")?,
            sqlite_i64(
                renewal.expected_expires_at_unix_ms,
                "causal expected expiry"
            )?,
        ],
    )?;
    if updated != 1 {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence renewal lost its compare-and-swap".to_string(),
        ));
    }
    let renewed = LineageFence {
        expires_at_unix_ms: renewal.renewed_expires_at_unix_ms,
        ..stored.fence
    };
    transaction.commit()?;
    Ok(renewed)
}

fn takeover_causal_fence_tx(
    connection: &mut Connection,
    takeover: &LineageFenceTakeover,
    now_unix_ms: u64,
) -> Result<LineageFence, chio_kernel::ReceiptStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_stored_fence(&transaction, &takeover.tenant_id, &takeover.action_id)?
        .ok_or_else(|| {
            chio_kernel::ReceiptStoreError::NotFound(
                "causal lineage fence does not exist".to_string(),
            )
        })?;
    if stored.state != "active"
        || stored.fence.expires_at_unix_ms <= now_unix_ms
        || stored.fence.fencing_token != takeover.expected_fencing_token
        || stored.fence.scheduler_lease_owner_id != takeover.expected_scheduler_lease_owner_id
        || stored.fence.scheduler_fencing_token != takeover.expected_scheduler_fencing_token
        || stored.fence.expires_at_unix_ms != takeover.expected_expires_at_unix_ms
        || takeover.successor_scheduler_fencing_token <= stored.fence.scheduler_fencing_token
        || takeover.successor_expires_at_unix_ms < stored.fence.expires_at_unix_ms
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence takeover binding mismatch".to_string(),
        ));
    }
    let prior_token: i64 = transaction.query_row(
        "SELECT last_fencing_token FROM causal_lineage_fence_sequences WHERE tenant_id = ?1",
        params![takeover.tenant_id.as_str()],
        |row| row.get(0),
    )?;
    let prior_token = receipt_u64(prior_token, "causal fencing token")?;
    if prior_token < stored.fence.fencing_token {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence sequence regressed".to_string(),
        ));
    }
    let successor_fencing_token = prior_token.checked_add(1).ok_or_else(|| {
        chio_kernel::ReceiptStoreError::Conflict("causal fencing token overflow".to_string())
    })?;
    let updated_sequence = transaction.execute(
        "UPDATE causal_lineage_fence_sequences SET last_fencing_token = ?2 WHERE tenant_id = ?1 AND last_fencing_token = ?3",
        params![
            takeover.tenant_id.as_str(),
            sqlite_i64(successor_fencing_token, "causal successor fencing token")?,
            sqlite_i64(prior_token, "causal prior fencing token")?
        ],
    )?;
    if updated_sequence != 1 {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence sequence takeover lost its compare-and-swap".to_string(),
        ));
    }
    let updated = transaction.execute(
        r#"
        UPDATE causal_lineage_fences
        SET fencing_token = ?9, scheduler_lease_owner_id = ?7,
            scheduler_fencing_token = ?8, expires_at_unix_ms = ?6
        WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
          AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
          AND expires_at_unix_ms = ?10 AND state = 'active'
        "#,
        params![
            takeover.tenant_id.as_str(),
            takeover.action_id.as_str(),
            sqlite_i64(
                takeover.expected_fencing_token,
                "causal expected fencing token"
            )?,
            takeover.expected_scheduler_lease_owner_id.as_str(),
            sqlite_i64(
                takeover.expected_scheduler_fencing_token,
                "causal expected scheduler fencing token"
            )?,
            sqlite_i64(
                takeover.successor_expires_at_unix_ms,
                "causal successor fence expiry"
            )?,
            takeover.successor_scheduler_lease_owner_id.as_str(),
            sqlite_i64(
                takeover.successor_scheduler_fencing_token,
                "causal successor scheduler fencing token"
            )?,
            sqlite_i64(successor_fencing_token, "causal successor fencing token")?,
            sqlite_i64(
                takeover.expected_expires_at_unix_ms,
                "causal expected fence expiry"
            )?,
        ],
    )?;
    if updated != 1 {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence takeover lost its compare-and-swap".to_string(),
        ));
    }
    let successor = LineageFence {
        fencing_token: successor_fencing_token,
        scheduler_lease_owner_id: takeover.successor_scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: takeover.successor_scheduler_fencing_token,
        expires_at_unix_ms: takeover.successor_expires_at_unix_ms,
        ..stored.fence
    };
    transaction.commit()?;
    Ok(successor)
}

#[derive(Clone)]
struct StoredCausalFence {
    fence: LineageFence,
    state: String,
}

type StoredFenceRow = (String, String, i64, Vec<u8>, i64, String, i64, i64, String);

fn load_stored_fence(
    connection: &Connection,
    tenant_id: &TenantId,
    action_id: &ActionId,
) -> Result<Option<StoredCausalFence>, chio_kernel::ReceiptStoreError> {
    load_stored_fence_row(connection, tenant_id.as_str(), action_id.as_str())?
        .map(stored_fence_from_row_receipt)
        .transpose()
}

fn load_stored_fence_port(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<StoredCausalFence>> {
    load_stored_fence_row(connection, tenant_id, action_id)
        .map_err(receipt_error_to_port)?
        .map(stored_fence_from_row_port)
        .transpose()
}

fn load_stored_fence_row(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> Result<Option<StoredFenceRow>, chio_kernel::ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT tenant_id, action_id, commit_index, affected_set_hash,
                   fencing_token, scheduler_lease_owner_id,
                   scheduler_fencing_token, expires_at_unix_ms, state
            FROM causal_lineage_fences
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id, action_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(Into::into)
}

fn stored_fence_from_row_receipt(
    row: StoredFenceRow,
) -> Result<StoredCausalFence, chio_kernel::ReceiptStoreError> {
    let tenant_id = TenantId::new(row.0).map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence tenant id is corrupt".to_string(),
        )
    })?;
    let action_id = ActionId::new(row.1).map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence action id is corrupt".to_string(),
        )
    })?;
    let commit_index = receipt_u64(row.2, "causal fence commit index")?;
    let affected_set_hash = digest32_receipt(row.3)?;
    let fencing_token = receipt_u64(row.4, "causal fencing token")?;
    let scheduler_lease_owner_id = LeaseOwnerId::new(row.5).map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence scheduler owner is corrupt".to_string(),
        )
    })?;
    let scheduler_fencing_token = receipt_u64(row.6, "causal scheduler fencing token")?;
    let expires_at_unix_ms = receipt_u64(row.7, "causal fence expiry")?;
    if commit_index == 0
        || affected_set_hash.as_bytes().iter().all(|byte| *byte == 0)
        || fencing_token == 0
        || scheduler_fencing_token == 0
        || expires_at_unix_ms == 0
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence binding is corrupt".to_string(),
        ));
    }
    Ok(StoredCausalFence {
        fence: LineageFence {
            tenant_id,
            action_id,
            commit_index,
            affected_set_hash,
            fencing_token,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            expires_at_unix_ms,
        },
        state: row.8,
    })
}

fn stored_fence_from_row_port(row: StoredFenceRow) -> PortResult<StoredCausalFence> {
    let commit_index = port_u64(row.2)?;
    let affected_set_hash = digest32_port(row.3)?;
    let fencing_token = port_u64(row.4)?;
    let scheduler_lease_owner_id =
        LeaseOwnerId::new(row.5).map_err(|_| PortError::integrity_failure())?;
    let scheduler_fencing_token = port_u64(row.6)?;
    let expires_at_unix_ms = port_u64(row.7)?;
    if commit_index == 0
        || affected_set_hash.as_bytes().iter().all(|byte| *byte == 0)
        || fencing_token == 0
        || scheduler_fencing_token == 0
        || expires_at_unix_ms == 0
    {
        return Err(PortError::integrity_failure());
    }
    Ok(StoredCausalFence {
        fence: LineageFence {
            tenant_id: TenantId::new(row.0).map_err(|_| PortError::integrity_failure())?,
            action_id: ActionId::new(row.1).map_err(|_| PortError::integrity_failure())?,
            commit_index,
            affected_set_hash,
            fencing_token,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            expires_at_unix_ms,
        },
        state: row.8,
    })
}

fn load_fence_target_strings(
    connection: &Connection,
    tenant_id: &TenantId,
    action_id: &ActionId,
) -> Result<Vec<String>, chio_kernel::ReceiptStoreError> {
    let mut statement = connection.prepare(
        r#"
        SELECT target_id FROM causal_lineage_fence_targets
        WHERE tenant_id = ?1 AND action_id = ?2
        ORDER BY target_id ASC
        "#,
    )?;
    let rows = statement.query_map(params![tenant_id.as_str(), action_id.as_str()], |row| {
        row.get::<_, String>(0)
    })?;
    let mut targets = Vec::new();
    for row in rows {
        targets.push(row?);
    }
    Ok(targets)
}

fn causal_affected_set_hash(
    tenant_id: &TenantId,
    affected_ids: &[RecordId],
) -> Result<Digest32, chio_kernel::ReceiptStoreError> {
    let affected_ids = RecordIdSet::new(affected_ids.to_vec())
        .map_err(|error| chio_kernel::ReceiptStoreError::Canonical(error.to_string()))?;
    response_affected_set_hash(tenant_id, &affected_ids)
        .map_err(|error| chio_kernel::ReceiptStoreError::Canonical(error.to_string()))
}

fn deterministic_fence_id(tenant_id: &TenantId, action_id: &ActionId) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(b"chio.causal-lineage-fence-id.v1\0");
    material.extend_from_slice(tenant_id.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(action_id.as_str().as_bytes());
    format!("causal-fence-{}", hex::encode(sha256(&material).as_bytes()))
}

fn node_kind_text(kind: CausalLineageNodeKind) -> &'static str {
    match kind {
        CausalLineageNodeKind::Capability => "capability",
        CausalLineageNodeKind::Receipt => "receipt",
    }
}

fn parse_node_kind(value: &str) -> PortResult<CausalLineageNodeKind> {
    match value {
        "capability" => Ok(CausalLineageNodeKind::Capability),
        "receipt" => Ok(CausalLineageNodeKind::Receipt),
        _ => Err(PortError::integrity_failure()),
    }
}

fn edge_kind_text(kind: CausalLineageEdgeKind) -> &'static str {
    match kind {
        CausalLineageEdgeKind::CapabilityDelegation => "capability_delegation",
        CausalLineageEdgeKind::CapabilityReceipt => "capability_receipt",
        CausalLineageEdgeKind::ReceiptLineage => "receipt_lineage",
    }
}

fn parse_edge_kind(value: &str) -> PortResult<CausalLineageEdgeKind> {
    match value {
        "capability_delegation" => Ok(CausalLineageEdgeKind::CapabilityDelegation),
        "capability_receipt" => Ok(CausalLineageEdgeKind::CapabilityReceipt),
        "receipt_lineage" => Ok(CausalLineageEdgeKind::ReceiptLineage),
        _ => Err(PortError::integrity_failure()),
    }
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, chio_kernel::ReceiptStoreError> {
    i64::try_from(value).map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict(format!(
            "{field} exceeds the SQLite integer range"
        ))
    })
}

fn port_sqlite_i64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

fn receipt_u64(value: i64, field: &'static str) -> Result<u64, chio_kernel::ReceiptStoreError> {
    u64::try_from(value).map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict(format!("{field} is a corrupt negative integer"))
    })
}

fn port_u64(value: i64) -> PortResult<u64> {
    u64::try_from(value).map_err(|_| PortError::integrity_failure())
}

fn digest32_receipt(bytes: Vec<u8>) -> Result<Digest32, chio_kernel::ReceiptStoreError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage fence digest length is corrupt".to_string(),
        )
    })?;
    Ok(Digest32::new(array))
}

fn digest32_port(bytes: Vec<u8>) -> PortResult<Digest32> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Digest32::new(array))
}

fn unix_time_ms() -> PortResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PortError::unavailable())?
        .as_millis()
        .try_into()
        .map_err(|_| PortError::unavailable())
}

fn unix_time_ms_receipt() -> Result<u64, chio_kernel::ReceiptStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            chio_kernel::ReceiptStoreError::Conflict(
                "trusted clock is before the Unix epoch".to_string(),
            )
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            chio_kernel::ReceiptStoreError::Conflict(
                "trusted clock exceeds the causal lineage range".to_string(),
            )
        })
}

fn receipt_error_to_port(error: chio_kernel::ReceiptStoreError) -> PortError {
    match error {
        chio_kernel::ReceiptStoreError::Conflict(_)
        | chio_kernel::ReceiptStoreError::RetentionTenantScopeUnsupported => {
            PortError::conflict()
        }
        chio_kernel::ReceiptStoreError::NotFound(_)
        | chio_kernel::ReceiptStoreError::CryptoDecode(_)
        | chio_kernel::ReceiptStoreError::Canonical(_)
        | chio_kernel::ReceiptStoreError::InvalidOutcome(_)
        | chio_kernel::ReceiptStoreError::ReadBoundary(_)
        | chio_kernel::ReceiptStoreError::Json(_)
        | chio_kernel::ReceiptStoreError::RetentionArchiveIncomplete { .. }
        | chio_kernel::ReceiptStoreError::RetentionWatermarkRegression { .. }
        | chio_kernel::ReceiptStoreError::ArchivedRangeProjection { .. } => {
            PortError::integrity_failure()
        }
        chio_kernel::ReceiptStoreError::Sqlite(_)
        | chio_kernel::ReceiptStoreError::Pool(_)
        | chio_kernel::ReceiptStoreError::Timeout { .. }
        | chio_kernel::ReceiptStoreError::Io(_)
        | chio_kernel::ReceiptStoreError::Unsupported(_)
        | chio_kernel::ReceiptStoreError::Fenced
        | chio_kernel::ReceiptStoreError::OutcomeUnknown(_)
        | chio_kernel::ReceiptStoreError::WriterDead { .. } => PortError::unavailable(),
    }
}
