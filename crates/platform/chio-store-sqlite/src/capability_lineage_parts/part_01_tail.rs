#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotentCapabilityIssuance {
    Created(Vec<u8>),
    Existing(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedCapabilityIssuance {
    Pending {
        intent_bytes: Vec<u8>,
        authorization_bytes: Option<Vec<u8>>,
        recorded_at: u64,
    },
    Aborted {
        reason: String,
    },
    Finalized(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySessionAdmissionRegistration {
    pub admission_nonce: String,
    pub operation_nonce: String,
    pub admission_digest: String,
    pub binding_bytes: Vec<u8>,
}

/// Immutable inputs for preparing or recovering a capability issuance intent.
pub struct PrepareCapabilityIssuanceIntentInput<'a> {
    pub request_nonce: &'a str,
    pub request_digest: &'a str,
    pub tenant_id: &'a TenantId,
    pub lineage_root_id: &'a LineageId,
    pub intent_bytes: &'a [u8],
    pub session_admission: &'a CapabilitySessionAdmissionRegistration,
    pub recorded_at: u64,
    pub expires_at: u64,
    pub expected_freeze_generation: u64,
}

/// Immutable bindings and signed artifact for finalizing a capability issuance.
pub struct FinalizeCapabilityIssuanceInput<'a> {
    pub request_nonce: &'a str,
    pub request_digest: &'a str,
    pub intent_bytes: &'a [u8],
    pub authorization_bytes: &'a [u8],
    pub tenant_id: &'a TenantId,
    pub lineage_root_id: &'a LineageId,
    pub capability: CapabilityToken,
    pub response_bytes: &'a [u8],
}

impl IdempotentCapabilityIssuance {
    #[must_use]
    pub fn response_bytes(self) -> Vec<u8> {
        match self {
            Self::Created(bytes) | Self::Existing(bytes) => bytes,
        }
    }
}

struct ContextualCapabilitySnapshot<'a> {
    tenant_id: &'a str,
    lineage_root_id: &'a str,
    capability_id: &'a str,
    subject_key: &'a str,
    issuer_key: &'a str,
    issued_at: u64,
    expires_at: u64,
    grants_json: &'a str,
    parent_capability_id: Option<&'a str>,
}

fn record_contextual_capability_snapshot_tx(
    transaction: &Transaction<'_>,
    snapshot: ContextualCapabilitySnapshot<'_>,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let ContextualCapabilitySnapshot {
        tenant_id,
        lineage_root_id,
        capability_id,
        subject_key,
        issuer_key,
        issued_at,
        expires_at,
        grants_json,
        parent_capability_id,
    } = snapshot;
    let (operation, delegation_depth) = match parent_capability_id {
        None => ("issue", 0),
        Some(parent_id) => {
            let parent_context = transaction
                .query_row(
                    r#"
                    SELECT tenant_id, lineage_root_id
                    FROM capability_lineage_admissions
                    WHERE capability_id = ?1
                    "#,
                    params![parent_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            if parent_context
                .as_ref()
                .is_none_or(|(parent_tenant, parent_lineage)| {
                    parent_tenant != tenant_id || parent_lineage != lineage_root_id
                })
            {
                return Err(chio_kernel::ReceiptStoreError::Conflict(
                    "delegation parent is not bound to the authoritative tenant and lineage"
                        .to_string(),
                ));
            }
            let parent_depth = transaction
                .query_row(
                    "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                    params![parent_id],
                    |row| non_negative_u64_from_column(row, 0, "delegation_depth"),
                )
                .optional()?
                .ok_or_else(|| {
                    chio_kernel::ReceiptStoreError::Conflict(
                        "delegation parent capability snapshot is missing".to_string(),
                    )
                })?;
            let depth = parent_depth.checked_add(1).ok_or_else(|| {
                chio_kernel::ReceiptStoreError::Conflict(
                    "capability delegation depth overflowed".to_string(),
                )
            })?;
            ("delegate", depth)
        }
    };

    let expected = CapabilitySnapshot {
        capability_id: capability_id.to_string(),
        subject_key: subject_key.to_string(),
        issuer_key: issuer_key.to_string(),
        issued_at,
        expires_at,
        grants_json: grants_json.to_string(),
        delegation_depth,
        parent_capability_id: parent_capability_id.map(ToString::to_string),
    };
    let existing = transaction
        .query_row(
            r#"
            SELECT capability_id, subject_key, issuer_key, issued_at, expires_at,
                   grants_json, delegation_depth, parent_capability_id
            FROM capability_lineage
            WHERE capability_id = ?1
            "#,
            params![capability_id],
            snapshot_from_row,
        )
        .optional()?;
    if existing
        .as_ref()
        .is_some_and(|snapshot| snapshot != &expected)
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "capability snapshot conflicts with its first recorded value".to_string(),
        ));
    }

    let binding = transaction
        .query_row(
            r#"
            SELECT tenant_id, lineage_root_id, parent_capability_id, operation
            FROM capability_lineage_admissions
            WHERE capability_id = ?1
            "#,
            params![capability_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    if let Some((bound_tenant, bound_lineage, bound_parent, bound_operation)) = binding {
        if existing.is_none()
            || bound_tenant != tenant_id
            || bound_lineage != lineage_root_id
            || bound_parent.as_deref() != parent_capability_id
            || bound_operation != operation
        {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "capability issuance admission binding changed".to_string(),
            ));
        }
        return Ok(());
    }

    reject_active_causal_issuance_fence(
        transaction,
        tenant_id,
        lineage_root_id,
        parent_capability_id,
        unix_time_ms_receipt()?,
    )?;

    if existing.is_none() {
        transaction.execute(
            r#"
            INSERT INTO capability_lineage (
                capability_id, subject_key, issuer_key, issued_at, expires_at,
                grants_json, delegation_depth, parent_capability_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                capability_id,
                subject_key,
                issuer_key,
                sqlite_i64(issued_at, "capability issued_at")?,
                sqlite_i64(expires_at, "capability expires_at")?,
                grants_json,
                sqlite_i64(delegation_depth, "capability delegation depth")?,
                parent_capability_id,
            ],
        )?;
    }
    let inserted = transaction.execute(
        r#"
        INSERT INTO capability_lineage_admissions (
            capability_id, tenant_id, lineage_root_id, parent_capability_id, operation
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            capability_id,
            tenant_id,
            lineage_root_id,
            parent_capability_id,
            operation
        ],
    )?;
    if inserted != 1 {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "capability issuance admission binding was not recorded".to_string(),
        ));
    }
    Ok(())
}

fn reject_active_causal_issuance_fence(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    lineage_root_id: &str,
    parent_capability_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let fenced: bool = transaction.query_row(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM causal_lineage_fences AS fences
            JOIN causal_lineage_fence_targets AS targets
              ON targets.tenant_id = fences.tenant_id
             AND targets.action_id = fences.action_id
            WHERE fences.tenant_id = ?1
              AND (
                    targets.target_id = ?2
                 OR (?3 IS NOT NULL AND targets.target_id = ?3)
              )
              AND fences.state = 'active'
              AND fences.expires_at_unix_ms > ?4
        )
        "#,
        params![
            tenant_id,
            lineage_root_id,
            parent_capability_id,
            sqlite_i64(now_unix_ms, "causal fence trusted time")?
        ],
        |row| row.get(0),
    )?;
    if fenced {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "capability issuance or delegation is blocked by an active causal lineage fence"
                .to_string(),
        ));
    }
    Ok(())
}

const MAX_CAUSAL_FENCE_LEASE_MS: u64 = 60_000;

fn ensure_sqlite_integrity(connection: &Connection) -> PortResult<()> {
    let result = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(|_| PortError::unavailable())?;
    if result != "ok" {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn ensure_query_prepares(connection: &Connection, query: &str) -> PortResult<()> {
    connection
        .prepare(query)
        .map(|_| ())
        .map_err(|_| PortError::integrity_failure())
}

impl CausalLineageCommitStore for SqliteReceiptStore {
    fn commit_causal_lineage(&self, request: &CausalLineageCommitRequest) -> PortResult<()> {
        validate_causal_commit(request)?;
        let request = request.clone();
        self.writer_handle()
            .run_write(move |connection| commit_causal_lineage_tx(connection, &request))
            .map_err(receipt_error_to_port)
    }
}

impl CausalLineageStore for SqliteReceiptStore {
    fn ensure_causal_lineage_ready(&self) -> PortResult<()> {
        let connection = self.connection().map_err(receipt_error_to_port)?;
        ensure_sqlite_integrity(&connection)?;
        ensure_query_prepares(
            &connection,
            r#"
            SELECT heads.tenant_id, heads.source_lineage_version,
                   heads.observed_commit_index, heads.authoritative_commit_index,
                   heads.completeness_watermark, nodes.node_id, nodes.node_kind,
                   nodes.first_commit_index, edges.parent_id, edges.child_id,
                   edges.edge_kind, edges.first_commit_index
            FROM causal_lineage_heads AS heads
            LEFT JOIN causal_lineage_nodes AS nodes
              ON nodes.tenant_id = heads.tenant_id
            LEFT JOIN causal_lineage_edges AS edges
              ON edges.tenant_id = heads.tenant_id
            LIMIT 0
            "#,
        )
    }

    fn load_causal_snapshot(
        &self,
        request: &CausalLineageSnapshotRequest,
    ) -> PortResult<CausalLineageSnapshot> {
        if request.seed_ids.is_empty()
            || request.query_bounds.max_depth == 0
            || request.query_bounds.max_nodes == 0
            || request.query_bounds.max_nodes > 4_096
            || request.query_bounds.max_edges == 0
            || request.query_bounds.max_edges > 8_192
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection().map_err(receipt_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| PortError::unavailable())?;
        if let Some(action_id) = &request.fence_action_id {
            let fence = load_live_causal_fence(
                &transaction,
                request.tenant_id.as_str(),
                action_id.as_str(),
                unix_time_ms()?,
            )?
            .ok_or_else(PortError::conflict)?;
            if fence.fencing_token == 0 {
                return Err(PortError::integrity_failure());
            }
        }
        let snapshot = load_causal_snapshot_tx(&transaction, request)?;
        transaction.commit().map_err(|_| PortError::unavailable())?;
        Ok(snapshot)
    }
}

impl LineageFenceStore for SqliteReceiptStore {
    fn acquire(&self, _: &LineageFenceRequest) -> PortResult<LineageFence> {
        Err(PortError::invalid_data())
    }

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        let connection = self.connection().map_err(receipt_error_to_port)?;
        load_live_causal_fence(
            &connection,
            action.tenant_id.as_str(),
            action.id.as_str(),
            unix_time_ms()?,
        )
    }

    fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        let now_unix_ms = unix_time_ms()?;
        if renewal.fencing_token == 0
            || renewal.scheduler_fencing_token == 0
            || renewal.expected_expires_at_unix_ms <= now_unix_ms
            || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
            || renewal
                .renewed_expires_at_unix_ms
                .saturating_sub(now_unix_ms)
                > MAX_CAUSAL_FENCE_LEASE_MS
        {
            return Err(PortError::invalid_data());
        }
        let renewal = renewal.clone();
        self.writer_handle()
            .run_write(move |connection| renew_causal_fence_tx(connection, &renewal, now_unix_ms))
            .map_err(receipt_error_to_port)
    }

    fn takeover(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        let now_unix_ms = unix_time_ms()?;
        if takeover.expected_fencing_token == 0
            || takeover.expected_scheduler_fencing_token == 0
            || takeover.successor_scheduler_fencing_token
                <= takeover.expected_scheduler_fencing_token
            || takeover.expected_expires_at_unix_ms <= now_unix_ms
            || takeover.successor_expires_at_unix_ms < takeover.expected_expires_at_unix_ms
            || takeover
                .successor_expires_at_unix_ms
                .saturating_sub(now_unix_ms)
                > MAX_CAUSAL_FENCE_LEASE_MS
        {
            return Err(PortError::invalid_data());
        }
        let takeover = takeover.clone();
        self.writer_handle()
            .run_write(move |connection| {
                takeover_causal_fence_tx(connection, &takeover, now_unix_ms)
            })
            .map_err(receipt_error_to_port)
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        if release.fencing_token == 0 || release.scheduler_fencing_token == 0 {
            return Err(PortError::invalid_data());
        }
        let release = release.clone();
        self.writer_handle()
            .run_write(move |connection| release_causal_fence_tx(connection, &release))
            .map_err(receipt_error_to_port)
    }
}

impl CausalLineageFenceStore for SqliteReceiptStore {
    fn ensure_causal_lineage_fences_ready(&self) -> PortResult<()> {
        let connection = self.connection().map_err(receipt_error_to_port)?;
        ensure_sqlite_integrity(&connection)?;
        ensure_query_prepares(
            &connection,
            r#"
            SELECT sequences.tenant_id, sequences.last_fencing_token,
                   fences.action_id, fences.fence_id, fences.commit_index,
                   fences.affected_set_hash, fences.fencing_token,
                   fences.scheduler_lease_owner_id, fences.scheduler_fencing_token,
                   fences.expires_at_unix_ms, fences.state, targets.target_id,
                   admissions.capability_id, admissions.lineage_root_id,
                   admissions.parent_capability_id, admissions.operation
            FROM causal_lineage_fence_sequences AS sequences
            LEFT JOIN causal_lineage_fences AS fences
              ON fences.tenant_id = sequences.tenant_id
            LEFT JOIN causal_lineage_fence_targets AS targets
              ON targets.tenant_id = fences.tenant_id
             AND targets.action_id = fences.action_id
            LEFT JOIN capability_lineage_admissions AS admissions
              ON admissions.tenant_id = sequences.tenant_id
            LIMIT 0
            "#,
        )
    }

    fn acquire_causal_fence(
        &self,
        request: &CausalLineageFenceRequest,
    ) -> PortResult<LineageFence> {
        let now_unix_ms = unix_time_ms()?;
        if request.frozen_affected_ids.as_slice().is_empty()
            || request.fence.expected_commit_index == 0
            || request
                .fence
                .expected_affected_set_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || request.fence.scheduler_fencing_token == 0
            || request.fence.expires_at_unix_ms <= now_unix_ms
            || request.fence.expires_at_unix_ms.saturating_sub(now_unix_ms)
                > MAX_CAUSAL_FENCE_LEASE_MS
        {
            return Err(PortError::invalid_data());
        }
        let request = request.clone();
        self.writer_handle()
            .run_write(move |connection| acquire_causal_fence_tx(connection, &request, now_unix_ms))
            .map_err(receipt_error_to_port)
    }
}

fn validate_causal_commit(request: &CausalLineageCommitRequest) -> PortResult<()> {
    if request.metadata.source_lineage_version == 0
        || request.metadata.observed_commit_index == 0
        || request.metadata.authoritative_commit_index < request.metadata.observed_commit_index
        || request
            .metadata
            .completeness_watermark
            .is_some_and(|watermark| watermark > request.metadata.observed_commit_index)
    {
        return Err(PortError::invalid_data());
    }
    let mut nodes = BTreeMap::new();
    for node in request.nodes.as_slice() {
        if node.tenant_id != request.tenant_id {
            return Err(PortError::invalid_data());
        }
        if let Some(existing) = nodes.insert(node.node_id.clone(), node.kind) {
            if existing != node.kind {
                return Err(PortError::invalid_data());
            }
        }
    }
    for edge in request.edges.as_slice() {
        if edge.tenant_id != request.tenant_id || edge.parent_id == edge.child_id {
            return Err(PortError::invalid_data());
        }
    }
    Ok(())
}

fn commit_causal_lineage_tx(
    connection: &mut Connection,
    request: &CausalLineageCommitRequest,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let prior = transaction
        .query_row(
            r#"
            SELECT source_lineage_version, observed_commit_index,
                   authoritative_commit_index, completeness_watermark
            FROM causal_lineage_heads WHERE tenant_id = ?1
            "#,
            params![request.tenant_id.as_str()],
            |row| {
                Ok((
                    non_negative_u64_from_column(row, 0, "source_lineage_version")?,
                    non_negative_u64_from_column(row, 1, "observed_commit_index")?,
                    non_negative_u64_from_column(row, 2, "authoritative_commit_index")?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()?;
    if let Some((source_version, observed, authoritative, watermark)) = prior {
        let watermark = watermark
            .map(|value| receipt_u64(value, "causal completeness watermark"))
            .transpose()?;
        let next = observed.checked_add(1).ok_or_else(|| {
            chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage commit index overflow".to_string(),
            )
        })?;
        if request.metadata.source_lineage_version < source_version
            || request.metadata.authoritative_commit_index < authoritative
            || request.metadata.completeness_watermark < watermark
            || (request.metadata.observed_commit_index != observed
                && request.metadata.observed_commit_index != next)
            || (request.metadata.observed_commit_index == observed
                && (!request.nodes.is_empty() || !request.edges.is_empty()))
        {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage commit is not monotonic".to_string(),
            ));
        }
    } else if request.metadata.observed_commit_index != 1 {
        return Err(chio_kernel::ReceiptStoreError::Conflict(
            "first causal lineage commit index must be one".to_string(),
        ));
    }
    reject_fenced_delegations(&transaction, request, unix_time_ms_receipt()?)?;

    for node in request.nodes.as_slice() {
        let node_kind = node_kind_text(node.kind);
        transaction.execute(
            r#"
            INSERT INTO causal_lineage_nodes (
                tenant_id, node_id, node_kind, first_commit_index
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(tenant_id, node_id) DO NOTHING
            "#,
            params![
                request.tenant_id.as_str(),
                node.node_id.as_str(),
                node_kind,
                sqlite_i64(
                    request.metadata.observed_commit_index,
                    "causal node commit index"
                )?
            ],
        )?;
        let stored_kind: String = transaction.query_row(
            "SELECT node_kind FROM causal_lineage_nodes WHERE tenant_id = ?1 AND node_id = ?2",
            params![request.tenant_id.as_str(), node.node_id.as_str()],
            |row| row.get(0),
        )?;
        if stored_kind != node_kind {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage node kind changed".to_string(),
            ));
        }
    }
    for edge in request.edges.as_slice() {
        require_edge_endpoints(&transaction, request, edge)?;
        transaction.execute(
            r#"
            INSERT INTO causal_lineage_edges (
                tenant_id, parent_id, child_id, edge_kind, first_commit_index
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(tenant_id, parent_id, child_id, edge_kind) DO NOTHING
            "#,
            params![
                request.tenant_id.as_str(),
                edge.parent_id.as_str(),
                edge.child_id.as_str(),
                edge_kind_text(edge.kind),
                sqlite_i64(
                    request.metadata.observed_commit_index,
                    "causal edge commit index"
                )?
            ],
        )?;
    }
    transaction.execute(
        r#"
        INSERT INTO causal_lineage_heads (
            tenant_id, source_lineage_version, observed_commit_index,
            authoritative_commit_index, completeness_watermark
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(tenant_id) DO UPDATE SET
            source_lineage_version = excluded.source_lineage_version,
            observed_commit_index = excluded.observed_commit_index,
            authoritative_commit_index = excluded.authoritative_commit_index,
            completeness_watermark = excluded.completeness_watermark
        "#,
        params![
            request.tenant_id.as_str(),
            sqlite_i64(
                request.metadata.source_lineage_version,
                "source lineage version"
            )?,
            sqlite_i64(
                request.metadata.observed_commit_index,
                "observed causal commit index"
            )?,
            sqlite_i64(
                request.metadata.authoritative_commit_index,
                "authoritative causal commit index"
            )?,
            request
                .metadata
                .completeness_watermark
                .map(|value| sqlite_i64(value, "causal completeness watermark"))
                .transpose()?,
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn reject_fenced_delegations(
    transaction: &Transaction<'_>,
    request: &CausalLineageCommitRequest,
    now_unix_ms: u64,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    for edge in request
        .edges
        .as_slice()
        .iter()
        .filter(|edge| edge.kind == CausalLineageEdgeKind::CapabilityDelegation)
    {
        let fenced: bool = transaction.query_row(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM causal_lineage_fences AS fences
                JOIN causal_lineage_fence_targets AS targets
                  ON targets.tenant_id = fences.tenant_id
                 AND targets.action_id = fences.action_id
                WHERE fences.tenant_id = ?1
                  AND targets.target_id = ?2
                  AND fences.state = 'active'
                  AND fences.expires_at_unix_ms > ?3
            )
            "#,
            params![
                request.tenant_id.as_str(),
                edge.parent_id.as_str(),
                sqlite_i64(now_unix_ms, "causal fence trusted time")?
            ],
            |row| row.get(0),
        )?;
        if fenced {
            return Err(chio_kernel::ReceiptStoreError::Conflict(
                "capability delegation is blocked by an active causal lineage fence".to_string(),
            ));
        }
    }
    Ok(())
}

fn require_edge_endpoints(
    transaction: &Transaction<'_>,
    request: &CausalLineageCommitRequest,
    edge: &CausalLineageEdge,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let parent_kind = load_node_kind(transaction, &request.tenant_id, &edge.parent_id)?;
    let child_kind = load_node_kind(transaction, &request.tenant_id, &edge.child_id)?;
    let valid = matches!(
        (parent_kind, child_kind, edge.kind),
        (
            CausalLineageNodeKind::Capability,
            CausalLineageNodeKind::Capability,
            CausalLineageEdgeKind::CapabilityDelegation
        ) | (
            CausalLineageNodeKind::Capability,
            CausalLineageNodeKind::Receipt,
            CausalLineageEdgeKind::CapabilityReceipt
        ) | (
            CausalLineageNodeKind::Receipt,
            CausalLineageNodeKind::Receipt,
            CausalLineageEdgeKind::ReceiptLineage
        )
    );
    if valid {
        Ok(())
    } else {
        Err(chio_kernel::ReceiptStoreError::Conflict(
            "causal lineage edge has missing or incompatible endpoints".to_string(),
        ))
    }
}

fn load_node_kind(
    transaction: &Transaction<'_>,
    tenant_id: &chio_security_types::ports::TenantId,
    node_id: &RecordId,
) -> Result<CausalLineageNodeKind, chio_kernel::ReceiptStoreError> {
    let value = transaction
        .query_row(
            "SELECT node_kind FROM causal_lineage_nodes WHERE tenant_id = ?1 AND node_id = ?2",
            params![tenant_id.as_str(), node_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            chio_kernel::ReceiptStoreError::Conflict(
                "causal lineage edge endpoint is missing".to_string(),
            )
        })?;
    parse_node_kind(&value).map_err(|_| {
        chio_kernel::ReceiptStoreError::Conflict("causal lineage node kind is corrupt".to_string())
    })
}

fn load_causal_snapshot_tx(
    transaction: &Transaction<'_>,
    request: &CausalLineageSnapshotRequest,
) -> PortResult<CausalLineageSnapshot> {
    let head = transaction
        .query_row(
            r#"
            SELECT source_lineage_version, observed_commit_index,
                   authoritative_commit_index, completeness_watermark
            FROM causal_lineage_heads
            WHERE tenant_id = ?1
            "#,
            params![request.tenant_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| PortError::unavailable())?;
    let Some((source_version, observed, authoritative, watermark)) = head else {
        return empty_causal_snapshot(request);
    };
    let metadata = CausalLineageCommitMetadata {
        source_lineage_version: port_u64(source_version)?,
        observed_commit_index: port_u64(observed)?,
        authoritative_commit_index: port_u64(authoritative)?,
        completeness_watermark: watermark.map(port_u64).transpose()?,
    };
    let max_nodes =
        usize::try_from(request.query_bounds.max_nodes).map_err(|_| PortError::invalid_data())?;
    let max_edges =
        usize::try_from(request.query_bounds.max_edges).map_err(|_| PortError::invalid_data())?;
    let mut pending = VecDeque::<(RecordId, u32)>::new();
    let mut scheduled = BTreeSet::<RecordId>::new();
    let mut seeds = request.seed_ids.as_slice().to_vec();
    seeds.sort();
    seeds.dedup();
    for seed in seeds {
        scheduled.insert(seed.clone());
        pending.push_back((seed, 0));
    }
    let mut nodes = BTreeMap::<RecordId, CausalLineageNode>::new();
    let mut edges = BTreeSet::<CausalLineageEdge>::new();
    let mut depth_truncated = false;
    let mut nodes_truncated = false;
    let mut edges_truncated = false;

    while let Some((node_id, depth)) = pending.pop_front() {
        if nodes.contains_key(&node_id) {
            continue;
        }
        if nodes.len() == max_nodes {
            nodes_truncated = true;
            break;
        }
        let stored_kind = transaction
            .query_row(
                r#"
                SELECT node_kind
                FROM causal_lineage_nodes
                WHERE tenant_id = ?1 AND node_id = ?2 AND first_commit_index <= ?3
                "#,
                params![request.tenant_id.as_str(), node_id.as_str(), observed],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PortError::unavailable())?;
        let Some(stored_kind) = stored_kind else {
            continue;
        };
        let kind = parse_node_kind(&stored_kind)?;
        nodes.insert(
            node_id.clone(),
            CausalLineageNode {
                tenant_id: request.tenant_id.clone(),
                node_id: node_id.clone(),
                kind,
            },
        );
        if depth == request.query_bounds.max_depth {
            if has_visible_outgoing_edge(
                transaction,
                &request.tenant_id,
                &node_id,
                metadata.observed_commit_index,
            )? {
                depth_truncated = true;
            }
            continue;
        }
        if depth > request.query_bounds.max_depth {
            depth_truncated = true;
            continue;
        }
        let remaining_edges = max_edges.saturating_sub(edges.len());
        let mut outgoing = load_visible_outgoing_edges(
            transaction,
            &request.tenant_id,
            &node_id,
            metadata.observed_commit_index,
            remaining_edges.saturating_add(1),
        )?;
        if outgoing.len() > remaining_edges {
            edges_truncated = true;
            outgoing.truncate(remaining_edges);
        }
        for edge in outgoing {
            if scheduled.insert(edge.child_id.clone()) {
                let next_depth = depth
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
                pending.push_back((edge.child_id.clone(), next_depth));
            }
            edges.insert(edge);
        }
    }

    let nodes = CausalLineageNodes::new(nodes.into_values().collect())
        .map_err(|_| PortError::integrity_failure())?;
    let edges = CausalLineageEdges::new(edges.into_iter().collect())
        .map_err(|_| PortError::integrity_failure())?;
    Ok(CausalLineageSnapshot {
        tenant_id: request.tenant_id.clone(),
        metadata,
        nodes,
        edges,
        depth_truncated,
        nodes_truncated,
        edges_truncated,
    })
}

fn empty_causal_snapshot(
    request: &CausalLineageSnapshotRequest,
) -> PortResult<CausalLineageSnapshot> {
    Ok(CausalLineageSnapshot {
        tenant_id: request.tenant_id.clone(),
        metadata: CausalLineageCommitMetadata {
            source_lineage_version: 0,
            observed_commit_index: 0,
            authoritative_commit_index: 0,
            completeness_watermark: None,
        },
        nodes: CausalLineageNodes::new(Vec::new()).map_err(|_| PortError::integrity_failure())?,
        edges: CausalLineageEdges::new(Vec::new()).map_err(|_| PortError::integrity_failure())?,
        depth_truncated: false,
        nodes_truncated: false,
        edges_truncated: false,
    })
}

fn has_visible_outgoing_edge(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    parent_id: &RecordId,
    observed_commit_index: u64,
) -> PortResult<bool> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM causal_lineage_edges
                WHERE tenant_id = ?1 AND parent_id = ?2 AND first_commit_index <= ?3
            )
            "#,
            params![
                tenant_id.as_str(),
                parent_id.as_str(),
                port_sqlite_i64(observed_commit_index)?
            ],
            |row| row.get(0),
        )
        .map_err(|_| PortError::unavailable())
}

fn load_visible_outgoing_edges(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    parent_id: &RecordId,
    observed_commit_index: u64,
    limit: usize,
) -> PortResult<Vec<CausalLineageEdge>> {
    let mut statement = transaction
        .prepare(
            r#"
            SELECT child_id, edge_kind
            FROM causal_lineage_edges
            WHERE tenant_id = ?1 AND parent_id = ?2 AND first_commit_index <= ?3
            ORDER BY child_id ASC, edge_kind ASC
            LIMIT ?4
            "#,
        )
        .map_err(|_| PortError::unavailable())?;
    let rows = statement
        .query_map(
            params![
                tenant_id.as_str(),
                parent_id.as_str(),
                port_sqlite_i64(observed_commit_index)?,
                i64::try_from(limit).map_err(|_| PortError::invalid_data())?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|_| PortError::unavailable())?;
    let mut edges = Vec::new();
    for row in rows {
        let (child_id, kind) = row.map_err(|_| PortError::unavailable())?;
        edges.push(CausalLineageEdge {
            tenant_id: tenant_id.clone(),
            parent_id: parent_id.clone(),
            child_id: RecordId::new(child_id).map_err(|_| PortError::integrity_failure())?,
            kind: parse_edge_kind(&kind)?,
        });
    }
    Ok(edges)
}
