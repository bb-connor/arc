#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_quarantine::CausalBlastRadiusResolver;
    use chio_security_types::ports::{
        ActionId, BlastRadiusFenceAcquisition, BlastRadiusPort, BlastRadiusQueryBounds,
        BlastRadiusRequest, BlastRadiusResult, BlastRadiusSeeds, CausalLineageCommitMetadata,
        CausalLineageCommitRequest, CausalLineageCommitStore, CausalLineageEdge,
        CausalLineageEdgeKind, CausalLineageEdges, CausalLineageFenceRequest,
        CausalLineageFenceStore, CausalLineageNode, CausalLineageNodeKind, CausalLineageNodes,
        CausalLineageSnapshotRequest, CausalLineageStore, LeaseOwnerId, LineageFenceRelease,
        LineageFenceRenewal, LineageFenceRequest, LineageFenceStore, LineageFenceTakeover,
        LineageId, RecordId, RecordIdSet, TenantId, TenantScopedId,
    };
    use chio_test_support::prelude::*;
    use rusqlite::params;

    use crate::receipt_store::SqliteReceiptStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    /// Build a test CapabilityToken with the given ID and subject/issuer keypairs.
    fn make_token(
        id: &str,
        subject_kp: &Keypair,
        issuer_kp: &Keypair,
        issued_at: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at,
            expires_at,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, issuer_kp).test_expect("sign failed")
    }

    fn tenant(value: &str) -> TenantId {
        TenantId::new(value).unwrap_or_else(|error| panic!("tenant id: {error}"))
    }

    fn lease_owner() -> LeaseOwnerId {
        LeaseOwnerId::new("causal-lineage-test-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}"))
    }

    fn action(value: &str) -> ActionId {
        ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
    }

    fn record(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
    }

    fn causal_node(
        tenant_id: &TenantId,
        node_id: &str,
        kind: CausalLineageNodeKind,
    ) -> CausalLineageNode {
        CausalLineageNode {
            tenant_id: tenant_id.clone(),
            node_id: record(node_id),
            kind,
        }
    }

    fn causal_edge(
        tenant_id: &TenantId,
        parent_id: &str,
        child_id: &str,
        kind: CausalLineageEdgeKind,
    ) -> CausalLineageEdge {
        CausalLineageEdge {
            tenant_id: tenant_id.clone(),
            parent_id: record(parent_id),
            child_id: record(child_id),
            kind,
        }
    }

    fn causal_commit(
        tenant_id: &TenantId,
        commit_index: u64,
        nodes: Vec<CausalLineageNode>,
        edges: Vec<CausalLineageEdge>,
    ) -> CausalLineageCommitRequest {
        CausalLineageCommitRequest {
            tenant_id: tenant_id.clone(),
            metadata: CausalLineageCommitMetadata {
                source_lineage_version: 1,
                observed_commit_index: commit_index,
                authoritative_commit_index: commit_index,
                completeness_watermark: Some(commit_index),
            },
            nodes: CausalLineageNodes::new(nodes)
                .unwrap_or_else(|error| panic!("bounded causal nodes: {error}")),
            edges: CausalLineageEdges::new(edges)
                .unwrap_or_else(|error| panic!("bounded causal edges: {error}")),
        }
    }

    fn committed_causal_graph(tenant_id: &TenantId) -> CausalLineageCommitRequest {
        causal_commit(
            tenant_id,
            1,
            vec![
                causal_node(tenant_id, "cap-root", CausalLineageNodeKind::Capability),
                causal_node(tenant_id, "cap-child", CausalLineageNodeKind::Capability),
                causal_node(tenant_id, "receipt-a", CausalLineageNodeKind::Receipt),
                causal_node(tenant_id, "receipt-b", CausalLineageNodeKind::Receipt),
            ],
            vec![
                causal_edge(
                    tenant_id,
                    "cap-root",
                    "cap-child",
                    CausalLineageEdgeKind::CapabilityDelegation,
                ),
                causal_edge(
                    tenant_id,
                    "cap-child",
                    "receipt-a",
                    CausalLineageEdgeKind::CapabilityReceipt,
                ),
                causal_edge(
                    tenant_id,
                    "receipt-a",
                    "receipt-b",
                    CausalLineageEdgeKind::ReceiptLineage,
                ),
            ],
        )
    }

    #[test]
    fn record_and_get_lineage_returns_matching_fields() {
        let path = unique_db_path("cl-persist");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-001", &subject_kp, &issuer_kp, 1000, 2000);

        store
            .record_capability_snapshot(&token, None)
            .test_expect("test operation");

        let snap = store
            .get_lineage("cap-001")
            .test_expect("test operation")
            .test_expect("test operation");
        assert_eq!(snap.capability_id, "cap-001");
        assert_eq!(snap.subject_key, subject_kp.public_key().to_hex());
        assert_eq!(snap.issuer_key, issuer_kp.public_key().to_hex());
        assert_eq!(snap.issued_at, 1000);
        assert_eq!(snap.expires_at, 2000);
        assert_eq!(snap.delegation_depth, 0);
        assert!(snap.parent_capability_id.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn delegated_bounded_snapshot_reads_parent_depth_inside_the_writer_job() {
        // The parent-depth lookup for a delegated capability must run on the
        // writer connection inside the bounded job, not on a reader-pool
        // connection ahead of it. With every reader-pool connection checked
        // out, a delegated bounded snapshot must still resolve the parent depth
        // and persist quickly, proving the read no longer sits unbounded on the
        // pre-dispatch hot path where an exhausted pool would stall it.
        let path = unique_db_path("cl-bounded-parent-read");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let kp_root = Keypair::generate();
        let kp_child = Keypair::generate();
        let root = make_token("cap-root-bounded", &kp_root, &kp_root, 1000, 9000);
        let child = make_token("cap-child-bounded", &kp_child, &kp_root, 1100, 8000);

        store
            .record_capability_snapshot(&root, None)
            .test_expect("test operation");

        // Exhaust the reader pool: hold every reader connection so any
        // reader-pool checkout on the hot path would block.
        let mut held = Vec::new();
        for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
            held.push(store.connection().test_expect("test operation"));
        }

        let start = std::time::Instant::now();
        store
            .record_capability_snapshot_with_timeout(
                &child,
                Some("cap-root-bounded"),
                std::time::Duration::from_millis(500),
            )
            .test_expect("test operation");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "delegated bounded snapshot must not wait on the exhausted reader pool"
        );

        // Release the reader pool so the read-back can observe the persisted row.
        drop(held);

        let snap = store
            .get_lineage("cap-child-bounded")
            .test_expect("test operation")
            .test_expect("test operation");
        assert_eq!(
            snap.delegation_depth, 1,
            "child depth must be resolved from the parent inside the bounded job"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn record_capability_snapshot_is_idempotent() {
        let path = unique_db_path("cl-idempotent");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-idem-001", &subject_kp, &issuer_kp, 1000, 2000);

        // Insert twice -- must not panic or error.
        store
            .record_capability_snapshot(&token, None)
            .test_expect("test operation");
        store
            .record_capability_snapshot(&token, None)
            .test_expect("test operation");

        // Only one row should exist.
        let connection = store.connection().test_expect("test operation");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM capability_lineage WHERE capability_id = ?1",
                params!["cap-idem-001"],
                |row| row.get(0),
            )
            .test_expect("test operation");
        assert_eq!(count, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn grants_json_round_trips_without_field_loss() {
        let path = unique_db_path("cl-json-rt");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-json-001", &subject_kp, &issuer_kp, 1000, 2000);

        store
            .record_capability_snapshot(&token, None)
            .test_expect("test operation");

        let snap = store
            .get_lineage("cap-json-001")
            .test_expect("test operation")
            .test_expect("test operation");
        let round_tripped: ChioScope =
            serde_json::from_str(&snap.grants_json).test_expect("test operation");

        assert_eq!(round_tripped.grants.len(), token.scope.grants.len());
        assert_eq!(round_tripped.grants[0].server_id, "shell");
        assert_eq!(round_tripped.grants[0].tool_name, "bash");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_lineage_returns_none_for_missing_capability() {
        let path = unique_db_path("cl-missing");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let result = store
            .get_lineage("nonexistent-cap")
            .test_expect("test operation");
        assert!(result.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_lineage_rejects_negative_persisted_unsigned_fields() {
        let path = unique_db_path("cl-corrupt-read");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let connection = store.connection().test_expect("test operation");
        connection
            .execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
                params![
                    "cap-corrupt-read",
                    "subject",
                    "issuer",
                    -1_i64,
                    2_000_i64,
                    "{}",
                    0_i64
                ],
            )
            .test_expect("test operation");
        drop(connection);

        let error = store
            .get_lineage("cap-corrupt-read")
            .test_expect_err("expected test failure");
        assert!(error.to_string().contains("issued_at"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn record_child_snapshot_rejects_negative_parent_depth() {
        let path = unique_db_path("cl-corrupt-parent");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let connection = store.connection().test_expect("test operation");
        connection
            .execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
                params![
                    "cap-corrupt-parent",
                    "subject",
                    "issuer",
                    1_000_i64,
                    2_000_i64,
                    "{}",
                    -1_i64
                ],
            )
            .test_expect("test operation");
        drop(connection);

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let child = make_token(
            "cap-child-from-corrupt",
            &subject_kp,
            &issuer_kp,
            1_100,
            1_900,
        );
        let error = store
            .record_capability_snapshot(&child, Some("cap-corrupt-parent"))
            .test_expect_err("expected test failure");
        assert!(error.to_string().contains("delegation_depth"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn lineage_replication_rejects_negative_snapshot_fields() {
        let path = unique_db_path("cl-corrupt-repl");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let connection = store.connection().test_expect("test operation");
        connection
            .execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
                params![
                    "cap-corrupt-repl",
                    "subject",
                    "issuer",
                    1_000_i64,
                    -2_000_i64,
                    "{}",
                    0_i64
                ],
            )
            .test_expect("test operation");
        drop(connection);

        let error = store
            .list_capability_snapshots_after_seq(0, 10)
            .test_expect_err("expected test failure");
        assert!(error.to_string().contains("expires_at"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_returns_root_first_for_three_level_chain() {
        let path = unique_db_path("cl-chain-3");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let kp_root = Keypair::generate();
        let kp_mid = Keypair::generate();
        let kp_leaf = Keypair::generate();

        // root -> parent -> child
        let root = make_token("cap-root", &kp_root, &kp_root, 1000, 9000);
        let parent = make_token("cap-parent", &kp_mid, &kp_root, 1100, 8000);
        let child = make_token("cap-child", &kp_leaf, &kp_mid, 1200, 7000);

        store
            .record_capability_snapshot(&root, None)
            .test_expect("test operation");
        store
            .record_capability_snapshot(&parent, Some("cap-root"))
            .test_expect("test operation");
        store
            .record_capability_snapshot(&child, Some("cap-parent"))
            .test_expect("test operation");

        // Walking the chain from child should return root, parent, child (root-first).
        let chain = store
            .get_delegation_chain("cap-child")
            .test_expect("test operation");
        assert_eq!(chain.len(), 3, "should have 3 entries in chain");
        assert_eq!(chain[0].capability_id, "cap-root", "root should be first");
        assert_eq!(
            chain[1].capability_id, "cap-parent",
            "parent should be second"
        );
        assert_eq!(chain[2].capability_id, "cap-child", "child should be last");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_returns_single_entry_for_root_capability() {
        let path = unique_db_path("cl-chain-root");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        let kp = Keypair::generate();
        let root = make_token("cap-solo", &kp, &kp, 1000, 9000);

        store
            .record_capability_snapshot(&root, None)
            .test_expect("test operation");

        let chain = store
            .get_delegation_chain("cap-solo")
            .test_expect("test operation");
        assert_eq!(chain.len(), 1, "root has no parent -- only itself in chain");
        assert_eq!(chain[0].capability_id, "cap-solo");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_enforces_max_depth_guard() {
        let path = unique_db_path("cl-depth-guard");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        // Build a chain of 25 entries (exceeds the level < 20 guard).
        let kp = Keypair::generate();
        let mut prev_id: Option<String> = None;
        for i in 0..25usize {
            let id = format!("cap-depth-{i:03}");
            let token = make_token(&id, &kp, &kp, 1000 + i as u64, 9000);
            store
                .record_capability_snapshot(&token, prev_id.as_deref())
                .test_expect("test operation");
            prev_id = Some(id);
        }

        // Walking the chain from the deepest node should be capped at 21 entries (depth guard).
        let chain = store
            .get_delegation_chain("cap-depth-024")
            .test_expect("test operation");
        // With level < 20, the recursion visits at most 21 distinct rows.
        assert!(
            chain.len() <= 21,
            "chain length {} exceeds max depth guard of 21",
            chain.len()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn capability_lineage_table_created_by_open() {
        let path = unique_db_path("cl-table-exists");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        // Query the table to verify it exists; COUNT(*) fails if the table is absent.
        let connection = store.connection().test_expect("test operation");
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM capability_lineage", [], |row| {
                row.get(0)
            })
            .test_expect("test operation");
        assert_eq!(count, 0, "table should exist and be empty");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn subject_key_index_exists() {
        let path = unique_db_path("cl-index-check");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");

        // PRAGMA index_list returns rows for each index on the table.
        let connection = store.connection().test_expect("test operation");
        let mut stmt = connection
            .prepare("PRAGMA index_list(capability_lineage)")
            .test_expect("test operation");
        let index_names: Vec<String> = stmt
            .query_map([], |row: &rusqlite::Row<'_>| row.get::<_, String>(1))
            .test_expect("test operation")
            .filter_map(|r: Result<String, _>| r.ok())
            .collect();

        assert!(
            index_names
                .iter()
                .any(|n| n == "idx_capability_lineage_subject"),
            "subject_key index not found; found: {index_names:?}"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn causal_lineage_schema_is_bootstrapped_and_repaired_on_existing_open() {
        let path = unique_db_path("causal-schema-repair");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let connection = store.connection().test_expect("test operation");
        let table_count: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*) FROM sqlite_master
                WHERE type = 'table' AND name IN (
                    'causal_lineage_heads',
                    'causal_lineage_nodes',
                    'causal_lineage_edges',
                    'causal_lineage_fences',
                    'causal_lineage_fence_targets'
                )
                "#,
                [],
                |row| row.get(0),
            )
            .test_expect("test operation");
        assert_eq!(table_count, 5);
        drop(connection);
        drop(store);

        let connection = rusqlite::Connection::open(&path).test_expect("test operation");
        connection
            .execute("DROP TABLE causal_lineage_heads", [])
            .test_expect("test operation");
        drop(connection);
        let repaired = SqliteReceiptStore::open_existing(&path).test_expect("test operation");
        let connection = repaired.connection().test_expect("test operation");
        let repaired_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM causal_lineage_heads", [], |row| {
                row.get(0)
            })
            .test_expect("test operation");
        assert_eq!(repaired_count, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn committed_capability_and_receipt_descendants_resolve_exactly() {
        let path = unique_db_path("causal-exact");
        let store = Arc::new(SqliteReceiptStore::open(&path).test_expect("test operation"));
        let tenant_id = tenant("tenant-a");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");
        let resolver = CausalBlastRadiusResolver::new(Arc::clone(&store), Arc::clone(&store));
        let blast_request = BlastRadiusRequest {
            tenant_id: tenant_id.clone(),
            action_id: action("action-a"),
            seed_ids: BlastRadiusSeeds::new(vec![record("cap-root")])
                .unwrap_or_else(|error| panic!("bounded blast seeds: {error}")),
            query_bounds: BlastRadiusQueryBounds {
                max_depth: 8,
                max_nodes: 32,
                max_edges: 32,
            },
        };
        let port: &dyn BlastRadiusPort = &resolver;
        port.ensure_blast_radius_ready()
            .unwrap_or_else(|error| panic!("causal blast-radius readiness: {error:?}"));
        let result = port.resolve(&blast_request).test_expect("test operation");
        let approved_result = result.clone();

        let BlastRadiusResult::Exact {
            metadata,
            sorted_affected_ids,
            affected_set_hash,
            graph_slice_hash,
        } = result
        else {
            panic!("authoritative committed causal graph was not exact");
        };
        assert_eq!(metadata.commit_index, 1);
        assert_eq!(metadata.authoritative_commit_index, 1);
        assert_eq!(metadata.completeness_watermark, Some(1));
        assert_eq!(
            sorted_affected_ids.as_slice(),
            &[record("cap-child"), record("cap-root")]
        );
        assert_ne!(affected_set_hash.as_bytes(), &[0; 32]);
        assert_ne!(graph_slice_hash.as_bytes(), &[0; 32]);
        let expires_at_unix_ms = super::unix_time_ms()
            .test_expect("test operation")
            .saturating_add(30_000);
        let expected_fence = LineageFenceRequest {
            tenant_id: tenant_id.clone(),
            action_id: blast_request.action_id.clone(),
            expected_commit_index: metadata.commit_index,
            expected_affected_set_hash: affected_set_hash,
            scheduler_lease_owner_id: lease_owner(),
            scheduler_fencing_token: 1,
            expires_at_unix_ms,
        };
        let fence = port
            .acquire_fence(
                &BlastRadiusFenceAcquisition {
                    request: blast_request,
                    approved_result,
                    expires_at_unix_ms,
                },
                &expected_fence,
            )
            .test_expect("test operation");
        assert_eq!(fence.commit_index, 1);
        assert!(fence.fencing_token > 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn bounded_snapshot_reports_depth_node_and_edge_truncation() {
        let path = unique_db_path("causal-bounds");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let tenant_id = tenant("tenant-a");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");

        let depth = store
            .load_causal_snapshot(&CausalLineageSnapshotRequest {
                tenant_id: tenant_id.clone(),
                seed_ids: BlastRadiusSeeds::new(vec![record("cap-root")])
                    .test_expect("test operation"),
                query_bounds: BlastRadiusQueryBounds {
                    max_depth: 1,
                    max_nodes: 32,
                    max_edges: 32,
                },
                fence_action_id: None,
            })
            .test_expect("test operation");
        assert!(depth.depth_truncated);

        let node_limited = store
            .load_causal_snapshot(&CausalLineageSnapshotRequest {
                tenant_id: tenant_id.clone(),
                seed_ids: BlastRadiusSeeds::new(vec![record("cap-root")])
                    .test_expect("test operation"),
                query_bounds: BlastRadiusQueryBounds {
                    max_depth: 8,
                    max_nodes: 1,
                    max_edges: 32,
                },
                fence_action_id: None,
            })
            .test_expect("test operation");
        assert!(node_limited.nodes_truncated);

        let edge_limited = store
            .load_causal_snapshot(&CausalLineageSnapshotRequest {
                tenant_id,
                seed_ids: BlastRadiusSeeds::new(vec![record("cap-root")])
                    .test_expect("test operation"),
                query_bounds: BlastRadiusQueryBounds {
                    max_depth: 8,
                    max_nodes: 32,
                    max_edges: 1,
                },
                fence_action_id: None,
            })
            .test_expect("test operation");
        assert!(edge_limited.edges_truncated);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn active_causal_fence_is_idempotent_and_blocks_delegation_in_commit_transaction() {
        let path = unique_db_path("causal-fence");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let tenant_id = tenant("tenant-a");
        let action_id = action("action-a");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");
        let frozen_affected_ids = RecordIdSet::new(vec![record("cap-child"), record("cap-root")])
            .unwrap_or_else(|error| panic!("sorted frozen ids: {error}"));
        let affected_set_hash =
            super::causal_affected_set_hash(&tenant_id, frozen_affected_ids.as_slice())
                .test_expect("test operation");
        let expiry = super::unix_time_ms()
            .test_expect("test operation")
            .saturating_add(30_000);
        let acquire = CausalLineageFenceRequest {
            fence: LineageFenceRequest {
                tenant_id: tenant_id.clone(),
                action_id: action_id.clone(),
                expected_commit_index: 1,
                expected_affected_set_hash: affected_set_hash,
                scheduler_lease_owner_id: lease_owner(),
                scheduler_fencing_token: 11,
                expires_at_unix_ms: expiry,
            },
            frozen_affected_ids,
        };
        let first = store
            .acquire_causal_fence(&acquire)
            .test_expect("test operation");
        let repeated = store
            .acquire_causal_fence(&acquire)
            .test_expect("test operation");
        assert_eq!(first, repeated);
        assert!(first.fencing_token > 0);
        let queried = store
            .query(&TenantScopedId {
                tenant_id: tenant_id.clone(),
                id: record(action_id.as_str()),
            })
            .test_expect("test operation");
        assert_eq!(queried, Some(first.clone()));

        let delegated = causal_commit(
            &tenant_id,
            2,
            vec![causal_node(
                &tenant_id,
                "cap-grandchild",
                CausalLineageNodeKind::Capability,
            )],
            vec![causal_edge(
                &tenant_id,
                "cap-child",
                "cap-grandchild",
                CausalLineageEdgeKind::CapabilityDelegation,
            )],
        );
        let blocked = store
            .commit_causal_lineage(&delegated)
            .test_expect_err("expected test failure");
        assert_eq!(
            blocked.kind(),
            chio_security_types::ports::PortErrorKind::Conflict
        );
        let connection = store.connection().test_expect("test operation");
        let inserted: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM causal_lineage_nodes WHERE tenant_id = ?1 AND node_id = ?2",
                params![tenant_id.as_str(), "cap-grandchild"],
                |row| row.get(0),
            )
            .test_expect("test operation");
        assert_eq!(inserted, 0, "fenced write must roll back atomically");
        drop(connection);

        store
            .release(&LineageFenceRelease {
                tenant_id: tenant_id.clone(),
                action_id,
                fencing_token: first.fencing_token,
                scheduler_lease_owner_id: first.scheduler_lease_owner_id,
                scheduler_fencing_token: first.scheduler_fencing_token,
            })
            .test_expect("test operation");
        store
            .commit_causal_lineage(&delegated)
            .test_expect("test operation");
        assert!(store
            .query(&TenantScopedId {
                tenant_id,
                id: record("action-a"),
            })
            .test_expect("test operation")
            .is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn causal_fence_takeover_advances_both_fencing_domains_and_rejects_stale_worker() {
        let path = unique_db_path("causal-fence-takeover");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let tenant_id = tenant("tenant-takeover");
        let action_id = action("action-takeover");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");
        let frozen_affected_ids = RecordIdSet::new(vec![record("cap-child"), record("cap-root")])
            .test_expect("test operation");
        let affected_set_hash =
            super::causal_affected_set_hash(&tenant_id, frozen_affected_ids.as_slice())
                .test_expect("test operation");
        let initial_expiry = super::unix_time_ms()
            .test_expect("test operation")
            .saturating_add(15_000);
        let initial = store
            .acquire_causal_fence(&CausalLineageFenceRequest {
                fence: LineageFenceRequest {
                    tenant_id: tenant_id.clone(),
                    action_id: action_id.clone(),
                    expected_commit_index: 1,
                    expected_affected_set_hash: affected_set_hash,
                    scheduler_lease_owner_id: lease_owner(),
                    scheduler_fencing_token: 11,
                    expires_at_unix_ms: initial_expiry,
                },
                frozen_affected_ids,
            })
            .test_expect("test operation");
        let takeover_owner =
            LeaseOwnerId::new("causal-takeover-worker").test_expect("test operation");
        let takeover_expiry = initial_expiry.saturating_add(15_000);
        let taken_over = store
            .takeover(&LineageFenceTakeover {
                tenant_id: tenant_id.clone(),
                action_id: action_id.clone(),
                expected_fencing_token: initial.fencing_token,
                expected_scheduler_lease_owner_id: initial.scheduler_lease_owner_id.clone(),
                expected_scheduler_fencing_token: initial.scheduler_fencing_token,
                expected_expires_at_unix_ms: initial.expires_at_unix_ms,
                successor_scheduler_lease_owner_id: takeover_owner.clone(),
                successor_scheduler_fencing_token: 12,
                successor_expires_at_unix_ms: takeover_expiry,
            })
            .test_expect("test operation");
        assert!(taken_over.fencing_token > initial.fencing_token);
        assert_eq!(taken_over.scheduler_lease_owner_id, takeover_owner);
        assert_eq!(taken_over.scheduler_fencing_token, 12);
        assert_eq!(taken_over.expires_at_unix_ms, takeover_expiry);

        let stale = store
            .renew(&LineageFenceRenewal {
                tenant_id: tenant_id.clone(),
                action_id: action_id.clone(),
                fencing_token: initial.fencing_token,
                scheduler_lease_owner_id: initial.scheduler_lease_owner_id,
                scheduler_fencing_token: initial.scheduler_fencing_token,
                expected_expires_at_unix_ms: initial.expires_at_unix_ms,
                renewed_expires_at_unix_ms: initial.expires_at_unix_ms.saturating_add(1_000),
            })
            .test_expect_err("expected test failure");
        assert_eq!(
            stale.kind(),
            chio_security_types::ports::PortErrorKind::Conflict
        );
        store
            .release(&LineageFenceRelease {
                tenant_id,
                action_id,
                fencing_token: taken_over.fencing_token,
                scheduler_lease_owner_id: taken_over.scheduler_lease_owner_id,
                scheduler_fencing_token: taken_over.scheduler_fencing_token,
            })
            .test_expect("test operation");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn application_fence_blocks_actual_contextual_delegation_snapshot_transaction() {
        let path = unique_db_path("causal-contextual-admission");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let tenant_id = tenant("tenant-a");
        let lineage_id = LineageId::new("cap-root").test_expect("test operation");
        let action_id = action("action-contextual");
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let root = make_token("cap-root", &subject, &issuer, 1_000, 2_000);
        let child = make_token("cap-child", &subject, &issuer, 1_100, 1_900);
        let grandchild = make_token("cap-grandchild", &subject, &issuer, 1_200, 1_800);

        store
            .record_capability_snapshot_with_issuance_admission(
                &tenant_id,
                &lineage_id,
                &root,
                None,
            )
            .test_expect("test operation");
        store
            .record_capability_snapshot_with_issuance_admission(
                &tenant_id,
                &lineage_id,
                &child,
                Some("cap-root"),
            )
            .test_expect("test operation");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");
        let frozen_affected_ids = RecordIdSet::new(vec![record("cap-child"), record("cap-root")])
            .test_expect("test operation");
        let affected_set_hash =
            super::causal_affected_set_hash(&tenant_id, frozen_affected_ids.as_slice())
                .test_expect("test operation");
        let fence = store
            .acquire_causal_fence(&CausalLineageFenceRequest {
                fence: LineageFenceRequest {
                    tenant_id: tenant_id.clone(),
                    action_id: action_id.clone(),
                    expected_commit_index: 1,
                    expected_affected_set_hash: affected_set_hash,
                    scheduler_lease_owner_id: lease_owner(),
                    scheduler_fencing_token: 11,
                    expires_at_unix_ms: super::unix_time_ms()
                        .test_expect("test operation")
                        .saturating_add(30_000),
                },
                frozen_affected_ids,
            })
            .test_expect("test operation");

        store
            .record_capability_snapshot_with_issuance_admission(
                &tenant_id,
                &lineage_id,
                &child,
                Some("cap-root"),
            )
            .test_expect("test operation");
        assert!(store
            .capability_snapshot_has_issuance_admission(
                &tenant_id,
                &lineage_id,
                &child,
                Some("cap-root"),
            )
            .test_expect("test operation"));

        let blocked = store
            .record_capability_snapshot_with_issuance_admission(
                &tenant_id,
                &lineage_id,
                &grandchild,
                Some("cap-child"),
            )
            .test_expect_err("expected test failure");
        assert!(blocked.to_string().contains("active causal lineage fence"));
        assert!(store
            .get_lineage("cap-grandchild")
            .test_expect("test operation")
            .is_none());

        store
            .release(&LineageFenceRelease {
                tenant_id: tenant_id.clone(),
                action_id,
                fencing_token: fence.fencing_token,
                scheduler_lease_owner_id: fence.scheduler_lease_owner_id,
                scheduler_fencing_token: fence.scheduler_fencing_token,
            })
            .test_expect("test operation");
        store
            .record_capability_snapshot_with_issuance_admission(
                &tenant_id,
                &lineage_id,
                &grandchild,
                Some("cap-child"),
            )
            .test_expect("test operation");
        assert!(store
            .get_lineage("cap-grandchild")
            .test_expect("test operation")
            .is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn corrupt_persisted_fence_binding_fails_closed() {
        let path = unique_db_path("causal-corrupt-fence");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let tenant_id = tenant("tenant-a");
        let action_id = action("action-a");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");
        let targets = RecordIdSet::new(vec![record("cap-child"), record("cap-root")])
            .test_expect("test operation");
        let affected_set_hash = super::causal_affected_set_hash(&tenant_id, targets.as_slice())
            .test_expect("test operation");
        store
            .acquire_causal_fence(&CausalLineageFenceRequest {
                fence: LineageFenceRequest {
                    tenant_id: tenant_id.clone(),
                    action_id: action_id.clone(),
                    expected_commit_index: 1,
                    expected_affected_set_hash: affected_set_hash,
                    scheduler_lease_owner_id: lease_owner(),
                    scheduler_fencing_token: 11,
                    expires_at_unix_ms: super::unix_time_ms()
                        .test_expect("test operation")
                        .saturating_add(30_000),
                },
                frozen_affected_ids: targets,
            })
            .test_expect("test operation");
        let connection = store.connection().test_expect("test operation");
        connection
            .execute(
                r#"
                UPDATE causal_lineage_fences SET fencing_token = 0
                WHERE tenant_id = ?1 AND action_id = ?2
                "#,
                params![tenant_id.as_str(), action_id.as_str()],
            )
            .test_expect("test operation");
        drop(connection);

        let error = store
            .query(&TenantScopedId {
                tenant_id,
                id: record(action_id.as_str()),
            })
            .test_expect_err("expected test failure");
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_orphan_fence_is_not_live_and_no_longer_blocks_delegation() {
        let path = unique_db_path("causal-expired-fence");
        let store = SqliteReceiptStore::open(&path).test_expect("test operation");
        let tenant_id = tenant("tenant-a");
        let action_id = action("action-a");
        store
            .commit_causal_lineage(&committed_causal_graph(&tenant_id))
            .test_expect("test operation");
        let targets = RecordIdSet::new(vec![record("cap-child"), record("cap-root")])
            .test_expect("test operation");
        let affected_set_hash = super::causal_affected_set_hash(&tenant_id, targets.as_slice())
            .test_expect("test operation");
        store
            .acquire_causal_fence(&CausalLineageFenceRequest {
                fence: LineageFenceRequest {
                    tenant_id: tenant_id.clone(),
                    action_id: action_id.clone(),
                    expected_commit_index: 1,
                    expected_affected_set_hash: affected_set_hash,
                    scheduler_lease_owner_id: lease_owner(),
                    scheduler_fencing_token: 11,
                    expires_at_unix_ms: super::unix_time_ms()
                        .test_expect("test operation")
                        .saturating_add(30_000),
                },
                frozen_affected_ids: targets,
            })
            .test_expect("test operation");
        let stale_expires_at_unix_ms = i64::try_from(
            super::unix_time_ms()
                .test_expect("test operation")
                .saturating_sub(1),
        )
        .test_expect("test operation");
        let connection = store.connection().test_expect("test operation");
        connection
            .execute(
                r#"
                UPDATE causal_lineage_fences SET expires_at_unix_ms = ?3
                WHERE tenant_id = ?1 AND action_id = ?2
                "#,
                params![
                    tenant_id.as_str(),
                    action_id.as_str(),
                    stale_expires_at_unix_ms
                ],
            )
            .test_expect("test operation");
        drop(connection);
        assert!(store
            .query(&TenantScopedId {
                tenant_id: tenant_id.clone(),
                id: record(action_id.as_str()),
            })
            .test_expect("test operation")
            .is_none());

        let delegated = causal_commit(
            &tenant_id,
            2,
            vec![causal_node(
                &tenant_id,
                "cap-after-expiry",
                CausalLineageNodeKind::Capability,
            )],
            vec![causal_edge(
                &tenant_id,
                "cap-child",
                "cap-after-expiry",
                CausalLineageEdgeKind::CapabilityDelegation,
            )],
        );
        store
            .commit_causal_lineage(&delegated)
            .test_expect("test operation");

        let _ = fs::remove_file(path);
    }
}
