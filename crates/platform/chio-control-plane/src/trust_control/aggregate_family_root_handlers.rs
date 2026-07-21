use super::report_validation::{load_existing_authority_signing_context, validate_service_auth};
use super::*;

#[derive(Clone)]
struct LookupReadContext {
    source_node_id: String,
}

pub(crate) async fn handle_lookup_aggregate_family_root(
    State(state): State<TrustServiceState>,
    AxumPath(root_capability_id): AxumPath<String>,
    Query(query): Query<AggregateFamilyRootLookupQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if root_capability_id.is_empty()
        || root_capability_id.len() > AGGREGATE_FAMILY_ROOT_ID_MAX_BYTES
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "aggregate family-root identifier is outside the supported bound",
        );
    }
    if let Err(error) = validate_lookup_nonce(&query.nonce) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }

    let read_context = match lookup_read_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let signing_context = match load_existing_authority_signing_context(&state.config) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let receipt_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "aggregate family-root storage is not configured",
            );
        }
    };

    let lookup = SqliteReceiptStore::lookup_existing_aggregate_family_root(
        receipt_path,
        &root_capability_id,
    );
    let (high_watermark, outcome) = match lookup {
        Ok(snapshot) => match snapshot.record {
            Some(record) => (
                Some(snapshot.high_watermark),
                AggregateFamilyRootLookupOutcome::Found {
                    source_seq: record.seq,
                    canonical_token_json: record.canonical_token_json,
                    token_digest: record.token_digest,
                },
            ),
            None => {
                return plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "aggregate family-root absence is not authoritative without durable completeness proof",
                );
            }
        },
        Err(chio_store_sqlite::AggregateFamilyRootStoreError::Unavailable(_)) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "aggregate family-root storage is unavailable",
            );
        }
        Err(_) => (
            None,
            AggregateFamilyRootLookupOutcome::Corrupt {
                code: AggregateFamilyRootCorruptionCode::StoreIntegrity,
            },
        ),
    };

    let read_context = match validate_lookup_read_context(&state, &read_context) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let signing_context_after = match load_existing_authority_signing_context(&state.config) {
        Ok(context) => context,
        Err(response) => return response,
    };
    if signing_context.keypair.public_key() != signing_context_after.keypair.public_key()
        || signing_context.generation != signing_context_after.generation
        || signing_context.rotated_at != signing_context_after.rotated_at
    {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "aggregate family-root authority changed during lookup",
        );
    }

    let issued_at = unix_timestamp_now();
    let expires_at = match lookup_response_expiry(issued_at, &read_context) {
        Ok(expires_at) => expires_at,
        Err(response) => return response,
    };
    let (source_node_id, consistency) = lookup_wire_context(read_context);
    let body = AggregateFamilyRootLookupBody {
        schema: AGGREGATE_FAMILY_ROOT_LOOKUP_SCHEMA.to_string(),
        endpoint: AGGREGATE_FAMILY_ROOT_LOOKUP_PATH.to_string(),
        source_node_id,
        request_nonce: query.nonce,
        requested_root_capability_id: root_capability_id,
        issued_at,
        expires_at,
        authority_generation: signing_context.generation,
        authority_rotated_at: signing_context.rotated_at,
        consistency,
        high_watermark,
        outcome,
    };
    let signed = match SignedAggregateFamilyRootLookup::sign(body, &signing_context.keypair) {
        Ok(signed) => signed,
        Err(error) => return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error),
    };
    canonical_lookup_response(&signed)
}

fn lookup_read_context(state: &TrustServiceState) -> Result<LookupReadContext, Response> {
    if state.cluster.is_some() {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "clustered aggregate family-root authority lookup is unsupported",
        ));
    }
    Ok(LookupReadContext {
        source_node_id: state
            .config
            .advertise_url
            .clone()
            .unwrap_or_else(|| format!("http://{}", state.config.listen)),
    })
}

fn validate_lookup_read_context(
    state: &TrustServiceState,
    expected: &LookupReadContext,
) -> Result<LookupReadContext, Response> {
    let current = lookup_read_context(state)?;
    if expected.source_node_id == current.source_node_id {
        Ok(current)
    } else {
        Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "aggregate family-root source context changed during lookup",
        ))
    }
}

fn lookup_response_expiry(now: u64, _context: &LookupReadContext) -> Result<u64, Response> {
    now.checked_add(AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_TTL_SECS)
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "aggregate family-root lookup time overflow",
            )
        })
}

fn lookup_wire_context(context: LookupReadContext) -> (String, AggregateFamilyRootReadConsistency) {
    (
        context.source_node_id,
        AggregateFamilyRootReadConsistency::Standalone,
    )
}

fn canonical_lookup_response(signed: &SignedAggregateFamilyRootLookup) -> Response {
    let body = match canonical_json_bytes(signed) {
        Ok(body) => body,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let body_len = match u64::try_from(body.len()) {
        Ok(body_len) => body_len,
        Err(_) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "aggregate family-root lookup response length overflow",
            );
        }
    };
    if body_len > AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_BYTES {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "aggregate family-root lookup response exceeds its byte bound",
        );
    }
    ([(CONTENT_TYPE, "application/json")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_test_support::prelude::*;

    fn unique_test_directory() -> PathBuf {
        chio_test_support::private_fs::private_tempdir("chio-aggregate-root-lookup-")
            .test_unwrap()
            .keep()
    }

    fn test_state(receipt_db_path: PathBuf, authority_db_path: PathBuf) -> TrustServiceState {
        TrustServiceState {
            config: TrustServiceConfig {
                listen: "127.0.0.1:0".parse().test_unwrap(),
                service_token: "service-secret".to_string(),
                dashboard_read_token: None,
                dashboard_report_origin: None,
                dashboard_report_token: None,
                dashboard_allow_insecure_report_origin: false,
                authority_admin_token: None,
                authority_workloads: Vec::new(),
                tenant_read_tokens: BTreeMap::new(),
                receipt_db_path: Some(receipt_db_path),
                revocation_db_path: None,
                authority_seed_path: None,
                authority_db_path: Some(authority_db_path),
                authority_keyring_config_path: None,
                budget_db_path: None,
                enterprise_providers_file: None,
                federation_policies_file: None,
                scim_lifecycle_file: None,
                verifier_policies_file: None,
                verifier_challenge_db_path: None,
                passport_statuses_file: None,
                passport_issuance_offers_file: None,
                certification_registry_file: None,
                certification_discovery_file: None,
                issuance_policy: None,
                runtime_assurance_policy: None,
                advertise_url: Some("http://node-a".to_string()),
                allow_local_peer_urls: true,
                certification_public_metadata_ttl_seconds: PUBLIC_DISCOVERY_TTL_SECS,
                peer_urls: Vec::new(),
                cluster_node_seed_path: None,
                cluster_replay_db_path: None,
                cluster_members: Vec::new(),
                cluster_sync_interval: Duration::from_millis(25),
                roster_policy: None,
                memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            },
            dashboard_sessions: dashboard_auth::DashboardSessionStore::production(),
            dashboard_report_bridge: None,
            authority_keyring: None,
            authority_test_backend: None,
            active_defense: service_runtime::TrustControlActiveDefenseService::disabled(),
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            authority_issuance_rotation_lock: Arc::new(Mutex::new(())),
            cluster: None,
            cluster_progress: None,
        }
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer service-secret"),
        );
        headers
    }

    fn delegable_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "root-server".to_string(),
                tool_name: "root-tool".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        }
    }

    async fn decode_signed(response: Response) -> SignedAggregateFamilyRootLookup {
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(
            response.into_body(),
            AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_BYTES as usize,
        )
        .await
        .test_unwrap();
        let signed: SignedAggregateFamilyRootLookup = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(body.as_ref(), canonical_json_bytes(&signed).test_unwrap());
        signed
    }

    #[tokio::test]
    async fn aggregate_family_root_lookup_returns_signed_found_and_refuses_absence() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        let authority_path = directory.join("authority.db");
        let state = test_state(receipt_path.clone(), authority_path.clone());
        let authority = SqliteCapabilityAuthority::open(&authority_path).test_unwrap();
        let subject = Keypair::generate();
        let token = authority
            .issue_capability(&subject.public_key(), delegable_scope(), 300)
            .test_unwrap();
        SqliteReceiptStore::open(&receipt_path)
            .test_unwrap()
            .record_aggregate_family_root(
                &token,
                &authority.trusted_public_keys(),
                unix_timestamp_now(),
            )
            .test_unwrap();
        let nonce = "ab".repeat(32);

        let found = decode_signed(
            handle_lookup_aggregate_family_root(
                State(state.clone()),
                AxumPath(token.id.clone()),
                Query(AggregateFamilyRootLookupQuery {
                    nonce: nonce.clone(),
                }),
                auth_headers(),
            )
            .await,
        )
        .await;
        found
            .verify_signature(&authority.status().test_unwrap().public_key)
            .test_unwrap();
        assert_eq!(found.body.request_nonce, nonce);
        assert_eq!(found.body.requested_root_capability_id, token.id);
        assert!(matches!(
            found.body.outcome,
            AggregateFamilyRootLookupOutcome::Found { source_seq: 1, .. }
        ));

        let absent = handle_lookup_aggregate_family_root(
            State(state),
            AxumPath("missing-root".to_string()),
            Query(AggregateFamilyRootLookupQuery {
                nonce: "cd".repeat(32),
            }),
            auth_headers(),
        )
        .await;
        assert_eq!(absent.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn aggregate_family_root_lookup_does_not_recreate_a_deleted_database() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        let authority_path = directory.join("authority.db");
        let state = test_state(receipt_path.clone(), authority_path.clone());
        SqliteCapabilityAuthority::open(authority_path).test_unwrap();
        drop(SqliteReceiptStore::open(&receipt_path).test_unwrap());
        std::fs::remove_file(&receipt_path).test_unwrap();

        let response = handle_lookup_aggregate_family_root(
            State(state),
            AxumPath("missing-root".to_string()),
            Query(AggregateFamilyRootLookupQuery {
                nonce: "de".repeat(32),
            }),
            auth_headers(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !receipt_path.exists(),
            "a point lookup must never recreate missing durable storage"
        );
    }

    #[tokio::test]
    async fn aggregate_family_root_lookup_does_not_recreate_a_deleted_seed() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        let authority_path = directory.join("authority.db");
        let seed_path = directory.join("authority.seed");
        let mut state = test_state(receipt_path.clone(), authority_path);
        state.config.authority_db_path = None;
        state.config.authority_seed_path = Some(seed_path.clone());
        drop(SqliteReceiptStore::open(receipt_path).test_unwrap());
        drop(load_or_create_authority_keypair(&seed_path).test_unwrap());
        std::fs::remove_file(&seed_path).test_unwrap();

        let response = handle_lookup_aggregate_family_root(
            State(state),
            AxumPath("missing-root".to_string()),
            Query(AggregateFamilyRootLookupQuery {
                nonce: "ed".repeat(32),
            }),
            auth_headers(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !seed_path.exists(),
            "a point lookup must never recreate missing signing custody"
        );
    }

    #[tokio::test]
    async fn aggregate_family_root_lookup_signs_corrupt_for_tampered_schema() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        let authority_path = directory.join("authority.db");
        let state = test_state(receipt_path.clone(), authority_path.clone());
        let authority = SqliteCapabilityAuthority::open(authority_path).test_unwrap();
        drop(SqliteReceiptStore::open(&receipt_path).test_unwrap());
        let connection = rusqlite::Connection::open(&receipt_path).test_unwrap();
        connection
            .execute_batch("DROP TRIGGER chio_aggregate_family_roots_immutable_update;")
            .test_unwrap();
        drop(connection);

        let signed = decode_signed(
            handle_lookup_aggregate_family_root(
                State(state),
                AxumPath("root-in-corrupt-store".to_string()),
                Query(AggregateFamilyRootLookupQuery {
                    nonce: "fa".repeat(32),
                }),
                auth_headers(),
            )
            .await,
        )
        .await;

        signed
            .verify_signature(&authority.status().test_unwrap().public_key)
            .test_unwrap();
        assert!(matches!(
            signed.body.outcome,
            AggregateFamilyRootLookupOutcome::Corrupt {
                code: AggregateFamilyRootCorruptionCode::StoreIntegrity
            }
        ));
        assert!(signed.body.high_watermark.is_none());
    }

    #[tokio::test]
    async fn aggregate_family_root_lookup_does_not_repair_removed_authority_schema() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        let authority_path = directory.join("authority.db");
        let state = test_state(receipt_path.clone(), authority_path.clone());
        let authority = SqliteCapabilityAuthority::open(authority_path).test_unwrap();
        drop(SqliteReceiptStore::open(&receipt_path).test_unwrap());
        let connection = rusqlite::Connection::open(&receipt_path).test_unwrap();
        connection
            .execute_batch(
                "DROP TABLE chio_aggregate_family_roots;
                 DROP TABLE chio_aggregate_family_root_schema;
                 DELETE FROM chio_module_schema_version
                 WHERE module = 'aggregate_family_root_authority';",
            )
            .test_unwrap();
        drop(connection);

        let signed = decode_signed(
            handle_lookup_aggregate_family_root(
                State(state),
                AxumPath("root-in-removed-store".to_string()),
                Query(AggregateFamilyRootLookupQuery {
                    nonce: "bc".repeat(32),
                }),
                auth_headers(),
            )
            .await,
        )
        .await;

        signed
            .verify_signature(&authority.status().test_unwrap().public_key)
            .test_unwrap();
        assert!(matches!(
            signed.body.outcome,
            AggregateFamilyRootLookupOutcome::Corrupt {
                code: AggregateFamilyRootCorruptionCode::StoreIntegrity
            }
        ));
        let connection = rusqlite::Connection::open(&receipt_path).test_unwrap();
        let object_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE name IN (
                    'chio_aggregate_family_roots',
                    'chio_aggregate_family_root_schema'
                 )",
                [],
                |row| row.get(0),
            )
            .test_unwrap();
        assert_eq!(object_count, 0);
    }

    #[tokio::test]
    async fn aggregate_family_root_lookup_rejects_unauthenticated_and_cluster_missing_reads() {
        let directory = unique_test_directory();
        let receipt_path = directory.join("receipts.db");
        let authority_path = directory.join("authority.db");
        let mut state = test_state(receipt_path.clone(), authority_path.clone());
        SqliteCapabilityAuthority::open(authority_path).test_unwrap();
        SqliteReceiptStore::open(receipt_path).test_unwrap();
        let query = AggregateFamilyRootLookupQuery {
            nonce: "ef".repeat(32),
        };

        let unauthenticated = handle_lookup_aggregate_family_root(
            State(state.clone()),
            AxumPath("missing-root".to_string()),
            Query(query.clone()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let peer = PeerSyncState {
            health: PeerHealth::Healthy,
            last_contact_at: Some(unix_timestamp_now()),
            ..PeerSyncState::default()
        };
        state.cluster = Some(Arc::new(Mutex::new(ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([("http://node-b".to_string(), peer)]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: 5_000,
        })));
        let clustered = handle_lookup_aggregate_family_root(
            State(state),
            AxumPath("missing-root".to_string()),
            Query(query),
            auth_headers(),
        )
        .await;
        assert_eq!(clustered.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
