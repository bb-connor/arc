use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::sha256;
use chio_security_types::ports::{
    derive_attested_finding_action_id, derive_attested_finding_batch_id,
    derive_attested_finding_reservation_id, ActionId, AdmissionArtifactRef,
    AttestedFindingBatchBinding, AttestedFindingBatchBindings, AttestedFindingBatchBody,
    AttestedFindingBatchKey, AttestedFindingBatchPublication, AttestedFindingBatchStore,
    AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxStore,
    AttestedFindingResponseOutboxTransition, AttestedFindingResponsePlanBody,
    AttestedFindingResponsePlanPublication, CanonicalBody, CreateOutcome, Digest32,
    OpaqueReceiptRef, PortErrorKind, PreparedActiveResponseDispatchBinding, RecordId,
    ResponseDispatchApproval, TenantId, ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
    ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::ResponsePlan;
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use rusqlite::{params, Connection, ErrorCode};
use tempfile::tempdir;

#[derive(Clone, Copy)]
struct FindingInput {
    evidence_id: &'static str,
    finding_id: &'static str,
    hash_byte: u8,
}

fn id<T, E: core::fmt::Display>(
    value: &str,
    constructor: impl FnOnce(String) -> Result<T, E>,
) -> T {
    constructor(value.to_owned()).unwrap_or_else(|error| panic!("identifier {value}: {error}"))
}

fn rejected<T: core::fmt::Debug, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(value) => panic!("{message}: {value:?}"),
        Err(error) => error,
    }
}

fn publication_for_tenant(
    tenant: &str,
    inputs: &[FindingInput],
) -> AttestedFindingBatchPublication {
    let tenant_id = id(tenant, TenantId::new);
    let evidence_ids = inputs
        .iter()
        .map(|input| id(input.evidence_id, OpaqueReceiptRef::new))
        .collect::<Vec<_>>();
    let batch_id = derive_attested_finding_batch_id(&evidence_ids)
        .unwrap_or_else(|error| panic!("batch id: {error}"));
    let bindings = inputs
        .iter()
        .zip(&evidence_ids)
        .enumerate()
        .map(|(ordinal, (input, evidence_id))| {
            let finding_id = id(input.finding_id, RecordId::new);
            let finding_hash = Digest32::new([input.hash_byte; 32]);
            let action_id = derive_attested_finding_action_id(
                &batch_id,
                ordinal,
                &tenant_id,
                evidence_id,
                &finding_id,
                &finding_hash,
            )
            .unwrap_or_else(|error| panic!("action id: {error}"));
            let reservation_id =
                derive_attested_finding_reservation_id(&batch_id, &action_id, evidence_id)
                    .unwrap_or_else(|error| panic!("reservation id: {error}"));
            AttestedFindingBatchBinding {
                tenant_id: tenant_id.clone(),
                evidence_id: evidence_id.clone(),
                finding_id,
                finding_hash,
                action_id,
                reservation_id,
            }
        })
        .collect::<Vec<_>>();
    let body = AttestedFindingBatchBody {
        schema_version: ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
        batch_id,
        tenant_id,
        bindings: AttestedFindingBatchBindings::new(bindings)
            .unwrap_or_else(|error| panic!("bindings: {error}")),
    };
    let canonical =
        canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical batch body: {error}"));
    let hash = sha256(&canonical);
    let mut body_hash = [0_u8; 32];
    body_hash.copy_from_slice(hash.as_ref());
    AttestedFindingBatchPublication {
        body,
        canonical_body: CanonicalBody::new(canonical)
            .unwrap_or_else(|error| panic!("bounded canonical body: {error}")),
        body_hash: Digest32::new(body_hash),
    }
}

fn publication(inputs: &[FindingInput]) -> AttestedFindingBatchPublication {
    publication_for_tenant("tenant-planning", inputs)
}

fn baseline() -> AttestedFindingBatchPublication {
    publication(&[
        FindingInput {
            evidence_id: "evidence-z",
            finding_id: "finding-z",
            hash_byte: 7,
        },
        FindingInput {
            evidence_id: "evidence-a",
            finding_id: "finding-a",
            hash_byte: 8,
        },
    ])
}

fn digest_bytes(bytes: &[u8]) -> Digest32 {
    let hash = sha256(bytes);
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(hash.as_ref());
    Digest32::new(digest)
}

fn response_plan_publication(
    batch: &AttestedFindingBatchPublication,
    ordinal: usize,
) -> AttestedFindingResponsePlanPublication {
    let binding = batch
        .body
        .bindings
        .as_slice()
        .get(ordinal)
        .unwrap_or_else(|| panic!("response binding ordinal {ordinal} missing"));
    let mut response_plan: ResponsePlan = serde_json::from_str(include_str!(
        "../../../../tests/bindings/vectors/security/active-defense/positive/response-plan-v1.json"
    ))
    .unwrap_or_else(|error| panic!("response plan fixture: {error}"));
    response_plan.tenant_id = binding.tenant_id.clone();
    response_plan.action_id = binding.action_id.clone();
    response_plan.trigger_finding_receipt_id = binding.evidence_id.clone();
    response_plan.trigger_finding_id = binding.finding_id.clone();
    response_plan.trigger_finding_hash = binding.finding_hash;
    response_plan.plan_hash = Digest32::new([61_u8; 32]);
    response_plan
        .validate_shape()
        .unwrap_or_else(|error| panic!("response plan shape: {error}"));
    let body = AttestedFindingResponsePlanBody {
        schema_version: ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
        batch_id: batch.body.batch_id.clone(),
        ordinal: u32::try_from(ordinal).unwrap_or_else(|error| panic!("response ordinal: {error}")),
        binding: binding.clone(),
        response_plan,
        admission_artifact_ref: id("artifact-response-1", AdmissionArtifactRef::new),
    };
    let canonical = canonical_json_bytes(&body)
        .unwrap_or_else(|error| panic!("canonical response plan: {error}"));
    AttestedFindingResponsePlanPublication {
        body,
        canonical_body: CanonicalBody::new(canonical.clone())
            .unwrap_or_else(|error| panic!("bounded response plan: {error}")),
        body_hash: digest_bytes(&canonical),
    }
}

fn prepared_dispatch_binding(
    publication: &AttestedFindingResponsePlanPublication,
) -> PreparedActiveResponseDispatchBinding {
    let response_plan = &publication.body.response_plan;
    let binding = PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: response_plan.tenant_id.clone(),
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        dispatch_id: id("dispatch-response-1", RecordId::new),
        executor_authority_id: id("executor-authority-response-1", RecordId::new),
        executor_authority_generation: 1,
        authorized_at_unix_ms: response_plan.created_at_unix_ms,
        authorization_capability_hash: response_plan.operator_capability.capability_digest,
        governed_intent_hash: Digest32::new([62_u8; 32]),
        policy_decision_hash: Digest32::new([63_u8; 32]),
        approval: ResponseDispatchApproval::Automatic,
    };
    binding
        .validate_for_plan(response_plan)
        .unwrap_or_else(|error| panic!("prepared dispatch binding: {error}"));
    binding
}

fn create_legacy_batch_schema(connection: &Connection) {
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE security_attested_finding_batches (
                batch_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (batch_id)
            );
            CREATE TABLE security_attested_finding_batch_items (
                batch_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
                tenant_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                finding_hash BLOB NOT NULL CHECK (length(finding_hash) = 32),
                action_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                PRIMARY KEY (batch_id, ordinal),
                UNIQUE (tenant_id, evidence_id),
                UNIQUE (tenant_id, finding_id),
                UNIQUE (tenant_id, action_id),
                UNIQUE (tenant_id, reservation_id),
                FOREIGN KEY (batch_id)
                    REFERENCES security_attested_finding_batches (batch_id)
            );
            "#,
        )
        .unwrap_or_else(|error| panic!("create legacy batch schema: {error}"));
}

fn insert_legacy_publication(
    connection: &Connection,
    publication: &AttestedFindingBatchPublication,
    item_tenant_override: Option<&str>,
) {
    connection
        .execute(
            r#"
            INSERT INTO security_attested_finding_batches (
                batch_id, tenant_id, item_count, body, body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                publication.body.batch_id.as_str(),
                publication.body.tenant_id.as_str(),
                i64::try_from(publication.body.bindings.len())
                    .unwrap_or_else(|error| panic!("binding count: {error}")),
                publication.canonical_body.as_bytes(),
                publication.body_hash.as_bytes().as_slice(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert legacy batch: {error}"));
    for (ordinal, binding) in publication.body.bindings.as_slice().iter().enumerate() {
        connection
            .execute(
                r#"
                INSERT INTO security_attested_finding_batch_items (
                    batch_id, ordinal, tenant_id, evidence_id, finding_id,
                    finding_hash, action_id, reservation_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    publication.body.batch_id.as_str(),
                    i64::try_from(ordinal)
                        .unwrap_or_else(|error| panic!("binding ordinal: {error}")),
                    item_tenant_override.unwrap_or_else(|| binding.tenant_id.as_str()),
                    binding.evidence_id.as_str(),
                    binding.finding_id.as_str(),
                    binding.finding_hash.as_bytes().as_slice(),
                    binding.action_id.as_str(),
                    binding.reservation_id.as_str(),
                ],
            )
            .unwrap_or_else(|error| panic!("insert legacy binding: {error}"));
    }
}

fn primary_key_columns(connection: &Connection, table: &str) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .unwrap_or_else(|error| panic!("inspect {table}: {error}"));
    let mut columns = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(5)?, row.get::<_, String>(1)?))
        })
        .unwrap_or_else(|error| panic!("query {table} columns: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("read {table} columns: {error}"));
    columns.retain(|(position, _)| *position > 0);
    columns.sort_by_key(|(position, _)| *position);
    columns.into_iter().map(|(_, column)| column).collect()
}

#[test]
fn identical_batch_ids_are_isolated_by_tenant() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory
        .path()
        .join("tenant-scoped-finding-batches.sqlite");
    let inputs = [
        FindingInput {
            evidence_id: "shared-evidence-z",
            finding_id: "shared-finding-z",
            hash_byte: 17,
        },
        FindingInput {
            evidence_id: "shared-evidence-a",
            finding_id: "shared-finding-a",
            hash_byte: 18,
        },
    ];
    let tenant_a = publication_for_tenant("tenant-planning-a", &inputs);
    let tenant_b = publication_for_tenant("tenant-planning-b", &inputs);
    assert_eq!(tenant_a.body.batch_id, tenant_b.body.batch_id);
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));

    assert_eq!(
        store
            .publish_attested_finding_batch(&tenant_a)
            .unwrap_or_else(|error| panic!("publish tenant A: {error}")),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .publish_attested_finding_batch(&tenant_b)
            .unwrap_or_else(|error| panic!("publish tenant B: {error}")),
        CreateOutcome::Created
    );
    for expected in [&tenant_a, &tenant_b] {
        let loaded = store
            .load_attested_finding_batch(&AttestedFindingBatchKey {
                tenant_id: expected.body.tenant_id.clone(),
                batch_id: expected.body.batch_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load tenant batch: {error}"))
            .unwrap_or_else(|| panic!("tenant batch missing"));
        assert_eq!(&loaded, expected);
        assert_eq!(
            store
                .publish_attested_finding_batch(expected)
                .unwrap_or_else(|error| panic!("retry tenant batch: {error}")),
            CreateOutcome::Existing
        );
    }
    let wrong_tenant = AttestedFindingBatchKey {
        tenant_id: id("tenant-planning-missing", TenantId::new),
        batch_id: tenant_a.body.batch_id.clone(),
    };
    assert!(store
        .load_attested_finding_batch(&wrong_tenant)
        .unwrap_or_else(|error| panic!("load wrong tenant: {error}"))
        .is_none());
}

#[test]
fn legacy_batch_keys_migrate_losslessly_and_reopen_idempotently() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("legacy-finding-batches.sqlite");
    let expected = baseline();
    let key = AttestedFindingBatchKey {
        tenant_id: expected.body.tenant_id.clone(),
        batch_id: expected.body.batch_id.clone(),
    };
    {
        let connection =
            Connection::open(&path).unwrap_or_else(|error| panic!("open legacy database: {error}"));
        create_legacy_batch_schema(&connection);
        insert_legacy_publication(&connection, &expected, None);
    }
    for attempt in 0..2 {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open migrated store attempt {attempt}: {error}"));
        store
            .ensure_attested_finding_batches_ready()
            .unwrap_or_else(|error| panic!("batch readiness attempt {attempt}: {error}"));
        let loaded = store
            .load_attested_finding_batch(&key)
            .unwrap_or_else(|error| panic!("load migrated batch attempt {attempt}: {error}"))
            .unwrap_or_else(|| panic!("migrated batch missing on attempt {attempt}"));
        assert_eq!(loaded, expected);
        assert_eq!(
            store
                .publish_attested_finding_batch(&expected)
                .unwrap_or_else(|error| panic!("retry migrated batch attempt {attempt}: {error}")),
            CreateOutcome::Existing
        );
    }
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect migrated database: {error}"));
    assert_eq!(
        primary_key_columns(&connection, "security_attested_finding_batches"),
        ["tenant_id", "batch_id"]
    );
    assert_eq!(
        primary_key_columns(&connection, "security_attested_finding_batch_items"),
        ["tenant_id", "batch_id", "ordinal"]
    );
}

#[test]
fn legacy_cross_tenant_binding_rejects_migration_and_preserves_legacy_rows() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory
        .path()
        .join("invalid-legacy-finding-batches.sqlite");
    let expected = baseline();
    {
        let connection =
            Connection::open(&path).unwrap_or_else(|error| panic!("open legacy database: {error}"));
        create_legacy_batch_schema(&connection);
        insert_legacy_publication(&connection, &expected, Some("tenant-cross-boundary"));
    }
    let error = match SqliteSecurityStateStore::open(&path) {
        Ok(_) => panic!("cross-tenant legacy binding unexpectedly migrated"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);

    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect rejected migration: {error}"));
    assert_eq!(
        primary_key_columns(&connection, "security_attested_finding_batches"),
        ["batch_id"]
    );
    assert_eq!(
        primary_key_columns(&connection, "security_attested_finding_batch_items"),
        ["batch_id", "ordinal"]
    );
    let counts = (
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_attested_finding_batches",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("count preserved batches: {error}")),
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_attested_finding_batch_items",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("count preserved bindings: {error}")),
    );
    assert_eq!(counts, (1, 2));
}

#[test]
fn mixed_batch_key_schema_is_rejected() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("mixed-finding-batch-schema.sqlite");
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("open mixed database: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TABLE security_attested_finding_batches (
                batch_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, batch_id)
            );
            CREATE TABLE security_attested_finding_batch_items (
                batch_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
                tenant_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                finding_hash BLOB NOT NULL CHECK (length(finding_hash) = 32),
                action_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                PRIMARY KEY (batch_id, ordinal),
                UNIQUE (tenant_id, evidence_id),
                UNIQUE (tenant_id, finding_id),
                UNIQUE (tenant_id, action_id),
                UNIQUE (tenant_id, reservation_id)
            );
            "#,
        )
        .unwrap_or_else(|error| panic!("create mixed schema: {error}"));
    drop(connection);
    let error = match SqliteSecurityStateStore::open(&path) {
        Ok(_) => panic!("mixed batch key schema unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn weakened_current_schema_is_rejected_even_with_matching_key_topology() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory
        .path()
        .join("weakened-finding-batch-schema.sqlite");
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("open weakened database: {error}"));
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE security_attested_finding_batches (
                batch_id TEXT NOT NULL,
                tenant_id TEXT,
                item_count INTEGER NOT NULL,
                body BLOB NOT NULL,
                body_hash BLOB NOT NULL,
                PRIMARY KEY (tenant_id, batch_id)
            );
            CREATE TABLE security_attested_finding_batch_items (
                batch_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                tenant_id TEXT,
                evidence_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                finding_hash BLOB NOT NULL,
                action_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, batch_id, ordinal),
                UNIQUE (tenant_id, evidence_id),
                UNIQUE (tenant_id, finding_id),
                UNIQUE (tenant_id, action_id),
                UNIQUE (tenant_id, reservation_id),
                FOREIGN KEY (tenant_id, batch_id)
                    REFERENCES security_attested_finding_batches (tenant_id, batch_id)
            );
            "#,
        )
        .unwrap_or_else(|error| panic!("create weakened schema: {error}"));
    drop(connection);

    let error = match SqliteSecurityStateStore::open(&path) {
        Ok(_) => panic!("weakened batch schema unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn arbitrary_schema_objects_on_batch_tables_fail_readiness() {
    for object in [
        "CREATE TRIGGER rogue_batch_rewrite AFTER UPDATE ON security_attested_finding_batches BEGIN SELECT 1; END;",
        "CREATE UNIQUE INDEX rogue_partial_evidence ON security_attested_finding_batch_items (tenant_id, evidence_id) WHERE ordinal >= 0;",
    ] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("extended-finding-batch-schema.sqlite");
        drop(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("create canonical store: {error}")),
        );
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open schema extension database: {error}"));
        connection
            .execute_batch(object)
            .unwrap_or_else(|error| panic!("install schema extension: {error}"));
        drop(connection);

        let error = match SqliteSecurityStateStore::open(&path) {
            Ok(_) => panic!("batch schema extension unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}

#[test]
fn corrupt_durable_batch_bytes_fail_startup_semantic_replay() {
    for mutation in [
        "UPDATE security_attested_finding_batches SET body = x'7b7d'",
        "UPDATE security_attested_finding_batch_items SET finding_hash = zeroblob(32) WHERE ordinal = 0",
    ] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("corrupt-finding-batch.sqlite");
        let expected = baseline();
        {
            let store = SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("create canonical store: {error}"));
            store
                .publish_attested_finding_batch(&expected)
                .unwrap_or_else(|error| panic!("publish batch: {error}"));
        }
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open corrupt batch database: {error}"));
        connection
            .execute_batch(mutation)
            .unwrap_or_else(|error| panic!("corrupt durable batch: {error}"));
        drop(connection);

        let error = match SqliteSecurityStateStore::open(&path) {
            Ok(_) => panic!("corrupt durable batch unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}

#[test]
fn composite_foreign_key_rejects_cross_tenant_binding() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("cross-tenant-finding-binding.sqlite");
    let expected = baseline();
    {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open store: {error}"));
        store
            .publish_attested_finding_batch(&expected)
            .unwrap_or_else(|error| panic!("publish parent batch: {error}"));
    }
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open direct database connection: {error}"));
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap_or_else(|error| panic!("enable foreign keys: {error}"));
    let error = rejected(
        connection.execute(
            r#"
            INSERT INTO security_attested_finding_batch_items (
                batch_id, ordinal, tenant_id, evidence_id, finding_id,
                finding_hash, action_id, reservation_id
            ) VALUES (?1, 100, 'tenant-cross-boundary', 'evidence-cross-boundary',
                      'finding-cross-boundary', ?2, 'action-cross-boundary',
                      'dispatch-cross-boundary')
            "#,
            params![expected.body.batch_id.as_str(), [91_u8; 32].as_slice(),],
        ),
        "cross-tenant child must fail its composite foreign key",
    );
    assert_eq!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );
    let item_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_attested_finding_batch_items",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count bindings: {error}"));
    assert_eq!(
        item_count,
        i64::try_from(expected.body.bindings.len())
            .unwrap_or_else(|error| panic!("binding count: {error}"))
    );
}

#[test]
fn restart_and_exact_retry_preserve_order_and_one_to_one_cardinality() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("finding-batches.sqlite");
    let expected = baseline();
    let key = AttestedFindingBatchKey {
        tenant_id: expected.body.tenant_id.clone(),
        batch_id: expected.body.batch_id.clone(),
    };
    {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open store: {error}"));
        assert_eq!(
            store
                .publish_attested_finding_batch(&expected)
                .unwrap_or_else(|error| panic!("publish: {error}")),
            CreateOutcome::Created
        );
        assert_eq!(
            store
                .publish_attested_finding_batch(&expected)
                .unwrap_or_else(|error| panic!("retry: {error}")),
            CreateOutcome::Existing
        );
    }
    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    let loaded = reopened
        .load_attested_finding_batch(&key)
        .unwrap_or_else(|error| panic!("load after restart: {error}"))
        .unwrap_or_else(|| panic!("published batch missing after restart"));
    assert_eq!(loaded, expected);
    assert_eq!(loaded.body.bindings.len(), 2);
    assert_eq!(
        loaded.body.bindings.as_slice()[0].evidence_id.as_str(),
        "evidence-z"
    );
    assert_eq!(
        loaded.body.bindings.as_slice()[1].evidence_id.as_str(),
        "evidence-a"
    );
    let action_ids = loaded
        .body
        .bindings
        .as_slice()
        .iter()
        .map(|binding| binding.action_id.clone())
        .collect::<Vec<ActionId>>();
    assert_ne!(action_ids[0], action_ids[1]);
    assert_ne!(
        loaded.body.bindings.as_slice()[0].reservation_id,
        loaded.body.bindings.as_slice()[1].reservation_id
    );
}

#[test]
fn mutation_reordering_and_cardinality_changes_conflict_with_prior_publication() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("finding-conflicts.sqlite");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let expected = baseline();
    store
        .publish_attested_finding_batch(&expected)
        .unwrap_or_else(|error| panic!("publish: {error}"));

    let mutated = publication(&[
        FindingInput {
            evidence_id: "evidence-z",
            finding_id: "finding-z-mutated",
            hash_byte: 9,
        },
        FindingInput {
            evidence_id: "evidence-a",
            finding_id: "finding-a",
            hash_byte: 8,
        },
    ]);
    let mutation_error = rejected(
        store.publish_attested_finding_batch(&mutated),
        "same batch id with mutated finding must conflict",
    );
    assert_eq!(mutation_error.kind(), PortErrorKind::Conflict);

    let reordered = publication(&[
        FindingInput {
            evidence_id: "evidence-a",
            finding_id: "finding-a",
            hash_byte: 8,
        },
        FindingInput {
            evidence_id: "evidence-z",
            finding_id: "finding-z",
            hash_byte: 7,
        },
    ]);
    let reorder_error = rejected(
        store.publish_attested_finding_batch(&reordered),
        "reordered authoritative evidence must conflict",
    );
    assert_eq!(reorder_error.kind(), PortErrorKind::Conflict);

    let shortened = publication(&[FindingInput {
        evidence_id: "evidence-z",
        finding_id: "finding-z",
        hash_byte: 7,
    }]);
    let cardinality_error = rejected(
        store.publish_attested_finding_batch(&shortened),
        "partial republish must conflict",
    );
    assert_eq!(cardinality_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn injected_second_item_failure_rolls_back_batch_and_every_binding() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("finding-rollback.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("initialize store: {error}"));
    {
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open trigger connection: {error}"));
        connection
            .execute_batch(
                r#"
                CREATE TRIGGER fail_second_finding_binding
                BEFORE INSERT ON security_attested_finding_batch_items
                WHEN NEW.ordinal = 1
                BEGIN
                    SELECT RAISE(ABORT, 'injected finding binding failure');
                END;
                "#,
            )
            .unwrap_or_else(|error| panic!("install trigger: {error}"));
    }
    let error = rejected(
        store.publish_attested_finding_batch(&baseline()),
        "injected item failure must abort publication",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    drop(store);

    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open inspection connection: {error}"));
    let batch_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_attested_finding_batches",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count batches: {error}"));
    let item_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_attested_finding_batch_items",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count bindings: {error}"));
    assert_eq!((batch_count, item_count), (0, 0));
}

#[test]
fn prepared_dispatch_binding_round_trips_and_tampering_fails_closed() {
    for tamper_kind in ["hash", "body", "authorized_at"] {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join(format!(
            "response-outbox-binding-{tamper_kind}-tamper.sqlite"
        ));
        let batch = baseline();
        let publication = response_plan_publication(&batch, 0);
        let key = AttestedFindingResponseOutboxKey {
            tenant_id: publication.body.binding.tenant_id.clone(),
            action_id: publication.body.binding.action_id.clone(),
        };
        let expected_binding = prepared_dispatch_binding(&publication);
        {
            let store = SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open prepared binding store: {error}"));
            store
                .publish_attested_finding_batch(&batch)
                .unwrap_or_else(|error| panic!("publish prepared binding batch: {error}"));
            store
                .publish_attested_finding_response_plan(&publication)
                .unwrap_or_else(|error| panic!("publish response plan: {error}"));
            let planned = store
                .load_attested_finding_response_outbox(&key)
                .unwrap_or_else(|error| panic!("load planned response: {error}"))
                .unwrap_or_else(|| panic!("planned response missing"));
            let bound = store
                .transition_attested_finding_response_outbox(
                    &planned,
                    AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                        artifact_digest: Digest32::new([64_u8; 32]),
                    },
                )
                .unwrap_or_else(|error| panic!("bind response artifacts: {error}"));
            let prepared = store
                .transition_attested_finding_response_outbox(
                    &bound,
                    AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                        prepared_dispatch_binding: Box::new(expected_binding.clone()),
                    },
                )
                .unwrap_or_else(|error| panic!("persist prepared binding: {error}"));
            assert_eq!(
                prepared.prepared_dispatch_binding.as_ref(),
                Some(&expected_binding)
            );
            assert_eq!(
                prepared.execution_dispatch_id.as_ref(),
                Some(&expected_binding.dispatch_id)
            );
        }

        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen prepared binding store: {error}"));
        let reloaded = store
            .load_attested_finding_response_outbox(&key)
            .unwrap_or_else(|error| panic!("reload prepared binding: {error}"))
            .unwrap_or_else(|| panic!("prepared binding missing after restart"));
        assert_eq!(
            reloaded.prepared_dispatch_binding.as_ref(),
            Some(&expected_binding)
        );

        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open binding tamper connection: {error}"));
        connection
            .execute_batch("DROP TRIGGER security_attested_finding_response_outbox_immutable;")
            .unwrap_or_else(|error| panic!("drop binding immutability trigger: {error}"));
        if tamper_kind == "body" {
            let corrupted = b"{}".to_vec();
            let corrupted_hash = digest_bytes(&corrupted);
            connection
                .execute(
                    r#"
                    UPDATE security_attested_finding_response_outbox
                    SET prepared_dispatch_binding = ?1,
                        prepared_dispatch_binding_hash = ?2
                    WHERE tenant_id = ?3 AND action_id = ?4
                    "#,
                    params![
                        corrupted.as_slice(),
                        corrupted_hash.as_bytes().as_slice(),
                        key.tenant_id.as_str(),
                        key.action_id.as_str(),
                    ],
                )
                .unwrap_or_else(|error| panic!("tamper prepared binding body: {error}"));
        } else if tamper_kind == "authorized_at" {
            let mut corrupted = serde_json::to_value(&expected_binding)
                .unwrap_or_else(|error| panic!("serialize prepared binding tamper: {error}"));
            corrupted["authorized_at_unix_ms"] =
                serde_json::json!(publication.body.response_plan.expires_at_unix_ms);
            let corrupted = canonical_json_bytes(&corrupted)
                .unwrap_or_else(|error| panic!("canonical prepared binding tamper: {error}"));
            let corrupted_hash = digest_bytes(&corrupted);
            connection
                .execute(
                    r#"
                    UPDATE security_attested_finding_response_outbox
                    SET prepared_dispatch_binding = ?1,
                        prepared_dispatch_binding_hash = ?2
                    WHERE tenant_id = ?3 AND action_id = ?4
                    "#,
                    params![
                        corrupted.as_slice(),
                        corrupted_hash.as_bytes().as_slice(),
                        key.tenant_id.as_str(),
                        key.action_id.as_str(),
                    ],
                )
                .unwrap_or_else(|error| panic!("tamper prepared binding time: {error}"));
        } else {
            connection
                .execute(
                    r#"
                    UPDATE security_attested_finding_response_outbox
                    SET prepared_dispatch_binding_hash = randomblob(32)
                    WHERE tenant_id = ?1 AND action_id = ?2
                    "#,
                    params![key.tenant_id.as_str(), key.action_id.as_str()],
                )
                .unwrap_or_else(|error| panic!("tamper prepared binding hash: {error}"));
        }
        let error = rejected(
            store.load_attested_finding_response_outbox(&key),
            "tampered prepared binding must fail at the typed load boundary",
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}

#[test]
fn response_outbox_sql_trigger_rejects_write_once_and_terminal_tampering() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("response-outbox-tamper.sqlite");
    let expected = baseline();
    {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open store: {error}"));
        store
            .publish_attested_finding_batch(&expected)
            .unwrap_or_else(|error| panic!("publish batch: {error}"));
    }
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open direct database connection: {error}"));
    let active = &expected.body.bindings.as_slice()[0];
    for mutation in [
        "UPDATE security_attested_finding_response_outbox SET planning_state = 'planned', plan_body = x'7b7d', plan_body_hash = zeroblob(32), admission_artifact_ref = 'artifact-ref' WHERE ordinal = 0",
        "UPDATE security_attested_finding_response_outbox SET finding_hash = zeroblob(32) WHERE ordinal = 0",
    ] {
        let error = rejected(
            connection.execute_batch(mutation),
            "zero outbox commitment unexpectedly persisted",
        );
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::ConstraintViolation)
        );
    }
    connection
        .execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET planning_state = 'planned', plan_body = x'7b7d',
                plan_body_hash = randomblob(32), admission_artifact_ref = 'artifact-ref',
                admission_artifact_digest = randomblob(32)
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![active.tenant_id.as_str(), active.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("stage planned outbox row: {error}"));
    for mutation in [
        "UPDATE security_attested_finding_response_outbox SET admission_artifact_digest = zeroblob(32) WHERE ordinal = 0",
        "UPDATE security_attested_finding_response_outbox SET admission_state = 'prepared', completion_state = 'pending', execution_dispatch_id = '0000', prepared_dispatch_binding = x'7b7d', prepared_dispatch_binding_hash = randomblob(32) WHERE ordinal = 0",
    ] {
        let error = rejected(
            connection.execute_batch(mutation),
            "zero artifact or dispatch identity unexpectedly persisted",
        );
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::ConstraintViolation)
        );
    }
    connection
        .execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET admission_state = 'prepared', completion_state = 'pending',
                execution_dispatch_id = 'kernel-dispatch',
                prepared_dispatch_binding = x'7b7d',
                prepared_dispatch_binding_hash = randomblob(32)
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![active.tenant_id.as_str(), active.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("stage prepared outbox row: {error}"));
    let zero_completion = rejected(
        connection.execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET completion_state = 'completed', completion_outcome = 'failed_before_effect',
                completion_evidence_id = 'signed-completion-evidence',
                completion_evidence_body_hash = zeroblob(32)
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![active.tenant_id.as_str(), active.action_id.as_str()],
        ),
        "zero completion evidence hash unexpectedly persisted",
    );
    assert_eq!(
        zero_completion.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );
    connection
        .execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET completion_state = 'completed', completion_outcome = 'failed_before_effect',
                completion_evidence_id = 'signed-completion-evidence',
                completion_evidence_body_hash = randomblob(32)
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![active.tenant_id.as_str(), active.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("stage completed outbox row: {error}"));

    for mutation in [
        "UPDATE security_attested_finding_response_outbox SET plan_body = x'7b7d20' WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET admission_artifact_digest = randomblob(32) WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET execution_dispatch_id = 'changed-dispatch' WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET prepared_dispatch_binding = x'5b5d' WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET prepared_dispatch_binding_hash = randomblob(32) WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET completion_outcome = 'activated' WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET completion_evidence_id = 'changed-evidence' WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET completion_evidence_body_hash = randomblob(32) WHERE execution_dispatch_id = 'kernel-dispatch'",
        "UPDATE security_attested_finding_response_outbox SET completion_state = 'pending' WHERE execution_dispatch_id = 'kernel-dispatch'",
    ] {
        let error = rejected(
            connection.execute_batch(mutation),
            "write-once outbox mutation unexpectedly succeeded",
        );
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::ConstraintViolation)
        );
    }

    let rejected_binding = &expected.body.bindings.as_slice()[1];
    connection
        .execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET planning_state = 'failed', admission_state = 'rejected',
                last_error_code = 'planning-rejected'
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![
                rejected_binding.tenant_id.as_str(),
                rejected_binding.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("stage rejected outbox row: {error}"));
    let error = rejected(
        connection.execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET planning_state = 'pending', admission_state = 'pending'
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![
                rejected_binding.tenant_id.as_str(),
                rejected_binding.action_id.as_str()
            ],
        ),
        "terminal outbox state regression unexpectedly succeeded",
    );
    assert_eq!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation)
    );
}

#[test]
fn response_outbox_load_rejects_a_zero_commitment_even_if_sql_checks_are_bypassed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("response-outbox-zero-load.sqlite");
    let expected = baseline();
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    store
        .publish_attested_finding_batch(&expected)
        .unwrap_or_else(|error| panic!("publish batch: {error}"));
    let binding = &expected.body.bindings.as_slice()[0];
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open direct database connection: {error}"));
    connection
        .execute_batch(
            r#"
            DROP TRIGGER security_attested_finding_response_outbox_immutable;
            PRAGMA ignore_check_constraints = ON;
            "#,
        )
        .unwrap_or_else(|error| panic!("bypass checks for corruption fixture: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_attested_finding_response_outbox
            SET finding_hash = zeroblob(32)
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![binding.tenant_id.as_str(), binding.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("install zero commitment fixture: {error}"));
    connection
        .execute_batch("PRAGMA ignore_check_constraints = OFF;")
        .unwrap_or_else(|error| panic!("restore SQL checks: {error}"));

    let error = rejected(
        store.load_attested_finding_response_outbox(&AttestedFindingResponseOutboxKey {
            tenant_id: binding.tenant_id.clone(),
            action_id: binding.action_id.clone(),
        }),
        "zero commitment must fail at the typed load boundary",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn response_outbox_backfill_collision_fails_integrity_instead_of_losing_a_row() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("response-outbox-collision.sqlite");
    let expected = baseline();
    {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open store: {error}"));
        store
            .publish_attested_finding_batch(&expected)
            .unwrap_or_else(|error| panic!("publish batch: {error}"));
    }
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open direct database connection: {error}"));
    let immutable_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'security_attested_finding_response_outbox_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load immutable trigger: {error}"));
    let delete_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'security_attested_finding_response_outbox_delete_rejected'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load delete trigger: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER security_attested_finding_response_outbox_immutable;\
             DROP TRIGGER security_attested_finding_response_outbox_delete_rejected;",
        )
        .unwrap_or_else(|error| panic!("temporarily remove outbox triggers: {error}"));
    let missing = &expected.body.bindings.as_slice()[0];
    let collision = &expected.body.bindings.as_slice()[1];
    connection
        .execute(
            "DELETE FROM security_attested_finding_response_outbox WHERE tenant_id = ?1 AND action_id = ?2",
            params![missing.tenant_id.as_str(), missing.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("remove one outbox row: {error}"));
    connection
        .execute(
            "UPDATE security_attested_finding_response_outbox SET reservation_id = ?1 WHERE tenant_id = ?2 AND action_id = ?3",
            params![
                missing.reservation_id.as_str(),
                collision.tenant_id.as_str(),
                collision.action_id.as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("install uniqueness collision: {error}"));
    connection
        .execute_batch(&format!("{immutable_trigger};{delete_trigger};"))
        .unwrap_or_else(|error| panic!("restore outbox triggers: {error}"));
    drop(connection);

    let error = match SqliteSecurityStateStore::open(&path) {
        Ok(_) => panic!("colliding outbox migration unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}
