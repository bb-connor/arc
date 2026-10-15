use super::*;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[path = "retained_request/authority_profile.rs"]
pub(super) mod authority_profile;

pub(super) fn original(
    fence: &StoreMutationFence,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    original_with_requirements(
        fence,
        "original-request",
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        },
    )
}

pub(super) fn original_with_requirements(
    fence: &StoreMutationFence,
    request_id: &str,
    requirements: AdmissionParticipantRequirements,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    original_with_intent(fence, request_id, requirements, None)
}

pub(super) fn original_with_intent(
    fence: &StoreMutationFence,
    request_id: &str,
    requirements: AdmissionParticipantRequirements,
    governed_intent: Option<chio_core::capability::governance::GovernedTransactionIntent>,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    original_with_intent_and_signer(
        fence,
        request_id,
        requirements,
        governed_intent,
        &original_signer()?,
    )
}

/// Policy hash bound into helper-built original requests. A kernel that
/// recovers these operations signs its refusal under this policy.
pub(super) fn original_policy_hash() -> String {
    "a".repeat(64)
}

/// Receipt signer frozen into helper-built original requests. A kernel that
/// recovers these operations must sign with this key.
pub(super) fn original_signer() -> TestResult<Keypair> {
    Ok(Keypair::from_seed_hex(&"5a".repeat(32))?)
}

pub(super) fn original_with_intent_and_signer(
    fence: &StoreMutationFence,
    request_id: &str,
    requirements: AdmissionParticipantRequirements,
    governed_intent: Option<chio_core::capability::governance::GovernedTransactionIntent>,
    key: &Keypair,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    let grant =
        serde_json::json!({"server_id": "server", "tool_name": "tool", "operations": ["invoke"]});
    let scope = serde_json::from_value(serde_json::json!({"grants": [grant.clone()]}))?;
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "original-capability".into(),
            issuer: key.public_key(),
            subject: key.public_key(),
            scope,
            issued_at: now_ms() / 1000,
            expires_at: now_ms() / 1000 + 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        key,
    )?;
    original_with_capability(
        fence,
        request_id,
        requirements,
        governed_intent,
        key,
        capability,
    )
}

pub(super) fn original_with_capability(
    fence: &StoreMutationFence,
    request_id: &str,
    requirements: AdmissionParticipantRequirements,
    governed_intent: Option<chio_core::capability::governance::GovernedTransactionIntent>,
    key: &Keypair,
    capability: CapabilityToken,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    let request: chio_kernel::ToolCallRequest = serde_json::from_value(serde_json::json!({
        "request_id": request_id, "capability": capability,
        "tool_name": "tool", "server_id": "server", "agent_id": key.public_key().to_hex(),
        "arguments": {"private_argument": "must-not-appear-in-debug"},
        "governed_intent": governed_intent,
    }))?;
    let profile = authority_profile::selection(None, None, None)?;
    let retained_wire = serde_json::json!({
        "schema": "chio.retained-tool-admission-request.v1", "request": request,
        "authority_profile": profile,
        "frozen_receipt_signing_identity": {
            "public_key": key.public_key(), "crypto_floor": "allow_classical",
        },
        "matching_grant_indices": [0], "post_return_steps": [],
    });
    let immutable = immutable_request_hash(&retained_wire)?;
    let retained = RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(
        &retained_wire,
    )?)?;
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "authority",
        &fence.store_uuid,
    ))?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request", &request.request_id),
        capability_id: identifier("capability", &request.capability.id),
        authorization_capability_hash: AdmissionDigest::try_new(
            "capability",
            sha256_hex(&canonical_json_bytes(&request.capability)?),
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            AdmissionDigest::try_new("immutable", immutable)?,
            AdmissionDigest::try_new(
                "action",
                sha256_hex(&canonical_json_bytes(&request.arguments)?),
            )?,
            requirements,
        )?,
        policy_hash: AdmissionDigest::try_new("policy", original_policy_hash())?,
        effect_class: SideEffectClass::SideEffecting,
    })?;
    Ok((
        AdmissionOperationV1::prepare(binding, fence.owner_epoch)?,
        retained,
    ))
}

pub(crate) fn immutable_request_hash(wire: &serde_json::Value) -> TestResult<String> {
    let request = &wire["request"];
    let indices = wire["matching_grant_indices"]
        .as_array()
        .ok_or("matching indices")?;
    let mut matching_grants = Vec::with_capacity(indices.len());
    for index in indices {
        let index = usize::try_from(index.as_u64().ok_or("matching index")?)?;
        let grant = request["capability"]["scope"]["grants"]
            .get(index)
            .ok_or("matching grant")?;
        matching_grants.push(serde_json::json!({"index": index, "grant": grant}));
    }
    Ok(sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.tool-admission-request.v1", "server_id": request["server_id"],
        "tool_name": request["tool_name"], "agent_id": request["agent_id"],
        "arguments": request["arguments"], "governed_intent": request["governed_intent"],
        "model_metadata": request["model_metadata"],
        "federated_origin_kernel_id": request["federated_origin_kernel_id"],
        "matching_grants": matching_grants, "post_return_steps": wire["post_return_steps"],
        "security_binding": wire["security_binding"],
        "authority_profile": wire["authority_profile"],
        "frozen_receipt_signing_identity": wire["frozen_receipt_signing_identity"],
    }))?))
}

#[test]
fn retained_request_reopens_under_the_current_fence_with_exact_bytes() -> TestResult {
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
        _clock,
    } = fixture();
    let (operation, request) = original(&fence)?;
    let now = now_ms();
    assert!(store
        .load_retained_tool_admission_custody(operation.binding().operation_id(), &fence, now)?
        .is_none());
    assert!(matches!(
        store.begin_with_retained_tool_request(&operation, &request, &fence, now)?,
        AdmissionBeginResult::Created(_)
    ));
    assert!(matches!(
        store.begin_with_retained_tool_request(&operation, &request, &fence, now)?,
        AdmissionBeginResult::ExactReplay { .. }
    ));
    let count: i64 = Connection::open(&database)?.query_row(
        "SELECT COUNT(*) FROM admission_operation_commits",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1, "exact replay must not append another begin");
    let unheld = store
        .load_retained_tool_admission_custody(operation.binding().operation_id(), &fence, now)?
        .ok_or("missing original custody snapshot")?;
    assert_eq!(unheld.operation, operation);
    assert_eq!(unheld.request.canonical_bytes(), request.canonical_bytes());
    assert!(unheld.custody.is_none());
    assert!(!format!("{unheld:?}").contains("must-not-appear-in-debug"));
    drop(store);
    drop(authority);
    let reopened = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    assert!(matches!(
        store.load_retained_tool_admission_custody(
            operation.binding().operation_id(),
            &fence,
            now_ms()
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(store
        .load_retained_tool_admission_custody(
            operation.binding().operation_id(),
            &reopened.mutation_fence(),
            0,
        )
        .is_err());
    let reopened_snapshot = store
        .load_retained_tool_admission_custody(
            operation.binding().operation_id(),
            &reopened.mutation_fence(),
            now_ms(),
        )?
        .ok_or("missing reopened custody snapshot")?;
    assert_eq!(reopened_snapshot.operation, operation);
    assert_eq!(
        reopened_snapshot.request.canonical_bytes(),
        request.canonical_bytes()
    );
    assert!(reopened_snapshot.custody.is_none());
    assert!(matches!(
        store.load_retained_tool_request(operation.binding().operation_id(), &fence, now_ms()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let (restored_operation, restored) = store
        .load_retained_tool_request(
            operation.binding().operation_id(),
            &reopened.mutation_fence(),
            now_ms(),
        )?
        .ok_or("missing original")?;
    assert_eq!(restored_operation, operation);
    assert_eq!(restored.canonical_bytes(), request.canonical_bytes());
    assert!(!format!("{restored:?}").contains("must-not-appear-in-debug"));
    Ok(())
}

#[test]
fn retained_request_insert_and_begin_commit_roll_back_together() -> TestResult {
    for target in [
        "admission_operation_tool_requests",
        "admission_operation_commits",
    ] {
        let fixture = fixture();
        let (operation, request) = original(&fixture.fence)?;
        let connection = Connection::open(&fixture.database)?;
        connection.execute_batch(&format!("CREATE TRIGGER fail_retained_insert BEFORE INSERT ON {target} BEGIN SELECT RAISE(ABORT, 'injected retention failure'); END;"))?;
        assert!(fixture
            .store
            .begin_with_retained_tool_request(&operation, &request, &fixture.fence, now_ms())
            .is_err());
        for table in [
            "admission_operations",
            "admission_operation_tool_requests",
            "admission_operation_commits",
        ] {
            let count: i64 =
                connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 0, "{target} failure partially committed {table}");
        }
    }
    Ok(())
}

#[test]
fn retained_request_rejects_wrong_binding_fence_and_regressed_time() -> TestResult {
    let fixture = fixture();
    let (operation, request) = original(&fixture.fence)?;
    let mut altered: serde_json::Value = serde_json::from_slice(request.canonical_bytes())?;
    altered["request"]["arguments"] = serde_json::json!({"changed": true});
    let changed =
        RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&altered)?)?;
    assert!(fixture
        .store
        .begin_with_retained_tool_request(&operation, &changed, &fixture.fence, now_ms())
        .is_err());
    assert!(fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())?
        .is_none());
    let now = now_ms();
    fixture
        .store
        .begin_with_retained_tool_request(&operation, &request, &fixture.fence, now)?;
    let mut wrong_fence = fixture.fence.clone();
    wrong_fence.lease_id.push_str("-wrong");
    assert!(matches!(
        fixture.store.load_retained_tool_request(
            operation.binding().operation_id(),
            &wrong_fence,
            now
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(fixture
        .store
        .load_retained_tool_request(operation.binding().operation_id(), &fixture.fence, now - 1)
        .is_err());
    assert!(fixture
        .store
        .begin_with_retained_tool_request(&operation, &request, &wrong_fence, now)
        .is_err());
    assert!(fixture
        .store
        .begin_with_retained_tool_request(&operation, &request, &fixture.fence, now - 1)
        .is_err());
    Ok(())
}

#[test]
fn retained_request_cannot_be_backfilled_for_a_legacy_operation() -> TestResult {
    let fixture = fixture();
    let (operation, request) = original(&fixture.fence)?;
    fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    assert!(fixture
        .store
        .load_retained_tool_request(operation.binding().operation_id(), &fixture.fence, now_ms())?
        .is_none());
    assert!(fixture
        .store
        .begin_with_retained_tool_request(&operation, &request, &fixture.fence, now_ms())
        .is_err());
    assert!(fixture
        .store
        .load_retained_tool_request(operation.binding().operation_id(), &fixture.fence, now_ms())?
        .is_none());
    Ok(())
}

#[test]
fn retained_request_tampering_or_removal_fails_reads_and_restart() -> TestResult {
    for remove in [false, true] {
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            fence,
            _clock,
        } = fixture();
        let (operation, request) = original(&fence)?;
        store.begin_with_retained_tool_request(&operation, &request, &fence, now_ms())?;
        let connection = Connection::open(&database)?;
        assert!(connection
            .execute(
                "UPDATE admission_operation_tool_requests SET request_json = request_json",
                []
            )
            .is_err());
        assert!(connection
            .execute("DELETE FROM admission_operation_tool_requests", [])
            .is_err());
        connection.execute_batch("DROP TRIGGER admission_operation_tool_requests_immutable; DROP TRIGGER admission_operation_tool_requests_no_delete;")?;
        if remove {
            connection.execute("DELETE FROM admission_operation_tool_requests", [])?;
        } else {
            let mut changed: serde_json::Value = serde_json::from_slice(request.canonical_bytes())?;
            changed["request"]["agent_id"] =
                serde_json::json!(Keypair::generate().public_key().to_hex());
            connection.execute(
                "UPDATE admission_operation_tool_requests SET request_json = ?1",
                [canonical_json_bytes(&changed)?],
            )?;
        }
        // Restore the canonical triggers so restart fails on retained evidence,
        // not merely on an intentionally altered test schema.
        connection.execute_batch(include_str!("../admission_operation_store.sql"))?;
        assert!(store
            .load_retained_tool_request(operation.binding().operation_id(), &fence, now_ms())
            .is_err());
        assert!(store
            .begin_with_retained_tool_request(&operation, &request, &fence, now_ms())
            .is_err());
        drop(connection);
        drop(store);
        drop(authority);
        assert!(SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock()
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn retained_request_decoder_is_bounded_strict_and_not_an_authenticator() -> TestResult {
    let fixture = fixture();
    let (operation, request) = original(&fixture.fence)?;
    for pointer in ["/extra", "/request/extra", "/request/capability/extra"] {
        let mut value: serde_json::Value = serde_json::from_slice(request.canonical_bytes())?;
        let (parent, key) = pointer.rsplit_once('/').ok_or("invalid pointer")?;
        value.pointer_mut(parent).ok_or("missing parent")?[key] = serde_json::json!(true);
        assert!(
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&value)?)
                .is_err()
        );
    }
    for indices in [
        serde_json::json!([]),
        serde_json::json!([0, 0]),
        serde_json::json!([1]),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(request.canonical_bytes())?;
        value["matching_grant_indices"] = indices;
        assert!(
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&value)?)
                .is_err()
        );
    }
    assert!(RetainedToolAdmissionRequestV1::from_canonical_bytes(&vec![b' '; 262_145]).is_err());
    let mut noncanonical = request.canonical_bytes().to_vec();
    noncanonical.push(b'\n');
    assert!(RetainedToolAdmissionRequestV1::from_canonical_bytes(&noncanonical).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(request.canonical_bytes())?;
    value["request"]["capability"]["id"] = serde_json::json!("unsigned-change");
    let decoded =
        RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&value)?)?;
    assert!(decoded.validate_binding(operation.binding()).is_err());
    Ok(())
}

#[test]
fn retained_request_orphan_is_rejected_at_restart() -> TestResult {
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
        _clock,
    } = fixture();
    let (_, request) = original(&fence)?;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    connection.execute(
        "INSERT INTO admission_operation_tool_requests (operation_id, request_json) VALUES (?1, ?2)",
        params!["a".repeat(64), request.canonical_bytes()],
    )?;
    drop(connection);
    assert!(SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock()
    )
    .is_err());
    Ok(())
}

#[test]
fn retained_request_lookup_rejects_ambiguous_namespaces_even_without_legacy_material() -> TestResult
{
    let fixture = fixture();
    let (operation, request) = original(&fixture.fence)?;
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &request,
        &fixture.fence,
        now_ms(),
    )?;
    let selector = operation.binding().request_id();
    assert!(fixture
        .store
        .load_unambiguous_retained_tool_request(selector, &fixture.fence, now_ms())?
        .is_some());
    let previous = operation.binding().to_persisted();
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: previous.kind,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "authority",
            "another-authority",
        ))?,
        request_id: previous.request_id,
        capability_id: previous.capability_id,
        authorization_capability_hash: previous.authorization_capability_hash,
        request_binding: previous.request_binding,
        policy_hash: previous.policy_hash,
        effect_class: previous.effect_class,
    })?;
    let legacy = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
    fixture.store.begin(&legacy, &fixture.fence, now_ms())?;
    let error = match fixture.store.load_unambiguous_retained_tool_request(
        selector,
        &fixture.fence,
        now_ms(),
    ) {
        Ok(_) => {
            return Err(
                "another namespace's legacy operation did not make the request ambiguous".into(),
            )
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("ambiguous"));
    let connection = Connection::open(&fixture.database)?;
    let plan: String = connection.query_row(
        "EXPLAIN QUERY PLAN SELECT operation_id FROM admission_operations WHERE request_id = ?1 ORDER BY operation_id LIMIT 2",
        [selector.as_str()], |row| row.get(3),
    )?;
    assert!(
        plan.contains("admission_operations_request_id"),
        "unindexed lookup: {plan}"
    );
    Ok(())
}
