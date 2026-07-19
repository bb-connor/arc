fn classify_reduce_command(
    payload: &ReduceChargeCostRequest,
) -> Result<(&'static str, AdmissionCommandKind), Response> {
    match (payload.exposure_units, payload.realized_spend_units) {
        (None, None) => Ok(("release", AdmissionCommandKind::ReleaseExposure)),
        (Some(exposure_units), Some(realized_spend_units))
            if exposure_units.checked_sub(realized_spend_units) == Some(payload.cost_units) =>
        {
            Ok(("reconcile", AdmissionCommandKind::ReconcileSpend))
        }
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "budget reconcile reduction must equal exposure minus realized spend",
        )),
        _ => Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "budget reconcile requires both exposure and realized spend",
        )),
    }
}

fn admission_consensus_terminal_event<'a>(
    state: &TrustServiceState,
    operation: &str,
    hold_id: Option<&'a str>,
    event_id: Option<&'a str>,
    authority: Option<&BudgetMutationAuthorityView>,
) -> Result<Option<&'a str>, Response> {
    let persisted_authority = if let Some(hold_id) = hold_id {
        let store = open_budget_store(&state.config)?;
        match store.hold_authority(hold_id) {
            Ok(authority) => authority,
            Err(error) => {
                return Err(plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &error.to_string(),
                ));
            }
        }
    } else {
        None
    };
    let persisted_is_admission = persisted_authority
        .as_ref()
        .is_some_and(is_admission_consensus_event_authority);
    let requested_is_admission = authority.is_some_and(is_admission_consensus_authority_view);
    if !persisted_is_admission && !requested_is_admission {
        return Ok(None);
    }
    if persisted_is_admission && budget_event_authority_from_view(authority) != persisted_authority
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("budget {operation} requires the exact persisted admission authority"),
        ));
    }
    if hold_id.is_none() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("budget {operation} requires hold_id under admission consensus"),
        ));
    }
    event_id.map(Some).ok_or_else(|| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("budget {operation} requires event_id under admission consensus"),
        )
    })
}

fn is_admission_consensus_authority_view(authority: &BudgetMutationAuthorityView) -> bool {
    authority.lease_epoch > 0
        && !authority.authority_id.is_empty()
        && authority.lease_id
            == format!(
                "{}#admission-term-{}",
                authority.authority_id, authority.lease_epoch
            )
}

fn is_admission_consensus_event_authority(authority: &BudgetEventAuthority) -> bool {
    authority.lease_epoch > 0
        && !authority.authority_id.is_empty()
        && authority.lease_id
            == format!(
                "{}#admission-term-{}",
                authority.authority_id, authority.lease_epoch
            )
}

async fn propose_admission_terminal_command<T, R>(
    state: &TrustServiceState,
    event_id: &str,
    command_kind: AdmissionCommandKind,
    command: &T,
    label: &str,
) -> Response
where
    T: Serialize,
    R: DeserializeOwned + Serialize,
{
    let result = match super::cluster::propose_admission_command(
        state,
        event_id.to_string(),
        command_kind,
        command,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match serde_json::from_str::<R>(&result.response_json) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("persisted {label} consensus result is invalid: {error}"),
        ),
    }
}

fn persisted_budget_authority_metadata_view(
    state: &TrustServiceState,
    event: &BudgetMutationRecord,
    budget_commit_index: Option<u64>,
) -> Option<BudgetAuthorityMetadataView> {
    let authority = event.authority.as_ref()?;
    let metadata = budget_authority_metadata_view(
        state,
        budget_commit_index,
        budget_authority_guarantee_level(state, budget_commit_index),
    )?;
    budget_authority_metadata_matches_event(&metadata, authority).then_some(metadata)
}

fn budget_authority_metadata_matches_event(
    metadata: &BudgetAuthorityMetadataView,
    authority: &BudgetEventAuthority,
) -> bool {
    metadata.authority_id == authority.authority_id
        && metadata.leader_url == authority.authority_id
        && metadata.budget_term == authority.lease_epoch
        && metadata.lease_id == authority.lease_id
        && metadata.lease_epoch == authority.lease_epoch
}

pub(crate) fn budget_event_authority_from_view(
    authority: Option<&BudgetMutationAuthorityView>,
) -> Option<BudgetEventAuthority> {
    authority.map(|authority| BudgetEventAuthority {
        authority_id: authority.authority_id.clone(),
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    })
}

fn verify_requested_budget_authority(
    operation: &str,
    requested: Option<&BudgetEventAuthority>,
    resolved: Option<BudgetEventAuthority>,
) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
    match requested {
        Some(requested) if resolved.as_ref() == Some(requested) => Ok(Some(requested.clone())),
        Some(_) => Err(BudgetStoreError::Invariant(format!(
            "requested budget {operation} authority does not match the server-resolved authority"
        ))),
        None => Ok(resolved),
    }
}

fn load_persisted_authorize_event(
    store: &SqliteBudgetStore,
    event_id: &str,
    request: &TryChargeCostRequest,
    allowed: bool,
    authority: Option<&BudgetEventAuthority>,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let grant_index = u32::try_from(request.grant_index).map_err(|_| {
        BudgetStoreError::Invariant("budget authorize grant index exceeds u32".to_string())
    })?;
    let event_seq = store
        .mutation_event_seq_for_event_id(event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget authorize event `{event_id}` is not persisted"
            ))
        })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "budget authorize event sequence must be greater than zero".to_string(),
        )
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget authorize event `{event_id}` is not readable"
            ))
        })?;
    let expected_monetary_state = if allowed && request.cost_units > 0 {
        BudgetMonetaryHoldState::Exposed
    } else {
        BudgetMonetaryHoldState::None
    };
    let usage_seq_matches = if allowed {
        event.usage_seq.is_some()
    } else {
        event.usage_seq.is_none()
    };
    if event.event_id != event_id
        || event.event_seq != event_seq
        || !usage_seq_matches
        || event.kind != BudgetMutationKind::AuthorizeExposure
        || event.allowed != Some(allowed)
        || event.monetary_state != expected_monetary_state
        || event.invocation_state != BudgetInvocationReservationState::Absent
        || event.capability_id != request.capability_id
        || event.grant_index != grant_index
        || event.hold_id != request.hold_id
        || event.exposure_units != request.cost_units
        || event.realized_spend_units != 0
        || event.max_invocations != request.max_invocations
        || event.max_cost_per_invocation != request.max_cost_per_invocation
        || event.max_total_cost_units != request.max_total_cost_units
        || event.authority.as_ref() != authority
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget authorize event `{event_id}` does not match the requested mutation"
        )));
    }
    Ok(event)
}

#[allow(clippy::too_many_arguments)]
fn load_persisted_budget_transition(
    store: &SqliteBudgetStore,
    event_id: &str,
    kind: BudgetMutationKind,
    capability_id: &str,
    grant_index: usize,
    hold_id: Option<&str>,
    exposure_units: u64,
    realized_spend_units: u64,
    authority: Option<&BudgetEventAuthority>,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let expected_monetary_state = match kind {
        BudgetMutationKind::ReverseExposure => BudgetMonetaryHoldState::Reversed,
        BudgetMutationKind::ReleaseExposure => BudgetMonetaryHoldState::Released,
        BudgetMutationKind::ReconcileSpend => BudgetMonetaryHoldState::Reconciled,
        _ => {
            return Err(BudgetStoreError::Invariant(
                "persisted budget transition requested an unsupported mutation kind".to_string(),
            ));
        }
    };
    let grant_index = u32::try_from(grant_index).map_err(|_| {
        BudgetStoreError::Invariant("budget transition grant index exceeds u32".to_string())
    })?;
    let event_seq = store
        .mutation_event_seq_for_event_id(event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget transition event `{event_id}` is not persisted"
            ))
        })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "budget transition event sequence must be greater than zero".to_string(),
        )
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget transition event `{event_id}` is not readable"
            ))
        })?;
    if event.event_id != event_id
        || event.event_seq != event_seq
        || event.usage_seq != Some(event_seq)
        || event.kind != kind
        || event.allowed.is_some()
        || event.monetary_state != expected_monetary_state
        || event.invocation_state != BudgetInvocationReservationState::Absent
        || event.capability_id != capability_id
        || event.grant_index != grant_index
        || event.hold_id.as_deref() != hold_id
        || event.exposure_units != exposure_units
        || event.realized_spend_units != realized_spend_units
        || event.authority.as_ref() != authority
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget transition event `{event_id}` does not match the requested mutation"
        )));
    }
    Ok(event)
}

fn load_persisted_capture_event(
    store: &SqliteBudgetStore,
    captured: &BudgetHoldMutationDecision,
    event_id: &str,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let event_seq = captured.metadata.budget_commit_index.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "captured budget decision omitted its persisted commit index".to_string(),
        )
    })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "captured budget event sequence must be greater than zero".to_string(),
        )
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "captured budget event `{event_id}` is not persisted"
            ))
        })?;
    let committed_cost_units_after = event
        .total_cost_exposed_after
        .checked_add(event.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "persisted captured committed cost overflowed u64".to_string(),
            )
        })?;
    if event.event_id != event_id
        || event.event_seq != event_seq
        || event.usage_seq != Some(event_seq)
        || event.kind != BudgetMutationKind::CaptureExposure
        || event.monetary_state != BudgetMonetaryHoldState::Captured
        || event.hold_id != captured.hold_id
        || event.exposure_units != captured.exposure_units
        || event.realized_spend_units != captured.realized_spend_units
        || event.invocation_count_after != captured.invocation_count_after
        || committed_cost_units_after != captured.committed_cost_units_after
        || event.authority != captured.metadata.authority
    {
        return Err(BudgetStoreError::Invariant(format!(
            "captured budget event `{event_id}` does not match its frozen decision"
        )));
    }
    Ok(event)
}

fn resolve_live_terminal_authority(
    operation: &str,
    hold_authority: Option<&BudgetEventAuthority>,
    live_authority: Option<&BudgetEventAuthority>,
) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
    match hold_authority {
        Some(hold_authority) if live_authority == Some(hold_authority) => {
            Ok(Some(hold_authority.clone()))
        }
        Some(_) => Err(BudgetStoreError::Invariant(format!(
            "budget {operation} hold authority does not match the live authority lease"
        ))),
        None => Ok(live_authority.cloned()),
    }
}

fn resolve_budget_hold_authority(
    operation: &str,
    state: &TrustServiceState,
    store: &SqliteBudgetStore,
    hold_id: Option<&str>,
) -> Result<Option<BudgetEventAuthority>, Response> {
    let hold_authority = if let Some(hold_id) = hold_id {
        match store.hold_authority(hold_id) {
            Ok(authority) => authority,
            Err(error) => {
                return Err(plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &error.to_string(),
                ));
            }
        }
    } else {
        None
    };
    let live_authority = current_budget_event_authority(state)?;
    resolve_live_terminal_authority(operation, hold_authority.as_ref(), live_authority.as_ref())
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))
}

#[cfg(test)]
mod budget_handlers_tests {
    use super::{
        budget_authority_metadata_matches_event, compensate_authorize_after_quorum_failure,
        generated_budget_event_id, load_persisted_authorize_event,
        load_persisted_budget_transition, load_persisted_capture_event,
        load_persisted_composite_authorize_event, load_persisted_invocation_capture_event,
        resolve_live_terminal_authority, sqlite_composite_authorize_input,
        verify_requested_budget_authority, BudgetAuthorityMetadataView,
        BudgetAuthorizeHoldDecision, BudgetInvocationAdmissionEvidenceView,
        BudgetInvocationQuotaView, BudgetInvocationReservationState, BudgetMonetaryHoldState,
        BudgetMutationAuthorityView, BudgetMutationKind, BudgetQuotaKeyView,
        BudgetQuotaProfileView, CanonicalRevocationSetView, CaptureInvocationReservationsRequest,
        CompositeBudgetAuthorizeRequest, TryChargeCostRequest,
    };
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::{canonical_json_bytes, sha256_hex};
    use chio_kernel::budget_store::{
        BudgetAdmissionOperationBinding, BudgetCaptureHoldRequest, BudgetCaptureInvocationRequest,
        BudgetEventAuthority,
    };
    use chio_kernel::BudgetStore;
    use chio_store_sqlite::SqliteBudgetStore;
    use chio_test_support::prelude::*;

    fn test_budget_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn generated_budget_event_id_is_unique_per_call() {
        // Each omitted-eventId write must get a distinct id so the mutation event
        // is stored under a known, unique key and the witness can look up THIS
        // write's exact event_seq.
        let first = generated_budget_event_id();
        let second = generated_budget_event_id();
        assert_ne!(first, second, "consecutive ids must differ");
        assert!(first.starts_with("cluster-budget-write-"));
        // A tight burst (same wall-clock nanos possible) is still all-distinct via
        // the monotonic counter.
        let ids: HashSet<String> = (0..10_000).map(|_| generated_budget_event_id()).collect();
        assert_eq!(ids.len(), 10_000, "all minted ids must be unique");
    }

    #[test]
    fn composite_handler_conversion_preserves_persisted_quota_and_capture_evidence() {
        let path = test_budget_path("chio-handler-composite-wire");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let ids = vec!["cap-composite".to_string(), "cap-root".to_string()];
        let canonical = canonical_json_bytes(&ids).test_unwrap();
        let mut digest_input = b"chio.revocation-set.v1\0".to_vec();
        digest_input.extend_from_slice(&canonical);
        let payload = CompositeBudgetAuthorizeRequest {
            operation_id: "operation-budget".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            requested_exposure_units: 10,
            max_exposure_per_invocation: Some(20),
            max_total_exposure_units: Some(100),
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:authorize".to_string(),
            admission_evidence: BudgetInvocationAdmissionEvidenceView {
                invocation_quotas: vec![
                    BudgetInvocationQuotaView {
                        key: BudgetQuotaKeyView {
                            profile: BudgetQuotaProfileView::GrantInvocation,
                            owner_id: "cap-composite".to_string(),
                            grant_index: Some(0),
                        },
                        max_invocations: 3,
                    },
                    BudgetInvocationQuotaView {
                        key: BudgetQuotaKeyView {
                            profile: BudgetQuotaProfileView::AggregateFamilyInvocation,
                            owner_id: "22".repeat(32),
                            grant_index: None,
                        },
                        max_invocations: 2,
                    },
                ],
                revocation_set: CanonicalRevocationSetView {
                    ids,
                    digest: sha256_hex(&digest_input),
                },
                aggregate_root_capability_id: Some("cap-root".to_string()),
                aggregate_binding_digest: Some("44".repeat(32)),
                supplemental_binding: None,
            },
        };
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        let prepared = sqlite_composite_authorize_input(&payload, authority.clone()).test_unwrap();
        assert_eq!(prepared.input().authority.as_ref(), Some(&authority));
        assert_eq!(prepared.input().invocation_quotas.len(), 2);
        assert_eq!(
            prepared.input().revocation_set.digest(),
            payload.admission_evidence.revocation_set.digest
        );
        let decision = prepared.authorize(&store).test_unwrap();
        let event =
            load_persisted_composite_authorize_event(&store, &payload, &decision).test_unwrap();
        assert_eq!(event.kind, BudgetMutationKind::ReserveInvocations);
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = &decision else {
            panic!("expected composite authorization");
        };
        assert_eq!(authorized.invocation_counts_after.len(), 2);
        assert_eq!(
            event.invocation_state,
            BudgetInvocationReservationState::Authorized
        );
        assert_eq!(event.monetary_state, BudgetMonetaryHoldState::Exposed);

        let capture_payload = CaptureInvocationReservationsRequest {
            operation_id: "operation-budget".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            hold_id: payload.hold_id.clone(),
            event_id: "hold-composite:capture-invocations".to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
        };
        let captured = store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                admission_operation: Some(
                    BudgetAdmissionOperationBinding::new(
                        capture_payload.operation_id.clone(),
                        capture_payload.request_binding_hash.clone(),
                    )
                    .test_unwrap(),
                ),
                capability_id: capture_payload.capability_id.clone(),
                grant_index: capture_payload.grant_index,
                hold_id: Some(capture_payload.hold_id.clone()),
                event_id: Some(capture_payload.event_id.clone()),
                authority: Some(authority),
            })
            .test_unwrap();
        let capture_event =
            load_persisted_invocation_capture_event(&store, &capture_payload, &captured)
                .test_unwrap();
        assert_eq!(capture_event.kind, BudgetMutationKind::CaptureInvocations);
        assert_eq!(
            capture_event.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);

        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn requested_transition_authority_must_match_the_server_resolved_authority() {
        let resolved = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert_eq!(
            verify_requested_budget_authority("capture", Some(&resolved), Some(resolved.clone()),)
                .test_unwrap(),
            Some(resolved.clone())
        );

        let mismatched = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-8".to_string(),
            lease_epoch: 8,
        };
        for operation in ["reverse", "release", "reconcile", "capture"] {
            let error = verify_requested_budget_authority(
                operation,
                Some(&mismatched),
                Some(resolved.clone()),
            )
            .test_expect_err("transition authority mismatch must fail closed");
            let message = error.to_string();
            assert!(message.contains(operation));
            assert!(message.contains("does not match the server-resolved authority"));
        }
    }

    #[test]
    fn terminal_live_authority_mismatch_is_rejected_before_store_mutation() {
        let path = test_budget_path("chio-handler-terminal-live-authority");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let hold_authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "budget-primary#term-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-terminal-authority",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-terminal-authority"),
                Some("hold-terminal-authority:authorize"),
                Some(&hold_authority),
            )
            .test_unwrap());
        let usage_before = store
            .get_usage("cap-terminal-authority", 0)
            .test_unwrap()
            .test_unwrap();
        let events_before = store
            .list_mutation_events(100, Some("cap-terminal-authority"), Some(0))
            .test_unwrap();

        let next_authority = BudgetEventAuthority {
            authority_id: "budget-secondary".to_string(),
            lease_id: "budget-secondary#term-8".to_string(),
            lease_epoch: 8,
        };
        for live in [None, Some(&next_authority)] {
            let error = resolve_live_terminal_authority("capture", Some(&hold_authority), live)
                .test_expect_err("detached or changed authority must fail closed");
            assert!(error.to_string().contains("live authority lease"));
            assert_eq!(
                store
                    .get_usage("cap-terminal-authority", 0)
                    .test_unwrap()
                    .test_unwrap(),
                usage_before
            );
            assert_eq!(
                store
                    .list_mutation_events(100, Some("cap-terminal-authority"), Some(0))
                    .test_unwrap(),
                events_before
            );
        }

        assert_eq!(
            resolve_live_terminal_authority(
                "capture",
                Some(&hold_authority),
                Some(&hold_authority),
            )
            .test_unwrap(),
            Some(hold_authority)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_authority_metadata_never_splices_a_different_live_lease() {
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "budget-primary#term-7".to_string(),
            lease_epoch: 7,
        };
        let mut metadata = BudgetAuthorityMetadataView {
            authority_id: authority.authority_id.clone(),
            leader_url: authority.authority_id.clone(),
            budget_term: authority.lease_epoch,
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
            lease_expires_at: 5_000,
            lease_ttl_ms: 750,
            guarantee_level: "ha_quorum_commit".to_string(),
            budget_commit_index: Some(42),
        };
        assert!(budget_authority_metadata_matches_event(
            &metadata, &authority
        ));

        metadata.leader_url = "budget-secondary".to_string();
        assert!(!budget_authority_metadata_matches_event(
            &metadata, &authority
        ));
        metadata.leader_url.clone_from(&authority.authority_id);
        metadata.lease_expires_at = 9_000;
        metadata.lease_epoch = 8;
        assert!(!budget_authority_metadata_matches_event(
            &metadata, &authority
        ));
    }

    #[test]
    fn persisted_authorize_retry_never_runs_fresh_write_compensation() {
        let compensation_calls = std::cell::Cell::new(0_u32);
        let compensated = compensate_authorize_after_quorum_failure(false, None, None, || {
            compensation_calls.set(compensation_calls.get() + 1);
            Ok(())
        })
        .test_unwrap();
        assert!(!compensated);
        assert_eq!(compensation_calls.get(), 0);

        let compensated = compensate_authorize_after_quorum_failure(true, None, None, || {
            compensation_calls.set(compensation_calls.get() + 1);
            Ok(())
        })
        .test_unwrap();
        assert!(compensated);
        assert_eq!(compensation_calls.get(), 1);
    }

    #[test]
    fn stale_term_quorum_failure_cannot_restore_usage_or_append_reverse() {
        let path = test_budget_path("chio-handler-stale-term-compensation");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let old_authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "budget-primary#term-7".to_string(),
            lease_epoch: 7,
        };
        let next_authority = BudgetEventAuthority {
            authority_id: "budget-secondary".to_string(),
            lease_id: "budget-secondary#term-8".to_string(),
            lease_epoch: 8,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-stale-compensation",
                0,
                Some(1),
                100,
                Some(100),
                Some(100),
                Some("hold-stale-compensation"),
                Some("hold-stale-compensation:authorize"),
                Some(&old_authority),
            )
            .test_unwrap());
        let usage_before = store
            .get_usage("cap-stale-compensation", 0)
            .test_unwrap()
            .test_unwrap();
        let events_before = store
            .list_mutation_events(10, Some("cap-stale-compensation"), Some(0))
            .test_unwrap();
        let compensation_calls = std::cell::Cell::new(0_u32);

        let error = compensate_authorize_after_quorum_failure(
            true,
            Some(&old_authority),
            Some(&next_authority),
            || {
                compensation_calls.set(compensation_calls.get() + 1);
                store.reverse_charge_cost_with_ids_and_authority(
                    "cap-stale-compensation",
                    0,
                    100,
                    Some("hold-stale-compensation"),
                    Some("hold-stale-compensation:rollback"),
                    Some(&old_authority),
                )
            },
        )
        .test_expect_err("stale-term compensation must fail closed");
        assert!(error.to_string().contains("live authority lease"));
        assert_eq!(compensation_calls.get(), 0);
        assert_eq!(
            store
                .get_usage("cap-stale-compensation", 0)
                .test_unwrap()
                .test_unwrap(),
            usage_before
        );
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-stale-compensation"), Some(0))
                .test_unwrap(),
            events_before
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_allowed_authorize_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-authorize-allowed-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        let request = TryChargeCostRequest {
            capability_id: "cap-authorize-allowed".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            cost_units: 100,
            max_cost_per_invocation: Some(200),
            max_total_cost_units: Some(1_000),
            hold_id: Some("hold-authorize-allowed-0".to_string()),
            event_id: Some("hold-authorize-allowed-0:authorize".to_string()),
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-authorize-allowed",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-authorize-allowed-1"),
                Some("hold-authorize-allowed-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());

        let snapshot = load_persisted_authorize_event(
            &store,
            "hold-authorize-allowed-0:authorize",
            &request,
            true,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 100);
        assert_eq!(snapshot.total_cost_realized_spend_after, 0);
        let current = store
            .get_usage("cap-authorize-allowed", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 110);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_denied_authorize_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-authorize-denied-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-authorize-denied",
                0,
                Some(10),
                80,
                Some(100),
                Some(100),
                Some("hold-authorize-denied-base"),
                Some("hold-authorize-denied-base:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        let request = TryChargeCostRequest {
            capability_id: "cap-authorize-denied".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            cost_units: 30,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(100),
            hold_id: Some("hold-authorize-denied-attempt".to_string()),
            event_id: Some("hold-authorize-denied-attempt:authorize".to_string()),
        };
        assert!(!store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-authorize-denied",
                0,
                20,
                Some("hold-authorize-denied-base"),
                Some("hold-authorize-denied-base:release"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(!store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());

        let snapshot = load_persisted_authorize_event(
            &store,
            "hold-authorize-denied-attempt:authorize",
            &request,
            false,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 80);
        assert_eq!(snapshot.total_cost_realized_spend_after, 0);
        let current = store
            .get_usage("cap-authorize-denied", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 1);
        assert_eq!(current.total_cost_exposed, 60);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_capture_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-capture-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-capture",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-capture-0"),
                Some("hold-capture-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        let captured = store
            .capture_budget_hold(BudgetCaptureHoldRequest {
                admission_operation: None,
                capability_id: "cap-capture".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 70,
                hold_id: Some("hold-capture-0".to_string()),
                event_id: Some("hold-capture-0:capture".to_string()),
                authority: Some(authority.clone()),
            })
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-capture",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-capture-1"),
                Some("hold-capture-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());

        let snapshot =
            load_persisted_capture_event(&store, &captured, "hold-capture-0:capture").test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 0);
        assert_eq!(snapshot.total_cost_realized_spend_after, 70);
        assert_eq!(
            snapshot.authority.as_ref(),
            captured.metadata.authority.as_ref()
        );
        let current = store
            .get_usage("cap-capture", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 10);
        assert_eq!(current.total_cost_realized_spend, 70);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_reverse_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-reverse-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-reverse-0"),
                Some("hold-reverse-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                100,
                Some("hold-reverse-0"),
                Some("hold-reverse-0:reverse"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-reverse-1"),
                Some("hold-reverse-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                100,
                Some("hold-reverse-0"),
                Some("hold-reverse-0:reverse"),
                Some(&authority),
            )
            .test_unwrap();

        let snapshot = load_persisted_budget_transition(
            &store,
            "hold-reverse-0:reverse",
            BudgetMutationKind::ReverseExposure,
            "cap-reverse",
            0,
            Some("hold-reverse-0"),
            100,
            0,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 0);
        assert_eq!(snapshot.total_cost_exposed_after, 0);
        let current = store
            .get_usage("cap-reverse", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 1);
        assert_eq!(current.total_cost_exposed, 10);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_release_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-release-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-release-0"),
                Some("hold-release-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                25,
                Some("hold-release-0"),
                Some("hold-release-0:release"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-release-1"),
                Some("hold-release-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                25,
                Some("hold-release-0"),
                Some("hold-release-0:release"),
                Some(&authority),
            )
            .test_unwrap();

        let snapshot = load_persisted_budget_transition(
            &store,
            "hold-release-0:release",
            BudgetMutationKind::ReleaseExposure,
            "cap-release",
            0,
            Some("hold-release-0"),
            25,
            0,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 75);
        let current = store
            .get_usage("cap-release", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 85);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_reconcile_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-reconcile-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-reconcile-0"),
                Some("hold-reconcile-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .settle_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                100,
                70,
                Some("hold-reconcile-0"),
                Some("hold-reconcile-0:reconcile"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-reconcile-1"),
                Some("hold-reconcile-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .settle_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                100,
                70,
                Some("hold-reconcile-0"),
                Some("hold-reconcile-0:reconcile"),
                Some(&authority),
            )
            .test_unwrap();

        let snapshot = load_persisted_budget_transition(
            &store,
            "hold-reconcile-0:reconcile",
            BudgetMutationKind::ReconcileSpend,
            "cap-reconcile",
            0,
            Some("hold-reconcile-0"),
            100,
            70,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 0);
        assert_eq!(snapshot.total_cost_realized_spend_after, 70);
        let current = store
            .get_usage("cap-reconcile", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 10);
        assert_eq!(current.total_cost_realized_spend, 70);

        let _ = fs::remove_file(path);
    }
}
