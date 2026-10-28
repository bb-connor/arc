use super::*;

const AUTHORITY: &str = "store-uuid-1";

fn fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: AUTHORITY.to_owned(),
        lease_id: "lease-1".to_owned(),
        owner_epoch: 1,
    }
}

fn record(previous: Option<&StopEpochV1>, transition: StopTransition) -> StopEpochV1 {
    let (expected_epoch, previous_digest) = match previous {
        None => (StopEpochId::GENESIS, STOP_ZERO_DIGEST.to_owned()),
        Some(previous) => (previous.id(), previous.digest().unwrap()),
    };
    StopEpochV1 {
        schema: STOP_EPOCH_SCHEMA.to_owned(),
        authority_id: AUTHORITY.to_owned(),
        scope: StopScope::Kernel,
        chain_generation: 1,
        epoch: expected_epoch.epoch + 1,
        transition,
        state: transition.resulting_state(),
        expected_epoch,
        reason_commitment: stop_reason_commitment(b"salt", "drill"),
        authorizer: StopAuthorizer::shared_credential("test"),
        decided_at: DecisionTime::Observed(1_800_000_000_000),
        trusted_floor_at_commit: 1_800_000_000_000,
        previous: previous_digest,
        allow_containment: true,
        requested_via: StopRequestPath::ControlSocket,
    }
}

/// The chain rules of the SQLite writer, held in memory.
#[derive(Default)]
struct MemoryStopStore {
    records: Mutex<Vec<StopEpochV1>>,
    fail_appends: AtomicBool,
    fail_loads: AtomicBool,
    withheld: AtomicU64,
    fail_counts: AtomicBool,
}

impl DurableStopStore for MemoryStopStore {
    fn load_stop_head(&self, scope: StopScope) -> Result<Option<StopEpochV1>, DurableStopError> {
        if self.fail_loads.load(Ordering::SeqCst) {
            return Err(StopChainError("corrupt".to_owned()).into());
        }
        let records = self.records.lock().unwrap();
        Ok(verify_stop_chain(AUTHORITY, scope, &records)?.cloned())
    }

    fn append_stop_transition(
        &self,
        request: &StopTransitionRequest,
        _fence: &StoreMutationFence,
    ) -> Result<Option<StopEpochV1>, DurableStopError> {
        if self.fail_appends.load(Ordering::SeqCst) {
            return Err(AdmissionOperationStoreError::Unavailable(
                "disk full at /private/stop-store.db".to_owned(),
            )
            .into());
        }
        let mut records = self.records.lock().unwrap();
        let head = verify_stop_chain(AUTHORITY, request.scope, &records)?.cloned();
        let state = head.as_ref().map_or(StopState::Running, |head| head.state);
        if state == request.transition.resulting_state() {
            return Ok(head);
        }
        if request.transition == StopTransition::Resume
            && request.expected_epoch != head.as_ref().map(StopEpochV1::id)
        {
            return Err(DurableStopError::HeadMoved {
                head: head.as_ref().map(StopEpochV1::id),
            });
        }
        let next = record(head.as_ref(), request.transition);
        records.push(next.clone());
        Ok(Some(next))
    }

    fn withheld_operations(&self) -> Result<u64, DurableStopError> {
        if self.fail_counts.load(Ordering::SeqCst) {
            return Err(AdmissionOperationStoreError::Unavailable("disk full".to_owned()).into());
        }
        Ok(self.withheld.load(Ordering::SeqCst))
    }
}

fn stop_command(reason: &str) -> StopCommand {
    StopCommand {
        reason: reason.to_owned(),
        authorizer: StopAuthorizer::shared_credential("test"),
        requested_via: StopRequestPath::ControlSocket,
        allow_containment: true,
    }
}

fn resume_command(expected_epoch: Option<StopEpochId>) -> ResumeCommand {
    ResumeCommand {
        expected_epoch,
        authorizer: StopAuthorizer::shared_credential("test"),
        requested_via: StopRequestPath::ControlSocket,
    }
}

#[test]
fn chain_accepts_alternating_transitions() {
    let first = record(None, StopTransition::Stop);
    let second = record(Some(&first), StopTransition::Resume);
    let third = record(Some(&second), StopTransition::Stop);
    let chain = [first, second, third.clone()];
    assert_eq!(
        verify_stop_chain(AUTHORITY, StopScope::Kernel, &chain).unwrap(),
        Some(&third)
    );
}

#[test]
fn chain_rejects_gaps_forks_repeats_and_foreign_records() {
    let first = record(None, StopTransition::Stop);
    let second = record(Some(&first), StopTransition::Resume);

    let mut gap = second.clone();
    gap.epoch = 3;
    let mut fork = second.clone();
    fork.previous = STOP_ZERO_DIGEST.to_owned();
    let repeat = record(Some(&first), StopTransition::Stop);
    let mut foreign = second.clone();
    foreign.authority_id = "another-store".to_owned();
    let mut wrong_schema = second.clone();
    wrong_schema.schema = "chio.stop-epoch.v0".to_owned();
    let mut clockless_resume = second.clone();
    clockless_resume.decided_at = DecisionTime::Unavailable;
    let mut inconsistent_state = second.clone();
    inconsistent_state.state = StopState::Stopped;

    for (bad, detail) in [
        (gap, "stop chain epoch is not contiguous"),
        (fork, "stop record does not extend its predecessor"),
        (repeat, "stop record repeats its predecessor's state"),
        (foreign, "stop record belongs to another authority"),
        (wrong_schema, "stop record schema is not chio.stop-epoch.v1"),
        (
            clockless_resume,
            "a resume requires observed authority time",
        ),
        (
            inconsistent_state,
            "stop record state does not follow its transition",
        ),
    ] {
        let chain = [first.clone(), bad];
        assert_eq!(
            verify_stop_chain(AUTHORITY, StopScope::Kernel, &chain),
            Err(StopChainError(detail.to_owned()))
        );
    }
    let opening_resume = record(None, StopTransition::Resume);
    assert_eq!(
        verify_stop_chain(AUTHORITY, StopScope::Kernel, &[opening_resume]),
        Err(StopChainError(
            "stop record repeats its predecessor's state".to_owned()
        ))
    );
}

#[test]
fn a_stop_without_authority_time_is_valid() {
    let mut stop = record(None, StopTransition::Stop);
    stop.decided_at = DecisionTime::Unavailable;
    assert!(verify_stop_chain(AUTHORITY, StopScope::Kernel, &[stop]).is_ok());
}

#[test]
fn durable_stop_survives_rebinding_and_resume_clears_it() {
    let store = Arc::new(MemoryStopStore::default());
    let control = StopControl::durable(&store, fence());
    assert!(!control.heads().is_stopped());

    let status = control.stop(stop_command("incident")).unwrap();
    assert!(status.stopped);
    assert_eq!(status.durability, "durable");
    assert_eq!(status.readiness, StopReadiness::ReadyStopped);
    let head = status.head.unwrap();
    assert_eq!((head.chain_generation, head.epoch), (1, 1));

    let restarted = StopControl::durable(&store, fence());
    assert!(restarted.heads().is_stopped());
    assert_eq!(restarted.status().readiness, StopReadiness::ReadyStopped);

    let resumed = restarted
        .resume(resume_command(Some(StopEpochId {
            chain_generation: 1,
            epoch: 1,
        })))
        .unwrap();
    assert!(!resumed.stopped);
    assert!(!StopControl::durable(&store, fence()).heads().is_stopped());
}

#[test]
fn a_repeated_stop_appends_nothing() {
    let store = Arc::new(MemoryStopStore::default());
    let control = StopControl::durable(&store, fence());
    control.stop(stop_command("first")).unwrap();
    control.stop(stop_command("second")).unwrap();
    assert_eq!(store.records.lock().unwrap().len(), 1);
}

#[test]
fn resume_against_a_moved_head_is_refused() {
    let store = Arc::new(MemoryStopStore::default());
    let control = StopControl::durable(&store, fence());
    control.stop(stop_command("incident")).unwrap();
    for stale in [None, Some(StopEpochId::GENESIS)] {
        assert!(matches!(
            control.resume(resume_command(stale)),
            Err(StopControlError::HeadMoved {
                head: Some(StopEpochId {
                    chain_generation: 1,
                    epoch: 1
                })
            })
        ));
        assert!(control.heads().is_stopped());
    }
}

#[test]
fn a_failed_durable_append_still_stops_this_process() {
    let store = Arc::new(MemoryStopStore::default());
    store.fail_appends.store(true, Ordering::SeqCst);
    let control = StopControl::durable(&store, fence());
    let Err(StopControlError::NotDurable { status, .. }) = control.stop(stop_command("incident"))
    else {
        panic!("a failed append must report a non-durable stop");
    };
    assert!(status.stopped);
    assert_eq!(status.durability, "process_only");
    assert!(control.heads().is_stopped());

    assert!(matches!(
        control.resume(resume_command(None)),
        Err(StopControlError::Refused(detail)) if detail.contains("disk full")
    ));
    assert!(control.heads().is_stopped());
    store.fail_appends.store(false, Ordering::SeqCst);
    assert!(!control.resume(resume_command(None)).unwrap().stopped);
}

#[test]
fn an_unverified_chain_fails_closed_and_refuses_resume() {
    let store = Arc::new(MemoryStopStore::default());
    store.fail_loads.store(true, Ordering::SeqCst);
    let control = StopControl::durable(&store, fence());
    assert!(control.heads().is_stopped());
    let status = control.status();
    assert_eq!(status.durability, "unverified");
    assert_eq!(
        status.readiness,
        StopReadiness::NotReady {
            reason: "stop_chain_unverified".to_owned()
        }
    );
    assert!(matches!(
        control.resume(resume_command(None)),
        Err(StopControlError::NotReady(_))
    ));
    assert!(control.heads().is_stopped());
}

#[test]
fn clones_share_one_stop() {
    let control = StopControl::process_local();
    let other = control.clone();
    control.stop(stop_command("incident")).unwrap();
    assert!(other.heads().is_stopped());
    assert_eq!(other.status().durability, "process_local");
    other.resume(resume_command(None)).unwrap();
    assert!(!control.heads().is_stopped());
}

#[test]
fn the_host_latch_is_independent_of_operator_resume() {
    let store = Arc::new(MemoryStopStore::default());
    let control = StopControl::durable(&store, fence());
    control.heads().latch_host("broker failed");
    assert!(control.status().host_latch);
    control.resume(resume_command(None)).unwrap();
    assert!(control.heads().is_stopped());
    control.heads().release_host_latch();
    assert!(!control.heads().is_stopped());
}

#[test]
fn stop_reasons_are_bounded() {
    let control = StopControl::process_local();
    for reason in ["", "  ", "line\nbreak"] {
        assert!(matches!(
            control.stop(stop_command(reason)),
            Err(StopControlError::BadRequest(_))
        ));
    }
    let long = "x".repeat(MAX_STOP_REASON_BYTES + 1);
    assert!(matches!(
        control.stop(stop_command(&long)),
        Err(StopControlError::BadRequest(detail)) if detail == "stop reason is too long"
    ));
    assert!(!control.heads().is_stopped());
}

#[test]
fn a_control_does_not_keep_its_store_open() {
    let store = Arc::new(MemoryStopStore::default());
    let control = StopControl::durable(&store, fence());
    drop(store);

    let Err(StopControlError::NotDurable { detail, status }) =
        control.stop(stop_command("incident"))
    else {
        panic!("a stop without its store must report a non-durable stop");
    };
    assert_eq!(detail, "stop store is closed");
    assert!(status.stopped);
    assert_eq!(status.withheld_operations, None);
    assert!(control.heads().is_stopped());
    assert!(matches!(
        control.resume(resume_command(None)),
        Err(StopControlError::NotReady(detail)) if detail == "stop store is closed"
    ));
    assert!(control.heads().is_stopped());
}

#[test]
fn a_stopped_status_counts_withheld_operations() {
    let store = Arc::new(MemoryStopStore::default());
    store.withheld.store(3, Ordering::SeqCst);
    let control = StopControl::durable(&store, fence());
    assert_eq!(control.status().withheld_operations, None);

    let stopped = control.stop(stop_command("incident")).unwrap();
    assert_eq!(stopped.withheld_operations, Some(3));
    let body = serde_json::to_value(&stopped).unwrap();
    assert_eq!(body["withheld_operations"], 3);

    store.fail_counts.store(true, Ordering::SeqCst);
    let unreadable = control.status();
    assert!(unreadable.stopped);
    assert_eq!(unreadable.withheld_operations, None);
    assert!(serde_json::to_value(&unreadable)
        .unwrap()
        .get("withheld_operations")
        .is_none());
    store.fail_counts.store(false, Ordering::SeqCst);

    let head = stopped.head.unwrap();
    let resumed = control
        .resume(resume_command(Some(StopEpochId {
            chain_generation: head.chain_generation,
            epoch: head.epoch,
        })))
        .unwrap();
    assert_eq!(resumed.withheld_operations, None);

    let local = StopControl::process_local();
    let stopped = local.stop(stop_command("incident")).unwrap();
    assert!(stopped.stopped);
    assert_eq!(stopped.withheld_operations, None);
}

#[test]
fn failed_stop_and_resume_keep_store_details_out_of_wire_bodies() {
    let store = Arc::new(MemoryStopStore::default());
    store.fail_appends.store(true, Ordering::SeqCst);
    let control = StopControl::durable(&store, fence());
    let stopped = control.stop(stop_command("incident")).unwrap_err();
    assert!(
        matches!(&stopped, StopControlError::NotDurable { detail, .. } if detail.contains("disk full"))
    );
    assert_eq!(stopped.http_status(), 503);
    let body = stopped.body();
    assert_eq!(
        body,
        serde_json::json!({
            "error": "stop_not_durable",
            "message": "Stop holds in this process but could not be made durable.",
            "urn": "urn:chio:error:kernel:stop-not-durable",
            "status": {
                "scope": {"kind": "kernel"}, "stopped": true,
                "readiness": {"state": "ready_stopped"},
                "durability": "process_only", "host_latch": false,
                "withheld_operations": 0
            }
        })
    );
    assert!(!body.to_string().contains("disk full"));
    assert!(!body.to_string().contains("/private/stop-store.db"));

    let refused = control.resume(resume_command(None)).unwrap_err();
    assert!(matches!(&refused, StopControlError::Refused(detail) if detail.contains("disk full")));
    assert_eq!(refused.http_status(), 503);
    assert_eq!(
        refused.body(),
        serde_json::json!({
            "error": "resume_refused",
            "message": "Resume was refused.",
            "urn": "urn:chio:error:kernel:resume-refused"
        })
    );
    assert!(control.heads().is_stopped());
}

#[test]
fn control_refusal_bodies_preserve_codes_and_conflict_heads_without_diagnostics() {
    for (error, status, expected) in [
        (
            StopControlError::BadRequest("private request diagnostic".to_owned()),
            400,
            serde_json::json!({"error": "bad_request", "message": "Invalid stop request.", "urn": "urn:chio:error:kernel:stop-bad-request"}),
        ),
        (
            StopControlError::NotReady("private readiness diagnostic".to_owned()),
            503,
            serde_json::json!({"error": "stop_not_ready", "message": "Stop control is not ready.", "urn": "urn:chio:error:kernel:stop-not-ready"}),
        ),
        (
            StopControlError::HeadMoved {
                head: Some(StopEpochId {
                    chain_generation: 1,
                    epoch: 7,
                }),
            },
            409,
            serde_json::json!({"error": "stop_head_moved", "message": "Stop head moved.", "urn": "urn:chio:error:kernel:stop-head-moved", "head": {"chain_generation": 1, "epoch": 7}}),
        ),
        (
            StopControlError::HeadMoved { head: None },
            409,
            serde_json::json!({"error": "stop_head_moved", "message": "Stop head moved.", "urn": "urn:chio:error:kernel:stop-head-moved", "head": null}),
        ),
    ] {
        assert_eq!(error.http_status(), status);
        assert_eq!(error.body(), expected);
    }
}
