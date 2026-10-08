//! The mediation kernel is shared, not locked: a slow kernel call occupies one
//! blocking worker, and only requests for the same request id wait for it.
use super::*;
use std::sync::{Condvar, Mutex as StdMutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct GateState {
    closed: bool,
    entered: bool,
}

/// Parks the kernel calls that pass through it for one capability until
/// released.
struct Gate {
    capability_id: String,
    state: StdMutex<GateState>,
    changed: Condvar,
}

impl Gate {
    fn new(capability_id: &str) -> Arc<Self> {
        Arc::new(Self {
            capability_id: capability_id.to_owned(),
            state: StdMutex::new(GateState::default()),
            changed: Condvar::new(),
        })
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.entered = false;
    }

    fn release(&self) {
        self.state.lock().unwrap().closed = false;
        self.changed.notify_all();
    }

    fn pass(&self, capability_id: &str) {
        if capability_id != self.capability_id {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if state.closed {
            state.entered = true;
            self.changed.notify_all();
            while state.closed {
                state = self.changed.wait(state).unwrap();
            }
        }
    }

    async fn wait_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.state.lock().unwrap().entered {
            assert!(
                Instant::now() < deadline,
                "the gated kernel call never reached its gate"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// A pre-invocation guard that parks one capability's evaluation.
struct GatedGuard(Arc<Gate>);

impl chio_kernel::Guard for GatedGuard {
    fn name(&self) -> &str {
        "test-gate"
    }

    fn evaluate(
        &self,
        ctx: &chio_kernel::GuardContext,
    ) -> Result<chio_kernel::GuardDecision, chio_kernel::KernelError> {
        self.0.pass(&ctx.request.capability.id);
        Ok(chio_kernel::GuardDecision::allow())
    }
}

/// A revocation store that parks one capability's lookup and revokes nothing.
struct GatedRevocations(Arc<Gate>);

impl chio_kernel::RevocationStore for GatedRevocations {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, chio_kernel::RevocationStoreError> {
        self.0.pass(capability_id);
        Ok(false)
    }

    fn revoke(&self, _capability_id: &str) -> Result<bool, chio_kernel::RevocationStoreError> {
        Ok(false)
    }
}

/// Configure the fresh state's kernel before it serves anything.
fn configured_state(
    signer: Keypair,
    budget: Arc<dyn BudgetStore>,
    configure: impl FnOnce(&mut ChioKernel),
) -> Arc<ProxyState> {
    let mut state = mediated_test_state(signer, budget, Vec::new());
    configure(
        Arc::get_mut(&mut state)
            .and_then(|state| state.mediation_kernel.as_mut())
            .and_then(Arc::get_mut)
            .expect("a fresh state owns its kernel"),
    );
    state
}

fn reserve_body(capability: &CapabilityToken, request_id: &str) -> serde_json::Value {
    serde_json::json!({
        "capability": capability,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": request_id },
        "request_id": request_id,
    })
}

fn spawn_evaluate(
    state: &Arc<ProxyState>,
    body: serde_json::Value,
) -> tokio::task::JoinHandle<(StatusCode, serde_json::Value)> {
    let state = Arc::clone(state);
    tokio::spawn(async move { post_evaluate(state, &body).await })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_slow_kernel_call_does_not_block_an_unrelated_reservation() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let slow = issue_invocation_capability(&issuer, &agent, "cost-srv", "compute", 1);
    let fast = issue_invocation_capability(&issuer, &agent, "cost-srv", "compute", 1);
    let gate = Gate::new(&slow.id);
    let guard = GatedGuard(Arc::clone(&gate));
    let state = configured_state(signer, budget, |kernel| kernel.add_guard(Box::new(guard)));
    gate.close();

    let parked = spawn_evaluate(&state, reserve_body(&slow, "slow-call"));
    gate.wait_entered().await;
    let (status, reply) = tokio::time::timeout(
        Duration::from_secs(5),
        post_evaluate(Arc::clone(&state), &reserve_body(&fast, "unrelated-call")),
    )
    .await
    .expect("an unrelated reservation must not wait for a parked kernel call");
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["status"], "reserved", "{reply}");
    assert!(
        !parked.is_finished(),
        "the slow kernel call is still parked"
    );

    gate.release();
    let (status, reply) = parked.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["status"], "reserved", "{reply}");
    assert_eq!(state.minted_request_ids.lock().unwrap().len(), 2);
    assert_eq!(state.request_flights.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_concurrent_reservations_admit_exactly_the_invocation_budget() {
    const BUDGET: u32 = 8;
    const CALLERS: usize = 12;
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let capability = issue_invocation_capability(&issuer, &agent, "cost-srv", "compute", BUDGET);
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

    let calls: Vec<_> = (0..CALLERS)
        .map(|caller| {
            spawn_evaluate(
                &state,
                reserve_body(&capability, &format!("caller-{caller}")),
            )
        })
        .collect();
    let mut reserved = 0;
    let mut denied = 0;
    for call in calls {
        let (status, reply) = tokio::time::timeout(Duration::from_secs(30), call)
            .await
            .expect("every concurrent reservation must complete")
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{reply}");
        match reply["status"].as_str() {
            Some("reserved") => reserved += 1,
            Some("deny") => denied += 1,
            other => panic!("unexpected mediated status {other:?}: {reply}"),
        }
    }
    assert_eq!(reserved, BUDGET as usize);
    assert_eq!(denied, CALLERS - BUDGET as usize);
    let usage = budget.get_usage(&capability.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, BUDGET);
    assert_eq!(
        state.minted_request_ids.lock().unwrap().len(),
        BUDGET as usize,
        "only reserved ids keep their claims"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_same_request_id_waits_for_its_in_flight_owner() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let gated = issue_invocation_capability(&issuer, &agent, "cost-srv", "compute", 1);
    let fresh = issue_invocation_capability(&issuer, &agent, "cost-srv", "compute", 1);
    let gate = Gate::new(&gated.id);
    let revocations: Arc<dyn chio_kernel::RevocationStore> =
        Arc::new(GatedRevocations(Arc::clone(&gate)));
    let state = configured_state(signer, Arc::clone(&budget), |kernel| {
        kernel.set_revocation_store_handle(revocations)
    });
    gate.close();

    // The id's first owner is parked in the kernel's revocation lookup and is
    // then denied for a tool outside its scope, so it places no hold.
    let mut unscoped = reserve_body(&gated, "shared-id");
    unscoped["tool_name"] = serde_json::json!("unlisted");
    let first = spawn_evaluate(&state, unscoped);
    gate.wait_entered().await;
    let second = spawn_evaluate(&state, reserve_body(&fresh, "shared-id"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !second.is_finished(),
        "a second request for a live id waits for its owner instead of racing it"
    );

    gate.release();
    let (status, first) = first.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["status"], "deny", "{first}");
    assert!(budget.get_usage(&gated.id, 0).unwrap().is_none());
    // The denied owner released its claim before its flight ended, so the
    // waiter is evaluated exactly as a request arriving afterwards would be.
    let (status, second) = second.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["status"], "reserved", "{second}");
    assert_eq!(state.minted_request_ids.lock().unwrap().len(), 1);
    assert_eq!(state.request_flights.len(), 0);
}
