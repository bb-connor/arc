//! Local demonstration only: fixed fixture keys, in-process tools and simulated payment.
use chio_core::{
    capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    crypto::{sha256_hex, Keypair},
};
use chio_kernel::*;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};
use chio_workflow::delegation::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

mod bank;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn key(n: u8) -> Keypair {
    Keypair::from_seed(&[n; 32])
}
pub fn now() -> Result<u64> {
    Ok(chio_test_support::clock::clock().unix_millis()?.as_secs())
}
pub fn slot(id: &str, holder: u8, units: u64, depth: u16) -> Result<WorkSlot> {
    Ok(WorkSlot {
        id: id.into(),
        holder: key(holder).public_key(),
        contract: WorkContract {
            effects: BTreeSet::from([Effect {
                server: "research".into(),
                tool: "analyze".into(),
            }]),
            readers: (1..=5).map(|n| key(n).public_key().to_hex()).collect(),
            max_units: units,
            currency: "USD".into(),
            expires_at: now()? + 3600,
            depth,
            acceptance: Acceptance {
                clauses: vec![Clause::IntegerRange {
                    pointer: "/count".into(),
                    min: 1,
                    max: 10,
                }],
            },
        },
    })
}
pub fn split(store: &DelegationStore, parent: &str, holder: u8, mut child: WorkSlot) -> Result {
    child.contract.expires_at = child
        .contract
        .expires_at
        .min(store.slot(parent)?.contract.expires_at);
    store.subdivide(
        &Signed::sign(
            Subdivision {
                parent_id: parent.into(),
                parent_allocation_hash: store.allocation_digest(parent)?,
                child,
            },
            &key(holder),
        )?,
        now()?,
    )?;
    Ok(())
}
struct Tool {
    calls: Arc<AtomicUsize>,
    bad: bool,
}
#[async_trait::async_trait]
impl ToolServerConnection for Tool {
    fn server_id(&self) -> &str {
        "research"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["analyze".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let items = args["payload"]
            .as_array()
            .ok_or_else(|| KernelError::ToolServerError("array input required".into()))?;
        Ok(json!({"count": if self.bad { 99 } else { items.len() }}))
    }
}
pub fn open(root: &Path, receiver: u8, bad: bool) -> Result<(ChioKernel, Arc<AtomicUsize>)> {
    open_with_clock(root, receiver, bad, None)
}
pub fn open_with_clock(
    root: &Path,
    receiver: u8,
    bad: bool,
    clock: Option<Arc<dyn Clock>>,
) -> Result<(ChioKernel, Arc<AtomicUsize>)> {
    open_with_layout(
        root,
        receiver,
        bad,
        clock,
        delegated_work::DelegatedWorkLayout::Arguments,
    )
}
pub fn open_with_layout(
    root: &Path,
    receiver: u8,
    bad: bool,
    clock: Option<Arc<dyn Clock>>,
    layout: delegated_work::DelegatedWorkLayout,
) -> Result<(ChioKernel, Arc<AtomicUsize>)> {
    open_configured(root, receiver, bad, clock, layout, |_| {})
}

pub fn open_configured(
    root: &Path,
    receiver: u8,
    bad: bool,
    clock: Option<Arc<dyn Clock>>,
    layout: delegated_work::DelegatedWorkLayout,
    configure: impl FnOnce(&mut ChioKernel),
) -> Result<(ChioKernel, Arc<AtomicUsize>)> {
    let dir = root.join(format!("receiver-{receiver}"));
    std::fs::create_dir_all(dir.join("locks"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(dir.join("locks"), std::fs::Permissions::from_mode(0o700))?;
    }
    let db = dir.join("authority.db");
    if !db.exists() {
        SqliteAuthorityStore::provision(&db, dir.join("locks"))?;
    }
    let (authority, mut kernel) = if let Some(clock) = clock {
        (
            SqliteAuthorityStore::open_serving_with_clock(&db, dir.join("locks"), clock.clone())?,
            ChioKernel::new_with_clock(configuration(receiver), clock),
        )
    } else {
        (
            SqliteAuthorityStore::open_serving_with_clock(
                &db,
                dir.join("locks"),
                chio_test_support::clock::clock(),
            )?,
            unconfigured(receiver),
        )
    };
    let receipts = SqliteReceiptStore::open(dir.join("receipts.db"))?;
    receipts.wait_for_writer_ready(Duration::from_secs(30))?;
    kernel.set_receipt_store(Box::new(receipts))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    if !root.join("bank.db").exists() {
        bank::Bank::provision(root)?;
    }
    kernel.set_payment_adapter(Box::new(bank::Bank {
        root: root.into(),
        role: receiver,
    }));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    delegated_work::install_delegated_work_with_layout(
        &mut kernel,
        vec![key(1).public_key()],
        layout,
    )?;
    let calls = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(Tool {
        calls: calls.clone(),
        bad,
    }));
    configure(&mut kernel);
    kernel.reconcile_durable_admission_startup()?;
    Ok((kernel, calls))
}
pub fn request(
    kernel: &ChioKernel,
    slot: &str,
    holder: u8,
    id: &str,
    limit: u64,
) -> Result<ToolCallRequest> {
    let amount = MonetaryAmount {
        units: limit,
        currency: "USD".into(),
    };
    let capability = kernel.issue_capability(
        &key(holder).public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "research".into(),
                tool_name: "analyze".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(1),
                max_cost_per_invocation: Some(amount.clone()),
                max_total_cost: Some(amount),
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        1800,
    )?;
    Ok(ToolCallRequest {
        request_id: id.into(),
        agent_id: capability.subject.to_hex(),
        capability,
        server_id: "research".into(),
        tool_name: "analyze".into(),
        arguments: json!({"slot_id":slot,"payload":["a","b","c"]}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })
}
pub fn choose(
    store: &DelegationStore,
    request: &ToolCallRequest,
    holder: u8,
    receiver: u8,
    revision: u64,
    price: u64,
) -> Result {
    let slot_id = request.arguments["slot_id"].as_str().ok_or("slot absent")?;
    let expires_at = store.slot(slot_id)?.contract.expires_at;
    let offer = Signed::sign(
        WorkOffer {
            allocation_hash: store.allocation_digest(slot_id)?,
            slot_id: slot_id.into(),
            contract_hash: binding_digest(&store.slot(slot_id)?)?,
            receiver: key(receiver).public_key(),
            effect: Effect {
                server: request.server_id.clone(),
                tool: request.tool_name.clone(),
            },
            arguments_hash: work_input_digest(slot_id, &request.arguments["payload"])?,
            price_units: price,
            expires_at,
        },
        &key(receiver),
    )?;
    store.select(
        &Signed::sign(
            Selection {
                offer,
                request_id: request.request_id.clone(),
                capability_hash: binding_digest(&request.capability)?,
                expected_revision: revision,
            },
            &key(holder),
        )?,
        now()?,
        &[
            key(3).public_key(),
            key(4).public_key(),
            key(5).public_key(),
        ],
    )?;
    Ok(())
}

pub fn demonstration(root: &Path) -> Result<Value> {
    let store = Arc::new(DelegationStore::open(root.join("allocation.db"))?);
    store.create_root(slot("root", 1, 100, 3)?)?;
    split(&store, "root", 1, slot("research", 2, 60, 2)?)?;
    split(&store, "root", 1, slot("independent", 1, 40, 2)?)?;
    split(&store, "research", 2, slot("specialist", 2, 30, 1)?)?;
    // Discovery occurs after the task/allocations exist. Both endpoints are owner-qualified.
    let (first, _) = open(root, 3, false)?;
    let original = request(&first, "specialist", 2, "candidate-a", 20)?;
    choose(&store, &original, 2, 3, 0, 20)?;
    let (replacement, calls) = open(root, 4, false)?;
    let mut selected = request(&replacement, "specialist", 2, "selected-b", 20)?;
    choose(&store, &selected, 2, 4, 1, 20)?;
    seal(&store, &mut selected, 20)?;
    let response = replacement.evaluate_tool_call_blocking(&selected)?;
    if response.verdict != Verdict::Allow || !response.receipt.verify_signature()? {
        return Err(format!("native delegation failed: {:?}", response.reason).into());
    }
    let before = calls.load(Ordering::SeqCst);
    drop(replacement);
    let (reopened, replay_calls) = open(root, 4, false)?;
    let replay = reopened.evaluate_tool_call_blocking(&selected)?;
    if serde_json::to_value(&replay.receipt)? != serde_json::to_value(&response.receipt)?
        || output(&replay)? != output(&response)?
        || replay_calls.load(Ordering::SeqCst) != 0
    {
        return Err("replay changed or dispatched twice".into());
    }
    let replacement_rejected = choose(&store, &original, 2, 3, 2, 20).is_err();
    let mut sibling = request(&first, "independent", 1, "sibling", 30)?;
    choose(&store, &sibling, 1, 3, 0, 30)?;
    seal(&store, &mut sibling, 30)?;
    let sibling_response = first.evaluate_tool_call_blocking(&sibling)?;
    if sibling_response.verdict != Verdict::Allow {
        return Err(format!("sibling failed: {:?}", sibling_response.reason).into());
    }
    Ok(
        json!({"native_dispatches_for_selected_work":before,"replay_dispatches":0,
        "replacement_after_dispatch_rejected":replacement_rejected,"sibling_completed":true,
        "selected_receiver":key(4).public_key().to_hex(),"output":output(&response)?,
        "receipt":response.receipt,"sibling_receipt":sibling_response.receipt,
        "administration":"one operator, local in-process tools","payment":"fixture balances; no real funds moved", "balances": bank::Bank::balances(root)?}),
    )
}

pub fn output(response: &ToolCallResponse) -> Result<Option<Value>> {
    match &response.output {
        Some(ToolCallOutput::Value(v)) => Ok(Some(v.clone())),
        None => Ok(None),
        _ => Err("unexpected stream".into()),
    }
}
pub fn seal(store: &DelegationStore, request: &mut ToolCallRequest, ceiling: u64) -> Result {
    let slot_id = request.arguments["slot_id"].as_str().ok_or("slot absent")?;
    let permit = store.seal_dispatch(
        &DispatchBinding {
            slot_id: slot_id.into(),
            receiver: request.capability.issuer.clone(),
            subject: request.capability.subject.clone(),
            request_id: request.request_id.clone(),
            capability_hash: binding_digest(&request.capability)?,
            arguments_hash: work_input_digest(slot_id, &request.arguments["payload"])?,
            effect: Effect {
                server: request.server_id.clone(),
                tool: request.tool_name.clone(),
            },
            max_units: ceiling,
            currency: "USD".into(),
        },
        now()?,
        &key(1),
    )?;
    request.arguments["allocation"] = serde_json::to_value(permit)?;
    Ok(())
}

pub fn unconfigured(receiver: u8) -> ChioKernel {
    ChioKernel::new_with_clock(configuration(receiver), chio_test_support::clock::clock())
}
fn configuration(receiver: u8) -> KernelConfig {
    KernelConfig {
        keypair: key(receiver),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"dynamic-delegation-demo-v1"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
        deadlines: HotPathDeadlineConfig::default(),
    }
}
