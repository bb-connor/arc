use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use chio_core::receipt::{body::ChioReceipt, decision::Decision};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};

pub fn key(role: u8) -> Keypair {
    Keypair::from_seed(&[role; 32])
}
pub fn digest(value: &impl serde::Serialize) -> Result<String> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}
pub fn directory(path: &Path) -> Result {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn write(path: impl AsRef<Path>, value: &impl serde::Serialize) -> Result {
    use std::io::Write;
    let mut file = fs::File::create(path)?;
    file.write_all(&canonical_json_bytes(value)?)?;
    file.sync_all()?;
    Ok(())
}
pub fn read<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
pub fn expected(role: u8) -> Value {
    match role {
        1 => json!({"text":"approved input","sourceVersion":1,
            "recipients":[key(2).public_key().to_hex(),key(3).public_key().to_hex()]}),
        3 => json!({"decision":"accept","evidenceIndex":0,"sourceVersion":1,
            "recipients":[key(2).public_key().to_hex(),key(1).public_key().to_hex()]}),
        _ => {
            json!({"decision":"accept","sourceVersion":1,"recipient":key(1).public_key().to_hex()})
        }
    }
}
pub fn maximum(role: u8) -> u64 {
    match role {
        1 => 1,
        2 => 100,
        _ => 30,
    }
}
fn approver(role: u8) -> u8 {
    if role == 3 {
        2
    } else {
        1
    }
}
fn payer(role: u8) -> u8 {
    if role == 2 {
        1
    } else {
        2
    }
}

struct Boundary(u8);
impl Guard for Boundary {
    fn name(&self) -> &str {
        "three-owner-profile"
    }
    fn evaluate(&self, ctx: &GuardContext<'_>) -> std::result::Result<GuardDecision, KernelError> {
        let check = || -> Result {
            let request = ctx.request;
            let approval = request
                .approval_token
                .as_ref()
                .ok_or("owner approval absent")?;
            if approval.approver != key(approver(self.0)).public_key()
                || request.arguments["recipient"] != key(self.0).public_key().to_hex()
                || request.arguments["sourceVersion"] != 1
            {
                return Err("profile owner, audience or version mismatch".into());
            }
            if self.0 != 1 {
                verify_handoff(&request.arguments["source"], 1)?;
            }
            Ok(())
        };
        check().map_err(|e| KernelError::GuardDenied(e.to_string()))?;
        Ok(GuardDecision::allow())
    }
}

pub fn handoff(response: &ToolCallResponse) -> Result<Value> {
    if response.verdict != Verdict::Allow {
        return Err(format!("handoff denied: {:?}", response.reason).into());
    }
    let Some(ToolCallOutput::Value(output)) = response.output.as_ref() else {
        return Err("missing output".into());
    };
    Ok(json!({"output":output,"receipt":response.receipt}))
}
pub fn verify_handoff(value: &Value, role: u8) -> Result {
    let receipt: ChioReceipt = serde_json::from_value(value["receipt"].clone())?;
    if receipt.kernel_key != key(role).public_key()
        || !receipt.verify_signature()?
        || receipt.decision != Some(Decision::Allow)
        || value["output"] != expected(role)
        || receipt.content_hash != digest(&value["output"])?
        || receipt.tool_server != "composition"
        || receipt.tool_name != "work"
    {
        return Err("source handoff failed authenticated artifact binding".into());
    }
    Ok(())
}

#[derive(Clone)]
struct Release(PathBuf);
impl SecurityRequestLifecyclePermit for Release {
    fn ensure_final_release(self: Box<Self>) -> std::result::Result<(), KernelError> {
        // This records an acknowledgement, not a transferable recovery permit.
        let path = self.0.join("release-ack.json");
        if path.exists() {
            return Err(KernelError::GuardDenied(
                "fresh release owner denied".into(),
            ));
        }
        write(path, &json!({"acknowledged":true})).map_err(|e| KernelError::Internal(e.to_string()))
    }
}
impl SecurityPreDispatchHook for Release {
    fn name(&self) -> &str {
        "composition-release-owner"
    }
    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> std::result::Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        Ok(Some(Box::new(self.clone())))
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> std::result::Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

struct Tool {
    root: PathBuf,
    role: u8,
    bad_parent: bool,
}
#[async_trait::async_trait]
impl ToolServerConnection for Tool {
    fn server_id(&self) -> &str {
        "composition"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["work".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let invoke = || -> Result<Value> {
            let counter = self.root.join(format!("effects-{}.json", self.role));
            let count: u64 = if counter.exists() { read(&counter)? } else { 0 };
            write(&counter, &(count + 1))?;
            if self.role == 2 {
                let request: ToolCallRequest = read(self.root.join("request-3.json"))?;
                if digest(&request)? != arguments["childRequestSha256"] {
                    return Err("child request substituted".into());
                }
                let root = self.root.clone();
                let child = std::thread::spawn(move || -> std::result::Result<Value, String> {
                    let execute = || -> Result<Value> {
                        let child = open(&root, 3, "none", false)?;
                        let response = child.evaluate_tool_call_blocking(&request)?;
                        let value = handoff(&response)?;
                        verify_handoff(&value, 3)?;
                        write(root.join("child-earned.json"), &value)?;
                        Ok(value)
                    };
                    execute().map_err(|e| e.to_string())
                })
                .join()
                .map_err(|_| "child worker panicked")??;
                verify_handoff(&child, 3)?;
            }
            Ok(if self.role == 2 && self.bad_parent {
                json!({"unapproved":"CANARY-PRIVATE"})
            } else {
                expected(self.role)
            })
        };
        invoke().map_err(|e| KernelError::Internal(e.to_string()))
    }
    async fn invoke_with_cost(
        &self,
        tool: &str,
        arguments: Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<(Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool, arguments, bridge).await?;
        Ok((
            value,
            Some(ToolInvocationCost {
                units: if self.role == 1 {
                    0
                } else {
                    maximum(self.role)
                },
                currency: "USD".into(),
                breakdown: None,
            }),
        ))
    }
}

pub fn open(root: &Path, role: u8, cut: &str, bad_parent: bool) -> Result<ChioKernel> {
    let dir = root.join(format!("owner-{role}"));
    directory(&dir)?;
    let locks = dir.join("locks");
    directory(&locks)?;
    let db = dir.join("authority.db");
    if !db.exists() {
        SqliteAuthorityStore::provision(&db, &locks)?;
    }
    let authority = SqliteAuthorityStore::open_serving(&db, &locks)?;
    let config = KernelConfig {
        keypair: key(role),
        ca_public_keys: vec![key(approver(role)).public_key()],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"three-owner-composition-v1"),
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
    };
    let mut kernel = ChioKernel::new(config);
    kernel.require_durable_request_retention();
    let receipts = SqliteReceiptStore::open(dir.join("receipts.db"))?;
    receipts.wait_for_writer_ready(Duration::from_secs(30))?;
    kernel.set_receipt_store(Box::new(receipts))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(Bank {
        root: root.into(),
        role,
    }));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.add_guard(Box::new(Boundary(role)));
    kernel.register_tool_server(Box::new(Tool {
        root: root.into(),
        role,
        bad_parent,
    }));
    if role == 2 {
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(Release(root.into())));
    }
    if cut != "none" {
        let point = DurableFinalizationCutpoint::parse(cut).ok_or("unknown native cut")?;
        let path = root.join("reached-cut.json");
        kernel.install_durable_finalization_cutpoint(Arc::new(move |current| {
            if current == point {
                if write(&path, &json!({"cut":current.name()})).is_err() {
                    std::process::exit(91);
                }
                // Actual SIGKILL, including destructors and buffered state.
                let _ = Command::new("kill")
                    .args(["-KILL", &std::process::id().to_string()])
                    .status();
                std::process::exit(92);
            }
        }));
    }
    kernel.reconcile_durable_admission_startup()?;
    Ok(kernel)
}

pub fn request(kernel: &ChioKernel, role: u8, arguments: Value) -> Result<ToolCallRequest> {
    let cap = kernel.issue_capability(
        &key(payer(role)).public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "composition".into(),
                tool_name: "work".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![
                    Constraint::OutputDigestSha256(digest(&expected(role))?),
                    Constraint::RequireApprovalAbove { threshold_units: 0 },
                ],
                max_invocations: None,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: maximum(role),
                    currency: "USD".into(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: maximum(role),
                    currency: "USD".into(),
                }),
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        3600,
    )?;
    let intent = GovernedTransactionIntent {
        id: format!("intent-{role}"),
        server_id: "composition".into(),
        tool_name: "work".into(),
        purpose: "approved materialized artifact handoff".into(),
        max_amount: Some(MonetaryAmount {
            units: maximum(role),
            currency: "USD".into(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: GovernedTransactionIntentBody::BoundToolInvocation {
            capability_id: cap.id.clone(),
            parameters_hash: chio_core::sha256(&canonical_json_bytes(&arguments)?),
        },
    };
    let request_id = format!("original-owner-{role}");
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{role}"),
            approver: key(approver(role)).public_key(),
            subject: cap.subject.clone(),
            governed_intent_hash: intent.binding_hash()?,
            request_id: request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: cap.issued_at,
            expires_at: cap.expires_at,
            decision: GovernedApprovalDecision::Approved,
        },
        &key(approver(role)),
    )?;
    Ok(ToolCallRequest {
        request_id,
        agent_id: cap.subject.to_hex(),
        capability: cap,
        tool_name: "work".into(),
        server_id: "composition".into(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: Some(token),
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })
}

pub fn evaluate(kernel: &ChioKernel, request: &ToolCallRequest) -> Result<ToolCallResponse> {
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("composition")?,
        SessionId::new("original-session")?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("original-isolation")?,
        LineageId::new(request.capability.id.clone())?,
        1,
    ));
    Ok(kernel.evaluate_tool_call_blocking_with_security_context(request, &context)?)
}
