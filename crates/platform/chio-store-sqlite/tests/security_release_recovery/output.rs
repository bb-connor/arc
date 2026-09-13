//! Current release policy sees the delivered representation, including chunks.
use super::*;
use chio_core::canonical_json_bytes;
use chio_kernel::post_invocation::{
    PostInvocationContext, PostInvocationHook, PostInvocationHookIdentity, PostInvocationVerdict,
};
use chio_kernel::tool_outcome::{DurableSecurityReleaseContext, ToolOutcomeStore};
use chio_kernel::{
    NestedFlowBridge, ToolCallChunk, ToolCallOutput, ToolCallStream, ToolServerConnection,
    ToolServerStreamResult,
};
use chio_store_sqlite::SqliteToolOutcomeStore;
use serde_json::{json, Value};
use std::sync::Mutex;

fn redacted() -> Value {
    json!({"visible": "redacted"})
}

struct Redact;
impl PostInvocationHook for Redact {
    fn name(&self) -> &str {
        "release-output-redaction"
    }

    fn inspect(&self, _: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict {
        let mut response = response.clone();
        match response.get("kind").and_then(Value::as_str) {
            Some("value") => response["value"] = redacted(),
            Some("stream") => {
                let Some(chunks) = response
                    .get_mut("stream")
                    .and_then(|stream| stream.get_mut("chunks"))
                    .and_then(Value::as_array_mut)
                else {
                    return PostInvocationVerdict::Block("missing stream chunks".into());
                };
                for chunk in chunks {
                    *chunk = redacted();
                }
            }
            _ => return PostInvocationVerdict::Block("unexpected output envelope".into()),
        }
        PostInvocationVerdict::Redact(response)
    }

    fn durable_identity(&self) -> Result<Option<PostInvocationHookIdentity>, String> {
        PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "1",
            "redact-to-configured-value",
            &redacted(),
        )
        .map(Some)
    }
}

struct Server {
    stream: bool,
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"private": "raw-connector-output"}))
    }

    async fn invoke_stream(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        if !self.stream {
            return Ok(None);
        }
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!({"private": "first"}),
                },
                ToolCallChunk {
                    data: json!({"private": "second"}),
                },
            ],
        })))
    }
}

#[derive(Clone, Copy)]
enum Decision {
    Allow,
    Refuse,
    Panic,
}

struct Seen {
    output: ToolCallOutput,
    signing_preimage: Vec<u8>,
    debug: String,
}

struct ReleaseState {
    store: SqliteToolOutcomeStore,
    decision: Decision,
    seen: Arc<Mutex<Vec<Seen>>>,
    context_free: Arc<AtomicUsize>,
    verification_error: Mutex<Option<String>>,
}

struct Hook(Arc<ReleaseState>);

struct Permit {
    hook: Arc<ReleaseState>,
    request: Vec<u8>,
    security_context: SecurityInvocationContext,
    commitment: chio_security_types::ports::RecordId,
}

impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        "output-aware-release"
    }

    fn acquire_request_lifecycle(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        Ok(Some(Box::new(Permit {
            hook: self.0.clone(),
            request: context.canonical_request.to_vec(),
            security_context: context.security_context.clone(),
            commitment: context.dispatch_commitment_id.clone(),
        })))
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

impl SecurityRequestLifecyclePermit for Permit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        self.hook.context_free.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::GuardDenied(
            "output context is required".into(),
        ))
    }

    fn ensure_final_release_with_output(
        self: Box<Self>,
        context: &DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        let verify = || -> TestResult {
            if context.request_canonical_json().as_bytes() != self.request
                || context.security_context() != &self.security_context
                || context.dispatch_commitment_id() != &self.commitment
            {
                return Err("release changed original invocation identity".into());
            }
            let operation = context.operation().binding().operation_id();
            context.outcome().validate_against(context.operation())?;
            context
                .evaluation()
                .validate_against(context.operation(), context.outcome())?;
            if self.hook.store.lookup_by_operation(operation)?.as_ref() != Some(context.outcome())
                || self
                    .hook
                    .store
                    .lookup_post_return_evaluation(operation)?
                    .as_ref()
                    != Some(context.evaluation())
                || self
                    .hook
                    .store
                    .lookup_security_release(operation)?
                    .is_some()
            {
                return Err("release does not match pending physical finalization".into());
            }
            let output = self
                .hook
                .store
                .load_resolved_output_by_operation(operation)?
                .ok_or("resolved output is absent before release")?;
            if output.bytes() != context.signing_preimage() {
                return Err("release does not match physical output".into());
            }
            self.hook
                .seen
                .lock()
                .map_err(|_| "seen lock poisoned")?
                .push(Seen {
                    output: context.output().clone(),
                    signing_preimage: context.signing_preimage().to_vec(),
                    debug: format!("{context:?}"),
                });
            Ok(())
        };
        if let Err(error) = verify() {
            let detail = error.to_string();
            *self
                .hook
                .verification_error
                .lock()
                .map_err(|_| KernelError::Internal("verification log poisoned".into()))? =
                Some(detail.clone());
            return Err(KernelError::Internal(detail));
        }
        match self.hook.decision {
            Decision::Allow => Ok(()),
            Decision::Refuse => Err(KernelError::GuardDenied(
                "current output policy refused".into(),
            )),
            Decision::Panic => panic!("private release callback panic"),
        }
    }
}

fn run(nested: bool, asynchronous: bool, stream: bool, decision: Decision) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let invocations = fixture.invocations.clone();
    fixture.tool_server = Some(Box::new(move || {
        Ok(Box::new(Server {
            stream,
            invocations: invocations.clone(),
        }))
    }));
    let mut runtime = fixture.open_with_reconcile(false)?;
    let hook = Arc::new(ReleaseState {
        store: runtime.authority.tool_outcome_store(),
        decision,
        seen: Arc::new(Mutex::new(Vec::new())),
        context_free: Arc::new(AtomicUsize::new(0)),
        verification_error: Mutex::new(None),
    });
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook(hook.clone())));
    kernel.add_post_invocation_hook(Box::new(Redact));
    kernel.reconcile_durable_admission_startup()?;
    let request = fixture.request(&runtime, "output-aware-security-release")?;
    let security_context = context(&request)?;
    let result = serialization::evaluate(
        &mut runtime,
        &request,
        &security_context,
        nested,
        asynchronous,
    )?;
    let seen = hook.seen.lock().map_err(|_| "seen lock poisoned")?;
    assert_eq!(
        *hook
            .verification_error
            .lock()
            .map_err(|_| "verification log poisoned")?,
        None
    );
    assert_eq!(
        seen.len(),
        1,
        "release must see the actual output exactly once: {result:?}"
    );
    assert_eq!(hook.context_free.load(Ordering::SeqCst), 0);
    let expected = if stream {
        ToolCallOutput::Stream(ToolCallStream {
            chunks: vec![
                ToolCallChunk { data: redacted() },
                ToolCallChunk { data: redacted() },
            ],
        })
    } else {
        ToolCallOutput::Value(redacted())
    };
    assert_eq!(seen[0].output, expected);
    let value_bytes = canonical_json_bytes(&redacted())?;
    let preimage = if stream {
        chio_core::sha256_hex(&value_bytes).repeat(2).into_bytes()
    } else {
        value_bytes
    };
    assert_eq!(seen[0].signing_preimage, preimage);
    assert_eq!(seen[0].debug, "DurableSecurityReleaseContext { .. }");
    drop(seen);
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context);
    match decision {
        Decision::Allow => {
            let response = result?;
            assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
            assert_eq!(response.output, Some(expected));
            assert!(response.receipt.verify_signature()?);
            assert_eq!(
                response.receipt.content_hash,
                chio_core::sha256_hex(&preimage)
            );
            assert_eq!(replay?.receipt.id, response.receipt.id);
        }
        Decision::Refuse | Decision::Panic => {
            assert_withheld(result);
            assert_withheld(replay);
        }
    }
    let (operation, state) = operation_state(&fixture, &request.request_id)?.ok_or("operation")?;
    let operation =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(operation)?;
    let allowed = matches!(decision, Decision::Allow);
    assert_eq!(state, if allowed { "completed" } else { "finalizing" });
    assert_eq!(
        hook.store.lookup_security_release(&operation)?.is_some(),
        allowed
    );
    assert_eq!(hook.seen.lock().map_err(|_| "seen lock poisoned")?.len(), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}

#[test]
fn release_owner_receives_the_exact_redacted_value() -> TestResult {
    for nested in [false, true] {
        for asynchronous in [false, true] {
            run(nested, asynchronous, false, Decision::Allow)?;
        }
    }
    Ok(())
}

#[test]
fn release_owner_receives_redacted_chunks_not_only_their_digests() -> TestResult {
    for nested in [false, true] {
        for asynchronous in [false, true] {
            run(nested, asynchronous, true, Decision::Allow)?;
        }
    }
    Ok(())
}

#[test]
fn current_output_refusal_withholds_value_and_stream_without_reinvocation() -> TestResult {
    for nested in [false, true] {
        for stream in [false, true] {
            run(nested, false, stream, Decision::Refuse)?;
        }
    }
    Ok(())
}

#[test]
fn output_release_callback_panic_cannot_publish_or_reinvoke() -> TestResult {
    for nested in [false, true] {
        run(nested, true, false, Decision::Panic)?;
    }
    Ok(())
}
