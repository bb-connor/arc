use super::*;

struct LegacyReceiptServer {
    receipt: ChioReceipt,
    preparations: Arc<AtomicU64>,
    invocations: Arc<AtomicU64>,
    revocation: Option<(Arc<crate::InMemoryRevocationStore>, String)>,
}

#[async_trait::async_trait]
impl ToolServerConnection for LegacyReceiptServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn prepare_delivery(&self, _: &ToolDispatchContext) -> Result<(), KernelError> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        if let Some((store, capability)) = &self.revocation {
            store
                .revoke(capability)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        Ok(())
    }

    fn prepared_native_launch_receipt(&self) -> Option<ChioReceipt> {
        (self.preparations.load(Ordering::SeqCst) == 1).then(|| self.receipt.clone())
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"prepared": true}))
    }
}

#[test]
fn legacy_preparation_preserves_signed_launch_binding_on_allow_and_revoke() -> TestResult {
    // Exercise attribution with a real signed receipt. The x86 broker
    // regression supplies the actual native enforcement receipt and child.
    let (source_kernel, source_request, _, _) =
        durable_admission_fixture("legacy-launch-receipt-source");
    let source = source_kernel.evaluate_tool_call_blocking(&source_request)?;
    assert_eq!(source.verdict, Verdict::Allow);
    assert!(source.receipt.verify_signature()?);
    let expected = serde_json::json!({
        "receipt_id": source.receipt.id,
        "receipt_sha256": sha256_hex(&chio_core::canonical_json_bytes(&source.receipt)?),
    });

    for nested in [false, true] {
        for revoke in [false, true] {
            let (mut kernel, request, store, invocations) =
                durable_admission_fixture("legacy-launch-binding");
            let preparations = Arc::new(AtomicU64::new(0));
            let revocations = Arc::new(crate::InMemoryRevocationStore::new());
            kernel.set_revocation_store_handle(revocations.clone());
            kernel.register_tool_server(Box::new(LegacyReceiptServer {
                receipt: source.receipt.clone(),
                preparations: preparations.clone(),
                invocations: invocations.clone(),
                revocation: revoke.then(|| (revocations, request.capability.id.clone())),
            }));
            let response = if nested {
                let session = kernel.open_session("legacy-parent".to_owned(), Vec::new())?;
                kernel.activate_session(&session)?;
                let parent =
                    make_operation_context(&session, "legacy-parent-request", "legacy-parent");
                kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
                kernel.evaluate_tool_call_with_nested_flow_client(
                    &parent,
                    &request,
                    &mut NoopNestedFlowClient,
                    None,
                )?
            } else {
                kernel.evaluate_tool_call_blocking(&request)?
            };
            assert_eq!(
                response.verdict,
                if revoke {
                    Verdict::Deny
                } else {
                    Verdict::Allow
                }
            );
            assert_eq!(preparations.load(Ordering::SeqCst), 1);
            assert_eq!(invocations.load(Ordering::SeqCst), u64::from(!revoke));
            assert!(response.receipt.verify_signature()?);
            assert_eq!(response.receipt.capability_id, request.capability.id);
            assert_eq!(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("native_launch")),
                Some(&expected),
                "completed legacy preparation lost its signed launch attribution",
            );
            assert_eq!(
                store.operation().state(),
                if revoke {
                    AdmissionOperationState::CompensatedBeforeDispatch
                } else {
                    AdmissionOperationState::Completed
                },
            );
        }
    }
    Ok(())
}
