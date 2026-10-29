use super::*;
use chio_core::capability::governance::{
    CallChainContinuationAudience, CallChainContinuationToken, CallChainContinuationTokenBody,
    GovernedCallChainContext, GovernedTransactionIntent, CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
    GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY,
};
use chio_core::receipt::metadata::{ReceiptSessionAnchorV1, SESSION_ANCHOR_METADATA_KEY};
use chio_core::session::{
    OperationContext, RequestId, SessionAnchorReference, SessionOperation, ToolCallOperation,
};
use chio_kernel::SessionOperationResponse;
use chio_store_sqlite::SqliteReceiptStore;

fn sqlite_kernel(
    keypair: &Keypair,
    receipts: &std::path::Path,
) -> Result<ChioKernel, Box<dyn Error>> {
    let mut kernel = ChioKernel::new_with_clock(
        kernel_config(keypair.clone()),
        chio_test_support::clock::clock(),
    );
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(receipts)?))?;
    kernel.register_tool_server(Box::new(MutationServer {
        invocations: Arc::new(AtomicU64::new(0)),
    }));
    Ok(kernel)
}

fn continuation_intent(
    signer: &Keypair,
    subject: &Keypair,
    parent_receipt_id: &str,
    parent_receipt_hash: &str,
    anchor: SessionAnchorReference,
) -> Result<GovernedTransactionIntent, Box<dyn Error>> {
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-sqlite-session-anchor".to_owned(),
        parent_request_id: "sqlite-anchor-parent".to_owned(),
        parent_receipt_id: Some(parent_receipt_id.to_owned()),
        origin_subject: "subject-origin".to_owned(),
        delegator_subject: "subject-delegator".to_owned(),
    };
    let now = now_unix_ms()? / 1_000;
    let token = CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_owned(),
            token_id: "sqlite-anchor-continuation".to_owned(),
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: call_chain.chain_id.clone(),
            parent_request_id: call_chain.parent_request_id.clone(),
            parent_receipt_id: call_chain.parent_receipt_id.clone(),
            parent_receipt_hash: Some(parent_receipt_hash.to_owned()),
            parent_session_anchor: Some(anchor),
            current_subject: subject.public_key().to_hex(),
            delegator_subject: call_chain.delegator_subject.clone(),
            origin_subject: call_chain.origin_subject.clone(),
            parent_capability_id: None,
            delegation_link_hash: None,
            governed_intent_hash: None,
            audience: Some(CallChainContinuationAudience {
                server_id: "sqlite-durable-server".to_owned(),
                tool_name: "mutate".to_owned(),
            }),
            nonce: Some("sqlite-anchor-nonce".to_owned()),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        signer,
    )?;
    Ok(GovernedTransactionIntent {
        id: "intent-sqlite-session-anchor".to_owned(),
        server_id: "sqlite-durable-server".to_owned(),
        tool_name: "mutate".to_owned(),
        purpose: "continue from a parent persisted in SQLite".to_owned(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain),
        autonomy: None,
        context: Some(serde_json::json!({
            GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: serde_json::to_value(&token)?,
        })),
        body: Default::default(),
    })
}

/// An in-session receipt written to SQLite carries its session anchor block,
/// and after the parent kernel and its session are gone a fresh kernel over
/// the same database continues from it on the block alone.
#[test]
fn sqlite_persisted_parent_continues_from_its_signed_session_anchor() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    secure_directory(directory.path())?;
    let receipts = directory.path().join("receipts.db");
    let keypair = Keypair::generate();
    let agent = Keypair::generate();

    let (parent_id, parent_hash, anchor) = {
        let kernel = sqlite_kernel(&keypair, &receipts)?;
        let capability = kernel.issue_capability(&agent.public_key(), scope(), 300)?;
        let session_id =
            kernel.open_session(agent.public_key().to_hex(), vec![capability.clone()])?;
        kernel.activate_session(&session_id)?;
        let anchor = kernel
            .session(&session_id)
            .ok_or("session vanished")?
            .session_anchor()
            .reference();
        let context = OperationContext::new(
            session_id,
            RequestId::new("sqlite-anchor-parent"),
            agent.public_key().to_hex(),
        );
        let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
            dpop_proof: None,
            capability,
            server_id: "sqlite-durable-server".to_owned(),
            tool_name: "mutate".to_owned(),
            arguments: serde_json::json!({"record": "ledger-anchor"}),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
            model_metadata: None,
            extra_metadata: None,
        }));
        let SessionOperationResponse::ToolCall(response) =
            kernel.evaluate_session_operation(&context, &operation)?
        else {
            return Err("expected a tool call response".into());
        };
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get(SESSION_ANCHOR_METADATA_KEY)),
            Some(&ReceiptSessionAnchorV1::commit(&anchor)?.to_metadata_value()?)
        );
        let hash = sha256_hex(&canonical_json_bytes(&response.receipt)?);
        (response.receipt.id.clone(), hash, anchor)
    };

    let kernel = sqlite_kernel(&keypair, &receipts)?;
    let capability = kernel.issue_capability(&agent.public_key(), scope(), 300)?;
    let mut child = request(&capability);
    child.request_id = "sqlite-anchor-child".to_owned();
    child.governed_intent = Some(continuation_intent(
        &keypair,
        &agent,
        &parent_id,
        &parent_hash,
        anchor.clone(),
    )?);
    let response = kernel.evaluate_tool_call_blocking(&child)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(
        response.receipt.metadata.as_ref().and_then(
            |metadata| metadata.pointer("/governed_transaction/call_chain/sessionAnchorId")
        ),
        Some(&serde_json::json!(anchor.session_anchor_id))
    );

    let other = SessionAnchorReference::new(anchor.session_anchor_id.clone(), "ab".repeat(32));
    let mut forged = request(&capability);
    forged.request_id = "sqlite-anchor-forged".to_owned();
    forged.governed_intent = Some(continuation_intent(
        &keypair,
        &agent,
        &parent_id,
        &parent_hash,
        other,
    )?);
    let response = kernel.evaluate_tool_call_blocking(&forged)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some(
            "governed transaction denied: governed call_chain continuation token session anchor does not match the parent receipt"
        )
    );
    Ok(())
}
