//! Request origin survives loss of its HTTP body until the actor is finished.

use super::*;

#[tokio::test]
async fn mcp_generation_original_same_id_after_disconnect_waits_for_its_actual_actor_result() {
    let gate = Arc::new((StdMutex::new(false), Condvar::new()));
    let fixture = fixture(0, Some(gate.clone()));
    let session = initialize(&fixture, false).await;
    initialized(&fixture, &session).await;
    let old_call = read_call(71);
    let old = post(&fixture, Some(&session.session_id), &old_call).await;
    assert_eq!(old.status(), StatusCode::OK);
    tokio::time::timeout(WAIT, async {
        while fixture.calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("OLD request did not reach its actual gated transport");
    drop(old);
    assert!(!session.has_active_request_stream());

    let mut new_call = read_call(71);
    new_call["params"]["arguments"]["path"] = json!("/workspace/new-generation.txt");
    let new = post(&fixture, Some(&session.session_id), &new_call).await;
    assert_eq!(new.status(), StatusCode::OK);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(session.input_tx.usage().unwrap().messages, 2);
    {
        let (released, changed) = &*gate;
        *released.lock().unwrap() = true;
        changed.notify_all();
    }
    let wire = tokio::time::timeout(WAIT, axum::body::to_bytes(new.into_body(), 128 * 1024))
        .await
        .expect("NEW body did not complete within the actor-result deadline")
        .unwrap();
    tokio::time::timeout(WAIT, async {
        while fixture.calls.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("NEW request was not processed after OLD completed");
    fixture.state.sessions.shutdown_all_active().await.unwrap();

    let messages = sse_messages(&wire);
    let terminals = messages
        .iter()
        .filter(|message| message["id"] == 71 && message.get("method").is_none())
        .collect::<Vec<_>>();
    assert_eq!(
        terminals.len(),
        1,
        "NEW body delivered extra terminal responses"
    );
    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_value(terminals[0]["result"]["_meta"]["chioEvidence"]["receipt"].clone())
            .unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(
        receipt.action.parameter_hash,
        sha256_hex(&canonical_json_bytes(&new_call["params"]["arguments"]).unwrap()),
        "NEW body accepted the genuine signed OLD actor result solely because its wire id matched"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    assert!(!session.has_active_request_stream());
}

#[tokio::test]
async fn mcp_generation_original_late_old_nested_request_does_not_enter_a_new_post() {
    let fixture = fixture(0, None);
    let (session, inbox) = controlled_session(&fixture, "late-old-generation", 16).await;
    let mut output = BroadcastJsonRpcWriter::new(
        session.event_tx.clone(),
        session.retained_notification_events.clone(),
        session.next_event_id.clone(),
        session.session_id.clone(),
        session.input_tx.response_context(),
    );
    let old = post(&fixture, Some(&session.session_id), &read_call(81)).await;
    assert_eq!(old.status(), StatusCode::OK);
    // The actor has taken OLD and still retains its bounded accounted message.
    let old_request = inbox.try_recv().unwrap().expect("OLD was not enqueued");
    assert_eq!(old_request.value()["id"], 81);
    let old_scope = inbox.enter_response_scope(&old_request).unwrap();
    drop(old);
    assert!(!session.has_active_request_stream());

    let new = post(&fixture, Some(&session.session_id), &read_call(82)).await;
    assert_eq!(new.status(), StatusCode::OK);
    assert!(session.has_active_request_stream());
    // NEW has subscribed and enqueued, but OLD is still the actor's request.
    // Its late nested request must not acquire NEW's HTTP delivery authority.
    let old_sample = json!({"jsonrpc":"2.0","id":"old-owner-late-sampling",
        "method":"sampling/createMessage","params":{"maxTokens":1,
        "messages":[{"role":"user","content":{"type":"text","text":"old-owner-late-sample"}}]}});
    let old_terminal = json!({"jsonrpc":"2.0","id":81,"result":{
        "content":[{"type":"text","text":"old-owner-late-result"}],"isError":false}});
    publish(&mut output, &old_sample);
    publish(&mut output, &old_terminal);
    drop(old_scope);
    drop(old_request);
    let new_request = inbox.try_recv().unwrap().expect("NEW was not enqueued");
    assert_eq!(new_request.value()["id"], 82);
    let new_terminal = json!({"jsonrpc":"2.0","id":82,"result":{
        "content":[{"type":"text","text":"new-owner-result"}],"isError":false}});
    let new_scope = inbox.enter_response_scope(&new_request).unwrap();
    publish(&mut output, &new_terminal);
    drop(new_scope);
    drop(new_request);
    let wire = tokio::time::timeout(WAIT, axum::body::to_bytes(new.into_body(), 64 * 1024))
        .await
        .expect("NEW POST did not end before its original outer deadline")
        .unwrap();
    fixture.state.sessions.shutdown_all_active().await.unwrap();
    assert_only_own_outcome(&OwnerHandOff {
        new_stream: sse_messages(&wire),
        new_terminal,
    });
    assert_eq!(session.input_tx.usage().unwrap().messages, 0);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert!(!session.has_active_request_stream());
    // Keep the controlled actor inbox alive through the accounting assertions.
    drop(inbox);
}
