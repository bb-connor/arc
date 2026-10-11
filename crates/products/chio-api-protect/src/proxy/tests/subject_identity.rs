use super::*;
use sha2::{Digest, Sha256};

fn mint_body(subject: &str, structured: bool) -> serde_json::Value {
    if structured {
        serde_json::json!({
            "subject": subject,
            "scope": {"grants": [{
                "server_id": "filesystem", "tool_name": "read",
                "operations": ["invoke"], "constraints": [],
                "dpop_required": true
            }], "resource_grants": [], "prompt_grants": []},
            "ttl_seconds": 600
        })
    } else {
        serde_json::json!({
            "subject": subject, "scopes": ["filesystem:read"],
            "job_uid": "public-job", "ttl_seconds": 600
        })
    }
}

async fn mint(state: Arc<ProxyState>, path: &str, body: &serde_json::Value) -> CapabilityToken {
    let (status, mut json) =
        post_json_with_bearer(state, path, body, Some(MEDIATED_CONTROL_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{path}: {json}");
    if path.ends_with("/mint") {
        json = json["capability"].take();
    }
    serde_json::from_value(json).test_unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subject_identity_all_mint_shapes_preserve_caller_public_key() {
    let agent = Keypair::generate();
    for (path, structured) in [
        ("/v1/capabilities/mint", false),
        ("/v1/capabilities", false),
        ("/v1/capabilities", true),
    ] {
        let state = mediated_test_state(
            Keypair::generate(),
            Arc::new(InMemoryBudgetStore::new()),
            Vec::new(),
        );
        let token = mint(
            state,
            path,
            &mint_body(&agent.public_key().to_hex(), structured),
        )
        .await;
        assert!(token.verify_signature().test_unwrap());
        assert_eq!(
            token.subject,
            agent.public_key(),
            "{path}, structured={structured}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subject_identity_invalid_subjects_reject_before_mutation() {
    let valid = Keypair::generate().public_key().to_hex();
    let padded = format!(" {valid}");
    // These have valid SEC1 lengths and prefixes but are not points on either curve.
    let off_curve_p256 = format!("p256:04{}", "00".repeat(64));
    let off_curve_p384 = format!("p384:04{}", "00".repeat(96));
    for (path, structured) in [
        ("/v1/capabilities/mint", false),
        ("/v1/capabilities", false),
        ("/v1/capabilities", true),
    ] {
        let directory = tempfile::tempdir().test_unwrap();
        let database = directory.path().join("receipts.sqlite");
        let state = mediated_test_state_inner(
            Keypair::generate(),
            Arc::new(InMemoryBudgetStore::new()),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_owned()),
            Some(SqliteReceiptStore::open(database.to_str().test_unwrap()).test_unwrap()),
            true,
        );
        for subject in [
            None,
            Some(""),
            Some("job/default/demo"),
            Some("bb"),
            Some("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"),
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            Some(padded.as_str()),
            Some(off_curve_p256.as_str()),
            Some(off_curve_p384.as_str()),
        ] {
            let mut body = mint_body("", structured);
            if let Some(subject) = subject {
                body["subject"] = serde_json::json!(subject);
            } else {
                body.as_object_mut().test_unwrap().remove("subject");
            }
            let (status, json) = post_json_with_bearer(
                Arc::clone(&state),
                path,
                &body,
                Some(MEDIATED_CONTROL_TOKEN),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{path} subject={subject:?}: {json}"
            );
            assert!(json.get("capability").is_none());
            assert!(state.receipt_log.lock().await.receipts.is_empty());
            assert!(state.tool_receipt_log.lock().await.receipts.is_empty());
            assert!(state.revoked_capability_ids.lock().await.is_empty());
            let store = state.receipt_store.as_ref().test_unwrap().lock().await;
            assert!(store.load_receipts().test_unwrap().is_empty());
            assert!(store.load_tool_receipts().test_unwrap().is_empty());
            assert!(store.load_revoked_capability_ids().test_unwrap().is_empty());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subject_identity_dpop_refuses_public_seed_wrong_key_and_stolen_token() {
    let agent = Keypair::generate();
    let subject = agent.public_key().to_hex();
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    hasher.update([0]);
    // The SDK scope alias defaults job_uid to the empty public string.
    let seed: [u8; 32] = hasher.finalize().into();
    let public_seed_attacker = Keypair::from_seed(&seed);
    let unrelated = Keypair::generate();
    let state = mediated_test_state(
        Keypair::generate(),
        Arc::new(InMemoryBudgetStore::new()),
        Vec::new(),
    );
    let token = mint(
        Arc::clone(&state),
        "/v1/capabilities",
        &mint_body(&subject, true),
    )
    .await;
    let params = serde_json::json!({"path": "safe.txt"});
    // A thief advertising the caller public key still needs its private signer.
    let mut forged = dpop_proof_for(&public_seed_attacker, &token, "filesystem", "read", &params);
    forged.body.agent_key = agent.public_key();
    let (_, denied) = post_evaluate(
        Arc::clone(&state),
        &serde_json::json!({
            "capability": token, "tool_server": "filesystem", "tool_name": "read",
            "parameters": params, "dpop_proof": forged
        }),
    )
    .await;
    assert_eq!(denied["status"], "deny", "{denied}");
    assert!(!denied["execution_nonce"].is_object());
    for (signer, expected) in [
        (Some(&public_seed_attacker), "deny"),
        (Some(&unrelated), "deny"),
        (None, "deny"),
        (Some(&agent), "reserved"),
    ] {
        let mut body = serde_json::json!({
            "capability": token, "tool_server": "filesystem", "tool_name": "read",
            "parameters": params
        });
        if let Some(signer) = signer {
            body["dpop_proof"] = serde_json::to_value(dpop_proof_for(
                signer,
                &token,
                "filesystem",
                "read",
                &params,
            ))
            .test_unwrap();
        }
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["status"], expected, "{json}");
        assert_eq!(json["execution_nonce"].is_object(), expected == "reserved");
    }
}
