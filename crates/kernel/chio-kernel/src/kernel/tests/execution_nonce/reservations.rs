use super::*;

#[test]
fn mediated_allow_receipt_records_bound_execution_nonce_id() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-nonce-link".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let nonce = response
        .execution_nonce
        .as_ref()
        .expect("mediated allow mints a nonce");
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    let recorded = metadata["budget_authority"]["execution_nonce_id"]
        .as_str()
        .expect("execution_nonce_id recorded on budget_authority metadata");
    assert_eq!(recorded, nonce.nonce_id());
    assert_eq!(
        metadata["budget_authority"]["mediated_spend"]["profile"],
        "chio.mediated_spend.v1"
    );
}

#[test]
fn reserving_authorization_keeps_hold_open_and_blocks_oversubscription() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    // max_cost_per_invocation == max_total_cost == 100: one authorization
    // reserves the entire grant budget.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let first = ToolCallRequest {
        request_id: "req-reserve-1".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    // The reserving authorization returns an allow verdict, an incomplete
    // terminal (no dispatch), and a freshly minted execution nonce.
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    assert!(matches!(
        &authorized.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        authorized.output.is_none(),
        "an authorization gate must not dispatch the tool"
    );
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("authorization mints a nonce");

    // The receipt records the reserved hold's authorize block with no terminal
    // reconcile, so it is truthfully non-authoritative.
    let metadata = authorized
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["authorize"]["exposure_units"], 100,
        "the reserved hold must record the authorized exposure"
    );
    assert!(
        metadata["budget_authority"].get("terminal").is_none(),
        "a reserved (not reconciled) hold must carry no terminal disposition"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert!(
        is_authoritative_spend_receipt(&authorized.receipt, &admitted, nonce.as_ref()).is_err(),
        "a reserved authorization receipt must not be an authoritative spend"
    );

    // The hold stayed reserved (not reversed), so a second
    // authorization for the same fully-reserved grant is denied. No
    // over-subscription past max_total_cost.
    let mut second = first.clone();
    second.request_id = "req-reserve-2".to_string();
    let denied = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied.verdict,
        Verdict::Deny,
        "the reserved hold must block a second authorization: {:?}",
        denied.reason
    );
}

#[test]
fn strict_retry_mediated_spend_receipt_names_presented_nonce() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let mut request = ToolCallRequest {
        request_id: "req-strict-retry-nonce".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    // The strict retry presents a nonce from a prior allow (the nonce binds the
    // capability/server/tool/parameter-hash, not the request id), so no nonce is
    // preminted during this completion.
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    request.execution_nonce = Some(nonce.clone());
    let executed = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(
        executed.output.is_some(),
        "strict retry must return tool output"
    );
    assert!(
        executed.execution_nonce.is_none(),
        "strict retry must not mint another nonce"
    );

    // The completed receipt must name the presented nonce id, not drop it.
    let metadata = executed
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["execution_nonce_id"]
            .as_str()
            .expect("execution_nonce_id recorded on budget_authority metadata"),
        nonce.nonce_id()
    );

    // The reconciled receipt is an authoritative mediated-spend receipt bound to
    // the presented nonce: no NonceLinkMissing.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&executed.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reconcile_by_nonce_settles_reserved_hold_and_frees_difference() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-1", &cap, &agent_kp);

    // Reserving authorization: hold H stays open, a nonce bound to H is minted.
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    assert!(
        nonce.reserved_hold_id().is_some(),
        "the reserving nonce must name the reserved hold"
    );
    assert_eq!(nonce.reserving_request_id(), Some("req-recon-1"));

    // A second authorization is blocked while the slack is reserved.
    let second = reserve_request("req-recon-2", &cap, &agent_kp);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "reserved hold must block the second authorization: {:?}",
        blocked.reason
    );

    // Reconcile H at realized 30 (< reserved 100): settle down, free 70.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    // The receipt is an authoritative mediated spend bound to the presented nonce.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["disposition"], "reconciled",
        "the reserved hold must be reconciled, not released"
    );
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"],
        30
    );
    assert_eq!(meta["budget_authority"]["authorize"]["exposure_units"], 100);
    assert_eq!(
        meta["budget_authority"]["execution_nonce_id"]
            .as_str()
            .unwrap(),
        nonce.nonce_id()
    );

    // The freed difference admits a subsequent authorization that was blocked.
    let third = reserve_request("req-recon-3", &cap, &agent_kp);
    let now_allowed = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        now_allowed.verdict,
        Verdict::Allow,
        "the freed budget must admit a new authorization: {:?}",
        now_allowed.reason
    );
}

#[test]
fn reconcile_by_nonce_receipt_binds_reserved_hold_into_authoritative_predicate() {
    use chio_core_types::receipt::authoritative_spend::{
        is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, PresentedNonceView,
    };

    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-bind", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    // The reconcile-by-nonce receipt commits the exact hold the nonce reserved,
    // so the nonce's signed reserved hold id equals the receipt's committed hold.
    let budget = BudgetAuthorityReceiptRef::from_receipt(&reconciled.receipt)
        .expect("reconciled receipt carries budget authority");
    assert_eq!(
        PresentedNonceView::bound_reserved_hold_id(&nonce),
        Some(budget.hold_id.as_str()),
        "the reconciled hold must equal the hold the nonce reserved"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reconcile_by_nonce_second_time_is_rejected_as_replay() {
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-replay", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };

    kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("nonce"),
        "second reconcile of the same nonce must be rejected as replay, got: {err}"
    );
}

#[test]
fn reconcile_by_nonce_rejects_forged_nonce() {
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-forge", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Repoint the signed hold id at an attacker-chosen hold without re-signing.
    let mut forged = nonce.clone();
    forged.nonce.reserved_hold_id = Some("budget-hold:attacker:cap:0".to_string());
    let realized = ToolInvocationCost {
        units: 10,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&forged, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("nonce"),
        "a tampered nonce must be rejected, got: {err}"
    );

    // The genuine hold is untouched: the real nonce still reconciles.
    let ok = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(ok.verdict, Verdict::Allow);
}

#[test]
fn reconcile_by_nonce_clamps_realized_above_reserved() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    // Reserve the whole grant (max_per == max_total == 100).
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let first = reserve_request("req-recon-clamp", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Realized cost 250 exceeds the reserved worst-case 100: clamp to 100.
    let realized = ToolInvocationCost {
        units: 250,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"], 100,
        "realized cost above the reserved worst-case must clamp to the reserved amount"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reserved_hold_ttl_reaper_settles_expired_authorization_at_worst_case() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    // Whole grant reserved by one authorization.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let first = reserve_request("req-reap-1", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    let hold_id = nonce
        .reserved_hold_id()
        .expect("reserving nonce names the reserved hold")
        .to_string();

    // Not yet expired: the reaper leaves the still-valid reserved hold in place.
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    assert_eq!(kernel.reap_expired_reserved_budget_holds(now).unwrap(), 0);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(
            &reserve_request("req-reap-2", &cap, &agent_kp),
            None,
        )
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "a still-valid reserved hold must keep blocking: {:?}",
        blocked.reason
    );

    // Past expiry: the reaper SETTLES the abandoned reserved hold at its reserved
    // worst-case (forfeit). The only evidence a spend occurred is a reconcile the
    // caller never sent, so an expired-and-unreconciled hold is treated as fully
    // spent: realized spend advances by the reserved amount and the difference is
    // NOT refunded. This is fail-closed for a cumulative spend cap.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.total_cost_realized_spend, 100,
        "the forfeited reserved worst-case becomes realized spend"
    );
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "committed spend stays at the worst-case, not released back to 0"
    );
    let settled = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the reaped hold is still present");
    assert_eq!(
        settled.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reconciled,
        "an expired reserved hold is settled at worst-case, not released"
    );

    // The forfeited worst-case stays consumed: a new authorization is DENIED, not
    // admitted by the freed difference the old release behavior used to give back.
    let forfeited = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(
            &reserve_request("req-reap-3", &cap, &agent_kp),
            None,
        )
        .unwrap();
    assert_eq!(
        forfeited.verdict,
        Verdict::Deny,
        "the forfeited reserved worst-case must stay consumed after reaping: {:?}",
        forfeited.reason
    );
}

#[test]
fn reserved_hold_ttl_matches_minted_nonce_expiry() {
    // The reserved-hold TTL deadline must be derived from the exact
    // instant the nonce is minted (its signed `expires_at`), so a valid nonce can
    // never expire after its hold has already been reaped. Guarantees the caller
    // can always reconcile-before-reaper while the nonce is still valid.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let request = reserve_request("req-ttl-match", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("reserving authorization mints a nonce");
    let hold_id = nonce
        .reserved_hold_id()
        .expect("reserving nonce names the reserved hold");
    let hold = kernel
        .budget_store
        .get_budget_hold(hold_id)
        .unwrap()
        .expect("reserved hold is present");
    assert_eq!(
        hold.reserved_until,
        Some(nonce.expires_at()),
        "the reserved-hold TTL deadline must equal the minted nonce's expiry, never earlier"
    );
}

#[test]
fn reconcile_by_nonce_rejects_mismatched_realized_currency() {
    // Reconcile must reject a realized cost whose currency differs from
    // the currency the hold/grant was authorized in, before settling or signing.
    // A caller-supplied currency is never stamped onto a signed authoritative
    // receipt unchecked.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-currency", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Reconcile with a currency the grant was NOT authorized in (grant is USD).
    let mismatched = ToolInvocationCost {
        units: 30,
        currency: "EUR".to_string(),
        breakdown: None,
    };
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &mismatched)
        .unwrap_err();
    assert!(
        err.to_string().contains("currency"),
        "a realized currency that differs from the reserved grant currency must be rejected, got: {err}"
    );

    // Fail-closed: no settle occurred, so the reserved worst-case still blocks a
    // second authorization (the whole slack is still reserved, not consumed).
    let second = reserve_request("req-recon-currency-2", &cap, &agent_kp);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "a rejected reconcile must not settle the reserved hold: {:?}",
        blocked.reason
    );

    // The nonce was not burned by the rejected reconcile, so the matching-currency
    // reconcile still succeeds and frees the difference.
    let matching = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let ok = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &matching)
        .unwrap();
    assert_eq!(ok.verdict, Verdict::Allow);
}

#[test]
fn reconcile_by_nonce_normalizes_currency_for_zero_exposure_invocation() {
    // A non-monetary invocation reserve carries zero exposure and no reserved
    // currency, so its realized currency is never validated (step 3). The
    // unchecked, caller-supplied currency must not reach the signed receipt: it is
    // normalized to the canonical inert value instead.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_invocation_limited_grant("cost-srv", "compute", 1);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-recon-invocation-currency", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Reconcile with an arbitrary, attacker-controlled currency string. The
    // invocation reserve has zero exposure, so the currency is not validated and
    // the realized cost is clamped to zero.
    let realized = ToolInvocationCost {
        units: 0,
        currency: "ATTACKER-CONTROLLED".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    // The signed receipt carries the canonical inert currency, never the caller
    // string, on any field.
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["financial"]["currency"], "",
        "a zero-exposure invocation reconcile must normalize the receipt currency to the inert value"
    );
    let serialized = serde_json::to_string(&reconciled.receipt).unwrap();
    assert!(
        !serialized.contains("ATTACKER-CONTROLLED"),
        "the unchecked caller-supplied currency must never reach the signed receipt"
    );
}

#[test]
fn reserving_authorization_succeeds_for_unregistered_tool_server() {
    // The reserve-for-caller authorization path never dispatches a tool
    // on this kernel, so it must NOT require the caller's tool server to be
    // registered. This lets the sidecar stop registering caller-arbitrary server
    // ids (unbounded growth) into the kernel.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Deliberately do NOT register "unreg-srv".
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-reserve".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(
        authorized.verdict,
        Verdict::Allow,
        "the reserve path must not require tool-server registration: {:?}",
        authorized.reason
    );
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("the reserve authorization mints a nonce even for an unregistered server");
    assert!(
        nonce.reserved_hold_id().is_some(),
        "the reserve path reserves a hold and binds it into the nonce"
    );
}

#[test]
fn dispatch_for_unregistered_tool_server_still_denies() {
    // The dispatch path (and every non-reserve disposition) must still require the
    // tool server to be registered: only the reserve-for-caller path is relaxed.
    let kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Non-strict kernel so the normal dispatch path (not the reserve preflight) runs.
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-dispatch".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not registered")),
        "dispatch to an unregistered server must deny ToolNotRegistered, got: {:?}",
        denied.reason
    );
}

#[test]
fn reserving_authorization_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-reserve-reason", &cap, &agent_kp);

    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);

    let terminal_reason = match &authorized.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("reserving authorization must be incomplete, got {other:?}"),
    };
    let decision_reason = match authorized.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("reserving authorization receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the reserve path terminal_state reason must match its receipt decision reason"
    );
    assert!(
        decision_reason.contains("reserved")
            && decision_reason.contains("present the minted execution nonce"),
        "the reserve path must report the reservation reason, got: {decision_reason}"
    );
    assert!(
        !terminal_reason.contains("retry with presented nonce"),
        "the reserve path must not borrow the retry-path terminal reason"
    );
}

#[test]
fn preflight_retry_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-preflight-reason", &cap, "read_file", "srv-a");

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);

    let terminal_reason = match &preflight.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("strict preflight must be incomplete, got {other:?}"),
    };
    let decision_reason = match preflight.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("strict preflight receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the retry path terminal_state reason must match its receipt decision reason"
    );
    assert_eq!(
        terminal_reason, "execution nonce preflight requires retry with presented nonce",
        "the reverse-for-retry preflight reason must be unchanged"
    );
}

#[test]
fn reserving_authorization_rejects_presented_execution_nonce() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // No presented nonce: the mint-only reserve entry point authorizes.
    let clean = reserve_request("req-reserve-clean", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&clean, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);

    // A presented nonce is a settlement artifact. The mint-only reserve entry
    // point must fail closed rather than silently skip the reserve path and fall
    // through to dispatch (the documented MUST-NOT invariant).
    let mut presented = reserve_request("req-reserve-presented", &cap, &agent_kp);
    presented.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &presented, &cfg));
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&presented, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "presenting a nonce at the reserve entry point must fail closed, got: {err}"
    );
}
