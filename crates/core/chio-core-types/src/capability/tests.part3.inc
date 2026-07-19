/// A wildcard parent grant (`*:*`) covers a concrete child step. Step
/// validation honors wildcard parent grants the same way scope subset
/// validation does, so a legitimate concrete-child step is accepted rather
/// than falsely rejected as targeting a tool outside the parent scope.
#[cfg(feature = "delegation")]
#[test]
fn delegate_honors_wildcard_parent_grant_in_step_validation() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    // Parent grants every server and tool via `*:*` and authorizes delegation.
    let parent_scope = make_scope(vec![make_grant(
        "*",
        "*",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child narrows to a single concrete tool; the step targets that concrete
    // tool, which the `*:*` parent grant covers. The declared AddConstraint step
    // must also be reflected in the child grant, so the child carries the
    // MaxLength(8) constraint the step adds.
    let child_scope = make_scope(vec![ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::MaxLength(8)],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::AddConstraint {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        constraint: Constraint::MaxLength(8),
    }]);

    let receipt = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [3_u8; 16],
    )
    .unwrap();
    assert!(receipt.link.verify_signature().unwrap());
    assert_eq!(receipt.link.attenuations.len(), 1);
}

/// Re-sign a plain token as an attenuated token carrying an explicit
/// `budget_share_bps`, so the share is covered by the signature.
#[cfg(feature = "delegation")]
fn attenuated_share_parent(
    issuer: &Keypair,
    plain: &CapabilityToken,
    budget_share_bps: u16,
) -> CapabilityToken {
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: plain.body(),
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&plain.scope).unwrap(),
                child_scope_hash: scope_hash(&plain.scope).unwrap(),
                normalized_subset_proof: compute_attenuation_witness(&plain.scope, &plain.scope)
                    .unwrap(),
                aggregate_family_preservation: None,
            },
            budget_share_bps: Some(budget_share_bps),
        },
        issuer,
    )
    .unwrap()
}

/// A parent that explicitly carries the FULL share (`Some(10_000)`) is not
/// actually budget-attenuated: omitting the child share is a no-op (downstream
/// admission treats a missing share as the same full ceiling). Such a
/// delegation must be ACCEPTED rather than rejected as if the parent held a
/// reduced share.
#[cfg(feature = "delegation")]
#[test]
fn delegate_allows_omitted_share_for_full_share_parent() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let plain = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let full_share_parent = attenuated_share_parent(&issuer, &plain, 10_000);
    assert!(full_share_parent.verify_signature().unwrap());
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    // Child OMITS budget_share_bps; the parent holds the full 100% share, so the
    // omission does not widen anything -> accept.
    let omitted = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: None,
    };
    let ok = delegate(
        &full_share_parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        omitted,
        1500,
        [7_u8; 16],
    );
    assert!(ok.is_ok());
}

/// Overlapping parent grants must be order-independent: a broad `*:*` grant that
/// lacks the targeted operation must not mask a later concrete grant that holds
/// it. A `RemoveOperation(ReadResult)` step is a valid narrowing because the
/// concrete `srv-a:tool-x` grant holds `ReadResult`, even though the leading
/// `*:*` grant only holds `Invoke`.
#[cfg(feature = "delegation")]
#[test]
fn delegate_searches_all_matching_grants_for_step_narrowing() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    // Parent has a broad `*:*` grant (Invoke + Delegate only) FIRST, then a
    // concrete grant that additionally holds ReadResult. The step targets
    // ReadResult, which only the second (concrete) grant satisfies.
    let parent_scope = make_scope(vec![
        make_grant("*", "*", vec![Operation::Invoke, Operation::Delegate]),
        make_grant(
            "srv-a",
            "tool-x",
            vec![
                Operation::Invoke,
                Operation::Delegate,
                Operation::ReadResult,
            ],
        ),
    ]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child drops ReadResult (keeps Invoke); the declared RemoveOperation step is
    // reflected because no covering child grant still holds ReadResult.
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::RemoveOperation {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        operation: Operation::ReadResult,
    }]);

    let receipt = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [8_u8; 16],
    )
    .unwrap();
    assert!(receipt.link.verify_signature().unwrap());
    assert_eq!(receipt.link.attenuations.len(), 1);
}

/// A declared step that is reduce-only against the parent but NOT reflected in
/// the child scope is rejected at mint time, so the helper never emits a receipt
/// that chio-kernel's declared-attenuation validation would later reject. Here
/// the step declares an added constraint the child grant does not carry.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_step_not_reflected_in_child() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child has NO constraint, but the step declares AddConstraint -> the
    // declared attenuation is not reflected in the child -> reject.
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::AddConstraint {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        constraint: Constraint::MaxLength(8),
    }]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// attenuation correctness regression: a wildcard
/// step TARGET must cover concrete child grants when checking that a declared
/// removal is reflected in the child.
///
/// A `*:*` parent delegates a concrete `srv-a:tool-x` child while declaring
/// `RemoveOperation { server_id: "*", tool_name: "*", operation: Invoke }`. The
/// parent-side step check accepts this (the `*:*` parent grant holds Invoke),
/// but the child still grants Invoke on the concrete tool, so the declared
/// removal is NOT truly reflected. Before the fix the reflection check used a
/// one-way matcher that only matched when the GRANT was wildcard, so the
/// concrete child grant never matched the wildcard step target and the
/// under-declared link was signed. With the child-side matcher the wildcard
/// step target covers the concrete child grant and the link is rejected
/// fail-closed.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_wildcard_remove_operation_step_not_reflected_in_concrete_child() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    // Parent grants every server and tool via `*:*` and authorizes delegation.
    let parent_scope = make_scope(vec![make_grant(
        "*",
        "*",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child is concrete and STILL holds Invoke on srv-a:tool-x.
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    // The step declares a wildcard removal of Invoke, but the concrete child
    // grant still holds Invoke -> the declared removal is not reflected.
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::RemoveOperation {
        server_id: "*".to_string(),
        tool_name: "*".to_string(),
        operation: Operation::Invoke,
    }]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [9_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// Companion to the regression above: a wildcard step TARGET that IS truly
/// reflected in the concrete child must be accepted. Here the parent `*:*` grant
/// holds `ReadResult`, the step declares its wildcard removal, and the concrete
/// child drops `ReadResult` (keeps Invoke), so the removal is genuinely
/// reflected. This proves the child-side matcher does not over-reject valid
/// wildcard-removal narrowings.
#[cfg(feature = "delegation")]
#[test]
fn delegate_accepts_wildcard_remove_operation_step_reflected_in_concrete_child() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "*",
        "*",
        vec![
            Operation::Invoke,
            Operation::Delegate,
            Operation::ReadResult,
        ],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Concrete child keeps Invoke but drops ReadResult, so the wildcard removal
    // of ReadResult is genuinely reflected.
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::RemoveOperation {
        server_id: "*".to_string(),
        tool_name: "*".to_string(),
        operation: Operation::ReadResult,
    }]);

    let receipt = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [10_u8; 16],
    )
    .unwrap();
    assert!(receipt.link.verify_signature().unwrap());
    assert_eq!(receipt.link.attenuations.len(), 1);
}

/// Attenuation correctness regression: the mirror of the wildcard-step case. A
/// CONCRETE step TARGET must cover a WILDCARD child grant
/// when checking that a declared removal is reflected in the child.
///
/// A `*:*` parent delegates a wildcard `*:*` child while declaring
/// `RemoveOperation { server_id: "srv-a", tool_name: "tool-x", operation: Invoke }`.
/// The parent-side step check accepts this (the `*:*` parent grant holds
/// Invoke), but the wildcard child grant STILL holds Invoke on srv-a:tool-x
/// through its asterisk, so the declared removal is NOT truly reflected. Before
/// the bidirectional matcher the reflection check matched only when the STEP
/// target was wildcard, so the concrete step never matched the wildcard child
/// grant and the under-declared link was signed; chio-kernel's
/// declared-attenuation check would then reject the minted token (mint and
/// kernel disagree). With the bidirectional matcher the concrete step target
/// covers the wildcard child grant and the link is rejected fail-closed.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_concrete_remove_operation_step_not_reflected_in_wildcard_child() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "*",
        "*",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child is wildcard and STILL holds Invoke on srv-a:tool-x via its asterisk.
    let child_scope = make_scope(vec![make_grant(
        "*",
        "*",
        vec![Operation::Invoke, Operation::Delegate],
    )]);

    // The step declares a concrete removal of Invoke, but the wildcard child
    // grant still holds Invoke on the targeted tool -> not reflected.
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::RemoveOperation {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        operation: Operation::Invoke,
    }]);

    let err = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [11_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

fn aggregate_invocation_wire_root_binding(
    issuer: &Keypair,
    subject: &PublicKey,
    max_invocations: u32,
) -> AggregateBudgetRootBinding {
    AggregateBudgetRootBinding {
        body: AggregateBudgetRootBindingBody {
            schema: CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA.to_string(),
            root_capability_id: "cap-family-root".to_string(),
            root_capability_hash: "11".repeat(32),
            root_issuer: issuer.public_key(),
            root_subject: subject.clone(),
            max_invocations,
            root_expires_at: 2_000,
            root_scope_hash: "22".repeat(32),
        },
        algorithm: None,
        signature: issuer.sign(b"aggregate-wire-shape"),
    }
}

fn aggregate_invocation_wire_body(
    issuer: &Keypair,
    scope: ChioScope,
    aggregate_invocation_budget: Option<AggregateInvocationBudget>,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap-aggregate-wire".to_string(),
        issuer: issuer.public_key(),
        subject: issuer.public_key(),
        scope,
        issued_at: 1_000,
        expires_at: 2_000,
        delegation_chain: vec![],
        aggregate_invocation_budget,
    }
}

fn aggregate_invocation_wire_unsigned_token(
    issuer: &Keypair,
    scope: ChioScope,
    aggregate_invocation_budget: AggregateInvocationBudget,
) -> CapabilityToken {
    CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: "cap-invalid-aggregate-wire".to_string(),
        issuer: issuer.public_key(),
        subject: issuer.public_key(),
        scope,
        issued_at: 1_000,
        expires_at: 2_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: Some(aggregate_invocation_budget),
        algorithm: None,
        caveats: vec![],
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        signature: issuer.sign(b"structural-validation-only"),
    }
}

#[test]
fn aggregate_invocation_wire_absence_preserves_exact_prechange_bytes() {
    let issuer =
        Keypair::from_seed_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .expect("fixed RFC 8032 key");
    let public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let body = CapabilityTokenBody {
        id: "cap-compat".to_string(),
        issuer: issuer.public_key(),
        subject: issuer.public_key(),
        scope: ChioScope::default(),
        issued_at: 1_000,
        expires_at: 2_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let expected_legacy = format!(
        "{{\"expires_at\":2000,\"id\":\"cap-compat\",\"issued_at\":1000,\"issuer\":\"{public_key}\",\"scope\":{{}},\"subject\":\"{public_key}\"}}"
    );
    assert_eq!(
        crate::canonical::canonical_json_bytes(&body).expect("canonical legacy body"),
        expected_legacy.as_bytes()
    );

    let signing_body = CapabilityTokenSigningBody {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        body: body.clone(),
        caveats: vec![],
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
    };
    let expected_schema_aware = format!(
        "{{\"expires_at\":2000,\"id\":\"cap-compat\",\"issued_at\":1000,\"issuer\":\"{public_key}\",\"schema\":\"chio.capability.v1\",\"scope\":{{}},\"subject\":\"{public_key}\"}}"
    );
    assert_eq!(
        crate::canonical::canonical_json_bytes(&signing_body).expect("canonical schema-aware body"),
        expected_schema_aware.as_bytes()
    );

    let body_json = serde_json::to_value(&body).expect("serialize body");
    assert!(body_json.get("aggregate_invocation_budget").is_none());
    let token = CapabilityToken::sign(body, &issuer).expect("sign token");
    let token_json = serde_json::to_value(&token).expect("serialize token");
    assert!(token_json.get("aggregate_invocation_budget").is_none());
}

#[test]
fn aggregate_invocation_wire_zero_limit_round_trips() {
    let issuer = Keypair::generate();
    let budget = AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 0,
        root_binding: None,
    };
    let body = aggregate_invocation_wire_body(&issuer, ChioScope::default(), Some(budget));
    let token = CapabilityToken::sign(body, &issuer).expect("zero is a valid aggregate maximum");
    let encoded = serde_json::to_vec(&token).expect("serialize token");
    let decoded: CapabilityToken = serde_json::from_slice(&encoded).expect("deserialize token");
    assert_eq!(
        decoded
            .aggregate_invocation_budget
            .as_ref()
            .expect("aggregate budget")
            .max_invocations,
        0
    );
    assert!(decoded.verify_signature().expect("verify signature"));
}

#[test]
fn aggregate_invocation_wire_scope_values_are_exact() {
    assert_eq!(
        serde_json::to_string(&AggregateInvocationScope::Capability).expect("capability scope"),
        "\"capability\""
    );
    assert_eq!(
        serde_json::to_string(&AggregateInvocationScope::DelegationFamily)
            .expect("delegation family scope"),
        "\"delegation_family\""
    );
}

#[test]
fn aggregate_invocation_wire_nested_shapes_reject_unknown_fields() {
    let issuer = Keypair::generate();
    let subject = issuer.public_key();
    let family = AggregateInvocationBudget {
        scope: AggregateInvocationScope::DelegationFamily,
        max_invocations: 3,
        root_binding: Some(aggregate_invocation_wire_root_binding(&issuer, &subject, 3)),
    };

    let mut budget_json = serde_json::to_value(&family).expect("serialize budget");
    budget_json
        .as_object_mut()
        .expect("budget object")
        .insert("unknown".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<AggregateInvocationBudget>(budget_json).is_err());

    let mut body_json = serde_json::to_value(&family.root_binding.as_ref().expect("binding").body)
        .expect("serialize binding body");
    body_json
        .as_object_mut()
        .expect("binding body object")
        .insert("unknown".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<AggregateBudgetRootBindingBody>(body_json).is_err());

    let mut binding_json =
        serde_json::to_value(family.root_binding.expect("binding")).expect("serialize binding");
    binding_json
        .as_object_mut()
        .expect("binding object")
        .insert("unknown".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<AggregateBudgetRootBinding>(binding_json).is_err());

    let commitment = AggregateBudgetRootCommitment {
        root_capability_id: "cap-family-root".to_string(),
        root_issuer: issuer.public_key(),
        root_subject: subject,
        root_scope_hash: "22".repeat(32),
        root_issued_at: 1_000,
        root_expires_at: 2_000,
        aggregate_scope: AggregateInvocationScope::DelegationFamily,
        max_invocations: 3,
    };
    let mut commitment_json = serde_json::to_value(commitment).expect("serialize commitment");
    commitment_json
        .as_object_mut()
        .expect("commitment object")
        .insert("unknown".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<AggregateBudgetRootCommitment>(commitment_json).is_err());
}

#[test]
fn aggregate_invocation_wire_rejects_invalid_scope_and_root_combinations() {
    let issuer = Keypair::generate();
    let subject = issuer.public_key();
    let binding = aggregate_invocation_wire_root_binding(&issuer, &subject, 3);

    let capability_with_binding = AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 3,
        root_binding: Some(binding.clone()),
    };
    assert!(capability_with_binding
        .validate_for_scope(&ChioScope::default())
        .is_err());
    assert!(aggregate_invocation_wire_unsigned_token(
        &issuer,
        ChioScope::default(),
        capability_with_binding,
    )
    .validate_schema()
    .is_err());

    let family_without_binding = AggregateInvocationBudget {
        scope: AggregateInvocationScope::DelegationFamily,
        max_invocations: 3,
        root_binding: None,
    };
    assert!(family_without_binding
        .validate_for_scope(&ChioScope::default())
        .is_err());
    assert!(aggregate_invocation_wire_unsigned_token(
        &issuer,
        ChioScope::default(),
        family_without_binding,
    )
    .validate_schema()
    .is_err());

    let capability = AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 3,
        root_binding: None,
    };
    for scope in [
        ChioScope {
            grants: vec![make_grant("server", "tool", vec![Operation::Delegate])],
            ..ChioScope::default()
        },
        ChioScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "resource://*".to_string(),
                operations: vec![Operation::Delegate],
            }],
            ..ChioScope::default()
        },
        ChioScope {
            prompt_grants: vec![PromptGrant {
                prompt_name: "*".to_string(),
                operations: vec![Operation::Delegate],
            }],
            ..ChioScope::default()
        },
    ] {
        assert!(capability.validate_for_scope(&scope).is_err());
        assert!(
            aggregate_invocation_wire_unsigned_token(&issuer, scope, capability.clone())
                .validate_schema()
                .is_err()
        );
    }

    let valid_family = AggregateInvocationBudget {
        scope: AggregateInvocationScope::DelegationFamily,
        max_invocations: 3,
        root_binding: Some(binding),
    };
    assert!(valid_family
        .validate_for_scope(&ChioScope::default())
        .is_ok());
}

#[test]
fn aggregate_invocation_wire_present_field_disables_plain_body_fallback() {
    let issuer = Keypair::generate();
    let body = aggregate_invocation_wire_body(
        &issuer,
        ChioScope::default(),
        Some(AggregateInvocationBudget {
            scope: AggregateInvocationScope::Capability,
            max_invocations: 1,
            root_binding: None,
        }),
    );
    let (signature, _) = issuer
        .sign_canonical(&body)
        .expect("sign legacy plain body");
    let token = CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: body.id,
        issuer: body.issuer,
        subject: body.subject,
        scope: body.scope,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        delegation_chain: body.delegation_chain,
        aggregate_invocation_budget: body.aggregate_invocation_budget,
        algorithm: None,
        caveats: vec![],
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        signature,
    };

    assert!(!token.verify_signature().expect("ordinary verification"));
    assert!(!token
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical)
        .expect("floor verification"));
}
