use super::*;

// ---------------------------------------------------------------------------
// Attenuation-step narrowing + parent-relative budget_share_bps.
// ---------------------------------------------------------------------------

#[cfg(feature = "delegation")]
fn capped_grant(
    server: &str,
    tool: &str,
    ops: Vec<Operation>,
    max_invocations: Option<u32>,
    max_total_cost: Option<MonetaryAmount>,
) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: ops,
        constraints: vec![],
        max_invocations,
        max_cost_per_invocation: None,
        max_total_cost,
        dpop_required: None,
    }
}

/// A valid narrowing step (reduce max_invocations below the parent cap) is
/// accepted and rides onto the signed link.
#[cfg(feature = "delegation")]
#[test]
fn delegate_accepts_valid_narrowing_step() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
        Some(10),
        None,
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child scope narrows max_invocations 10 -> 4; the step mirrors that.
    let child_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke],
        Some(4),
        None,
    )]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::ReduceBudget {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        max_invocations: 4,
    }]);

    let receipt = delegate(
        &parent,
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [9_u8; 16],
        },
    )
    .unwrap();
    assert!(receipt.link.verify_integrity_embedded_key().unwrap());
    assert_eq!(receipt.link.attenuations.len(), 1);
}

/// A widening step (raise max_invocations above the parent cap) is rejected
/// fail-closed even though the child *scope* itself is a subset.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_widening_step() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
        Some(10),
        None,
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    // Child scope is a valid subset (max 5 <= 10), so subset validation passes,
    // but the step claims a budget of 50 invocations -- a widening.
    let child_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke],
        Some(5),
        None,
    )]);
    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::ReduceBudget {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        max_invocations: 50, // > parent cap 10
    }]);

    let err = delegate(
        &parent,
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [0_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// A step targeting a tool the parent never held is a widening and rejected.
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_step_for_unknown_tool() {
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
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::AddConstraint {
        server_id: "srv-a".to_string(),
        tool_name: "tool-NOT-IN-PARENT".to_string(),
        constraint: Constraint::MaxLength(8),
    }]);

    let err = delegate(
        &parent,
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [0_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// A monetary cost step in a different currency than the parent's cap is
/// rejected (same currency required for a meaningful narrowing comparison).
#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_cost_step_currency_switch() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
        None,
        Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        }),
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let child_scope = make_scope(vec![capped_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke],
        None,
        Some(MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        }),
    )]);

    let attenuation = ScopeAttenuation::from_steps(vec![Attenuation::ReduceTotalCost {
        server_id: "srv-a".to_string(),
        tool_name: "tool-x".to_string(),
        // Lower number but different currency: not a valid narrowing.
        max_total_cost: MonetaryAmount {
            units: 1,
            currency: "EUR".to_string(),
        },
    }]);

    let err = delegate(
        &parent,
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [0_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// A child budget_share_bps within the parent's share is accepted; one that
/// exceeds the parent's share is rejected parent-relative.
#[cfg(feature = "delegation")]
#[test]
fn delegate_enforces_parent_relative_budget_share() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    // Parent only holds 30% of the budget; re-sign as an attenuated token so the
    // budget_share_bps is covered by the signature and verify_signature() passes.
    let plain = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let attenuated_parent = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: plain.body(),
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&plain.scope).unwrap(),
                child_scope_hash: scope_hash(&plain.scope).unwrap(),
                normalized_subset_proof: compute_attenuation_witness(&plain.scope, &plain.scope)
                    .unwrap(),
            },
            budget_share_bps: Some(3_000),
        },
        &issuer,
    )
    .unwrap();
    assert!(attenuated_parent.verify_integrity_embedded_key().unwrap());
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    // A child claiming 50% exceeds the parent's 30% -> reject.
    let over = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: Some(5_000),
    };
    let err = delegate(
        &attenuated_parent,
        &attenuated_parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        over,
        DelegationStamp {
            signed_at: 1500,
            nonce: [0_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));

    // A child claiming 20% is within the parent's 30% -> accept.
    let within = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: Some(2_000),
    };
    let ok = delegate(
        &attenuated_parent,
        &attenuated_parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        within,
        DelegationStamp {
            signed_at: 1500,
            nonce: [1_u8; 16],
        },
    );
    assert!(ok.is_ok());
}

/// When the parent is budget-attenuated (holds a reduced `budget_share_bps`), a
/// child that omits its own `budget_share_bps` is rejected fail-closed:
/// downstream admission treats a missing child share as the full 100% ceiling,
/// so omission would silently widen the parent's reduced share. A child that
/// states an explicit share `<=` the parent's is accepted.
#[cfg(feature = "delegation")]
#[test]
fn delegate_requires_child_share_under_attenuated_parent() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();

    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    // Parent only holds 30% of the budget; re-sign as an attenuated token so the
    // budget_share_bps is covered by the signature and verify_signature() passes.
    let plain = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    let attenuated_parent = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: plain.body(),
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&plain.scope).unwrap(),
                child_scope_hash: scope_hash(&plain.scope).unwrap(),
                normalized_subset_proof: compute_attenuation_witness(&plain.scope, &plain.scope)
                    .unwrap(),
            },
            budget_share_bps: Some(3_000),
        },
        &issuer,
    )
    .unwrap();
    assert!(attenuated_parent.verify_integrity_embedded_key().unwrap());
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    // Child OMITS budget_share_bps while the parent holds a reduced 30% share ->
    // reject: an absent child share would widen to the full budget downstream.
    let omitted = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: None,
    };
    let err = delegate(
        &attenuated_parent,
        &attenuated_parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        omitted,
        DelegationStamp {
            signed_at: 1500,
            nonce: [0_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));

    // Child states an explicit share within the parent's 30% -> accept.
    let within = ScopeAttenuation {
        steps: vec![],
        child_expires_at: None,
        budget_share_bps: Some(2_500),
    };
    let ok = delegate(
        &attenuated_parent,
        &attenuated_parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        within,
        DelegationStamp {
            signed_at: 1500,
            nonce: [2_u8; 16],
        },
    );
    assert!(ok.is_ok());
}

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
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [3_u8; 16],
        },
    )
    .unwrap();
    assert!(receipt.link.verify_integrity_embedded_key().unwrap());
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
    assert!(full_share_parent.verify_integrity_embedded_key().unwrap());
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
        &full_share_parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        omitted,
        DelegationStamp {
            signed_at: 1500,
            nonce: [7_u8; 16],
        },
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
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [8_u8; 16],
        },
    )
    .unwrap();
    assert!(receipt.link.verify_integrity_embedded_key().unwrap());
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
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [0_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// Attenuation correctness: a wildcard step TARGET must cover concrete child grants when checking that a declared
/// removal is reflected in the child.
///
/// A `*:*` parent delegates a concrete `srv-a:tool-x` child while declaring
/// `RemoveOperation { server_id: "*", tool_name: "*", operation: Invoke }`. The
/// parent-side step check accepts this (the `*:*` parent grant holds Invoke),
/// but the child still grants Invoke on the concrete tool, so the declared
/// removal is NOT truly reflected. The child-side matcher lets the wildcard
/// step target cover the concrete child grant, so the link is rejected
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
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [9_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

/// Companion to the case above: a wildcard step TARGET that IS truly
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
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [10_u8; 16],
        },
    )
    .unwrap();
    assert!(receipt.link.verify_integrity_embedded_key().unwrap());
    assert_eq!(receipt.link.attenuations.len(), 1);
}

/// Attenuation correctness: the mirror of the wildcard-step case. A
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
        &parent.issuer,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        DelegationStamp {
            signed_at: 1500,
            nonce: [11_u8; 16],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}
