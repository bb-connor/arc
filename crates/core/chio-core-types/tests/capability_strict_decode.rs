//! Every signed type in the capability tree refuses a member it would not
//! sign, so a padded token cannot decode and still verify.

use chio_core_types::capability::attenuation::{Attenuation, DelegationLink, DelegationLinkBody};
use chio_core_types::capability::scope::{
    ChioScope, Constraint, ModelSafetyTier, Operation, PromptGrant, ResourceGrant, ToolGrant,
};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::Keypair;
use chio_security_types::strict_serde::DUPLICATE_KEY;
use serde::Deserialize;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signed_token() -> TestResult<Value> {
    let issuer = Keypair::from_seed(&[3; 32]);
    let delegatee = Keypair::from_seed(&[4; 32]);
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-parent".to_string(),
            delegator: issuer.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: vec![Attenuation::RemoveTool {
                server_id: "srv".to_string(),
                tool_name: "other".to_string(),
            }],
            timestamp: 1_710_000_000,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )?;
    let body = CapabilityTokenBody {
        id: "cap-strict".to_string(),
        issuer: issuer.public_key(),
        subject: delegatee.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![
                    Constraint::PathPrefix("/workspace".to_string()),
                    Constraint::GovernedIntentRequired,
                    Constraint::ModelConstraint {
                        allowed_model_ids: vec!["model-a".to_string()],
                        min_safety_tier: Some(ModelSafetyTier::Standard),
                    },
                ],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
            prompt_grants: vec![PromptGrant {
                prompt_name: "summarize".to_string(),
                operations: vec![Operation::Get],
            }],
        },
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
        delegation_chain: vec![link],
        aggregate_invocation_budget: None,
    };
    Ok(serde_json::to_value(CapabilityToken::sign(body, &issuer)?)?)
}

fn refusal(value: Value) -> Option<String> {
    serde_json::from_value::<CapabilityToken>(value)
        .err()
        .map(|error| error.to_string())
}

#[test]
fn the_signed_token_decodes_and_verifies() -> TestResult {
    let token: CapabilityToken = serde_json::from_value(signed_token()?)?;
    assert!(token.verify_integrity_embedded_key()?);
    let link = token.delegation_chain.first().ok_or("delegation link")?;
    assert!(link.verify_integrity_embedded_key()?);
    Ok(())
}

#[test]
fn every_capability_record_refuses_an_unknown_member() -> TestResult {
    let token = signed_token()?;
    for (record, path) in [
        ("CapabilityToken", ""),
        ("ChioScope", "/scope"),
        ("ToolGrant", "/scope/grants/0"),
        ("ResourceGrant", "/scope/resource_grants/0"),
        ("PromptGrant", "/scope/prompt_grants/0"),
        ("DelegationLink", "/delegation_chain/0"),
        ("Attenuation", "/delegation_chain/0/attenuations/0"),
    ] {
        let mut padded = token.clone();
        padded
            .pointer_mut(path)
            .and_then(Value::as_object_mut)
            .ok_or(record)?
            .insert("pad".to_string(), json!(0));
        let error = refusal(padded).ok_or(record)?;
        assert!(
            error.starts_with("unknown field `pad`, expected"),
            "{record}: {error}"
        );
    }
    Ok(())
}

#[test]
fn a_unit_constraint_refuses_a_value_member() -> TestResult {
    let mut padded = signed_token()?;
    padded["scope"]["grants"][0]["constraints"][1]["value"] = Value::Null;
    assert_eq!(
        refusal(padded).as_deref(),
        Some(chio_security_types::strict_serde::DROPPED_INPUT)
    );
    Ok(())
}

#[test]
fn a_token_body_refuses_an_unknown_member() -> TestResult {
    let mut body = signed_token()?;
    let members = body.as_object_mut().ok_or("token object")?;
    for signed_only in ["schema", "signature"] {
        members.remove(signed_only);
    }
    members.insert("pad".to_string(), json!(0));
    let error = serde_json::from_value::<CapabilityTokenBody>(body)
        .err()
        .map(|error| error.to_string())
        .ok_or("padded body decoded")?;
    assert!(
        error.starts_with("unknown field `pad`, expected"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_delegation_link_body_refuses_an_unknown_member() -> TestResult {
    let mut link = signed_token()?["delegation_chain"][0].clone();
    let members = link.as_object_mut().ok_or("link object")?;
    members.remove("signature");
    members.insert("pad".to_string(), json!(0));
    let error = serde_json::from_value::<DelegationLinkBody>(link)
        .err()
        .map(|error| error.to_string())
        .ok_or("padded link body decoded")?;
    assert!(
        error.starts_with("unknown field `pad`, expected"),
        "{error}"
    );
    Ok(())
}

fn token_with_add_constraint() -> TestResult<String> {
    let issuer = Keypair::from_seed(&[5; 32]);
    let delegatee = Keypair::from_seed(&[6; 32]);
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-parent".to_string(),
            delegator: issuer.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: vec![Attenuation::AddConstraint {
                server_id: "srv".to_string(),
                tool_name: "read".to_string(),
                constraint: Constraint::DomainExact("a.example".to_string()),
            }],
            timestamp: 1_710_000_000,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )?;
    let body = CapabilityTokenBody {
        id: "cap-duplicate".to_string(),
        issuer: issuer.public_key(),
        subject: delegatee.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/workspace".to_string())],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
        delegation_chain: vec![link],
        aggregate_invocation_budget: None,
    };
    Ok(serde_json::to_string(&CapabilityToken::sign(
        body, &issuer,
    )?)?)
}

fn replace_once(text: &str, from: &str, to: &str) -> TestResult<String> {
    if text.matches(from).count() != 1 {
        return Err(format!("{from} must appear once").into());
    }
    Ok(text.replacen(from, to, 1))
}

#[test]
fn a_raw_token_refuses_a_repeated_constraint_key_in_a_grant_or_an_attenuation() -> TestResult {
    let token = token_with_add_constraint()?;
    assert!(serde_json::from_str::<CapabilityToken>(&token)?.verify_integrity_embedded_key()?);
    let grant = r#"{"type":"path_prefix","value":"/workspace"}"#;
    let attenuation = r#"{"type":"domain_exact","value":"a.example"}"#;
    for (padded, key) in [
        (
            replace_once(
                &token,
                grant,
                r#"{"type":"domain_exact","type":"path_prefix","value":"/workspace"}"#,
            )?,
            "type",
        ),
        (
            replace_once(
                &token,
                grant,
                r#"{"type":"path_prefix","value":"/x","value":"/workspace"}"#,
            )?,
            "value",
        ),
        (
            replace_once(
                &token,
                attenuation,
                r#"{"type":"path_prefix","type":"domain_exact","value":"a.example"}"#,
            )?,
            "type",
        ),
        (
            replace_once(
                &token,
                attenuation,
                r#"{"type":"domain_exact","value":"b.example","value":"a.example"}"#,
            )?,
            "value",
        ),
    ] {
        let expected = format!("{DUPLICATE_KEY}: {key:?}");
        let direct =
            <CapabilityToken>::deserialize(&mut serde_json::Deserializer::from_str(&padded))
                .err()
                .map(|error| error.to_string());
        assert!(
            direct
                .as_deref()
                .is_some_and(|error| error.starts_with(&expected)),
            "{direct:?}"
        );
        let decoded = serde_json::from_str::<CapabilityToken>(&padded)
            .err()
            .map(|error| error.to_string());
        assert!(
            decoded
                .as_deref()
                .is_some_and(|error| error.starts_with(&expected)),
            "{decoded:?}"
        );
    }
    Ok(())
}
