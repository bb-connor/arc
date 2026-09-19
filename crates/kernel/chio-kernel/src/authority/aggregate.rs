//! Explicit aggregate issuance never relaxes validation of ordinary responses.

use super::*;
use chio_core::capability::aggregate_invocation::{
    verify_aggregate_invocation_budget, AggregateInvocationScope,
};

/// Validate a direct family root, including its signed root commitment and
/// exactly the limit requested. Ordinary issuance continues to reject roots.
pub fn validate_issued_aggregate_family_root_response(
    capability: &CapabilityToken,
    requested_subject: &PublicKey,
    requested_scope: &ChioScope,
    requested_ttl_seconds: u64,
    current_issuer: &PublicKey,
    max_invocations: u32,
) -> Result<(), KernelError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
        .as_secs();
    validate_issued_response_at(
        capability,
        requested_subject,
        requested_scope,
        requested_ttl_seconds,
        current_issuer,
        now,
        DEFAULT_CAPABILITY_ISSUANCE_CLOCK_SKEW_SECONDS,
        None,
        Some(max_invocations),
    )
}

pub(super) fn validate_requested_aggregate(
    capability: &CapabilityToken,
    current_issuer: &PublicKey,
    expected_limit: Option<u32>,
) -> Result<(), KernelError> {
    match (expected_limit, &capability.aggregate_invocation_budget) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(KernelError::CapabilityIssuanceDenied(
            "aggregate invocation capability issuance requires atomic composite admission enforcement".into(),
        )),
        (Some(limit), Some(budget))
            if budget.scope == AggregateInvocationScope::DelegationFamily
                && budget.max_invocations == limit
                && capability.delegation_chain.is_empty() => {
            let verified = verify_aggregate_invocation_budget(
                capability, std::slice::from_ref(current_issuer), None,
            ).map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            if verified.is_none() {
                return Err(KernelError::CapabilityIssuanceFailed(
                    "aggregate family-root response omitted verified budget authority".into(),
                ));
            }
            Ok(())
        }
        _ => Err(KernelError::CapabilityIssuanceFailed(
            "issued aggregate family root does not match the requested limit and scope".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};

    fn scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "tools".into(),
                tool_name: "read".into(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn aggregate_root_response_is_explicit_exact_and_ca_authenticated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let authority = LocalCapabilityAuthority::new(key.clone());
        let scope = scope();
        let root = authority.issue_aggregate_family_root(&subject, scope.clone(), 300, 2)?;
        let validate = |root: &CapabilityToken, limit| {
            validate_issued_aggregate_family_root_response(
                root,
                &subject,
                &scope,
                300,
                &key.public_key(),
                limit,
            )
        };
        validate(&root, 2)?;
        assert!(validate(&root, 1).is_err());
        assert!(validate(&root, 3).is_err());
        assert!(validate_issued_capability_response(
            &root,
            &subject,
            &scope,
            300,
            &key.public_key(),
        )
        .is_err());
        let plain = authority.issue_capability(&subject, scope.clone(), 300)?;
        assert!(validate(&plain, 2).is_err());
        let mut changed = root.clone();
        changed.subject = Keypair::generate().public_key();
        assert!(validate(&changed, 2).is_err());
        let mut changed = root.clone();
        let budget = changed
            .aggregate_invocation_budget
            .as_mut()
            .ok_or("budget")?;
        budget
            .root_binding
            .as_mut()
            .ok_or("root binding")?
            .body
            .max_invocations = 3;
        changed.signature = key.sign_canonical(&changed.signing_body())?.0;
        assert!(validate(&changed, 2).is_err());
        assert!(validate_issued_aggregate_family_root_response(
            &root,
            &subject,
            &scope,
            1,
            &key.public_key(),
            2,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn backend_aggregate_root_retains_governed_signing_custody(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let backend: Arc<dyn SigningBackend> =
            Arc::new(chio_core::crypto::Ed25519Backend::new(key.clone()));
        let authority =
            GovernedCapabilityAuthority::new(backend, Arc::new(SystemCapabilityAuthorityClock));
        let scope = scope();
        let root = authority.issue_aggregate_family_root(&subject, scope.clone(), 300, 2)?;
        validate_issued_aggregate_family_root_response(
            &root,
            &subject,
            &scope,
            300,
            &key.public_key(),
            2,
        )?;
        Ok(())
    }
}
