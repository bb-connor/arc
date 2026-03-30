#[cfg(test)]
mod tests {
    use arc_core::capability::{
        RuntimeAssuranceTier, WorkloadCredentialKind, WorkloadIdentity, WorkloadIdentityScheme,
    };

    use crate::models::{
        DefaultAction, Extensions, HushSpec, OriginMatch, OriginProfile, OriginsExtension, Rules,
        ToolAccessRule, WorkloadIdentityMatch,
    };

    use super::{
        evaluate, selected_origin_profile_id, Decision, EvaluationAction, OriginContext,
        RuntimeAttestationContext,
    };

    fn origin_profile(id: &str, match_rules: OriginMatch) -> OriginProfile {
        OriginProfile {
            id: id.to_string(),
            match_rules: Some(match_rules),
            posture: None,
            tool_access: None,
            egress: None,
            data: None,
            budgets: None,
            bridge: None,
            explanation: None,
        }
    }

    fn enterprise_origin_spec(profiles: Vec<OriginProfile>) -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("enterprise-origin-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules::default()),
            extensions: Some(Extensions {
                posture: None,
                origins: Some(OriginsExtension {
                    default_behavior: None,
                    profiles,
                }),
                detection: None,
                reputation: None,
                runtime_assurance: None,
            }),
            metadata: None,
        }
    }

    fn runtime_assurance_spec(
        required: Option<RuntimeAssuranceTier>,
        preferred: Option<RuntimeAssuranceTier>,
    ) -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("runtime-assurance-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["payments.charge".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Allow,
                    max_args_size: None,
                    require_runtime_assurance_tier: required,
                    prefer_runtime_assurance_tier: preferred,
                    require_workload_identity: None,
                    prefer_workload_identity: None,
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions {
                posture: None,
                origins: None,
                detection: None,
                reputation: None,
                runtime_assurance: None,
            }),
            metadata: None,
        }
    }

    #[test]
    fn enterprise_origin_matches_provider_tenant_and_organization_exactly() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "enterprise",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-456".to_string()),
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-456".to_string()),
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched.as_deref(), Some("enterprise"));
    }

    #[test]
    fn enterprise_origin_denies_when_organization_is_missing() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "enterprise",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-456".to_string()),
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn enterprise_origin_matches_required_group_subset() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "group-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["eng".to_string(), "ops".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["ops".to_string(), "eng".to_string(), "finance".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched.as_deref(), Some("group-match"));
    }

    #[test]
    fn enterprise_origin_denies_when_required_group_is_missing() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "group-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["eng".to_string(), "ops".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["eng".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn enterprise_origin_matches_required_role_subset() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "role-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string()],
                sensitivity: None,
                actor_role: Some("viewer".to_string()),
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string(), "admin".to_string()],
                sensitivity: None,
                actor_role: Some("viewer".to_string()),
            },
        );

        assert_eq!(matched.as_deref(), Some("role-match"));
    }

    #[test]
    fn tool_access_runtime_assurance_requirement_denies_lower_tier() {
        let spec = runtime_assurance_spec(Some(RuntimeAssuranceTier::Attested), None);
        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Basic,
                    valid: true,
                    verifier: Some("verifier.arc".to_string()),
                    workload_identity: None,
                }),
            },
        );

        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("below required")),
            "expected assurance-tier denial reason"
        );
    }

    #[test]
    fn tool_access_runtime_assurance_preference_warns_when_missing() {
        let spec = runtime_assurance_spec(None, Some(RuntimeAssuranceTier::Attested));
        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: None,
            },
        );

        assert_eq!(result.decision, Decision::Warn);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("below preferred")),
            "expected assurance-tier warning reason"
        );
    }

    #[test]
    fn tool_access_runtime_assurance_requirement_allows_matching_tier() {
        let spec = runtime_assurance_spec(Some(RuntimeAssuranceTier::Attested), None);
        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Verified,
                    valid: true,
                    verifier: Some("verifier.arc".to_string()),
                    workload_identity: None,
                }),
            },
        );

        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn enterprise_origin_denies_when_required_role_is_missing() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "role-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string()],
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["viewer".to_string()],
                sensitivity: None,
                actor_role: Some("operator".to_string()),
            },
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn enterprise_origin_keeps_legacy_actor_role_matching_when_roles_are_absent() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "legacy-actor-role",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: Some("approver".to_string()),
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string()],
                sensitivity: None,
                actor_role: Some("approver".to_string()),
            },
        );

        assert_eq!(matched.as_deref(), Some("legacy-actor-role"));
    }

    #[test]
    fn tool_access_workload_identity_requirement_denies_mismatched_identity() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("workload-identity-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["payments.charge".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Allow,
                    max_args_size: None,
                    require_runtime_assurance_tier: None,
                    prefer_runtime_assurance_tier: None,
                    require_workload_identity: Some(WorkloadIdentityMatch {
                        scheme: Some(WorkloadIdentityScheme::Spiffe),
                        trust_domain: Some("prod.arc".to_string()),
                        path_prefixes: vec!["/payments".to_string()],
                        credential_kinds: vec![WorkloadCredentialKind::X509Svid],
                    }),
                    prefer_workload_identity: None,
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions::default()),
            metadata: None,
        };

        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Verified,
                    valid: true,
                    verifier: Some("verifier.arc".to_string()),
                    workload_identity: Some(WorkloadIdentity {
                        scheme: WorkloadIdentityScheme::Spiffe,
                        credential_kind: WorkloadCredentialKind::X509Svid,
                        uri: "spiffe://dev.arc/payments/worker".to_string(),
                        trust_domain: "dev.arc".to_string(),
                        path: "/payments/worker".to_string(),
                    }),
                }),
            },
        );

        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("workload identity")),
            "expected workload-identity denial reason"
        );
    }

    #[test]
    fn tool_access_workload_identity_preference_warns_when_missing() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("workload-identity-preference".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["payments.charge".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Allow,
                    max_args_size: None,
                    require_runtime_assurance_tier: None,
                    prefer_runtime_assurance_tier: None,
                    require_workload_identity: None,
                    prefer_workload_identity: Some(WorkloadIdentityMatch {
                        scheme: Some(WorkloadIdentityScheme::Spiffe),
                        trust_domain: Some("prod.arc".to_string()),
                        path_prefixes: vec!["/payments".to_string()],
                        credential_kinds: Vec::new(),
                    }),
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions::default()),
            metadata: None,
        };

        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Verified,
                    valid: true,
                    verifier: Some("verifier.arc".to_string()),
                    workload_identity: None,
                }),
            },
        );

        assert_eq!(result.decision, Decision::Warn);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("workload identity")),
            "expected workload-identity warning reason"
        );
    }
}
