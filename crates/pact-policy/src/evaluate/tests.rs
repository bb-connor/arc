#[cfg(test)]
mod tests {
    use crate::models::{
        Extensions, HushSpec, OriginMatch, OriginProfile, OriginsExtension, Rules,
    };

    use super::{selected_origin_profile_id, OriginContext};

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
}
