use super::super::route_authorization::{RouteCredential, TenantRule, ROUTE_TABLE};
use super::*;

fn names(role: CredentialRole) -> Vec<&'static str> {
    role.scopes().iter().map(|scope| scope.as_str()).collect()
}

#[test]
fn presets_hold_exactly_their_scopes() {
    assert_eq!(
        names(CredentialRole::KernelHost),
        [
            "admission-authority:write",
            "authority:read",
            "budgets:read",
            "budgets:write",
            "capabilities:issue",
            "lineage:write",
            "receipt-openings:read",
            "receipts:append",
            "receipts:read",
            "reports:read",
            "revocations:read",
            "revocations:write",
        ]
    );
    assert_eq!(
        names(CredentialRole::Operator),
        [
            "admin:emergency",
            "authority:admin",
            "certifications:read",
            "certifications:write",
            "credit:read",
            "credit:write",
            "evidence:read",
            "evidence:write",
            "federation:read",
            "federation:write",
            "findings:read",
            "findings:write",
            "fiscal:read",
            "fiscal:write",
            "lineage:read",
            "metrics:read",
            "passport:read",
            "passport:write",
            "receipts:admin",
            "receipts:read",
            "registry:write",
            "reports:read",
            "reputation:read",
            "reputation:write",
            "revocations:read",
            "revocations:write",
            "scim:write",
        ]
    );
    assert_eq!(
        names(CredentialRole::AuthorityWorkload),
        ["authority:read", "capabilities:issue"]
    );
    assert_eq!(
        names(CredentialRole::TenantReader),
        ["evidence:read", "receipts:read", "reports:read"]
    );
}

#[test]
fn preset_kinds_and_tenant_rule() {
    assert_eq!(
        CredentialRole::KernelHost.kind(),
        CredentialKind::Deployment
    );
    assert_eq!(
        CredentialRole::AuthorityWorkload.kind(),
        CredentialKind::Deployment
    );
    assert_eq!(CredentialRole::Operator.kind(), CredentialKind::Caller);
    assert_eq!(CredentialRole::TenantReader.kind(), CredentialKind::Caller);
    let requiring: Vec<_> = CredentialRole::ALL
        .iter()
        .filter(|role| role.requires_tenant())
        .collect();
    assert_eq!(requiring, [&CredentialRole::TenantReader]);
}

#[test]
fn role_names_round_trip_and_unknown_names_refuse() {
    for role in CredentialRole::ALL {
        assert_eq!(CredentialRole::parse(role.as_str()), Some(*role));
    }
    for unknown in [
        "",
        "admin",
        "kernel_host",
        "Kernel-Host",
        "all-caller-scopes",
    ] {
        assert_eq!(CredentialRole::parse(unknown), None, "{unknown}");
    }
}

#[test]
fn openings_scopes_stay_with_kernel_hosts() {
    for role in CredentialRole::ALL {
        let scopes = role.scopes();
        assert!(!scopes.contains(&Scope::ReceiptOpeningsErase), "{role:?}");
        assert_eq!(
            scopes.contains(&Scope::ReceiptOpeningsRead),
            *role == CredentialRole::KernelHost,
            "{role:?}"
        );
    }
}

#[test]
fn operator_holds_no_openings_budget_or_admission_scope() {
    for scope in CredentialRole::Operator.scopes() {
        let name = scope.as_str();
        assert!(
            !name.starts_with("receipt-openings:")
                && !name.starts_with("budgets:")
                && name != "admission-authority:write",
            "{name}"
        );
    }
}

#[test]
fn presets_hold_no_cluster_or_unrouted_scope() {
    for role in CredentialRole::ALL {
        for scope in role.scopes() {
            assert!(!scope.is_cluster(), "{role:?} {scope:?}");
            assert!(
                !matches!(
                    scope.as_str(),
                    "attestation:write" | "settlement:write" | "root-exchange:sign"
                ),
                "{role:?} {scope:?}"
            );
        }
    }
}

#[test]
fn presets_are_sorted_without_duplicates() {
    for role in CredentialRole::ALL {
        let names = names(*role);
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "{role:?}");
    }
}

/// Every preset scope is the scope of a route the role's kind and tenant
/// authority can use. `receipt-openings:read` is granted ahead of the
/// internal openings read route, which the committed receipts plan adds.
#[test]
fn every_preset_scope_reaches_a_route_of_its_role() {
    for role in CredentialRole::ALL {
        for scope in role.scopes() {
            if *scope == Scope::ReceiptOpeningsRead {
                continue;
            }
            let reachable = ROUTE_TABLE.iter().any(|rule| {
                let kind_fits = match rule.credential {
                    RouteCredential::Caller | RouteCredential::FindingBuyerOrCaller => true,
                    RouteCredential::Deployment => role.kind() == CredentialKind::Deployment,
                    _ => false,
                };
                let tenant_fits =
                    !role.requires_tenant() || rule.tenant == TenantRule::TenantScoped;
                rule.scope == Some(*scope) && kind_fits && tenant_fits
            });
            assert!(reachable, "{role:?} {scope:?}");
        }
    }
}

#[test]
fn each_preset_loads_as_an_access_configuration() {
    for (index, role) in CredentialRole::ALL.iter().enumerate() {
        let scopes = role
            .scopes()
            .iter()
            .map(|scope| format!("\"{}\"", scope.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let kind = match role.kind() {
            CredentialKind::Caller => "caller",
            CredentialKind::Deployment => "deployment",
        };
        let tenant = if role.requires_tenant() {
            "{ tenant = \"tenant-a\" }"
        } else {
            "\"deployment\""
        };
        let text = format!(
            "deployment = \"dep-a\"\ninternal_listen = \"127.0.0.1:9101\"\n[[credentials]]\nid = \"{}\"\nkind = \"{kind}\"\nsecret_sha256 = \"{index:064x}\"\nscopes = [{scopes}]\ndeployment = \"dep-a\"\ntenant_authority = {tenant}\n",
            role.as_str()
        );
        let loaded = super::super::caller_credentials::tests::parse(&text);
        assert!(loaded.is_ok(), "{role:?}: {:?}", loaded.err());
    }
}
