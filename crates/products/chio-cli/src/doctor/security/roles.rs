//! Bearer role separation for a hosted deployment.
//!
//! A hosted edge carries up to four bearer roles: the session credential
//! clients present, the admin credential for the admin routes, the control
//! credential it presents to the trust service, and the workload credential
//! the trust service accepts only for capability issuance. The edge refuses
//! a launch that reuses a value across roles, and this probe reports that
//! refusal before the launch, from the same environment variables the launch
//! reads. A role that is not set is not an error: a local edge without a
//! control URL legitimately carries fewer roles.

use std::collections::BTreeMap;

use super::super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

/// The environment variables the launch surface reads for each role.
pub const ROLE_VARIABLES: [(&str, &str); 4] = [
    ("session", "CHIO_AUTH_TOKEN"),
    ("admin", "CHIO_ADMIN_TOKEN"),
    ("control", "CHIO_CONTROL_TOKEN"),
    ("workload", "CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN"),
];

/// One defect in the presented roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleDefect {
    /// The value carries surrounding whitespace or a control character.
    Unusable(String),
    /// Two roles share one value.
    Reused(String, String),
}

impl std::fmt::Display for RoleDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unusable(role) => write!(f, "the {role} credential is padded, empty or carries a control character"),
            Self::Reused(left, right) => write!(f, "the {left} and {right} credentials share one value"),
        }
    }
}

/// The defects among the roles present in `values` (role name to value).
pub fn role_defects(values: &BTreeMap<&str, String>) -> Vec<RoleDefect> {
    let mut defects = Vec::new();
    let roles: Vec<(&str, &String)> = ROLE_VARIABLES
        .iter()
        .filter_map(|(role, _)| values.get(role).map(|value| (*role, value)))
        .collect();
    for (role, value) in &roles {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed != *value || value.chars().any(char::is_control) {
            defects.push(RoleDefect::Unusable((*role).to_string()));
        }
    }
    for (index, (left, left_value)) in roles.iter().enumerate() {
        for (right, right_value) in &roles[index + 1..] {
            if left_value == right_value {
                defects.push(RoleDefect::Reused((*left).to_string(), (*right).to_string()));
            }
        }
    }
    defects
}

/// Reports whether the bearer roles in the environment are usable and distinct.
pub struct BearerRoleProbe {
    values: BTreeMap<&'static str, String>,
}

impl BearerRoleProbe {
    /// The roles set in the process environment.
    pub fn from_environment() -> Self {
        let values = ROLE_VARIABLES
            .iter()
            .filter_map(|(role, variable)| std::env::var(variable).ok().map(|value| (*role, value)))
            .collect();
        Self { values }
    }

    pub fn with_values(values: BTreeMap<&'static str, String>) -> Self {
        Self { values }
    }
}

impl Probe for BearerRoleProbe {
    fn name(&self) -> &'static str {
        "security.bearer_roles"
    }

    fn run(&self, _config: &ProbeConfig) -> ProbeReport {
        let present: Vec<&str> = ROLE_VARIABLES
            .iter()
            .filter(|(role, _)| self.values.contains_key(role))
            .map(|(role, _)| *role)
            .collect();
        let report = if present.is_empty() {
            ProbeReport::fail(
                self.name(),
                ProbeSeverity::Info,
                "urn:chio:error:cli:other",
                "no bearer role is set in the environment, so role separation was not checked",
            )
            .with_help("export CHIO_AUTH_TOKEN, CHIO_ADMIN_TOKEN, CHIO_CONTROL_TOKEN and CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN as the launch would")
        } else {
            let defects = role_defects(&self.values);
            if defects.is_empty() {
                ProbeReport::ok(
                    self.name(),
                    format!("{} bearer roles are usable and distinct", present.len()),
                )
            } else {
                let listed = defects.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
                ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:other",
                    format!("bearer roles are not separated: {listed}"),
                )
                .with_help("the edge refuses a launch whose roles share a value or carry padding")
            }
        };
        report.with_context("present", present.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&'static str, &str)]) -> BTreeMap<&'static str, String> {
        pairs.iter().map(|(role, value)| (*role, (*value).to_string())).collect()
    }

    #[test]
    fn distinct_usable_roles_pass() {
        let roles = values(&[("session", "s"), ("admin", "a"), ("control", "c"), ("workload", "w")]);
        assert!(role_defects(&roles).is_empty());
        let report = BearerRoleProbe::with_values(roles).run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Ok);
        assert!(report.context.iter().any(|entry| entry.key == "present" && entry.value == "session,admin,control,workload"));
    }

    #[test]
    fn reuse_and_padding_are_named() {
        let roles = values(&[("session", "same"), ("admin", "same"), ("control", " padded")]);
        assert_eq!(
            role_defects(&roles),
            vec![
                RoleDefect::Unusable("control".to_string()),
                RoleDefect::Reused("session".to_string(), "admin".to_string()),
            ]
        );
        let report = BearerRoleProbe::with_values(roles).run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Error);
        assert!(report.message.contains("session and admin"));
    }

    #[test]
    fn an_empty_environment_is_informational() {
        let report = BearerRoleProbe::with_values(BTreeMap::new()).run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Info);
    }
}
