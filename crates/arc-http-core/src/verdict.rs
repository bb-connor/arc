//! HTTP-layer verdict type, consistent with the existing ARC Decision enum
//! in arc-core-types but specialized for the HTTP substrate.

use serde::{Deserialize, Serialize};

/// The verdict for an HTTP request evaluation.
/// Consistent with `arc_core_types::Decision` but carries HTTP-specific context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Request is allowed. Proceed to upstream.
    Allow,

    /// Request is denied. Return a structured error response.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
        /// The guard or policy rule that triggered the denial.
        guard: String,
        /// Suggested HTTP status code for the error response (default 403).
        #[serde(default = "default_deny_status")]
        http_status: u16,
    },

    /// Request evaluation was cancelled (e.g., timeout, circuit breaker).
    Cancel {
        /// Reason for cancellation.
        reason: String,
    },

    /// Request evaluation did not reach a terminal state.
    Incomplete {
        /// Reason for incomplete evaluation.
        reason: String,
    },
}

fn default_deny_status() -> u16 {
    403
}

impl Verdict {
    /// Deny with a 403 status.
    #[must_use]
    pub fn deny(reason: impl Into<String>, guard: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
            guard: guard.into(),
            http_status: 403,
        }
    }

    /// Deny with a custom HTTP status code.
    #[must_use]
    pub fn deny_with_status(
        reason: impl Into<String>,
        guard: impl Into<String>,
        http_status: u16,
    ) -> Self {
        Self::Deny {
            reason: reason.into(),
            guard: guard.into(),
            http_status,
        }
    }

    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Convert to the core Decision type for receipt signing.
    #[must_use]
    pub fn to_decision(&self) -> arc_core_types::Decision {
        match self {
            Self::Allow => arc_core_types::Decision::Allow,
            Self::Deny { reason, guard, .. } => arc_core_types::Decision::Deny {
                reason: reason.clone(),
                guard: guard.clone(),
            },
            Self::Cancel { reason } => arc_core_types::Decision::Cancelled {
                reason: reason.clone(),
            },
            Self::Incomplete { reason } => arc_core_types::Decision::Incomplete {
                reason: reason.clone(),
            },
        }
    }
}

impl From<arc_core_types::Decision> for Verdict {
    fn from(decision: arc_core_types::Decision) -> Self {
        match decision {
            arc_core_types::Decision::Allow => Self::Allow,
            arc_core_types::Decision::Deny { reason, guard } => Self::Deny {
                reason,
                guard,
                http_status: 403,
            },
            arc_core_types::Decision::Cancelled { reason } => Self::Cancel { reason },
            arc_core_types::Decision::Incomplete { reason } => Self::Incomplete { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_deny_default_status() {
        let v = Verdict::deny("no capability", "CapabilityGuard");
        assert!(v.is_denied());
        assert!(!v.is_allowed());
        if let Verdict::Deny { http_status, .. } = &v {
            assert_eq!(*http_status, 403);
        }
    }

    #[test]
    fn verdict_to_decision_roundtrip() {
        let v = Verdict::deny("blocked", "TestGuard");
        let d = v.to_decision();
        let v2 = Verdict::from(d);
        assert!(v2.is_denied());
    }

    #[test]
    fn serde_roundtrip() {
        let v = Verdict::Allow;
        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn deny_serde_includes_status() {
        let v = Verdict::deny_with_status("rate limited", "RateGuard", 429);
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("429"));
        let back: Verdict = serde_json::from_str(&json).unwrap();
        if let Verdict::Deny { http_status, .. } = back {
            assert_eq!(http_status, 429);
        } else {
            panic!("expected Deny");
        }
    }

    #[test]
    fn cancel_verdict_conversion() {
        let v = Verdict::Cancel {
            reason: "timed out".to_string(),
        };
        assert!(!v.is_allowed());
        assert!(!v.is_denied());
        let decision = v.to_decision();
        assert!(matches!(
            decision,
            arc_core_types::Decision::Cancelled { .. }
        ));
        let v2 = Verdict::from(decision);
        assert!(matches!(v2, Verdict::Cancel { reason } if reason == "timed out"));
    }

    #[test]
    fn incomplete_verdict_conversion() {
        let v = Verdict::Incomplete {
            reason: "partial evaluation".to_string(),
        };
        assert!(!v.is_allowed());
        assert!(!v.is_denied());
        let decision = v.to_decision();
        assert!(matches!(
            decision,
            arc_core_types::Decision::Incomplete { .. }
        ));
        let v2 = Verdict::from(decision);
        assert!(matches!(v2, Verdict::Incomplete { reason } if reason == "partial evaluation"));
    }

    #[test]
    fn cancel_serde_roundtrip() {
        let v = Verdict::Cancel {
            reason: "circuit breaker".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn incomplete_serde_roundtrip() {
        let v = Verdict::Incomplete {
            reason: "pending approval".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn deny_default_status_via_serde_default() {
        // When deserializing a Deny variant without the http_status field,
        // the default should be 403.
        let json = r#"{"verdict":"deny","reason":"blocked","guard":"TestGuard"}"#;
        let v: Verdict = serde_json::from_str(json).unwrap();
        if let Verdict::Deny { http_status, .. } = v {
            assert_eq!(http_status, 403);
        } else {
            panic!("expected Deny");
        }
    }

    #[test]
    fn allow_roundtrip_through_decision() {
        let v = Verdict::Allow;
        let decision = v.to_decision();
        assert!(matches!(decision, arc_core_types::Decision::Allow));
        let v2 = Verdict::from(decision);
        assert!(v2.is_allowed());
    }
}
