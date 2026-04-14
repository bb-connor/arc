//! ARC extension field handling for OpenAPI operations.
//!
//! OpenAPI operations may include `x-arc-*` extension fields to override
//! default policy decisions on a per-route basis.

use serde::{Deserialize, Serialize};

/// Sensitivity classification for a route. Used by the guard pipeline to
/// decide logging level and approval requirements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// Publicly available data, no special handling.
    Public,
    /// Internal data, logged but not restricted beyond defaults.
    #[default]
    Internal,
    /// Sensitive data, may require additional approval.
    Sensitive,
    /// Highly restricted data, always requires approval.
    Restricted,
}

/// Parsed `x-arc-*` extension fields from an OpenAPI operation.
#[derive(Debug, Clone, Default)]
pub struct ArcExtensions {
    /// `x-arc-sensitivity` -- data sensitivity classification.
    pub sensitivity: Option<Sensitivity>,
    /// `x-arc-side-effects` -- explicit override for whether the operation
    /// has side effects (overrides the HTTP method default).
    pub side_effects: Option<bool>,
    /// `x-arc-approval-required` -- whether human approval is needed.
    pub approval_required: Option<bool>,
    /// `x-arc-budget-limit` -- maximum cost in minor currency units that a
    /// single invocation may charge.
    pub budget_limit: Option<u64>,
    /// `x-arc-publish` -- whether to include this operation in the generated
    /// manifest. Defaults to true if absent.
    pub publish: Option<bool>,
}

impl ArcExtensions {
    /// Extract ARC extension fields from a raw JSON object (the operation
    /// object as parsed from the OpenAPI spec).
    pub fn from_operation(obj: &serde_json::Value) -> Self {
        let map = match obj.as_object() {
            Some(m) => m,
            None => return Self::default(),
        };

        Self {
            sensitivity: map
                .get("x-arc-sensitivity")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "public" => Some(Sensitivity::Public),
                    "internal" => Some(Sensitivity::Internal),
                    "sensitive" => Some(Sensitivity::Sensitive),
                    "restricted" => Some(Sensitivity::Restricted),
                    _ => None,
                }),
            side_effects: map.get("x-arc-side-effects").and_then(|v| v.as_bool()),
            approval_required: map.get("x-arc-approval-required").and_then(|v| v.as_bool()),
            budget_limit: map.get("x-arc-budget-limit").and_then(|v| v.as_u64()),
            publish: map.get("x-arc-publish").and_then(|v| v.as_bool()),
        }
    }

    /// Whether this operation should be included in the generated manifest.
    /// Returns `true` unless `x-arc-publish` is explicitly set to `false`.
    pub fn should_publish(&self) -> bool {
        self.publish.unwrap_or(true)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_object() {
        let val = serde_json::json!({});
        let ext = ArcExtensions::from_operation(&val);
        assert!(ext.sensitivity.is_none());
        assert!(ext.side_effects.is_none());
        assert!(ext.approval_required.is_none());
        assert!(ext.budget_limit.is_none());
        assert!(ext.publish.is_none());
        assert!(ext.should_publish());
    }

    #[test]
    fn all_fields_present() {
        let val = serde_json::json!({
            "x-arc-sensitivity": "restricted",
            "x-arc-side-effects": true,
            "x-arc-approval-required": true,
            "x-arc-budget-limit": 5000,
            "x-arc-publish": false
        });
        let ext = ArcExtensions::from_operation(&val);
        assert_eq!(ext.sensitivity, Some(Sensitivity::Restricted));
        assert_eq!(ext.side_effects, Some(true));
        assert_eq!(ext.approval_required, Some(true));
        assert_eq!(ext.budget_limit, Some(5000));
        assert_eq!(ext.publish, Some(false));
        assert!(!ext.should_publish());
    }

    #[test]
    fn unknown_sensitivity_ignored() {
        let val = serde_json::json!({ "x-arc-sensitivity": "unknown" });
        let ext = ArcExtensions::from_operation(&val);
        assert!(ext.sensitivity.is_none());
    }

    #[test]
    fn non_object_returns_default() {
        let val = serde_json::json!("not an object");
        let ext = ArcExtensions::from_operation(&val);
        assert!(ext.sensitivity.is_none());
    }

    #[test]
    fn sensitivity_serde_roundtrip() {
        let s = Sensitivity::Sensitive;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"sensitive\"");
        let back: Sensitivity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
