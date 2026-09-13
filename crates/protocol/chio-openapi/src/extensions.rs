//! Chio extension field handling for OpenAPI operations.
//!
//! OpenAPI operations may include `x-chio-*` extension fields to override
//! default policy decisions on a per-route basis.

use serde::{Deserialize, Serialize};

use crate::OpenApiError;
use chio_core_types::manifest::{ToolDefinition, ToolFlowDeclaration};

/// Export a normative tool flow declaration back to an OpenAPI operation.
/// Existing `x-chio-flow` content is replaced by the signed tool declaration.
pub fn export_tool_flow_extension(
    tool: &ToolDefinition,
    operation: &mut serde_json::Value,
) -> Result<(), OpenApiError> {
    let object = operation.as_object_mut().ok_or_else(|| {
        OpenApiError::InvalidSpec("OpenAPI operation must be an object".to_string())
    })?;
    match tool.flow.as_ref() {
        Some(flow) => {
            let value = serde_json::to_value(flow).map_err(|error| {
                OpenApiError::InvalidSpec(format!("cannot serialize x-chio-flow: {error}"))
            })?;
            object.insert("x-chio-flow".to_string(), value);
        }
        None => {
            object.remove("x-chio-flow");
        }
    }
    Ok(())
}

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

/// Parsed `x-chio-*` extension fields from an OpenAPI operation.
#[derive(Debug, Clone, Default)]
pub struct ChioExtensions {
    /// `x-chio-sensitivity` -- data sensitivity classification.
    pub sensitivity: Option<Sensitivity>,
    /// `x-chio-side-effects` -- explicit override for whether the operation
    /// has side effects (overrides the HTTP method default).
    pub side_effects: Option<bool>,
    /// `x-chio-approval-required` -- whether human approval is needed.
    pub approval_required: Option<bool>,
    /// `x-chio-budget-limit` -- maximum cost in minor currency units that a
    /// single invocation may charge.
    pub budget_limit: Option<u64>,
    /// `x-chio-publish` -- whether to include this operation in the generated
    /// manifest. Defaults to true if absent.
    pub publish: Option<bool>,
    /// Strict information-flow declaration for the generated tool.
    pub flow: Option<ToolFlowDeclaration>,
}

impl ChioExtensions {
    /// Extract Chio extension fields from a raw JSON object (the operation
    /// object as parsed from the OpenAPI spec).
    pub fn from_operation(obj: &serde_json::Value) -> Result<Self, OpenApiError> {
        let map = match obj.as_object() {
            Some(m) => m,
            None => return Ok(Self::default()),
        };

        let flow = map
            .get("x-chio-flow")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| OpenApiError::InvalidSpec(format!("invalid x-chio-flow: {error}")))?;

        Ok(Self {
            sensitivity: map
                .get("x-chio-sensitivity")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "public" => Some(Sensitivity::Public),
                    "internal" => Some(Sensitivity::Internal),
                    "sensitive" => Some(Sensitivity::Sensitive),
                    "restricted" => Some(Sensitivity::Restricted),
                    _ => None,
                }),
            side_effects: map.get("x-chio-side-effects").and_then(|v| v.as_bool()),
            approval_required: map
                .get("x-chio-approval-required")
                .and_then(|v| v.as_bool()),
            budget_limit: map.get("x-chio-budget-limit").and_then(|v| v.as_u64()),
            publish: map.get("x-chio-publish").and_then(|v| v.as_bool()),
            flow,
        })
    }

    /// Whether this operation should be included in the generated manifest.
    /// Returns `true` unless `x-chio-publish` is explicitly set to `false`.
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
        let ext = ChioExtensions::from_operation(&val).unwrap();
        assert!(ext.sensitivity.is_none());
        assert!(ext.side_effects.is_none());
        assert!(ext.approval_required.is_none());
        assert!(ext.budget_limit.is_none());
        assert!(ext.publish.is_none());
        assert!(ext.flow.is_none());
        assert!(ext.should_publish());
    }

    #[test]
    fn all_fields_present() {
        let val = serde_json::json!({
            "x-chio-sensitivity": "restricted",
            "x-chio-side-effects": true,
            "x-chio-approval-required": true,
            "x-chio-budget-limit": 5000,
            "x-chio-publish": false
        });
        let ext = ChioExtensions::from_operation(&val).unwrap();
        assert_eq!(ext.sensitivity, Some(Sensitivity::Restricted));
        assert_eq!(ext.side_effects, Some(true));
        assert_eq!(ext.approval_required, Some(true));
        assert_eq!(ext.budget_limit, Some(5000));
        assert_eq!(ext.publish, Some(false));
        assert!(!ext.should_publish());
    }

    #[test]
    fn unknown_sensitivity_ignored() {
        let val = serde_json::json!({ "x-chio-sensitivity": "unknown" });
        let ext = ChioExtensions::from_operation(&val).unwrap();
        assert!(ext.sensitivity.is_none());
    }

    #[test]
    fn non_object_returns_default() {
        let val = serde_json::json!("not an object");
        let ext = ChioExtensions::from_operation(&val).unwrap();
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

    #[test]
    fn x_chio_flow_parses_strict_declaration() {
        let val = serde_json::json!({
            "x-chio-flow": {
                "output_label": {"kind": "known", "owners": {}, "compartments": ["pii"]},
                "input_clearance": {"kind": "known", "owners": {}, "compartments": ["pii"]},
                "egress": true,
                "declassification_purposes": ["billing"]
            }
        });
        let ext = ChioExtensions::from_operation(&val)
            .unwrap_or_else(|error| panic!("valid flow extension: {error}"));
        assert!(ext.flow.as_ref().is_some_and(|flow| flow.egress));

        let invalid = serde_json::json!({
            "x-chio-flow": {"egress": false, "declassification_purposes": [], "unknown": true}
        });
        assert!(ChioExtensions::from_operation(&invalid).is_err());
    }

    #[test]
    fn normative_tool_flow_exports_back_to_identical_extension() {
        let input = serde_json::json!({
            "x-chio-flow": {
                "output_label": {"kind": "known", "owners": {}, "compartments": ["pii"]},
                "input_clearance": {"kind": "known", "owners": {}, "compartments": ["pii"]},
                "egress": true,
                "declassification_purposes": ["billing"]
            }
        });
        let flow = ChioExtensions::from_operation(&input)
            .unwrap_or_else(|error| panic!("parse extension: {error}"))
            .flow;
        let tool = ToolDefinition {
            name: "store".to_string(),
            description: "Store".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_core_types::manifest::ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: false,
                requires_approval: false,
                estimated_duration_ms: None,
            },
            latency_hint: None,
            flow,
        };
        let mut output = serde_json::json!({});
        export_tool_flow_extension(&tool, &mut output)
            .unwrap_or_else(|error| panic!("export extension: {error}"));
        assert_eq!(output["x-chio-flow"], input["x-chio-flow"]);
    }
}
