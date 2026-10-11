//! Chio extension field handling for OpenAPI operations.
//!
//! OpenAPI operations may include `x-chio-*` extension fields to override
//! default policy decisions on a per-route basis.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
            let value =
                serde_json::to_value(flow).map_err(|source| OpenApiError::InvalidExtension {
                    field: "x-chio-flow",
                    source,
                })?;
            object.insert("x-chio-flow".to_string(), value);
        }
        None => {
            object.remove("x-chio-flow");
        }
    }
    Ok(())
}

/// Sensitivity classification used for default policy and tool approval metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// Publicly available data, no special handling.
    Public,
    /// Internal data, logged but not restricted beyond defaults.
    #[default]
    Internal,
    /// Sensitive data, requires approval metadata and an explicit capability grant.
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
    /// `x-chio-approval-required` -- explicit approval metadata requirement.
    pub approval_required: Option<bool>,
    /// Reserved budget data retained for API compatibility. Raw operation values
    /// are unsupported because no consumer binds their currency and exposure.
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
        let map = obj.as_object().ok_or_else(|| {
            OpenApiError::InvalidSpec("OpenAPI operation must be an object".into())
        })?;

        if map.contains_key("x-chio-budget-limit") {
            return Err(OpenApiError::InvalidSpec(
                "unsupported Chio operation budget limit: no currency-bound consumer".into(),
            ));
        }
        for key in map.keys() {
            if key.starts_with("x-chio-")
                && !matches!(
                    key.as_str(),
                    "x-chio-sensitivity"
                        | "x-chio-side-effects"
                        | "x-chio-approval-required"
                        | "x-chio-publish"
                        | "x-chio-flow"
                )
            {
                return Err(OpenApiError::InvalidSpec(
                    "unsupported Chio operation extension".into(),
                ));
            }
        }

        Ok(Self {
            sensitivity: decode_extension(map, "x-chio-sensitivity")?,
            side_effects: decode_extension(map, "x-chio-side-effects")?,
            approval_required: decode_extension(map, "x-chio-approval-required")?,
            budget_limit: None,
            publish: decode_extension(map, "x-chio-publish")?,
            flow: decode_extension(map, "x-chio-flow")?,
        })
    }

    /// Effective approval requirement. Explicit false cannot weaken a sensitive
    /// or restricted declaration.
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        self.approval_required == Some(true)
            || matches!(
                self.sensitivity,
                Some(Sensitivity::Sensitive | Sensitivity::Restricted)
            )
    }

    /// Whether this operation should be included in the generated manifest.
    /// Returns `true` unless `x-chio-publish` is explicitly set to `false`.
    pub fn should_publish(&self) -> bool {
        self.publish.unwrap_or(true)
    }
}

fn decode_extension<T: DeserializeOwned>(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<Option<T>, OpenApiError> {
    map.get(field)
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|source| OpenApiError::InvalidExtension { field, source })
        })
        .transpose()
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
    fn all_supported_fields_present() {
        let val = serde_json::json!({
            "x-chio-sensitivity": "restricted",
            "x-chio-side-effects": true,
            "x-chio-approval-required": true,
            "x-chio-publish": false
        });
        let ext = ChioExtensions::from_operation(&val).unwrap();
        assert_eq!(ext.sensitivity, Some(Sensitivity::Restricted));
        assert_eq!(ext.side_effects, Some(true));
        assert_eq!(ext.approval_required, Some(true));
        assert_eq!(ext.budget_limit, None);
        assert_eq!(ext.publish, Some(false));
        assert!(!ext.should_publish());
    }

    #[test]
    fn unknown_sensitivity_rejected() {
        let val = serde_json::json!({ "x-chio-sensitivity": "unknown" });
        assert!(matches!(
            ChioExtensions::from_operation(&val),
            Err(OpenApiError::InvalidExtension { .. })
        ));
    }

    #[test]
    fn non_object_rejected() {
        let val = serde_json::json!("not an object");
        assert!(matches!(
            ChioExtensions::from_operation(&val),
            Err(OpenApiError::InvalidSpec(_))
        ));
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
