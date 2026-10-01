//! Preserve security wire constraints at the public generated parser boundary.
//!
//! Generated coercion and omission defaults must not change signed values.
//! Preserve required nullable fields and opaque payloads while rejecting scalar
//! coercion and nulls where the authoritative security schemas forbid them.

use std::{fs, path::Path};

use crate::{display_path, XtaskError};

pub(super) fn harden(root: &Path) -> Result<(), XtaskError> {
    for (file, objects, non_null_properties) in [
        ("security/tool_manifest_v2_schema.py", 7, true),
        ("security/tool_flow_declaration_schema.py", 2, true),
        ("security/signed_tool_manifest_v2_schema.py", 1, true),
        ("kernel/execution_nonce_schema.py", 3, true),
        ("kernel/combined_capture_metadata_schema.py", 2, true),
        ("kernel/caller_dispatch_authorization_schema.py", 8, true),
        // A delivery report must retain explicit null output and cost values.
        ("kernel/caller_delivery_report_schema.py", 3, false),
        ("capability/aggregate_invocation_budget_schema.py", 2, true),
        ("capability/aggregate_budget_root_schema.py", 2, true),
        ("capability/cumulative_approval_root_schema.py", 3, true),
        ("capability/threshold_approval_proposal_schema.py", 1, true),
        ("capability/governed_approval_token_schema.py", 1, true),
        ("capability/supplemental_authorization_schema.py", 1, true),
        ("agent/active_response_governed_intent_schema.py", 1, true),
        ("result/pending_approval_schema.py", 1, true),
        // Extensible generic constraint values may contain explicit null. Do
        // not apply a manifest-style omission contract to these payloads.
        ("capability/token_schema.py", 20, false),
    ] {
        let path = root.join(file);
        let source = fs::read_to_string(&path)
            .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        let hardened = harden_source(&source, objects, non_null_properties).map_err(|error| {
            XtaskError::ToolFailed(format!("Python security model {file}: {error}"))
        })?;
        let hardened = if file == "kernel/caller_delivery_report_schema.py" {
            require_nullable_cost(&hardened).map_err(|error| {
                XtaskError::ToolFailed(format!("Python security model {file}: {error}"))
            })?
        } else {
            hardened
        };
        fs::write(&path, hardened).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    }
    Ok(())
}

fn require_nullable_cost(source: &str) -> Result<String, &'static str> {
    const GENERATED: &str = "realized_cost: RealizedCost | None = None";
    if source.matches(GENERATED).count() != 1 {
        return Err("generated required nullable cost inventory changed");
    }
    Ok(source.replacen(
        GENERATED,
        "realized_cost: RealizedCost | None = Field(...)",
        1,
    ))
}

fn harden_source(
    source: &str,
    expected_objects: usize,
    non_null_properties: bool,
) -> Result<String, &'static str> {
    const IMPORT: &str = "from pydantic import BaseModel, ";
    if source.matches(IMPORT).count() != 1
        || source.matches("(BaseModel):").count() != expected_objects
    {
        return Err("generated security import or object inventory changed");
    }
    let mut hardened = if non_null_properties {
        source.replacen(
            IMPORT,
            "from chio_sdk._manifest_wire import SecurityWireModel as BaseModel\n\nfrom pydantic import ",
            1,
        )
    } else {
        source.to_owned()
    };
    if hardened.contains(": bool\n") || hardened.contains(": bool | None") {
        hardened = hardened.replacen(
            "from pydantic import ",
            "from pydantic import StrictBool, ",
            1,
        );
        hardened = hardened.replace(": bool\n", ": StrictBool\n");
        hardened = hardened.replace(": bool | None", ": StrictBool | None");
    }
    hardened = hardened.replace("conint(", "conint(strict=True, ");
    Ok(hardened)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "from pydantic import BaseModel, conint\n\nclass Tool(BaseModel):\n    egress: bool\n    count: conint(ge=1)\n    optional: str | None = None\n    dpop_required: bool | None = None\n";

    #[test]
    fn caller_cost_requires_presence_without_rejecting_null() -> Result<(), &'static str> {
        let source = "    realized_cost: RealizedCost | None = None\n";
        assert_eq!(
            require_nullable_cost(source)?,
            "    realized_cost: RealizedCost | None = Field(...)\n"
        );
        assert!(require_nullable_cost("").is_err());
        assert!(require_nullable_cost(&source.repeat(2)).is_err());
        Ok(())
    }

    #[test]
    fn manifest_wire_hardening_preserves_fields_and_default_omission() -> Result<(), &'static str> {
        let hardened = harden_source(SOURCE, 1, true)?;
        assert!(hardened.contains("SecurityWireModel as BaseModel"));
        assert!(hardened.contains("egress: StrictBool\n"));
        assert!(hardened.contains("count: conint(strict=True, ge=1)\n"));
        assert!(hardened.contains("optional: str | None = None\n"));
        assert!(hardened.contains("dpop_required: StrictBool | None = None\n"));
        Ok(())
    }

    #[test]
    fn changed_generated_manifest_inventory_fails_closed() {
        assert!(harden_source(SOURCE, 2, true).is_err());
        assert!(harden_source(&SOURCE.replace("BaseModel", "OtherModel"), 1, true).is_err());
        assert!(harden_source(&format!("{SOURCE}{SOURCE}"), 2, true).is_err());
    }

    #[test]
    fn extensible_payloads_keep_null_semantics_but_reject_numeric_coercion(
    ) -> Result<(), &'static str> {
        let hardened = harden_source(SOURCE, 1, false)?;
        assert!(hardened.contains("from pydantic import StrictBool, BaseModel"));
        assert!(!hardened.contains("SecurityWireModel"));
        assert!(hardened.contains("conint(strict=True, ge=1)"));
        assert!(hardened.contains("dpop_required: StrictBool | None = None"));
        Ok(())
    }
}
