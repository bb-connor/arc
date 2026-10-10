//! OCSF 1.3.0 Authorization mapping from the closed unsigned sink projection.
//! Original payloads and signatures require separate authorized evidence reads.

use chio_core::receipt::body::ChioReceipt;
use serde_json::{json, Value};

use crate::event::SiemEvent;
use crate::sink_projection::{SiemSinkProjection, SinkDecision};

pub const OCSF_SCHEMA_VERSION: &str = "1.3.0";
pub const OCSF_CLASS_UID: u32 = 3002;
pub const OCSF_CLASS_NAME: &str = "Authorization";
pub const OCSF_CATEGORY_UID: u32 = 3;
pub const OCSF_CATEGORY_NAME: &str = "Identity & Access Management";
pub const OCSF_PRODUCT_NAME: &str = "Chio";
pub const OCSF_PRODUCT_VENDOR: &str = "Backbay Labs";

/// Map an original receipt without supplying independent signer trust.
/// An embedded self-signature cannot produce an authorization Grant/Success.
#[must_use]
pub fn receipt_to_ocsf(receipt: &ChioReceipt) -> Value {
    projection_to_ocsf(&SiemSinkProjection::from_receipt(receipt, None))
}

/// Reverify an event's original receipt against its privately accepted pin,
/// then format only the closed projection. Public cached flags are ignored.
#[must_use]
pub fn siem_event_to_ocsf(event: &SiemEvent) -> Value {
    projection_to_ocsf(&event.sink_projection())
}

fn projection_to_ocsf(projection: &SiemSinkProjection) -> Value {
    let Ok(mut source) = serde_json::to_value(projection) else {
        return json!({
            "class_uid": OCSF_CLASS_UID, "status_id": 0, "status": "Unknown",
            "payload_included": false, "original_retrieval_required": true,
            "projection_signed": false,
        });
    };
    // Compatibility classification derived exclusively from the closed owner.
    source["decision.verdict"] = json!(projection.decision_label());
    let (activity_id, activity_name, status_id, status) = match projection.decision {
        SinkDecision::Authorized => (1, "Grant", 1, "Success"),
        SinkDecision::Denied => (1, "Grant", 2, "Failure"),
        SinkDecision::Cancelled => (99, "Other", 2, "Failure"),
        _ => (99, "Other", 99, "Other"),
    };
    let severity = match projection.severity_id {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        _ => "Unknown",
    };
    let mut observables = vec![
        json!({"name":"chio.receipt.id","type":"Resource UID","type_id":10,"value":projection.event_reference()}),
        json!({"name":"chio.capability.id","type":"Resource UID","type_id":10,"value":projection.capability_id_sha256}),
        json!({"name":"chio.tool.server","type":"Endpoint Name","type_id":20,"value":projection.tool_server_sha256}),
        json!({"name":"chio.tool.name","type":"Other","type_id":99,"value":projection.tool_name_sha256}),
    ];
    for (name, value) in [
        ("chio.policy.hash", &projection.policy_hash),
        ("chio.content.hash", &projection.content_hash),
        ("chio.guard", &projection.guard_sha256),
    ] {
        if let Some(value) = value {
            observables.push(json!({"name":name,"type":"Resource UID","type_id":10,"value":value}));
        }
    }
    let mut enrichments = vec![
        json!({"name":"chio.trust_level","type":"string","value":projection.trust_level.as_str(),"data":{"trust_level":projection.trust_level.as_str()}}),
        json!({"name":"chio.receipt_semantics","type":"dict","value":projection.receipt_kind.as_str(),"data":{"receipt_kind":projection.receipt_kind,"boundary_class":projection.boundary_class,"result":projection.result_label()}}),
    ];
    if let Some(tenant) = &projection.tenant_id_sha256 {
        enrichments.push(json!({"name":"chio.tenant_id_sha256","type":"string","value":tenant,"data":{"tenant_id_sha256":tenant}}));
    }
    let mut event = json!({
        "category_uid":OCSF_CATEGORY_UID, "category_name":OCSF_CATEGORY_NAME,
        "class_uid":OCSF_CLASS_UID, "class_name":OCSF_CLASS_NAME,
        "type_uid":OCSF_CLASS_UID * 100 + activity_id,
        "type_name":format!("{OCSF_CLASS_NAME}: {activity_name}"),
        "activity_id":activity_id, "activity_name":activity_name,
        "status_id":status_id, "status":status,
        "severity_id":projection.severity_id, "severity":severity,
        "time":projection.timestamp.saturating_mul(1000),
        "metadata":{"version":OCSF_SCHEMA_VERSION,"uid":projection.event_reference(),"product":{"name":OCSF_PRODUCT_NAME,"vendor_name":OCSF_PRODUCT_VENDOR}},
        "api":{"operation":format!("sha256:{}",projection.tool_name_sha256.as_str()),"service":{"name":format!("sha256:{}",projection.tool_server_sha256.as_str())},"request":{"uid":projection.event_reference()}},
        "dst_endpoint":{"name":format!("sha256:{}",projection.tool_server_sha256.as_str()),"svc_name":format!("sha256:{}",projection.tool_server_sha256.as_str())},
        "actor":{"invoked_by":"chio-agent","authorizations":[{"decision":projection.result_label()}]},
        "observables":observables, "enrichments":enrichments,
        "unmapped":{"chio":source},
    });
    if let Some(policy) = &projection.policy_hash {
        event["policy"] = json!({"uid":policy,"name":"chio-policy"});
        event["actor"]["authorizations"][0]["policy"] = json!({"uid":policy});
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        kinds::TrustLevel, metadata::ReceiptSemanticFields,
    };
    use chio_test_support::prelude::*;

    fn test_receipt(id: &str, decision: Decision) -> ChioReceipt {
        test_receipt_with_semantics(id, decision, None, TrustLevel::Mediated)
    }

    fn test_receipt_with_semantics(
        id: &str,
        decision: Decision,
        semantics: Option<ReceiptSemanticFields>,
        trust_level: TrustLevel,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let action = match ToolCallAction::from_parameters(serde_json::json!({
            "path": "/etc/passwd"
        })) {
            Ok(action) => action,
            Err(error) => panic!("hash receipt parameters: {error}"),
        };
        let semantics = semantics.unwrap_or_else(ReceiptSemanticFields::mediated_prevent);
        let decision =
            if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::MediatedDecision {
                Some(decision)
            } else {
                None
            };
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_712_345_678,
            capability_id: "cap-abc".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action,
            decision,
            receipt_kind: semantics.receipt_kind,
            boundary_class: semantics.boundary_class,
            observation_outcome: semantics.observation_outcome,
            tool_origin: semantics.tool_origin,
            redaction_mode: semantics.redaction_mode,
            actor_chain: semantics.actor_chain,
            content_hash: "content-xyz".to_string(),
            policy_hash: "policy-xyz".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level,
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        #[allow(clippy::unwrap_used)]
        ChioReceipt::sign(body, &kp).test_unwrap()
    }

    #[test]
    fn raw_receipt_allow_without_trusted_signer_is_unverified() {
        let ev = receipt_to_ocsf(&test_receipt("r-1", Decision::Allow));
        assert_eq!(ev["class_uid"], 3002);
        assert_eq!(ev["category_uid"], 3);
        assert_ne!(ev["activity_name"], "Grant");
        assert_ne!(ev["status"], "Success");
        assert_eq!(ev["unmapped"]["chio"]["signer_trusted"], false);
        assert_eq!(ev["unmapped"]["chio"]["authorized"], false);
    }

    #[test]
    fn trace_observation_allow_never_maps_to_authorization_grant() {
        let receipt = test_receipt_with_semantics(
            "trace-1",
            Decision::Allow,
            Some(ReceiptSemanticFields::trace_detect_only()),
            TrustLevel::Verified,
        );
        let ev = receipt_to_ocsf(&receipt);

        assert_ne!(ev["activity_name"], "Grant");
        assert_ne!(ev["status"], "Success");
        assert_eq!(ev["unmapped"]["chio"]["receipt_kind"], "trace_observation");
        assert_eq!(ev["unmapped"]["chio"]["boundary_class"], "detect_only");
        assert_eq!(ev["unmapped"]["chio"]["authorized"], false);
    }
}
