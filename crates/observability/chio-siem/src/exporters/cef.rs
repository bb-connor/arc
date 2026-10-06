//! CEF formatter for Chio receipt audit events.
//!
//! CEF is the text SIEM format shipped alongside the OCSF JSON mapper.
//! This module formats one CEF v0 event per receipt. Transport remains
//! owned by existing webhook or collector-specific exporters.

use crate::event::SiemEvent;
use crate::exporter::{ExportError, ExportFuture, Exporter};
use crate::sink_projection::SinkDecision;

#[derive(Debug, Clone)]
pub struct CefExporterConfig {
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
}

impl Default for CefExporterConfig {
    fn default() -> Self {
        Self {
            device_vendor: "Backbay Labs".to_string(),
            device_product: "Chio".to_string(),
            device_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CefExporter {
    config: CefExporterConfig,
}

impl CefExporter {
    #[must_use]
    pub fn new(config: CefExporterConfig) -> Self {
        Self { config }
    }

    pub fn format_events(&self, events: &[SiemEvent]) -> Result<Vec<String>, ExportError> {
        events
            .iter()
            .map(|event| self.format_event(event))
            .collect()
    }

    pub fn format_event(&self, event: &SiemEvent) -> Result<String, ExportError> {
        let projection = event.sink_projection();
        let (signature_id, name) = match projection.decision {
            SinkDecision::Authorized => ("chio.allow", "Chio allow"),
            SinkDecision::Denied => ("chio.deny", "Chio guard deny"),
            SinkDecision::Cancelled => ("chio.cancelled", "Chio cancelled"),
            SinkDecision::Incomplete => ("chio.incomplete", "Chio incomplete"),
            SinkDecision::TraceObservation => ("chio.trace_observation", "Chio trace observation"),
            SinkDecision::AdvisoryEvaluation => {
                ("chio.advisory_evaluation", "Chio advisory evaluation")
            }
            _ => ("chio.observation", "Chio observation"),
        };
        let severity = match projection.alert_severity {
            crate::AlertSeverity::Info => 2,
            crate::AlertSeverity::Low => 3,
            crate::AlertSeverity::Medium => 5,
            crate::AlertSeverity::High => 8,
            crate::AlertSeverity::Critical => 10,
        };
        let header = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|",
            escape_header(&self.config.device_vendor),
            escape_header(&self.config.device_product),
            escape_header(&self.config.device_version),
            signature_id,
            name,
            severity,
        );
        let extension = [
            ("rt", projection.timestamp.saturating_mul(1000).to_string()),
            ("msg", projection.result_label().to_string()),
            ("act", projection.decision_label().to_string()),
            ("dvc", projection.tool_server_sha256.as_str().to_string()),
            ("dvchost", projection.tool_name_sha256.as_str().to_string()),
            ("cs1Label", "receipt_id".to_string()),
            ("cs1", projection.event_reference().to_string()),
            ("cs2Label", "capability_id_sha256".to_string()),
            ("cs2", projection.capability_id_sha256.as_str().to_string()),
            ("cs3Label", "policy_hash".to_string()),
            (
                "cs3",
                projection
                    .policy_hash
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap_or("absent")
                    .to_string(),
            ),
            ("cs4Label", "parameter_hash".to_string()),
            (
                "cs4",
                projection
                    .parameter_hash
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap_or("absent")
                    .to_string(),
            ),
            ("cs5Label", "tenant_id_sha256".to_string()),
            (
                "cs5",
                projection
                    .tenant_id_sha256
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap_or("single-tenant")
                    .to_string(),
            ),
            ("cs6Label", "source_redaction_mode".to_string()),
            ("cs6", projection.source_redaction_mode.as_str().to_string()),
            ("receiptKind", projection.receipt_kind.as_str().to_string()),
            (
                "boundaryClass",
                projection.boundary_class.as_str().to_string(),
            ),
            ("result", projection.result_label().to_string()),
            ("authorized", projection.authorized.to_string()),
            ("signature_scope", "original_receipt".to_string()),
            ("payload_included", "false".to_string()),
            ("original_retrieval_required", "true".to_string()),
            ("projection_signed", "false".to_string()),
        ]
        .into_iter()
        .map(|(key, value)| format!("{key}={}", escape_extension(&value)))
        .collect::<Vec<String>>()
        .join(" ");
        Ok(format!("{header}{extension}"))
    }
}

impl Exporter for CefExporter {
    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            let formatted = self.format_events(events)?;
            Ok(formatted.len())
        })
    }

    fn name(&self) -> &str {
        "cef"
    }
}

fn escape_header(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<char>>(),
            '|' => "\\|".chars().collect::<Vec<char>>(),
            '\n' | '\r' => " ".chars().collect::<Vec<char>>(),
            other => vec![other],
        })
        .collect()
}

fn escape_extension(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<char>>(),
            '=' => "\\=".chars().collect::<Vec<char>>(),
            '\n' | '\r' => " ".chars().collect::<Vec<char>>(),
            other => vec![other],
        })
        .collect()
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

    #[test]
    fn escapes_header_separator() {
        assert_eq!(escape_header("a|b"), "a\\|b");
    }

    #[test]
    fn escapes_extension_equals() {
        assert_eq!(escape_extension("a=b"), "a\\=b");
    }

    #[test]
    fn trace_observation_allow_formats_as_trace_not_authorization_allow() {
        let event = SiemEvent::from_receipt(test_receipt_with_semantics(
            Decision::Allow,
            ReceiptSemanticFields::trace_detect_only(),
            TrustLevel::Verified,
        ));
        let cef = CefExporter::default()
            .format_event(&event)
            .test_expect("format trace CEF");

        assert!(cef.contains("receiptKind=trace_observation"));
        assert!(cef.contains("boundaryClass=detect_only"));
        assert!(cef.contains("authorized=false"));
        assert!(!cef.contains("act=allow"));
        assert!(!cef.contains("chio.allow"));
        assert!(!cef.contains("Chio allow"));
    }

    #[test]
    fn metadata_tenant_id_does_not_drive_authoritative_cef_tenant() {
        let mut receipt = test_receipt_with_semantics(
            Decision::Allow,
            ReceiptSemanticFields::mediated_prevent(),
            TrustLevel::Mediated,
        );
        receipt.metadata = Some(serde_json::json!({
            "tenant_id": "metadata-tenant"
        }));
        let event = SiemEvent::from_receipt(receipt);
        let cef = CefExporter::default()
            .format_event(&event)
            .test_expect("format CEF");

        assert!(cef.contains("cs5=single-tenant"));
        assert!(!cef.contains("metadata-tenant"));
    }

    fn test_receipt_with_semantics(
        decision: Decision,
        semantics: ReceiptSemanticFields,
        trust_level: TrustLevel,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "path": "/etc/passwd"
        }))
        .test_expect("hash test receipt parameters");
        let decision =
            if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::MediatedDecision {
                Some(decision)
            } else {
                None
            };
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "trace-cef-1".to_string(),
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
            },
            &kp,
        )
        .test_expect("sign test receipt")
    }
}
