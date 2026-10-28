use std::path::Path;

use crate::evidence_io::write_runtime_json_artifact;
use crate::kernel::execute_runtime_loopback_step;
use crate::scenario::RuntimeLoopbackStep;
use crate::treaty::RuntimeLoopbackTreatyContext;
use crate::RuntimeLoopbackError;

#[derive(Clone)]
pub(crate) struct RuntimeLoopbackAdmissionOutput {
    pub(crate) accepted: bool,
    pub(crate) failure_code: Option<String>,
    pub(crate) evidence_paths: Vec<String>,
    pub(crate) evidence_manifest_entries: Vec<chio_runtime_core::RuntimeEvidenceManifestEntry>,
    pub(crate) live_tool_receipts: Vec<chio_core::receipt::body::ChioReceipt>,
    pub(crate) live_treaty_contexts: Vec<Option<RuntimeLoopbackTreatyContext>>,
}

pub(crate) fn execute_runtime_admission_loop(
    steps: &[RuntimeLoopbackStep],
    authority: &chio_store_sqlite::SqliteAuthorityStore,
    receipt_store: &std::sync::Arc<chio_store_sqlite::SqliteReceiptStore>,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<RuntimeLoopbackAdmissionOutput, RuntimeLoopbackError> {
    let mut accepted = true;
    let mut failure_code = None;
    let mut evidence_paths = Vec::new();
    let mut evidence_manifest_entries = Vec::new();
    let mut live_tool_receipts = Vec::new();
    let mut live_treaty_contexts = Vec::new();

    for (index, step) in steps.iter().enumerate() {
        let arguments = step.arguments.clone().ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime step {} did not carry executable arguments",
                step.admission_bundle.step_index
            ))
        })?;
        let execution = execute_runtime_loopback_step(
            index,
            step,
            arguments,
            authority,
            receipt_store,
            now_unix_ms,
            out_dir,
        )?;
        let suffix = if steps.len() == 1 {
            String::new()
        } else {
            format!("-{}", index + 1)
        };
        let receipt_name = format!("runtime-admission-receipt{suffix}.json");
        write_runtime_json_artifact(
            out_dir,
            "admission_receipt",
            &receipt_name,
            &execution.receipt,
            "Chio runtime admission receipt JSON",
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        if !execution.accepted {
            accepted = false;
            failure_code = execution.failure_code;
            break;
        }
        live_tool_receipts.push(execution.receipt);
        live_treaty_contexts.push(execution.treaty);
    }

    Ok(RuntimeLoopbackAdmissionOutput {
        accepted,
        failure_code,
        evidence_paths,
        evidence_manifest_entries,
        live_tool_receipts,
        live_treaty_contexts,
    })
}
