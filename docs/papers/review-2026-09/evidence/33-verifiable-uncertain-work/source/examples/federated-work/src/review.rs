use crate::{common::*, market::*};
use base64::{engine::general_purpose::STANDARD, Engine};
use chio_core_types::{canonical_json_bytes, receipt::lineage::SignedExportEnvelope, sha256_hex};
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, ToolServerOutput};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRequest {
    pub acceptance: Acceptance,
    pub input: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub path: String,
    pub method: String,
    pub authentication_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub schema: String,
    pub agreement_sha256: String,
    pub accepted_bid_sha256: String,
    pub input_sha256: String,
    pub checker: String,
    pub operations: Vec<Observation>,
}
pub type SignedReport = SignedExportEnvelope<Report>;

impl ReviewRequest {
    pub fn validate(&self, peers: &Peers) -> Result<()> {
        self.acceptance.verify(peers)?;
        let agreement = &self.acceptance.quote.agreement;
        if agreement.profile != WORK_PROFILE
            || self.input.len() > 64 * 1024
            || sha256_hex(self.input.as_bytes()) != agreement.input_sha256
        {
            return Err("input disclosure or work profile differs from accepted agreement".into());
        }
        Ok(())
    }
    pub fn report(&self) -> Result<Report> {
        let a = &self.acceptance.quote.agreement;
        Ok(Report {
            schema: "chio.example.openapi-auth-review.v1".into(),
            agreement_sha256: digest(a)?,
            accepted_bid_sha256: digest(&self.acceptance.accepted)?,
            input_sha256: a.input_sha256.clone(),
            checker: a.checker.clone(),
            operations: check_openapi(&self.input)?,
        })
    }
}

/// Inventory declared authentication for a bounded, self-contained OpenAPI 3.1 document.
/// This checks the document's declarations, not the behavior of a deployed API.
pub fn check_openapi(input: &str) -> Result<Vec<Observation>> {
    if input.len() > 64 * 1024 {
        return Err("OpenAPI input exceeds 64 KiB".into());
    }
    let canonical = chio_core_types::canonical::canonical_json_bytes_from_str(input)?;
    let document: Value = serde_json::from_slice(&canonical)?;
    if document["openapi"] != "3.1.0" {
        return Err("checker requires OpenAPI 3.1.0".into());
    }
    let paths = document["paths"]
        .as_object()
        .ok_or("paths must be an object")?;
    if paths.is_empty() || paths.len() > 256 || document.get("webhooks").is_some() {
        return Err("checker requires 1..256 paths and no webhooks".into());
    }
    let empty = serde_json::Map::new();
    let schemes = match document
        .get("components")
        .and_then(|v| v.get("securitySchemes"))
    {
        Some(value) => value
            .as_object()
            .ok_or("securitySchemes must be an object")?,
        None => &empty,
    };
    let mut declared = BTreeSet::new();
    for (name, scheme) in schemes {
        if name.is_empty() || scheme.get("$ref").is_some() {
            return Err("referenced security schemes are unsupported".into());
        }
        match scheme["type"].as_str() {
            Some("http") if scheme["scheme"].as_str().is_some_and(|s| !s.is_empty()) => {}
            Some("apiKey")
                if ["query", "header", "cookie"]
                    .iter()
                    .any(|location| scheme["in"] == *location)
                    && scheme["name"].as_str().is_some_and(|s| !s.is_empty()) => {}
            _ => return Err("checker supports inline HTTP and API-key security schemes".into()),
        }
        declared.insert(name.as_str());
    }
    fn required(value: Option<&Value>, declared: &BTreeSet<&str>) -> Result<bool> {
        let Some(value) = value else {
            return Ok(false);
        };
        let alternatives = value.as_array().ok_or("security must be an array")?;
        let mut required = !alternatives.is_empty();
        for requirement in alternatives {
            let requirement = requirement
                .as_object()
                .ok_or("security requirement must be an object")?;
            if requirement.is_empty() {
                required = false;
            }
            for (name, roles) in requirement {
                if !declared.contains(name.as_str())
                    || !roles
                        .as_array()
                        .is_some_and(|values| values.iter().all(Value::is_string))
                {
                    return Err(
                        "security requirement refers to an unknown or malformed scheme".into(),
                    );
                }
            }
        }
        Ok(required)
    }
    let inherited = required(document.get("security"), &declared)?;
    let mut observations = Vec::new();
    for (path, item) in paths {
        let item = item.as_object().ok_or("path item must be an object")?;
        if !path.starts_with('/') || path.len() > 256 || item.contains_key("$ref") {
            return Err("checker requires inline path items".into());
        }
        for (method, operation) in item {
            if ![
                "get", "put", "post", "delete", "options", "head", "patch", "trace",
            ]
            .contains(&method.as_str())
            {
                continue;
            }
            let operation = operation.as_object().ok_or("operation must be an object")?;
            if operation.contains_key("callbacks") || operation.contains_key("$ref") {
                return Err("callbacks and referenced operations are unsupported".into());
            }
            let authentication_required = if operation.contains_key("security") {
                required(operation.get("security"), &declared)?
            } else {
                inherited
            };
            observations.push(Observation {
                path: path.clone(),
                method: method.clone(),
                authentication_required,
            });
        }
    }
    if observations.is_empty() || observations.len() > 512 {
        return Err("checker requires 1..512 operations".into());
    }
    observations
        .sort_by(|left, right| (&left.path, &left.method).cmp(&(&right.path, &right.method)));
    Ok(observations)
}

pub fn envelope(report: &SignedReport) -> Result<Value> {
    Ok(serde_json::to_value(
        chio_finding::finding_reveal_envelope("application/json", &canonical_json_bytes(report)?),
    )?)
}
pub fn decode(value: &Value) -> Result<SignedReport> {
    if value["media_type"] != "application/json" {
        return Err("unexpected reveal media type".into());
    }
    let bytes = STANDARD.decode(
        value["payload_b64"]
            .as_str()
            .ok_or("missing report payload")?,
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn verify_report(request: &ReviewRequest, report: &SignedReport) -> Result<()> {
    if report.signer_key != request.acceptance.quote.agreement.provider
        || !report.verify_signature()?
        || report.body != request.report()?
    {
        return Err("review report does not reproduce the agreed check".into());
    }
    Ok(())
}

pub struct ReviewGuard {
    pub db: Arc<Mutex<Connection>>,
    pub peers: Peers,
}
impl ReviewGuard {
    pub fn check(&self, ctx: &GuardContext) -> Result<()> {
        if ctx.request.tool_name != "review" {
            return Ok(());
        }
        let request: ReviewRequest = serde_json::from_value(ctx.request.arguments.clone())?;
        request.validate(&self.peers)?;
        let a = &request.acceptance;
        if now()? >= a.quote.agreement.deadline
            || digest(&ctx.request.capability)? != digest(&a.ask.body.token_offer)?
        {
            return Err("work capability or deadline differs from accepted offer".into());
        }
        let db = self.db.lock().map_err(|_| "review journal lock poisoned")?;
        let retained: Option<String> = db
            .query_row(
                "SELECT accepted FROM jobs WHERE job=? AND state='accepted'",
                [&a.quote.agreement.job_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let retained: Acceptance =
            serde_json::from_str(&retained.ok_or("job has no retained acceptance")?)?;
        if digest(&retained)? != digest(a)? {
            return Err("work request changes retained acceptance".into());
        }
        request.report()?;
        Ok(())
    }
}
impl Guard for ReviewGuard {
    fn name(&self) -> &str {
        "accepted-security-review"
    }
    fn evaluate(&self, ctx: &GuardContext) -> std::result::Result<GuardDecision, KernelError> {
        self.check(ctx)
            .map(|_| GuardDecision::allow())
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn revalidate_before_dispatch(
        &self,
        ctx: &GuardContext,
    ) -> std::result::Result<(), KernelError> {
        self.check(ctx)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
    fn output_rejection_is_zero_charge(&self, ctx: &GuardContext) -> bool {
        ctx.request.tool_name == "review"
    }
    fn validate_output_before_release(
        &self,
        ctx: &GuardContext,
        output: &ToolServerOutput,
    ) -> std::result::Result<(), KernelError> {
        if ctx.request.tool_name != "review" {
            return Ok(());
        }
        let check = || -> Result<()> {
            let request = serde_json::from_value(ctx.request.arguments.clone())?;
            let ToolServerOutput::Value(value) = output else {
                return Err("streamed review is unsupported".into());
            };
            let report = decode(value)?;
            verify_report(&request, &report)
        };
        check().map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Delivery {
    pub finding: chio_finding::Finding,
    pub report: SignedReport,
    pub receipt: chio_core_types::receipt::body::ChioReceipt,
    pub checkpoint: chio_kernel::checkpoint::KernelCheckpoint,
    pub inclusion: chio_kernel::checkpoint::ReceiptInclusionProof,
}

pub fn delivery(
    db: &Connection,
    store: &chio_store_sqlite::SqliteReceiptStore,
    key: &chio_core_types::Keypair,
    a: &Acceptance,
    admissions: &chio_store_sqlite::SqliteAdmissionOperationStore,
    authority_database: &std::path::Path,
) -> Result<Value> {
    let job = &a.quote.agreement.job_id;
    let retained: String = db.query_row(
        "SELECT accepted FROM jobs WHERE job=? AND state='accepted'",
        [job],
        |r| r.get(0),
    )?;
    if digest(&serde_json::from_str::<Acceptance>(&retained)?)? != digest(a)? {
        return Err("delivery request changes the retained acceptance".into());
    }
    let existing: Option<String> = db
        .query_row("SELECT artifact FROM deliveries WHERE job=?", [job], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(encoded) = existing {
        return Ok(serde_json::from_str(&encoded)?);
    }
    let stored: Option<(String, String)> = db
        .query_row(
            "SELECT request,report FROM review_runs WHERE job=?",
            [job],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((request, report)) = stored else {
        return crate::incident::delivery(a, authority_database, admissions, key);
    };
    let request: ReviewRequest = serde_json::from_str(&request)?;
    let report: SignedReport = serde_json::from_str(&report)?;
    if digest(&request.acceptance)? != digest(a)? {
        return Err("delivery names another acceptance".into());
    }
    let end = store.latest_committed_entry_seq()?;
    if end == 0 || end > 4096 {
        return Err("receipt recovery exceeds this bounded profile".into());
    }
    let receipts = store.receipts_canonical_bytes_range(1, end)?;
    let mut selected = None;
    for (seq, bytes) in &receipts {
        let Ok(receipt) =
            serde_json::from_slice::<chio_core_types::receipt::body::ChioReceipt>(bytes)
        else {
            continue;
        };
        if receipt.capability_id == a.ask.body.token_offer.id
            && receipt.tool_name == "review"
            && (receipt.decision == Some(chio_core_types::receipt::decision::Decision::Allow)
                || is_rejection_receipt(&receipt))
        {
            if selected.is_some() {
                return Err("multiple terminal review receipts for one offer".into());
            }
            selected = Some((*seq, receipt));
        }
    }
    let Some((receipt_seq, receipt)) = selected else {
        return crate::incident::delivery(a, authority_database, admissions, key);
    };
    while store.create_next_receipt_checkpoint(1024, key)?.created {}
    let mut checkpoint_seq = 1;
    let checkpoint = loop {
        let checkpoint = store
            .load_checkpoint_by_seq(checkpoint_seq)?
            .ok_or("review receipt has no checkpoint")?;
        if checkpoint.body.batch_start_seq <= receipt_seq
            && receipt_seq <= checkpoint.body.batch_end_seq
        {
            break checkpoint;
        }
        checkpoint_seq += 1;
    };
    let batch = store.receipts_canonical_bytes_range(
        checkpoint.body.batch_start_seq,
        checkpoint.body.batch_end_seq,
    )?;
    let leaf = usize::try_from(receipt_seq - checkpoint.body.batch_start_seq)?;
    let bytes: Vec<_> = batch.into_iter().map(|(_, bytes)| bytes).collect();
    let tree = chio_core_types::merkle::MerkleTree::from_leaves(&bytes)?;
    let inclusion = chio_kernel::checkpoint::build_inclusion_proof(
        &tree,
        leaf,
        checkpoint.body.checkpoint_seq,
        receipt_seq,
    )?;
    if is_rejection_receipt(&receipt) {
        let rejection = Rejection {
            schema: REJECTION_SCHEMA.into(),
            agreement_sha256: digest(&a.quote.agreement)?,
            accepted_bid_sha256: digest(&a.accepted)?,
            receipt,
            checkpoint,
            inclusion,
        };
        verify_rejection(&request, &rejection)?;
        let value = serde_json::to_value(rejection)?;
        db.execute(
            "INSERT INTO deliveries(job,artifact) VALUES(?,?)",
            rusqlite::params![job, serde_json::to_string(&value)?],
        )?;
        return Ok(value);
    }
    verify_report(&request, &report)?;
    let body = &a.quote.agreement;
    let mut finding = chio_finding::Finding {
        schema: chio_finding::FINDING_SCHEMA_V1.into(),
        finding_id: String::new(),
        descriptor: chio_finding::FindingDescriptor {
            topic: "security:openapi:authentication-declarations".into(),
            context_sha256: digest(body)?,
            outcome_class: chio_finding::FindingOutcomeClass::PositiveResult,
        },
        guarantee_class: chio_finding::FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: digest(&envelope(&report)?)?,
        payload_media_type: "application/json".into(),
        evidence_receipt_ids: vec![receipt.id.clone()],
        evidence_checkpoint_ref: digest(&checkpoint)?,
        evidence_cost: amount(100),
        runtime_assurance_tier: None,
        evidence_class: chio_finding::FindingEvidenceClass::Observed,
        replay_recipe_sha256: Some(recipe_digest(body)?),
        intent_commitment_receipt_id: None,
        bond_ref: format!("unbacked:{}", digest(body)?),
        status_feed_ref: format!("local-job:{job}"),
        license_ref: None,
        price_hint_ref: None,
        issuer: key.public_key(),
        issued_at: receipt.timestamp,
        expires_at: body.deadline,
        signature: String::new(),
    };
    finding.finding_id = chio_finding::compute_finding_id(&finding)?;
    let finding = chio_finding::sign_finding(finding, key)?;
    let delivery = Delivery {
        finding,
        report,
        receipt,
        checkpoint,
        inclusion,
    };
    verify_delivery(&request, &delivery)?;
    let value = serde_json::to_value(delivery)?;
    db.execute(
        "INSERT INTO deliveries(job,artifact) VALUES(?,?)",
        rusqlite::params![job, serde_json::to_string(&value)?],
    )?;
    Ok(value)
}
fn recipe_digest(a: &Agreement) -> Result<String> {
    digest(&json!({"checker":a.checker,"inputSha256":a.input_sha256}))
}

pub fn verify_delivery(request: &ReviewRequest, delivery: &Delivery) -> Result<()> {
    use chio_core_types::receipt::{
        decision::Decision,
        economics::{FinancialReceiptMetadata, SettlementStatus},
        metadata::FINANCIAL_METADATA_KEY,
    };
    let a = &request.acceptance;
    let provider = &a.quote.agreement.provider;
    verify_report(request, &delivery.report)?;
    chio_finding::verify_finding(&delivery.finding)?;
    let receipt = &delivery.receipt;
    let finding = &delivery.finding;
    if &receipt.kernel_key != provider
        || !receipt.verify_signature()?
        || !receipt.action.verify_hash()?
        || receipt.tool_server != SERVER
        || receipt.tool_name != "review"
        || receipt.capability_id != a.ask.body.token_offer.id
        || receipt.action.parameters != serde_json::to_value(request)?
        || receipt.decision != Some(Decision::Allow)
        || receipt.content_hash != digest(&envelope(&delivery.report)?)?
        || receipt.timestamp < a.accepted.body.accepted_at
        || receipt.timestamp >= a.quote.agreement.deadline
        || &finding.issuer != provider
        || finding.descriptor.context_sha256 != digest(&a.quote.agreement)?
        || finding.payload_sha256 != receipt.content_hash
        || finding.payload_media_type != "application/json"
        || finding.evidence_receipt_ids != vec![receipt.id.clone()]
        || finding.evidence_checkpoint_ref != digest(&delivery.checkpoint)?
        || finding.replay_recipe_sha256 != Some(recipe_digest(&a.quote.agreement)?)
        || finding.guarantee_class != chio_finding::FindingGuaranteeClass::DeterministicReplay
        || finding.evidence_class != chio_finding::FindingEvidenceClass::Observed
        || finding.evidence_cost != amount(100)
    {
        return Err("finding does not bind the paid review and agreed input".into());
    }
    if finding.descriptor.topic != "security:openapi:authentication-declarations"
        || finding.descriptor.outcome_class != chio_finding::FindingOutcomeClass::PositiveResult
        || finding.runtime_assurance_tier.is_some()
        || finding.intent_commitment_receipt_id.is_some()
        || finding.license_ref.is_some()
        || finding.price_hint_ref.is_some()
        || finding.bond_ref != format!("unbacked:{}", digest(&a.quote.agreement)?)
        || finding.status_feed_ref != format!("local-job:{}", a.quote.agreement.job_id)
        || finding.issued_at != receipt.timestamp
        || finding.expires_at != a.quote.agreement.deadline
    {
        return Err("finding changes the agreed evidence profile".into());
    }
    let finance: FinancialReceiptMetadata = serde_json::from_value(
        receipt
            .metadata
            .as_ref()
            .ok_or("missing financial receipt")?[FINANCIAL_METADATA_KEY]
            .clone(),
    )?;
    if finance.cost_charged != 100
        || finance.currency != "TST"
        || finance.settlement_status != SettlementStatus::Settled
        || finance.budget_remaining != 0
        || finance.budget_total != 100
        || finance.grant_index != 0
        || finance
            .payment_reference
            .as_ref()
            .is_none_or(String::is_empty)
    {
        return Err("review has no completed local-credit settlement".into());
    }
    verify_inclusion(receipt, &delivery.checkpoint, &delivery.inclusion, provider)
}

fn verify_inclusion(
    receipt: &chio_core_types::receipt::body::ChioReceipt,
    checkpoint: &chio_kernel::checkpoint::KernelCheckpoint,
    inclusion: &chio_kernel::checkpoint::ReceiptInclusionProof,
    provider: &chio_core_types::PublicKey,
) -> Result<()> {
    chio_kernel::checkpoint::validate_checkpoint(checkpoint)?;
    if &checkpoint.body.kernel_key != provider
        || !chio_kernel::checkpoint::verify_checkpoint_signature(checkpoint)?
        || inclusion.checkpoint_seq != checkpoint.body.checkpoint_seq
        || checkpoint
            .body
            .batch_start_seq
            .checked_add(inclusion.leaf_index as u64)
            != Some(inclusion.receipt_seq)
        || inclusion.merkle_root != checkpoint.body.merkle_root
        || inclusion.receipt_seq > checkpoint.body.batch_end_seq
        || !inclusion.verify(
            &canonical_json_bytes(receipt)?,
            &checkpoint.body.merkle_root,
        )
    {
        return Err("review receipt is not included in the pinned provider checkpoint".into());
    }
    Ok(())
}

const REJECTION_SCHEMA: &str = "chio.example.checked-review-rejection.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rejection {
    pub schema: String,
    pub agreement_sha256: String,
    pub accepted_bid_sha256: String,
    pub receipt: chio_core_types::receipt::body::ChioReceipt,
    pub checkpoint: chio_kernel::checkpoint::KernelCheckpoint,
    pub inclusion: chio_kernel::checkpoint::ReceiptInclusionProof,
}

pub fn is_rejection_receipt(receipt: &chio_core_types::receipt::body::ChioReceipt) -> bool {
    receipt.decision
        == Some(chio_core_types::receipt::decision::Decision::Deny {
            guard: "checked_output".into(),
            reason: chio_kernel::admission_operation::OUTPUT_GUARD_REJECTION_REASON.into(),
        })
}

pub fn verify_rejection(request: &ReviewRequest, rejection: &Rejection) -> Result<()> {
    use chio_core_types::receipt::economics::{FinancialReceiptMetadata, SettlementStatus};
    let a = &request.acceptance;
    let receipt = &rejection.receipt;
    if rejection.schema != REJECTION_SCHEMA
        || rejection.agreement_sha256 != digest(&a.quote.agreement)?
        || rejection.accepted_bid_sha256 != digest(&a.accepted)?
        || receipt.kernel_key != a.quote.agreement.provider
        || !receipt.verify_signature()?
        || !receipt.action.verify_hash()?
        || receipt.tool_server != SERVER
        || receipt.tool_name != "review"
        || receipt.capability_id != a.ask.body.token_offer.id
        || receipt.action.parameters != serde_json::to_value(request)?
        || !is_rejection_receipt(receipt)
        || receipt.content_hash
            != sha256_hex(chio_kernel::admission_operation::OUTPUT_GUARD_REJECTION_REDACTION_DOMAIN)
        || receipt.timestamp < a.accepted.body.accepted_at
    {
        return Err("rejection does not bind the agreed review".into());
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or("missing rejection metadata")?;
    let finance: FinancialReceiptMetadata = serde_json::from_value(metadata["financial"].clone())?;
    let admission: chio_kernel::admission_operation::AdmissionReceiptMetadataV1 =
        serde_json::from_value(
            metadata[chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY].clone(),
        )?;
    if finance.cost_charged != 0
        || finance.currency != "TST"
        || finance.settlement_status != SettlementStatus::Settled
        || finance.budget_remaining != 100
        || finance.budget_total != 100
        || finance.grant_index != 0
        || finance
            .payment_reference
            .as_ref()
            .is_none_or(String::is_empty)
        || admission.projected_state
            != chio_kernel::admission_operation::AdmissionOperationState::DeniedAfterDelivery
        || admission.retained_dispatch_commit.is_none()
    {
        return Err("rejection does not prove completed zero-charge local settlement".into());
    }
    verify_inclusion(
        receipt,
        &rejection.checkpoint,
        &rejection.inclusion,
        &a.quote.agreement.provider,
    )
}

pub fn verify_terminal(request: &ReviewRequest, value: &Value) -> Result<(bool, String)> {
    if value.get("schema").is_some() {
        let rejection: Rejection = serde_json::from_value(value.clone())?;
        verify_rejection(request, &rejection)?;
        Ok((true, rejection.receipt.id))
    } else {
        let delivery: Delivery = serde_json::from_value(value.clone())?;
        verify_delivery(request, &delivery)?;
        Ok((false, delivery.receipt.id))
    }
}
