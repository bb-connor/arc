use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core::crypto::{Keypair, PublicKey, Signature};
use chio_core::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};

use crate::receipt_store::{AuthorizationReceiptConsumption, PendingSettlementObservation};

use super::*;

const SIGNED_TERMINAL_PROJECTION_SCHEMA: &str = "chio.signed-admission-terminal-projection.v1";
const SIGNED_TERMINAL_PROJECTION_DOMAIN: &[u8] = b"chio.signed-admission-terminal-projection.v1\0";
pub const MAX_ADMISSION_TERMINAL_PROJECTION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ADMISSION_TERMINAL_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_ADMISSION_TERMINAL_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_ADMISSION_TERMINAL_RECORDS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedAdmissionTerminalProjectionRecordV1 {
    pub kind: AdmissionProjectionRecordKind,
    pub record_id: AdmissionIdentifier,
    pub record_digest: AdmissionDigest,
    pub canonical_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTerminalObserverProjectionV1 {
    pub receipt_id: AdmissionIdentifier,
    pub pending: PendingSettlementObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmissionTerminalProjectionBodyV1 {
    schema: String,
    signer_key: PublicKey,
    context: AdmissionProjectionContext,
    source_operation: PersistedAdmissionOperationV1,
    terminal_operation: PersistedAdmissionOperationV1,
    projection_json: String,
    manifest_json: String,
    records: Vec<PersistedAdmissionTerminalProjectionRecordV1>,
    authorization_consumption: Option<AuthorizationReceiptConsumption>,
    observer: Option<AdmissionTerminalObserverProjectionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmissionTerminalProjectionV1 {
    body: SignedAdmissionTerminalProjectionBodyV1,
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmissionTerminalProjectionRecordV1 {
    kind: AdmissionProjectionRecordKind,
    record_id: AdmissionIdentifier,
    record_digest: AdmissionDigest,
    canonical_json: Vec<u8>,
}

impl VerifiedAdmissionTerminalProjectionRecordV1 {
    #[must_use]
    pub const fn kind(&self) -> AdmissionProjectionRecordKind {
        self.kind
    }

    #[must_use]
    pub const fn record_id(&self) -> &AdmissionIdentifier {
        &self.record_id
    }

    #[must_use]
    pub const fn record_digest(&self) -> &AdmissionDigest {
        &self.record_digest
    }

    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmissionTerminalProjectionV1 {
    signer_key: PublicKey,
    context: AdmissionProjectionContext,
    source_operation: AdmissionOperationV1,
    terminal_operation: AdmissionOperationV1,
    projection_json: Vec<u8>,
    manifest_json: Vec<u8>,
    records: Vec<VerifiedAdmissionTerminalProjectionRecordV1>,
    authorization_consumption: Option<AuthorizationReceiptConsumption>,
    observer: Option<AdmissionTerminalObserverProjectionV1>,
}

impl SignedAdmissionTerminalProjectionV1 {
    pub fn from_verified(
        source_operation: &AdmissionOperationV1,
        projection: &AdmissionTerminalProjection,
        capabilities: &AdmissionProjectionCapabilities,
        signer: &Keypair,
    ) -> Result<Self, AdmissionOperationError> {
        let canonical = projection.canonical_projection()?;
        let terminal_operation =
            source_operation.apply_terminal_projection(projection, capabilities)?;
        let (authorization_consumption, observer) = match projection {
            AdmissionTerminalProjection::Completed(completed) => (
                completed
                    .authorization
                    .as_ref()
                    .map(|authorization| authorization.consumption().clone()),
                completed
                    .observer_work
                    .as_ref()
                    .map(|observer| {
                        Ok(AdmissionTerminalObserverProjectionV1 {
                            receipt_id: AdmissionIdentifier::try_new(
                                "observer_receipt_id",
                                completed.receipt.receipt().id.clone(),
                            )?,
                            pending: *observer.pending(),
                        })
                    })
                    .transpose()?,
            ),
            _ => (None, None),
        };
        let records = canonical
            .records()
            .iter()
            .map(|record| PersistedAdmissionTerminalProjectionRecordV1 {
                kind: record.commitment().kind(),
                record_id: record.commitment().record_id().clone(),
                record_digest: record.commitment().record_digest().clone(),
                canonical_json: STANDARD.encode(record.canonical_bytes()),
            })
            .collect();
        let body = SignedAdmissionTerminalProjectionBodyV1 {
            schema: SIGNED_TERMINAL_PROJECTION_SCHEMA.to_owned(),
            signer_key: signer.public_key(),
            context: projection.context().clone(),
            source_operation: source_operation.to_persisted(),
            terminal_operation: terminal_operation.to_persisted(),
            projection_json: STANDARD.encode(canonical.projection_bytes()),
            manifest_json: STANDARD.encode(canonical.manifest_bytes()),
            records,
            authorization_consumption,
            observer,
        };
        let signature = signer.sign(&signing_preimage(&body)?);
        let envelope = Self { body, signature };
        envelope.verify()?;
        Ok(envelope)
    }

    pub fn verify(&self) -> Result<VerifiedAdmissionTerminalProjectionV1, AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        if self.body.schema != SIGNED_TERMINAL_PROJECTION_SCHEMA
            || !self
                .body
                .signer_key
                .verify(&signing_preimage(&self.body)?, &self.signature)
        {
            return Err(mismatch());
        }
        self.body.context.validate()?;
        let source_operation =
            AdmissionOperationV1::from_persisted(self.body.source_operation.clone())?;
        let terminal_operation =
            AdmissionOperationV1::from_persisted(self.body.terminal_operation.clone())?;
        let projection_json = decode_bounded(
            &self.body.projection_json,
            MAX_ADMISSION_TERMINAL_PROJECTION_BYTES,
        )?;
        let manifest_json = decode_bounded(
            &self.body.manifest_json,
            MAX_ADMISSION_TERMINAL_MANIFEST_BYTES,
        )?;
        let manifest = AdmissionProjectionManifestV1::from_canonical_bytes(&manifest_json)?;
        manifest.verify_projection_body(&projection_json)?;
        let projection_digest = manifest.projection_digest()?;
        validate_terminal_successor(
            &source_operation,
            &terminal_operation,
            &self.body.context,
            &projection_digest,
        )?;
        validate_projection_body(
            &projection_json,
            &self.body.context,
            terminal_operation.state(),
        )?;
        let records = validate_records(&self.body.records, &manifest)?;
        validate_record_set(&source_operation, terminal_operation.state(), &records)?;
        validate_receipt_record(
            &records,
            &source_operation,
            &terminal_operation,
            &self.body.context,
            &self.body.signer_key,
        )?;
        validate_sidecars(
            &records,
            self.body.authorization_consumption.as_ref(),
            self.body.observer.as_ref(),
        )?;
        Ok(VerifiedAdmissionTerminalProjectionV1 {
            signer_key: self.body.signer_key.clone(),
            context: self.body.context.clone(),
            source_operation,
            terminal_operation,
            projection_json,
            manifest_json,
            records,
            authorization_consumption: self.body.authorization_consumption.clone(),
            observer: self.body.observer.clone(),
        })
    }
}

impl VerifiedAdmissionTerminalProjectionV1 {
    #[must_use]
    pub const fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }

    #[must_use]
    pub const fn context(&self) -> &AdmissionProjectionContext {
        &self.context
    }

    #[must_use]
    pub const fn source_operation(&self) -> &AdmissionOperationV1 {
        &self.source_operation
    }

    #[must_use]
    pub const fn terminal_operation(&self) -> &AdmissionOperationV1 {
        &self.terminal_operation
    }

    #[must_use]
    pub fn projection_json(&self) -> &[u8] {
        &self.projection_json
    }

    #[must_use]
    pub fn manifest_json(&self) -> &[u8] {
        &self.manifest_json
    }

    #[must_use]
    pub fn records(&self) -> &[VerifiedAdmissionTerminalProjectionRecordV1] {
        &self.records
    }

    #[must_use]
    pub const fn authorization_consumption(&self) -> Option<&AuthorizationReceiptConsumption> {
        self.authorization_consumption.as_ref()
    }

    #[must_use]
    pub const fn observer(&self) -> Option<&AdmissionTerminalObserverProjectionV1> {
        self.observer.as_ref()
    }

    pub fn terminal(&self) -> Result<AdmissionTerminal, AdmissionOperationError> {
        Ok(AdmissionTerminal {
            operation_id: self.context.operation_id.clone(),
            state: self.terminal_operation.state(),
            replay: self
                .terminal_operation
                .terminal_replay()
                .cloned()
                .ok_or(AdmissionOperationError::TerminalReplayMismatch)?,
        })
    }
}

fn signing_preimage(
    body: &SignedAdmissionTerminalProjectionBodyV1,
) -> Result<Vec<u8>, AdmissionOperationError> {
    let canonical = canonical_json_bytes(body)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut preimage =
        Vec::with_capacity(SIGNED_TERMINAL_PROJECTION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(SIGNED_TERMINAL_PROJECTION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

fn decode_bounded(value: &str, maximum: usize) -> Result<Vec<u8>, AdmissionOperationError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(bytes)
}

fn validate_terminal_successor(
    source: &AdmissionOperationV1,
    terminal: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projection_digest: &AdmissionDigest,
) -> Result<(), AdmissionOperationError> {
    let source_persisted = source.to_persisted();
    let terminal_persisted = terminal.to_persisted();
    if source.state().is_terminal()
        || !terminal.state().is_terminal()
        || context.operation_id != *source.binding().operation_id()
        || context.request_id != source.replay_key().request_id
        || context.expected_operation_version != source.version()
        || context.coordinator_lease_epoch != source.coordinator_lease_epoch()
        || source_persisted.binding != terminal_persisted.binding
        || source_persisted.attachments != terminal_persisted.attachments
        || source_persisted.dispatch_commit != terminal_persisted.dispatch_commit
        || source_persisted.coordinator_lease_epoch != terminal_persisted.coordinator_lease_epoch
        || source_persisted.last_error != terminal_persisted.last_error
        || terminal.version() != next_version(source.version())?
        || !is_legal_transition(
            source.binding().kind(),
            source.binding().participant_requirements(),
            source.state(),
            terminal.state(),
        )
        || terminal
            .terminal_replay()
            .is_none_or(|replay| replay.projection_digest() != projection_digest)
        || source.dispatch_commit().is_some_and(|commit| {
            commit.store_fence.store_uuid != context.store_fence.store_uuid
                || (context.store_fence != commit.store_fence
                    && context.store_fence.owner_epoch <= commit.store_fence.owner_epoch)
        })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn validate_projection_body(
    bytes: &[u8],
    context: &AdmissionProjectionContext,
    terminal_state: AdmissionOperationState,
) -> Result<(), AdmissionOperationError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    if canonical_json_bytes(&value)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
        != bytes
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let expected_terminal = match terminal_state {
        AdmissionOperationState::Completed => "completed",
        AdmissionOperationState::CompensatedBeforeDispatch => "compensated_before_dispatch",
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            "not_accepted_after_dispatch_commit"
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        AdmissionOperationState::EconomicMutationApplied => "economic_mutation_applied",
        AdmissionOperationState::EconomicMutationNotApplied => "economic_mutation_not_applied",
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    };
    if value.get("terminal").and_then(serde_json::Value::as_str) != Some(expected_terminal)
        || value.get("context")
            != Some(
                &serde_json::to_value(context)
                    .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
            )
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn validate_records(
    records: &[PersistedAdmissionTerminalProjectionRecordV1],
    manifest: &AdmissionProjectionManifestV1,
) -> Result<Vec<VerifiedAdmissionTerminalProjectionRecordV1>, AdmissionOperationError> {
    if records.is_empty()
        || records.len() > MAX_ADMISSION_TERMINAL_RECORDS
        || records.len() != manifest.records().len()
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    records
        .iter()
        .zip(manifest.records())
        .map(|(record, commitment)| {
            let canonical_json =
                decode_bounded(&record.canonical_json, MAX_ADMISSION_TERMINAL_RECORD_BYTES)?;
            let value: serde_json::Value = serde_json::from_slice(&canonical_json)
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
            if canonical_json_bytes(&value)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
                != canonical_json
                || sha256_hex(&canonical_json) != record.record_digest.as_str()
                || record.kind != commitment.kind()
                || record.record_id != *commitment.record_id()
                || record.record_digest != *commitment.record_digest()
            {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
            }
            Ok(VerifiedAdmissionTerminalProjectionRecordV1 {
                kind: record.kind,
                record_id: record.record_id.clone(),
                record_digest: record.record_digest.clone(),
                canonical_json,
            })
        })
        .collect()
}

fn validate_record_set(
    source: &AdmissionOperationV1,
    terminal_state: AdmissionOperationState,
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
) -> Result<(), AdmissionOperationError> {
    let actual = records
        .iter()
        .map(|record| record.kind)
        .collect::<BTreeSet<_>>();
    if actual.len() != records.len() {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let requirements = source.binding().participant_requirements();
    let mut expected = BTreeSet::new();
    match terminal_state {
        AdmissionOperationState::Completed => {
            expected.insert(AdmissionProjectionRecordKind::Receipt);
            if source.binding().kind() == AdmissionOperationKind::ToolDispatch {
                expected.insert(AdmissionProjectionRecordKind::ToolOutcome);
            }
            for (required, kind) in [
                (
                    requirements.payment,
                    AdmissionProjectionRecordKind::PaymentTerminal,
                ),
                (
                    requirements.authorization_consumption,
                    AdmissionProjectionRecordKind::AuthorizationConsumption,
                ),
                (
                    requirements.outcome_eligibility,
                    AdmissionProjectionRecordKind::OutcomeEligibility,
                ),
                (
                    requirements.observation_attempt_zero,
                    AdmissionProjectionRecordKind::ObservationAttemptZero,
                ),
                (
                    requirements.obligation,
                    AdmissionProjectionRecordKind::Obligation,
                ),
            ] {
                if required {
                    expected.insert(kind);
                }
            }
        }
        AdmissionOperationState::CompensatedBeforeDispatch
        | AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            expected.insert(AdmissionProjectionRecordKind::ReleaseProof);
            let evidence_count =
                usize::from(actual.contains(&AdmissionProjectionRecordKind::Receipt))
                    + usize::from(actual.contains(&AdmissionProjectionRecordKind::Incident));
            if evidence_count != 1 {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
            }
            expected.insert(
                if actual.contains(&AdmissionProjectionRecordKind::Receipt) {
                    AdmissionProjectionRecordKind::Receipt
                } else {
                    AdmissionProjectionRecordKind::Incident
                },
            );
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            expected.insert(AdmissionProjectionRecordKind::Incident);
        }
        AdmissionOperationState::EconomicMutationApplied
        | AdmissionOperationState::EconomicMutationNotApplied => {
            expected.insert(AdmissionProjectionRecordKind::EconomicMutationResult);
            expected.insert(AdmissionProjectionRecordKind::MutationAudit);
        }
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
    if actual != expected {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn validate_receipt_record(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    source: &AdmissionOperationV1,
    terminal: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    signer_key: &PublicKey,
) -> Result<(), AdmissionOperationError> {
    let Some(record) = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::Receipt)
    else {
        return Ok(());
    };
    let receipt: ChioReceipt = serde_json::from_slice(&record.canonical_json)
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    if receipt.id != record.record_id.as_str() || receipt.kernel_key != *signer_key {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(ADMISSION_RECEIPT_METADATA_KEY))
        .cloned()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)
        .and_then(|value| {
            serde_json::from_value::<AdmissionReceiptMetadataV1>(value)
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)
        })?;
    let outcome = metadata
        .tool_outcome_id
        .as_ref()
        .zip(metadata.tool_outcome_version);
    let compensation = match terminal.state() {
        AdmissionOperationState::Completed => AdmissionCompensationStatus::NotCompensated,
        AdmissionOperationState::CompensatedBeforeDispatch => {
            AdmissionCompensationStatus::CompensatedBeforeDispatch
        }
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            AdmissionCompensationStatus::NotAcceptedAfterDispatchCommit
        }
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    };
    validate_receipt_projection(
        &receipt,
        source,
        context,
        terminal.state(),
        compensation,
        outcome,
    )
}

fn validate_sidecars(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    authorization: Option<&AuthorizationReceiptConsumption>,
    observer: Option<&AdmissionTerminalObserverProjectionV1>,
) -> Result<(), AdmissionOperationError> {
    let authorization_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::AuthorizationConsumption);
    match (authorization_record, authorization) {
        (Some(record), Some(authorization))
            if record.record_id.as_str() == authorization.authorization_receipt_id
                && record.canonical_json
                    == canonical_json_bytes(authorization).map_err(|error| {
                        AdmissionOperationError::CanonicalJson(error.to_string())
                    })? => {}
        (None, None) => {}
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
    let observer_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::ObservationAttemptZero);
    match (observer_record, observer) {
        (Some(record), Some(observer))
            if record.record_id == observer.receipt_id
                && record.canonical_json
                    == canonical_json_bytes(&observer.pending).map_err(|error| {
                        AdmissionOperationError::CanonicalJson(error.to_string())
                    })? => {}
        (None, None) => {}
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
    Ok(())
}
