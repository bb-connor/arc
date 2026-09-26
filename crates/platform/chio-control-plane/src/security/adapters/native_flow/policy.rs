//! Exact policy evidence for the native ledger. Only the live prepared resolver
//! produces this record; copying its bytes never grants dispatch authority.

use super::*;
use chio_security_types::flow::ToolFlowDeclaration;
use serde::Serialize;
use std::io::Write;

const MAX_POLICY_BYTES: usize = 256 * 1024;
const SCHEMA: &str = "chio.native-flow-dispatch-policy.v1";
const DECLASSIFIED_SCHEMA: &str = "chio.native-flow-dispatch-policy.v2";

/// Canonical historical policy inputs and decision. No reusable credentials or
/// argument payload are retained. This is neither a durable ledger attachment
/// nor an execution permit; those require the operation's physical transaction.
pub struct NativeFlowPolicyEvidence {
    canonical: Vec<u8>,
    digest: Digest32,
}

impl std::fmt::Debug for NativeFlowPolicyEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFlowPolicyEvidence")
            .field("encoded_bytes", &self.canonical.len())
            .finish_non_exhaustive()
    }
}

impl NativeFlowPolicyEvidence {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub fn digest(&self) -> Digest32 {
        self.digest
    }
}

/// Private, bounded intermediate. Producing final evidence never reruns a
/// classifier or resolves a second, potentially different manifest/policy.
pub(super) struct PreparedInputs(serde_json::Value);

impl PreparedInputs {
    pub(super) fn capture(
        resolver: &NativeFlowResolver,
        custody: &PreparedNativeSecurityEgress<'_>,
        resolved: &flow_policy::ResolvedFlowPolicy<'_>,
    ) -> Result<Self, NativeFlowError> {
        #[derive(Serialize)]
        struct ManifestAttestation<'a> {
            manifest_digest: &'a str,
            signer_key: &'a chio_core::PublicKey,
            signature: &'a chio_core::Signature,
        }
        #[derive(Serialize)]
        struct Inputs<'a> {
            operation_id: &'a AdmissionOperationId,
            operation_version: u64,
            retained_request_digest: chio_kernel::admission_operation::AdmissionDigest,
            live_request_digest: Digest32,
            kernel_policy_hash: &'a str,
            native_authority: &'a NativeSecurityAuthorityBindingV1,
            observation: &'a FlowStateSnapshot,
            observed_at_unix_ms: u64,
            stored_context_generation: Option<u64>,
            classification: &'a ClassificationResult,
            category_bindings: &'a BTreeMap<RecordId, InformationLabel>,
            classified_label: &'a InformationLabel,
            operator_input_floor: &'a InformationLabel,
            admitted_security: &'a AdmittedToolSecurity,
            bridge: &'a BridgeSecurityMetadata,
            manifest_attestation: ManifestAttestation<'a>,
            runtime_egress: bool,
            manifest: &'a ToolFlowDeclaration,
            policy_clearances: &'a [InformationLabel],
            transition_id: &'a RecordId,
            destination_id: &'a DestinationId,
            tool_name: &'a RecordId,
            prepared_at_unix_ms: u64,
            valid_until_unix_ms: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            declassification:
                Option<chio_kernel::admission_operation::NativeSecurityDeclassificationGrantV1>,
        }
        let request = &resolved.request;
        let manifest = resolver
            .manifests
            .verified_manifest(&custody.request().server_id)
            .ok_or(FlowDenial::InvalidManifest)?;
        // The admitted bridge already commits to the complete canonical
        // manifest. Retain that exact digest and attestation, not a new copy of
        // every tool schema in the registry's potentially much larger manifest.
        let manifest_digest = resolved
            .bridge
            .manifest_digest()
            .ok_or(FlowDenial::InvalidManifest)?;
        let inputs =
            Inputs {
                operation_id: custody.operation_id(),
                operation_version: custody.operation_version(),
                retained_request_digest: custody.retained_request_digest()?,
                live_request_digest: flow_dispatch::live_request_digest(custody.request())?,
                kernel_policy_hash: custody.kernel_policy_hash(),
                native_authority: custody.observation().binding(),
                observation: &request.state,
                observed_at_unix_ms: custody.observation().observed_at_unix_ms(),
                stored_context_generation: custody.observation().stored_context_generation(),
                classification: resolved.classification.evidence(),
                category_bindings: resolver.config.category_labels.bindings(),
                classified_label: resolved.classification.label(),
                operator_input_floor: &request.operator_input_floor,
                admitted_security: resolved.admitted_security,
                bridge: &resolved.bridge,
                manifest_attestation: ManifestAttestation {
                    manifest_digest,
                    signer_key: &manifest.signer_key,
                    signature: &manifest.signature,
                },
                runtime_egress: request.runtime_egress,
                manifest: &request.manifest,
                policy_clearances: request.policy_clearances.as_slice(),
                transition_id: &request.transition_id,
                destination_id: &request.destination_id,
                tool_name: &request.tool_name,
                prepared_at_unix_ms: request.now_unix_ms,
                valid_until_unix_ms: request.fence_expires_at_unix_ms,
                declassification: custody
                    .request()
                    .declassification_grant
                    .as_ref()
                    .map(|signed| {
                        let verified = request
                            .declassification
                            .as_ref()
                            .ok_or(NativeFlowError::PolicyEvidence)?;
                        if verified.authority_key() != signed.authority_key() {
                            return Err(NativeFlowError::PolicyEvidence);
                        }
                        Ok(chio_kernel::admission_operation::NativeSecurityDeclassificationGrantV1 {
                    body: signed.body().clone(),
                    authority_key: verified.authority_key().clone(),
                    artifact_hash: declassification_grant_hash(signed)?,
                })
                    })
                    .transpose()?,
            };
        Ok(Self(bounded_value(&inputs)?))
    }

    pub(super) fn finish(
        self,
        prepared: &chio_flow::PreparedFlowAdmission,
    ) -> Result<NativeFlowPolicyEvidence, NativeFlowError> {
        #[derive(Serialize)]
        struct Decision<'a> {
            request_hash: Digest32,
            source_label: &'a InformationLabel,
            egress_source_label: &'a InformationLabel,
            effective_egress: bool,
            taint_transition: &'a FlowJoinRequest,
            egress_expires_at_unix_ms: Option<u64>,
            declassification: bool,
        }
        #[derive(Serialize)]
        struct Record<'a> {
            schema: &'static str,
            inputs: &'a serde_json::Value,
            decision: Decision<'a>,
        }
        let admission = prepared.admission();
        let declassification = prepared.declassification().is_some();
        if admission.declassification.is_some()
            || (declassification && !admission.effective_egress)
            || admission.effective_egress != admission.egress_fence_plan.is_some()
        {
            return Err(NativeFlowError::PolicyEvidence);
        }
        let canonical = canonical_bounded(&Record {
            schema: if declassification {
                DECLASSIFIED_SCHEMA
            } else {
                SCHEMA
            },
            inputs: &self.0,
            decision: Decision {
                request_hash: admission.request_hash,
                source_label: &admission.source_label,
                egress_source_label: &admission.egress_source_label,
                effective_egress: admission.effective_egress,
                taint_transition: &admission.taint_transition,
                egress_expires_at_unix_ms: admission
                    .egress_fence_plan
                    .as_ref()
                    .map(|plan| plan.expires_at_unix_ms),
                declassification,
            },
        })?;
        Ok(NativeFlowPolicyEvidence {
            digest: digest(&canonical),
            canonical,
        })
    }
}

/// Stop serialization at the byte limit, before building a serde value or a
/// canonical copy. The enclosing snapshot limit also bounds nested collections.
fn bounded_value(value: &impl Serialize) -> Result<serde_json::Value, NativeFlowError> {
    struct Writer(Vec<u8>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_POLICY_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(
                    "native policy evidence exceeds its bound",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| NativeFlowError::PolicyEvidence)?;
    serde_json::from_slice(&writer.0).map_err(|_| NativeFlowError::PolicyEvidence)
}

fn canonical_bounded(value: &impl Serialize) -> Result<Vec<u8>, NativeFlowError> {
    let bytes = chio_core::canonical_json_bytes(&bounded_value(value)?)
        .map_err(|_| NativeFlowError::PolicyEvidence)?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(NativeFlowError::PolicyEvidence);
    }
    Ok(bytes)
}
