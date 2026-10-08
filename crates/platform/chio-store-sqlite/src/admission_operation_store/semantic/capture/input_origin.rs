//! Refused Input provenance is data bound to the actual owning native journal.
use super::*;
use chio_core::CanonicalBytes;
use chio_kernel::admission_operation::{
    NativeSecurityInputJoinRequestV1, RetainedToolAdmissionRequestV1,
};
use chio_security_types::knowledge::ArtifactInfluenceV1;
use chio_security_types::ports::{FlowJoinRequest, FlowStateKey, FlowStateSnapshot};
use chio_security_types::InformationLabel;

#[path = "input_origin/framing.rs"]
mod framing;
#[path = "input_origin/historical.rs"]
mod historical;
#[path = "input_origin/source_records.rs"]
mod source_records;
use framing::FramingSources;
pub(in crate::admission_operation_store) use historical::{
    validate_historical_semantic_refused_input_origin, HistoricalSemanticRefusedInputObservation,
    SemanticHistoricalInputOriginData,
};
use source_records::{AudienceSources, SourceRecord};

const MAX_ORIGIN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusedInputOriginBody {
    domain_version: VersionV1,
    operation: AdmissionOperationId,
    original_request: serde_json::Value,
    native_authority: NativeSecurityAuthorityBindingV1,
    security_context: SecurityInvocationContext,
    input: NativeSecurityInputJoinRequestV1,
    before: FlowStateSnapshot,
    resolved: FlowJoinRequest,
    invocation: SemanticInvocationV1,
    route: SemanticRouteV1,
    contract: SemanticOperationContractV1,
    installation: SourceRecord<NativeSemanticInstallationV1>,
    route_selection: SourceRecord<RecoveryScopeV1>,
    framing: FramingSources,
    audience: AudienceSources,
    annotations: BoundedList<SourceRecord<SignedSemanticAnnotationV1>, 8>,
    prior_influence: Option<ArtifactInfluenceV1>,
    selected_source_cut: SafeInteger,
    observed_at_unix_ms: SafeInteger,
    source_label: InformationLabel,
    externally_influenced: bool,
    unknown: bool,
}

/// Only the verified Refused branch constructs this immutable observation.
/// No Deserialize, Clone, public constructor or emission authority exists.
pub(in crate::admission_operation_store) struct SemanticRefusedInputOriginData {
    body: RefusedInputOriginBody,
    canonical: CanonicalBytes,
    influence: ArtifactInfluenceV1,
}

impl SemanticRefusedInputOriginData {
    pub(in crate::admission_operation_store) fn native_authority(
        &self,
    ) -> &NativeSecurityAuthorityBindingV1 {
        &self.body.native_authority
    }

    pub(in crate::admission_operation_store) fn source_key(&self) -> &FlowStateKey {
        self.body.input.key()
    }

    pub(in crate::admission_operation_store) fn operation_id(&self) -> &AdmissionOperationId {
        &self.body.operation
    }

    pub(in crate::admission_operation_store) fn source_label(&self) -> &InformationLabel {
        &self.body.source_label
    }

    pub(in crate::admission_operation_store) fn influence(&self) -> &ArtifactInfluenceV1 {
        &self.influence
    }

    pub(in crate::admission_operation_store) fn canonical_origin(&self) -> &CanonicalBytes {
        &self.canonical
    }

    pub(in crate::admission_operation_store) fn selected_source_cut(&self) -> u64 {
        self.body.selected_source_cut.get()
    }

    /// These are data relationships. The separate native writer must prove
    /// its actual Input record, fresh global receipt, source cut and phase owner.
    pub(in crate::admission_operation_store) fn validate_source(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
        key: &FlowStateKey,
        operation: &AdmissionOperationId,
        input: &NativeSecurityInputJoinRequestV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        input.validate(operation)?;
        if self.body.native_authority != *binding
            || self.body.operation != *operation
            || self.body.input != *input
            || self.body.input.key() != key
            || recovery_flow_key(&self.body.security_context) != *key
        {
            return Err(refused("refused semantic Input changed its native source"));
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn validate_joined_request(
        &self,
        joined: &FlowJoinRequest,
        snapshot: &FlowStateSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        validate_joined_body(&self.body, joined, snapshot)
    }
}

pub(super) fn authenticate_refused_input_origin(
    tx: &Transaction<'_>,
    observed: &SemanticInputObservation<'_>,
    verified: &SemanticSourceVerification,
    restriction_floor: &InformationLabel,
    status_floor: Option<&InformationLabel>,
) -> Result<SemanticRefusedInputOriginData, AdmissionOperationStoreError> {
    if !verified.input_refused || !matches!(verified.facts, SemanticSourceFacts::Input(_)) {
        return Err(refused("only refused semantic Input retains influence"));
    }
    let record = &verified.record;
    let scope = &record.invocation.action.scope;
    let selected_cut: i64 = tx
        .query_row(
            "SELECT coalesce(max(commit_sequence),0) FROM authority_global_commits",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let selected_cut = u64::try_from(selected_cut).map_err(refused)?;
    let mut source_label = restriction_floor.clone();
    if let Some(status) = status_floor {
        source_label = source_label.join_restrictions(status).map_err(refused)?;
    }
    let mut body = RefusedInputOriginBody {
        domain_version: VersionV1,
        operation: observed.operation.binding().operation_id().clone(),
        original_request: serde_json::from_slice(observed.original.canonical_bytes())
            .map_err(refused)?,
        native_authority: observed.binding.clone(),
        security_context: observed.context.clone(),
        input: observed.input.clone(),
        before: observed
            .before
            .ok_or_else(|| refused("refused semantic Input original source absent"))?
            .clone(),
        resolved: observed.resolved.clone(),
        invocation: record.invocation.clone(),
        route: record.route.clone(),
        contract: record.contract.clone(),
        installation: SourceRecord::load(
            tx,
            &format!("semantic-deployment:{}", scope_key(scope)?),
            scope,
            "deployment",
        )?,
        route_selection: SourceRecord::load(
            tx,
            &route_key(
                observed.binding,
                observed.context,
                record.route.server.as_str(),
                record.route.tool.as_str(),
            )?,
            scope,
            "deployment",
        )?,
        framing: FramingSources::load(tx, &record.invocation)?,
        audience: AudienceSources::load(tx, record.invocation.audience.body())?,
        annotations: source_records::selected_annotations(tx, &record.invocation)?,
        prior_influence: verified.prior_influence.clone(),
        selected_source_cut: SafeInteger::new(selected_cut).map_err(refused)?,
        observed_at_unix_ms: SafeInteger::new(observed.now).map_err(refused)?,
        source_label,
        externally_influenced: false,
        unknown: false,
    };
    let request = observed
        .classification
        .ok_or_else(|| refused("refused semantic Input original request callback absent"))?
        .request();
    let classification = classify_body(&body, request)?;
    if !classification.refused || classification.label != body.source_label {
        return Err(refused("refused semantic Input classification changed"));
    }
    body.externally_influenced = classification.external;
    body.unknown = classification.unknown;
    let canonical = CanonicalBytes::new(&body).map_err(refused)?;
    if canonical.is_empty() || canonical.len() > MAX_ORIGIN_BYTES {
        return Err(refused("refused semantic Input origin envelope exhausted"));
    }
    let influence = origin_influence(&canonical, &body);
    Ok(SemanticRefusedInputOriginData {
        body,
        canonical,
        influence,
    })
}

fn origin_influence(
    canonical: &CanonicalBytes,
    body: &RefusedInputOriginBody,
) -> ArtifactInfluenceV1 {
    ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            *RecoveryDigestDomain::SemanticNativeInputOrigin
                .digest(canonical)
                .as_bytes(),
        ),
        externally_influenced: body.externally_influenced,
        unknown: body.unknown,
    }
}

struct InputClassification {
    label: InformationLabel,
    external: bool,
    unknown: bool,
    refused: bool,
}

fn classify_body(
    body: &RefusedInputOriginBody,
    request: &ToolCallRequest,
) -> Result<InputClassification, AdmissionOperationStoreError> {
    let action = &body.invocation.action;
    let now = body.observed_at_unix_ms.get();
    let (_, inherited_external, mut unknown) = body.framing.influence_basis(
        &body.invocation,
        request,
        body.contract.external_influence,
        body.prior_influence.as_ref(),
    )?;
    if inherited_external && !action.externally_influenced {
        return Err(refused("refused semantic Input lost inherited influence"));
    }
    let mut external = action.externally_influenced || body.contract.external_influence;
    let mut label = action.source_label.clone();
    let current = body.audience.selected(body.invocation.audience.body())?;
    let mut refused_input = current != Some(&body.invocation.audience);
    if let Some(current) = current {
        let acl = current.body();
        acl.validate().map_err(refused)?;
        if semantic_key_digest(current.authority_key()).map_err(refused)? != body.route.resolver_key
            || !current.verify_signature().map_err(refused)?
        {
            return Err(refused("refused semantic Input current ACL authority"));
        }
        unknown |= acl.completeness != SemanticAudienceCompletenessV1::Complete
            || acl.observed_at_unix_ms.get() > now
            || acl.valid_until_unix_ms.get() <= now;
        if refused_input {
            label = label.join_restrictions(&acl.audience).map_err(refused)?;
        }
    } else {
        unknown = true;
    }
    if body.annotations.as_slice().len() != body.invocation.annotations.as_slice().len() {
        return Err(refused(
            "refused semantic Input annotation inventory changed",
        ));
    }
    let mut changed = false;
    let mut annotation_floor = InformationLabel::bottom();
    for (source, original) in body
        .annotations
        .as_slice()
        .iter()
        .zip(body.invocation.annotations.as_slice())
    {
        let current = &source.body;
        let annotation = current.body();
        annotation.validate().map_err(refused)?;
        let signer = semantic_key_digest(current.authority_key()).map_err(refused)?;
        let authority = body
            .route
            .annotators
            .as_slice()
            .iter()
            .find(|authority| authority.key == signer)
            .ok_or_else(|| refused("refused semantic Input annotator no longer selected"))?;
        if signer != semantic_key_digest(original.authority_key()).map_err(refused)?
            || annotation.scope != action.scope
            || annotation.input != original.body().input
            || !current.verify_signature().map_err(refused)?
            || annotation.issued_at_unix_ms.get() > now
            || annotation.valid_until_unix_ms.get() <= now
            || (!annotation.facts.as_slice().is_empty() && !authority.may_attest_facts)
            || !annotation
                .facts
                .as_slice()
                .iter()
                .all(|fact| authority.facts.as_slice().contains(fact))
        {
            return Err(refused(
                "refused semantic Input selected annotation authority",
            ));
        }
        changed |= current != original;
        external |= annotation.externally_influenced;
        annotation_floor = annotation_floor
            .join_restrictions(&annotation.restrictions)
            .map_err(refused)?;
    }
    unknown |= body.route.annotators.as_slice().iter().any(|authority| {
        action.inputs.as_slice().iter().any(|input| {
            !body.annotations.as_slice().iter().any(|source| {
                semantic_key_digest(source.body.authority_key())
                    .is_ok_and(|key| key == authority.key)
                    && source.body.body().input == *input
            })
        })
    });
    if changed {
        refused_input = true;
        label = label
            .join_restrictions(&annotation_floor)
            .map_err(refused)?;
    }
    if action.output == SemanticOutputDispositionV1::Withhold {
        if let Some(status) = &body.contract.withheld_status {
            label = label.join_restrictions(&status.audience).map_err(refused)?;
        } else {
            unknown = true;
        }
    }
    Ok(InputClassification {
        label,
        external,
        unknown,
        refused: refused_input,
    })
}

fn validate_joined_body(
    body: &RefusedInputOriginBody,
    joined: &FlowJoinRequest,
    snapshot: &FlowStateSnapshot,
) -> Result<(), AdmissionOperationStoreError> {
    let mut expected = body.resolved.clone();
    expected.principal_join = expected
        .principal_join
        .join_restrictions(&body.source_label)
        .map_err(refused)?;
    expected.lineage_join = expected
        .lineage_join
        .join_restrictions(&body.source_label)
        .map_err(refused)?;
    expected.session_join = expected
        .session_join
        .join_restrictions(&body.source_label)
        .map_err(refused)?;
    body.input
        .validate_resolution(&body.operation, joined, snapshot)?;
    // Independent full keys share the native tenant generation allocator.
    // This data check requires advancement from the original context; the
    // owning native join and authenticated history bind the exact generation.
    if expected != *joined || snapshot.context_generation <= body.before.context_generation {
        return Err(refused(
            "refused semantic Input final journal source changed",
        ));
    }
    Ok(())
}
