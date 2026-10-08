//! Fresh native observations borrow their real writer and immutable source.
use super::*;
use crate::admission_operation_store::projection::native_status::AuthenticatedNativeStatusAppend;
use crate::serving_owner::NativeSourceTransactionOrigin;
use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
use chio_security_types::knowledge::ArtifactInfluenceV1;
use chio_security_types::recovery::{CanonicalPayloadDigest, SafeInteger};

/// Serialized source identity is data. Decoding it cannot create an append
/// witness, a phase allocation, current custody or an effect permission.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum NativeInfluenceReference {
    Output {
        operation: AdmissionOperationId,
        sequence: SafeInteger,
        record_digest: AdmissionDigest,
        global_commit_sequence: SafeInteger,
    },
    Status {
        operation: AdmissionOperationId,
        terminal_version: SafeInteger,
        incident: AdmissionIdentifier,
        projection_digest: AdmissionDigest,
        global_commit_sequence: SafeInteger,
        capture_global_commit_sequence: SafeInteger,
    },
    Artifact {
        record_key: String,
        record_digest: CanonicalPayloadDigest,
        event_sequence: SafeInteger,
        global_commit_sequence: SafeInteger,
    },
}

enum CommittedSource<'tx, 'conn> {
    Output {
        operation: AdmissionOperationId,
        origin: NativeSourceTransactionOrigin<'tx>,
    },
    Status(AuthenticatedNativeStatusAppend<'tx, 'conn>),
    Artifact {
        reference: protected::ProtectedSourceReference,
        sequence: u64,
        origin: NativeSourceTransactionOrigin<'tx>,
    },
}

/// This source authorizes no writes. A separate phase owner must preserve all
/// physical liabilities before it can retain the exact source observation.
pub(super) struct CommittedNativeInfluenceSource<'tx, 'conn> {
    tx: &'tx Transaction<'conn>,
    owner: &'tx SqliteServingOwner,
    source: CommittedSource<'tx, 'conn>,
    native_authority: NativeSecurityAuthorityBindingV1,
    key: FlowStateKey,
    reference: NativeInfluenceReference,
    influence: ArtifactInfluenceV1,
    source_label: InformationLabel,
}

impl<'tx, 'conn> CommittedNativeInfluenceSource<'tx, 'conn> {
    pub(super) fn output(
        tx: &'tx Transaction<'conn>,
        owner: &'tx SqliteServingOwner,
        origin: &NativeSourceTransactionOrigin<'tx>,
        operation: &AdmissionOperationId,
    ) -> Result<Self, AdmissionOperationStoreError> {
        verify_origin(tx, owner, origin)?;
        let data = output_data(tx, owner, operation)?;
        require_fresh(&data.reference, origin)?;
        Ok(Self {
            tx,
            owner,
            source: CommittedSource::Output {
                operation: operation.clone(),
                origin: origin.fork_for_source(),
            },
            native_authority: data.binding,
            key: data.key,
            reference: data.reference,
            influence: data.influence,
            source_label: data.label,
        })
    }

    pub(super) fn status(
        tx: &'tx Transaction<'conn>,
        owner: &'tx SqliteServingOwner,
        append: AuthenticatedNativeStatusAppend<'tx, 'conn>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        append.verify(tx)?;
        if !append.matches_owner(owner) {
            return Err(invalid(
                "native status observation changed its exact writer",
            ));
        }
        let data = status_data(&append)?;
        if data.binding.store_uuid().as_str() != owner.fence.store_uuid {
            return Err(invalid("native status observation changed its real owner"));
        }
        super::super::super::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
        Ok(Self {
            tx,
            owner,
            source: CommittedSource::Status(append),
            native_authority: data.binding,
            key: data.key,
            reference: data.reference,
            influence: data.influence,
            source_label: data.label,
        })
    }

    pub(super) fn artifact(
        tx: &'tx Transaction<'conn>,
        owner: &'tx SqliteServingOwner,
        origin: &NativeSourceTransactionOrigin<'tx>,
        binding: &NativeSecurityAuthorityBindingV1,
        sequence: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        verify_origin(tx, owner, origin)?;
        let (data, reference) = artifact_data(tx, owner, binding, sequence)?;
        require_fresh(&data.reference, origin)?;
        Ok(Self {
            tx,
            owner,
            source: CommittedSource::Artifact {
                reference,
                sequence,
                origin: origin.fork_for_source(),
            },
            native_authority: data.binding,
            key: data.key,
            reference: data.reference,
            influence: data.influence,
            source_label: data.label,
        })
    }

    pub(super) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(&**self.tx, &**tx) {
            return Err(invalid("native influence source changed its transaction"));
        }
        let data = match &self.source {
            CommittedSource::Output { operation, origin } => {
                verify_origin(tx, self.owner, origin)?;
                let data = output_data(tx, self.owner, operation)?;
                require_fresh(&data.reference, origin)?;
                data
            }
            CommittedSource::Status(append) => {
                append.verify(tx)?;
                status_data(append)?
            }
            CommittedSource::Artifact {
                reference,
                sequence,
                origin,
            } => {
                verify_origin(tx, self.owner, origin)?;
                protected::verify_source_reference(tx, reference)?;
                let (data, _) = artifact_data(tx, self.owner, &self.native_authority, *sequence)?;
                require_fresh(&data.reference, origin)?;
                data
            }
        };
        if data.binding != self.native_authority
            || data.key != self.key
            || data.reference != self.reference
            || data.influence != self.influence
            || data.label != self.source_label
        {
            return Err(invalid(
                "native influence changed its exact committed source",
            ));
        }
        Ok(())
    }

    pub(super) fn native_authority(&self) -> &NativeSecurityAuthorityBindingV1 {
        &self.native_authority
    }

    pub(super) fn key(&self) -> &FlowStateKey {
        &self.key
    }

    pub(super) fn reference(&self) -> &NativeInfluenceReference {
        &self.reference
    }

    pub(super) fn influence(&self) -> &ArtifactInfluenceV1 {
        &self.influence
    }

    pub(super) fn source_label(&self) -> &InformationLabel {
        &self.source_label
    }
}

struct SourceData {
    binding: NativeSecurityAuthorityBindingV1,
    key: FlowStateKey,
    reference: NativeInfluenceReference,
    influence: ArtifactInfluenceV1,
    label: InformationLabel,
}

fn verify_origin(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    origin: &NativeSourceTransactionOrigin<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    origin.verify(tx).map_err(map_owner_error)?;
    if !origin.matches_owner(owner) {
        return Err(invalid("native influence source changed its actual writer"));
    }
    super::super::super::schema::verify_active_owner(tx, owner, Some(&owner.fence))
}

fn require_fresh(
    reference: &NativeInfluenceReference,
    origin: &NativeSourceTransactionOrigin<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let sequence = match reference {
        NativeInfluenceReference::Output {
            global_commit_sequence,
            ..
        }
        | NativeInfluenceReference::Status {
            global_commit_sequence,
            ..
        }
        | NativeInfluenceReference::Artifact {
            global_commit_sequence,
            ..
        } => global_commit_sequence.get(),
    };
    if sequence <= origin.prepared_global_sequence() {
        return Err(invalid("historical influence data is not a fresh append"));
    }
    Ok(())
}

fn output_data(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation_id: &AdmissionOperationId,
) -> Result<SourceData, AdmissionOperationStoreError> {
    let record = super::super::output::load_operation(tx, operation_id)?
        .ok_or_else(|| invalid("native influence output source is absent"))?;
    let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    let original = super::super::super::retained_request::load_retained_request_tx(tx, &operation)?
        .ok_or_else(|| invalid("native influence output original is absent"))?;
    let binding = original
        .native_security_authority_binding()
        .ok_or_else(|| invalid("native influence output lost its native binding"))?
        .clone();
    if binding.store_uuid().as_str() != owner.fence.store_uuid
        || record.authority != *binding.security_authority_id()
        || record.initialization != binding.initialization_digest().as_str()
        || record.intent.operation_id() != operation_id
    {
        return Err(invalid("native influence output source changed its owner"));
    }
    let digest = AdmissionDigest::try_new("native_influence_output", record.digest()?)?;
    let mut statement = tx
        .prepare(
            "SELECT commit_sequence FROM authority_global_commits
         WHERE projection_kind='security_participant_output' AND projection_key=?1
           AND projection_sequence=?2 AND mutation_kind='join_security_participant_output'
           AND projection_reference_digest=?3 AND store_uuid=?4
           AND store_lease_id=?5 AND store_owner_epoch=?6 LIMIT 2",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            binding.security_authority_id().as_str(),
            i64::try_from(record.sequence).map_err(invalid)?,
            digest.as_str(),
            record.lease.fence.store_uuid,
            record.lease.fence.lease_id,
            i64::try_from(record.lease.fence.owner_epoch).map_err(invalid)?
        ])
        .map_err(sqlite_error)?;
    let sequence: i64 = rows
        .next()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("native output lost its owning global source"))?
        .get(0)
        .map_err(sqlite_error)?;
    if rows.next().map_err(sqlite_error)?.is_some() {
        return Err(invalid("native output has ambiguous owning global sources"));
    }
    let reference = NativeInfluenceReference::Output {
        operation: operation_id.clone(),
        sequence: SafeInteger::new(record.sequence).map_err(invalid)?,
        record_digest: digest,
        global_commit_sequence: SafeInteger::new(u64::try_from(sequence).map_err(invalid)?)
            .map_err(invalid)?,
    };
    let semantic = super::super::super::semantic::output::authenticated_native_output_influence(
        tx, &operation, &original, &binding,
    )?;
    let influence = match &semantic {
        Some(data) => data.influence().clone(),
        None => unclassified_influence(&binding, &record.request.key, &reference)?,
    };
    if semantic
        .as_ref()
        .is_some_and(|data| !data.output_label().flows_to(&record.request.principal_join))
    {
        return Err(invalid(
            "native output source lost its authenticated restriction floor",
        ));
    }
    Ok(SourceData {
        binding,
        key: record.request.key,
        reference,
        influence,
        label: record.request.principal_join,
    })
}

fn status_data(
    append: &AuthenticatedNativeStatusAppend<'_, '_>,
) -> Result<SourceData, AdmissionOperationStoreError> {
    let source = append.source();
    source.verify(source.transaction())?;
    let reference = NativeInfluenceReference::Status {
        operation: source.operation().binding().operation_id().clone(),
        terminal_version: SafeInteger::new(source.terminal_version()).map_err(invalid)?,
        incident: source.incident_id().clone(),
        projection_digest: source.projection_digest().clone(),
        global_commit_sequence: SafeInteger::new(source.global_commit_sequence())
            .map_err(invalid)?,
        capture_global_commit_sequence: SafeInteger::new(source.capture_global_commit_sequence())
            .map_err(invalid)?,
    };
    let semantic =
        super::super::super::semantic::status::authenticated_native_status_influence(source)?;
    let influence = match &semantic {
        Some(data) => data.influence().clone(),
        None => unclassified_influence(source.native_binding(), source.key(), &reference)?,
    };
    Ok(SourceData {
        binding: source.native_binding().clone(),
        key: source.key().clone(),
        reference,
        influence,
        label: semantic.map_or(InformationLabel::Top, |data| data.source_label().clone()),
    })
}

fn artifact_data(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    binding: &NativeSecurityAuthorityBindingV1,
    sequence: u64,
) -> Result<(SourceData, protected::ProtectedSourceReference), AdmissionOperationStoreError> {
    if binding.store_uuid().as_str() != owner.fence.store_uuid {
        return Err(invalid(
            "native artifact observation changed its serving owner",
        ));
    }
    let initialized = super::super::records::load_current_metadata(tx, binding)?;
    let (record, digest) =
        load_with_digest(tx, binding.security_authority_id().as_str(), sequence)?;
    if record.initialization != initialized.digest {
        return Err(invalid(
            "native artifact observation changed its initialization",
        ));
    }
    let key = record_key(binding.security_authority_id().as_str(), sequence);
    let protected = protected::source_reference(tx, &key)?;
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(digest, &mut bytes).map_err(invalid)?;
    let reference = NativeInfluenceReference::Artifact {
        record_key: key,
        record_digest: CanonicalPayloadDigest::from_bytes(bytes),
        event_sequence: SafeInteger::new(protected.event_sequence()).map_err(invalid)?,
        global_commit_sequence: SafeInteger::new(protected.global_commit_sequence())
            .map_err(invalid)?,
    };
    Ok((
        SourceData {
            binding: binding.clone(),
            key: record.request.key,
            reference,
            influence: record.release.influence,
            label: record.release.source_label,
        },
        protected,
    ))
}

fn unclassified_influence(
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    reference: &NativeInfluenceReference,
) -> Result<ArtifactInfluenceV1, AdmissionOperationStoreError> {
    Ok(ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeSemanticInfluence,
                &("native-unclassified-source-v1", binding, key, reference),
            )
            .map_err(invalid)?,
        ),
        externally_influenced: false,
        unknown: true,
    })
}
