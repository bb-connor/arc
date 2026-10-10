//! Private atom contracts; genuine chunks use the authenticated native writer.
use super::*;
use chio_security_types::{InformationLabel, PrincipalId};
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// This fixture isolates the private format gate. It does not claim a serving
// catalog, authenticated native state, or compatibility with an old binary.
fn format_fixture(version: i32) -> TestResult<rusqlite::Connection> {
    let connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch("CREATE TABLE admission_operations(id TEXT PRIMARY KEY);")?;
    crate::check_schema_version(
        &connection,
        crate::admission_operation_store::ADMISSION_OPERATION_SCHEMA_KEY,
        version,
        crate::admission_operation_store::ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )?;
    crate::stamp_schema_version(
        &connection,
        crate::admission_operation_store::ADMISSION_OPERATION_SCHEMA_KEY,
        version,
    )?;
    Ok(connection)
}

fn fixture_body(
    connection: &rusqlite::Connection,
    record: &RestoreRecord,
) -> TestResult<serde_json::Value> {
    if canonical(record)?.len() > 262_144 {
        require_restore_format(connection)?;
    }
    let bytes = logical_body(record)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn fixture_decode(
    connection: &rusqlite::Connection,
    bytes: &[u8],
) -> Result<RestoreRecord, AdmissionOperationStoreError> {
    // Only inline/Legacy paths are used by these data-only unit controls.
    // Real chunk roots authenticate their actual key/version in native tests.
    decode(connection, "format-only-unit-data", 1, bytes)
}

fn large_label(readers_per_owner: usize) -> TestResult<InformationLabel> {
    let mut owners = BTreeMap::new();
    for index in 0..4 {
        let owner = PrincipalId::new(format!("owner-{index}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..readers_per_owner {
            readers.insert(PrincipalId::new(format!(
                "reader-{index}-{reader:02}-{}",
                "r".repeat(238)
            ))?);
        }
        owners.insert(owner, readers);
    }
    Ok(InformationLabel::try_known(owners, BTreeSet::new())?)
}

fn record(label: InformationLabel) -> TestResult<RestoreRecord> {
    let scope = RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new("authority")?,
        tenant_id: RecoveryTenantId::new("tenant")?,
        process_id: ProcessId::new("process")?,
    };
    let artifact = ArtifactVersionRefV1 {
        scope: scope.clone(),
        artifact: ArtifactId::new("artifact")?,
        version: ArtifactRevisionId::new("revision")?,
        provenance: ProvenanceDigest::from_bytes([1; 32]),
    };
    let influence = ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes([2; 32]),
        externally_influenced: true,
        unknown: false,
    };
    let checkpoint = LabeledCheckpointV1 {
        domain_version: VersionV1,
        checkpoint: CheckpointId::new("job:1")?,
        revision: SafeInteger::new(7)?,
        scope: scope.clone(),
        runtime: ProtectedText::new("runtime")?,
        artifacts: NonEmptyBoundedList::new(vec![artifact.clone()])?,
        model_contexts: BoundedList::new(vec![])?,
        label: label.clone(),
        influence: influence.clone(),
        lineage: IsolationLineageId::new("lineage")?,
        isolation_epoch: ProtectedText::new("epoch")?,
        native_evidence_sequence: SafeInteger::new(11)?,
        policy: PolicyDigest::from_bytes([3; 32]),
    };
    let recipient = ArtifactRecipientV1 {
        recipient: ArtifactRecipientId::new("recipient")?,
        scope,
        runtime: checkpoint.runtime.clone(),
        principal: PrincipalId::new("agent")?,
        lineage: checkpoint.lineage.clone(),
        isolation_epoch: checkpoint.isolation_epoch.clone(),
        context_generation: SafeInteger::new(9)?,
        clearance: label.clone(),
        sink: ArtifactSinkV1::Agent,
    };
    let intent = ArtifactReleaseIntentV1 {
        domain_version: VersionV1,
        release: ReleaseId::new("release")?,
        kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
            request: RequestId::new("restore")?,
        },
        artifact,
        source_label: label.clone(),
        admitted_label: label,
        influence,
        recipient: recipient.clone(),
        policy: checkpoint.policy,
        authorization: ReleaseAuthorizationDigest::from_bytes([4; 32]),
        observation_transition: EvidenceRef::new("knowledge:release")?,
        observation_generation: SafeInteger::new(9)?,
        state: ArtifactDeliveryStateV1::Uncertain,
    };
    Ok(RestoreRecord {
        checkpoint,
        recipient,
        intent,
        actor_binding: Some(RestoreActorBinding {
            principal: PrincipalId::new("reviewer")?,
            authority_scope: AuthorityScopeDigest::from_bytes([5; 32]),
        }),
        installation_generation: Some(SafeInteger::new(3)?),
    })
}

#[test]
fn restore_encoding_preserves_exact_legacy_bytes_and_original_actor_custody() -> TestResult {
    let connection = format_fixture(40)?;
    for legacy_identity in [false, true] {
        let mut original = record(InformationLabel::bottom())?;
        if legacy_identity {
            original.actor_binding = None;
            original.installation_generation = None;
        }
        let expected = canonical(&original)?;
        let encoded = protected::encode(&fixture_body(&connection, &original)?)?;
        assert_eq!(encoded, expected);
        assert_eq!(
            canonical(&fixture_decode(&connection, &encoded)?)?,
            expected
        );
    }
    Ok(())
}

#[test]
fn restore_encoding_reconstructs_complete_large_checkpoint_and_owed_intent() -> TestResult {
    let connection = format_fixture(40)?;
    let original = record(large_label(60)?)?;
    assert!(canonical(&original.checkpoint)?.len() <= 65_536);
    assert!(canonical(&original)?.len() > 262_144);
    let encoded = protected::encode(&fixture_body(&connection, &original)?)?;
    assert!(encoded.len() <= 262_144);
    assert_eq!(
        canonical(&fixture_decode(&connection, &encoded)?)?,
        canonical(&original)?
    );
    Ok(())
}

#[test]
fn restore_encoding_refuses_noncanonical_or_unknown_label_references() -> TestResult {
    let connection = format_fixture(40)?;
    let mut original = record(large_label(60)?)?;
    let joined = large_label(59)?;
    assert!(original.checkpoint.label.flows_to(&joined));
    original.recipient.clearance = joined.clone();
    original.intent.admitted_label = joined;
    original.intent.recipient = original.recipient.clone();
    assert!(canonical(&original)?.len() > 262_144);
    let wire = serde_json::to_value(fixture_body(&connection, &original)?)?;
    let mut invalid = Vec::new();

    let mut unknown_index = wire.clone();
    unknown_index["checkpoint"]["label"] = serde_json::json!(255);
    invalid.push(unknown_index);
    let mut unused_label = wire.clone();
    unused_label["labels"]["values"]
        .as_array_mut()
        .ok_or("private label palette")?
        .push(serde_json::json!({"kind": "top"}));
    invalid.push(unused_label);
    let mut duplicate_label = wire.clone();
    let first = duplicate_label["labels"]["values"][0].clone();
    duplicate_label["labels"]["values"]
        .as_array_mut()
        .ok_or("private label palette")?
        .push(first);
    invalid.push(duplicate_label);

    let mut unknown_atom = wire.clone();
    unknown_atom["labels"]["policies"][0]["owner"] = serde_json::json!(u32::MAX);
    invalid.push(unknown_atom);
    let mut unknown_readers = wire.clone();
    unknown_readers["labels"]["policies"][0]["readers"] = serde_json::json!(u16::MAX);
    invalid.push(unknown_readers);
    let mut absent_self_reader = wire.clone();
    absent_self_reader["labels"]["readers"][0]["readers"] = serde_json::json!([]);
    invalid.push(absent_self_reader);
    let mut unused_atom = wire.clone();
    unused_atom["labels"]["atoms"]
        .as_array_mut()
        .ok_or("private atom table")?
        .push(serde_json::json!("unused-reader"));
    invalid.push(unused_atom);

    let mut reordered = wire.clone();
    reordered["labels"]["values"]
        .as_array_mut()
        .ok_or("private label palette")?
        .swap(0, 1);
    // Preserve the complete logical meaning while changing its private palette
    // order. The deterministic first-occurrence representation must refuse it.
    for pointer in [
        "/checkpoint/label",
        "/recipient/clearance",
        "/intent/source_label",
        "/intent/admitted_label",
        "/intent/recipient/clearance",
    ] {
        let value = reordered.pointer_mut(pointer).ok_or("label reference")?;
        let index = value.as_u64().ok_or("label index")?;
        *value = serde_json::json!(1u64.checked_sub(index).ok_or("label permutation")?);
    }
    invalid.push(reordered);

    for marker in [
        serde_json::Value::Null,
        serde_json::json!("future_encoding"),
    ] {
        let mut unknown_format = wire.clone();
        unknown_format["checkpoint_restore_encoding"] = marker;
        invalid.push(unknown_format);
    }
    let mut unknown_field = wire;
    unknown_field["unverified_authority"] = serde_json::json!(true);
    invalid.push(unknown_field);
    for forged in invalid {
        assert!(fixture_decode(&connection, &protected::encode(&forged)?).is_err());
    }
    Ok(())
}

#[test]
fn restore_encoding_refuses_compact_emission_and_decode_under_predecessor_format() -> TestResult {
    let current = format_fixture(40)?;
    let original = record(large_label(60)?)?;
    let encoded = protected::encode(&fixture_body(&current, &original)?)?;
    let predecessor = format_fixture(39)?;
    let changes = predecessor.total_changes();
    assert!(fixture_body(&predecessor, &original).is_err());
    assert!(fixture_decode(&predecessor, &encoded).is_err());
    assert_eq!(predecessor.total_changes(), changes);
    let legacy = record(InformationLabel::bottom())?;
    let legacy_bytes = canonical(&legacy)?;
    assert_eq!(
        canonical(&fixture_decode(&predecessor, &legacy_bytes)?)?,
        legacy_bytes
    );
    assert_eq!(predecessor.total_changes(), changes);
    Ok(())
}

#[test]
fn restore_encoding_refuses_compact_wire_for_small_logical_records() -> TestResult {
    let connection = format_fixture(40)?;
    let small = record(InformationLabel::bottom())?;
    assert!(canonical(&small)?.len() <= 262_144);
    let compact = CompactRestoreRecord::capture(&small)?;
    let bytes = protected::encode(&compact)?;
    assert!(fixture_decode(&connection, &bytes).is_err());
    assert_eq!(
        protected::encode(&fixture_body(&connection, &small)?)?,
        canonical(&small)?
    );
    Ok(())
}

#[test]
fn restore_encoding_refuses_future_database_floor_without_mutation() -> TestResult {
    let current = format_fixture(40)?;
    let original = record(large_label(60)?)?;
    let bytes = protected::encode(&fixture_body(&current, &original)?)?;
    let future = format_fixture(41)?;
    let changes = future.total_changes();
    assert!(fixture_body(&future, &original).is_err());
    assert!(fixture_decode(&future, &bytes).is_err());
    assert_eq!(future.total_changes(), changes);
    Ok(())
}
