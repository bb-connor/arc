//! Pure index data controls complement the owning native custody regressions.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn reference() -> Result<ArtifactVersionRefV1, Box<dyn std::error::Error>> {
    Ok(ArtifactVersionRefV1 {
        scope: RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("reference-domain")?,
            tenant_id: RecoveryTenantId::new("reference-tenant")?,
            process_id: ProcessId::new("reference-process")?,
        },
        artifact: ArtifactId::new("reference-artifact")?,
        version: ArtifactRevisionId::new("reference-version")?,
        provenance: ProvenanceDigest::from_bytes([1; 32]),
    })
}

fn anchor(scope: &RecoveryScopeV1) -> Result<SourceAnchor, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(serde_json::json!({
        "record_key":"knowledge-source:reference-data-control",
        "scope_key":scope_key(scope)?,
        "kind":"command",
        "version":1,
        "digest":vec![1_u8;32],
        "event_sequence":1,
        "global_commit_sequence":1
    }))?)
}

fn regular() -> Result<ReferenceAggregate, Box<dyn std::error::Error>> {
    let reference = reference()?;
    let inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(vec![])?,
    };
    Ok(ReferenceAggregate {
        schema: ReferenceSchema::V1,
        baseline: ReferenceBaseline {
            source: ReferenceBaselineSource::NewArtifact {
                source: anchor(&reference.scope)?,
            },
            active_owners: SafeInteger::ZERO,
            next_bucket: SafeInteger::new(1)?,
            inventory: inventory.clone(),
        },
        reference,
        accepted: SafeInteger::ZERO,
        retired: SafeInteger::ZERO,
        rebuilds: SafeInteger::ZERO,
        active_owners: SafeInteger::ZERO,
        next_bucket: SafeInteger::new(1)?,
        inventory,
    })
}

fn overflow() -> Result<ReferenceAggregate, Box<dyn std::error::Error>> {
    let mut aggregate = regular()?;
    let cohort = CanonicalPayloadDigest::from_bytes([2; 32]);
    let census = CanonicalPayloadDigest::from_bytes([3; 32]);
    let inventory = ReferenceInventory::LegacyOverflow { cohort, census };
    aggregate.baseline.source = ReferenceBaselineSource::Cold {
        cutoff: serde_json::from_value(serde_json::json!({
            "sequence":1,"chain_digest":vec![4_u8;32]
        }))?,
        cohort_digest: cohort,
        census_digest: census,
    };
    aggregate.baseline.active_owners = SafeInteger::new(4097)?;
    aggregate.baseline.inventory = inventory.clone();
    aggregate.active_owners = aggregate.baseline.active_owners;
    aggregate.inventory = inventory;
    Ok(aggregate)
}

#[test]
fn reference_identity_includes_full_provenance_and_logical_owner() -> TestResult {
    let first = reference()?;
    let mut second = first.clone();
    second.provenance = ProvenanceDigest::from_bytes([2; 32]);
    assert_ne!(reference_identity(&first)?, reference_identity(&second)?);
    let owner = ReferenceOwner::ProductReport {
        scope: first.scope.clone(),
        id: EvidenceRef::new("retained-report")?,
        digest: CommandDigest::from_bytes([3; 32]),
    };
    assert_ne!(
        owner.identity(reference_identity(&first)?)?,
        owner.identity(reference_identity(&second)?)?
    );
    let mut other_scope = first.scope.clone();
    other_scope.process_id = ProcessId::new("different-owning-process")?;
    let other = ReferenceOwner::ProductReport {
        scope: other_scope,
        id: EvidenceRef::new("retained-report")?,
        digest: CommandDigest::from_bytes([3; 32]),
    };
    assert_ne!(
        owner.identity(reference_identity(&first)?)?,
        other.identity(reference_identity(&first)?)?
    );
    Ok(())
}

#[test]
fn more_than_one_bucket_keeps_the_complete_regular_count() -> TestResult {
    let mut aggregate = regular()?;
    aggregate.accepted = SafeInteger::new(66)?;
    aggregate.active_owners = aggregate.accepted;
    aggregate.next_bucket = SafeInteger::new(3)?;
    aggregate.inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(vec![SafeInteger::new(1)?, SafeInteger::new(2)?])?,
    };
    aggregate.validate(67)?;
    assert_eq!(aggregate.collection_count()?, 66);
    assert!(aggregate.validate(66).is_err());
    let first = aggregate.original()?;
    first.validate(1)?;
    assert_eq!(first.active_owners.get(), 0);
    assert_eq!(first.next_bucket.get(), 1);
    aggregate.inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(vec![SafeInteger::new(1)?])?,
    };
    assert!(aggregate.validate(67).is_err());
    Ok(())
}

#[test]
fn ordinary_inventory_cannot_be_reclassified_as_legacy_overflow() -> TestResult {
    let mut aggregate = regular()?;
    aggregate.inventory = ReferenceInventory::LegacyOverflow {
        cohort: CanonicalPayloadDigest::from_bytes([2; 32]),
        census: CanonicalPayloadDigest::from_bytes([3; 32]),
    };
    assert!(aggregate.validate(1).is_err());
    Ok(())
}

#[test]
fn drained_overflow_still_requires_a_fenced_rebuild() -> TestResult {
    let mut aggregate = overflow()?;
    aggregate.validate(1)?;
    aggregate.retired = SafeInteger::new(4097)?;
    aggregate.active_owners = SafeInteger::ZERO;
    aggregate.validate(4098)?;
    assert!(aggregate.collection_count().is_err());
    aggregate.inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(vec![])?,
    };
    assert!(aggregate.validate(4098).is_err());
    aggregate.rebuilds = SafeInteger::new(1)?;
    aggregate.validate(4099)?;
    assert_eq!(aggregate.collection_count()?, 0);
    assert_eq!(aggregate.original()?.baseline.active_owners.get(), 4097);
    Ok(())
}

#[test]
fn legacy_overflow_counter_cannot_admit_a_new_owner_or_change_its_census() -> TestResult {
    let mut aggregate = overflow()?;
    aggregate.accepted = SafeInteger::new(1)?;
    aggregate.active_owners = SafeInteger::new(4098)?;
    assert!(aggregate.validate(2).is_err());
    aggregate = overflow()?;
    aggregate.inventory = ReferenceInventory::LegacyOverflow {
        cohort: CanonicalPayloadDigest::from_bytes([2; 32]),
        census: CanonicalPayloadDigest::from_bytes([5; 32]),
    };
    assert!(aggregate.validate(1).is_err());
    Ok(())
}

#[test]
fn source_anchor_equal_version_requires_the_exact_original_tuple() -> TestResult {
    let source = anchor(&reference()?.scope)?;
    assert!(source.not_after(&source));
    for field in ["digest", "event_sequence", "global_commit_sequence"] {
        let mut encoded = serde_json::to_value(&source)?;
        encoded[field] = if field == "digest" {
            serde_json::json!(vec![2_u8; 32])
        } else {
            serde_json::json!(2)
        };
        let changed = serde_json::from_value(encoded)?;
        assert!(
            !source.not_after(&changed),
            "same-version source changed {field}"
        );
    }
    let mut encoded = serde_json::to_value(&source)?;
    encoded["version"] = serde_json::json!(2);
    encoded["event_sequence"] = serde_json::json!(2);
    encoded["global_commit_sequence"] = serde_json::json!(2);
    let advanced = serde_json::from_value(encoded)?;
    assert!(source.not_after(&advanced));
    Ok(())
}

#[test]
fn product_reference_owner_preserves_full_source_scope_across_processes() -> TestResult {
    let reference = reference()?;
    let mut scope = reference.scope.clone();
    scope.process_id = ProcessId::new("report-owning-process")?;
    let mut leaf = ReferenceLeaf {
        schema: ReferenceSchema::V1,
        reference,
        owner: ReferenceOwner::ProductReport {
            scope: scope.clone(),
            id: EvidenceRef::new("retained-report")?,
            digest: CommandDigest::from_bytes([3; 32]),
        },
        original: anchor(&scope)?,
        location: ReferenceLocation::Bucket {
            bucket: SafeInteger::new(1)?,
        },
        state: ReferenceOwnerState::Active,
        retirement: None,
    };
    leaf.validate(1)?;
    leaf.original = anchor(&leaf.reference.scope)?;
    assert!(leaf.validate(1).is_err());
    Ok(())
}

#[test]
fn ordinary_sources_enforce_key_and_cross_language_counter_limits() -> TestResult {
    let mut value = serde_json::to_value(anchor(&reference()?.scope)?)?;
    value["record_key"] = serde_json::json!("k".repeat(512));
    let source: SourceAnchor = serde_json::from_value(value.clone())?;
    source.validate_ordinary()?;
    value["record_key"] = serde_json::json!("k".repeat(513));
    let legacy: SourceAnchor = serde_json::from_value(value.clone())?;
    legacy.validate()?;
    assert!(legacy.validate_ordinary().is_err());
    value["record_key"] = serde_json::json!("k".repeat(512));
    for field in ["version", "event_sequence", "global_commit_sequence"] {
        let mut boundary = value.clone();
        boundary[field] = serde_json::json!(SafeInteger::MAX);
        serde_json::from_value::<SourceAnchor>(boundary.clone())?.validate_ordinary()?;
        boundary[field] = serde_json::json!(SafeInteger::MAX + 1);
        assert!(serde_json::from_value::<SourceAnchor>(boundary)?
            .validate_ordinary()
            .is_err());
    }
    Ok(())
}

#[test]
fn ordinary_reference_slots_cover_the_bounded_encoded_rows() -> TestResult {
    let text = "i".repeat(chio_security_types::recovery::MAX_RECOVERY_IDENTIFIER_BYTES);
    let reference = ArtifactVersionRefV1 {
        scope: RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new(&text)?,
            tenant_id: RecoveryTenantId::new(&text)?,
            process_id: ProcessId::new(&text)?,
        },
        artifact: ArtifactId::new(&text)?,
        version: ArtifactRevisionId::new(&text)?,
        provenance: ProvenanceDigest::from_bytes([255; 32]),
    };
    // Canonical JSON can expand every source-key byte into a six-byte escape.
    // These are descriptive bounds; they do not construct native source proof.
    let source: SourceAnchor = serde_json::from_value(serde_json::json!({
        "record_key":"\u{0001}".repeat(512),
        "scope_key":scope_key(&reference.scope)?,
        "kind":"command",
        "version":SafeInteger::MAX-1,
        "digest":vec![255_u8;32],
        "event_sequence":SafeInteger::MAX-1,
        "global_commit_sequence":SafeInteger::MAX-1
    }))?;
    source.validate_ordinary()?;
    let mut terminal = serde_json::to_value(&source)?;
    for field in ["version", "event_sequence", "global_commit_sequence"] {
        terminal[field] = serde_json::json!(SafeInteger::MAX);
    }
    let leaf = ReferenceLeaf {
        schema: ReferenceSchema::V1,
        reference: reference.clone(),
        owner: ReferenceOwner::LegacyPinSource {
            scope: reference.scope.clone(),
            original: source.clone(),
        },
        original: source.clone(),
        location: ReferenceLocation::LegacyCohort {
            cohort: CanonicalPayloadDigest::from_bytes([255; 32]),
            census: CanonicalPayloadDigest::from_bytes([255; 32]),
        },
        state: ReferenceOwnerState::Retired,
        retirement: Some(serde_json::from_value(terminal)?),
    };
    leaf.validate(2)?;
    let owners = (192_u8..=255)
        .map(|first| {
            let mut bytes = [255; 32];
            bytes[0] = first;
            CanonicalPayloadDigest::from_bytes(bytes)
        })
        .collect::<Vec<_>>();
    let bucket = ReferenceBucket {
        schema: ReferenceSchema::V1,
        reference: reference.clone(),
        bucket: SafeInteger::new(SafeInteger::MAX - 1)?,
        state: BucketState::Active,
        owners: BoundedList::new(owners)?,
    };
    bucket.validate()?;
    let empty = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(vec![])?,
    };
    let aggregate = ReferenceAggregate {
        schema: ReferenceSchema::V1,
        reference,
        baseline: ReferenceBaseline {
            source: ReferenceBaselineSource::NewArtifact { source },
            active_owners: SafeInteger::ZERO,
            next_bucket: SafeInteger::new(1)?,
            inventory: empty,
        },
        accepted: SafeInteger::new(4096)?,
        retired: SafeInteger::ZERO,
        rebuilds: SafeInteger::ZERO,
        active_owners: SafeInteger::new(4096)?,
        next_bucket: SafeInteger::new(SafeInteger::MAX)?,
        inventory: ReferenceInventory::Regular {
            active_buckets: BoundedList::new(
                (SafeInteger::MAX - 64..SafeInteger::MAX)
                    .map(SafeInteger::new)
                    .collect::<Result<Vec<_>, _>>()?,
            )?,
        },
    };
    aggregate.validate(4097)?;
    for (kind, payload) in [
        ("owner", protected::encode(&leaf)?),
        ("bucket", protected::encode(&bucket)?),
        ("aggregate", protected::encode(&aggregate)?),
    ] {
        assert!(
            payload.len() <= 16_384,
            "{kind} exceeds its reserved reference slot: {} bytes",
            payload.len()
        );
    }
    Ok(())
}
