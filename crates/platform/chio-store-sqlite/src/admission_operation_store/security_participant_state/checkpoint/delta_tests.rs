//! Delta folds and seal planning over in-memory records and images.
use super::*;
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_invariant(result: Result<(), AdmissionOperationStoreError>, reason: &str) {
    match result {
        Err(AdmissionOperationStoreError::Invariant(detail)) => {
            assert_eq!(detail, format!("native security state: {reason}"));
        }
        other => panic!("expected invariant {reason:?}, got {other:?}"),
    }
}

fn record(sequence: u64, delta: Option<Delta>) -> Result<Record, AdmissionOperationStoreError> {
    Ok(Record {
        schema: Record::format(delta.is_some()),
        authority: AdmissionIdentifier::try_new("authority", "delta-unit")?,
        sequence,
        initialization: "1".repeat(64),
        previous: "1".repeat(64),
        global_sequence: 1,
        global_digest: "2".repeat(64),
        fence: StoreMutationFence {
            store_uuid: "delta-store".into(),
            lease_id: "delta-lease".into(),
            owner_epoch: 1,
        },
        observed_at: 1,
        heads: [1, 0, 0, 0].map(|sequence| FamilyHead {
            sequence,
            digest: "1".repeat(64),
        }),
        tables: Vec::new(),
        current_rows: 0,
        current_bytes: 0,
        segment_events: 0,
        segment_bytes: 0,
        delta,
    })
}

fn tombstone(row: &[u8]) -> Tombstone {
    Tombstone {
        table: super::super::super::schema::TABLES[0].source.into(),
        digest: sha256_hex(row),
        encoded_bytes: row.len() as u64,
    }
}

fn delta(
    base: u64,
    chain: (u64, u64),
    removed: Vec<Tombstone>,
    added: &[&[u8]],
) -> Result<Delta, AdmissionOperationStoreError> {
    Ok(Delta {
        base,
        base_rows: 0,
        base_bytes: 0,
        chain_rows: chain.0,
        chain_bytes: chain.1,
        added_rows: added.len() as u64,
        added_bytes: added.iter().map(|row| row.len() as u64).sum(),
        added_digest: added_digest(added.iter().map(|row| (0, *row)))?,
        removed,
    })
}

fn step(
    sequence: u64,
    base: u64,
    chain: (u64, u64),
    removed: Vec<Tombstone>,
) -> Result<Record, AdmissionOperationStoreError> {
    record(sequence, Some(delta(base, chain, removed, &[])?))
}

fn keyframe() -> Result<(Chain, Image), AdmissionOperationStoreError> {
    let mut image = Image::new();
    image.insert(0, b"kept".to_vec())?;
    image.insert(0, b"removed".to_vec())?;
    Ok((Chain::start(&record(1, None)?)?, image))
}

fn image(rows: &[Vec<u8>]) -> Result<Image, AdmissionOperationStoreError> {
    let mut image = Image::new();
    for row in rows {
        image.insert(0, row.clone())?;
    }
    Ok(image)
}

fn keyframe_of(image: &Image) -> Result<Record, AdmissionOperationStoreError> {
    let mut keyframe = record(1, None)?;
    (keyframe.current_rows, keyframe.current_bytes) = image.totals();
    Ok(keyframe)
}

#[test]
fn delta_chain_applies_tombstones_then_adds() -> TestResult {
    let (mut chain, mut image) = keyframe()?;
    chain.apply(
        &mut image,
        &step(2, 1, (2, 12), vec![tombstone(b"removed")])?,
        vec![(0, b"added".to_vec())],
    )?;
    let rows = image
        .rows()
        .map(|(_, row)| row.to_vec())
        .collect::<BTreeSet<_>>();
    assert_eq!(rows, BTreeSet::from([b"kept".to_vec(), b"added".to_vec()]));
    assert_eq!(image.totals(), (2, 9));
    Ok(())
}

#[test]
fn delta_chain_refuses_mixed_base_missing_reordered_or_keyframe_steps() -> TestResult {
    let (mut chain, mut image) = keyframe()?;
    assert_invariant(
        chain.apply(&mut image, &step(2, 7, (1, 1), Vec::new())?, Vec::new()),
        "native checkpoint delta chain mixes keyframes",
    );
    let mut misstated = step(2, 1, (1, 1), Vec::new())?;
    if let Some(delta) = misstated.delta.as_mut() {
        delta.base_rows = 2;
    }
    assert_invariant(
        chain.apply(&mut image, &misstated, Vec::new()),
        "native checkpoint delta chain mixes keyframes",
    );
    assert_invariant(
        chain.apply(&mut image, &step(3, 1, (1, 1), Vec::new())?, Vec::new()),
        "native checkpoint delta chain is out of order",
    );
    chain.apply(&mut image, &step(2, 1, (1, 1), Vec::new())?, Vec::new())?;
    assert_invariant(
        chain.apply(&mut image, &step(2, 1, (2, 2), Vec::new())?, Vec::new()),
        "native checkpoint delta chain is out of order",
    );
    assert_invariant(
        chain.apply(&mut image, &record(3, None)?, Vec::new()),
        "native checkpoint delta chain crosses a keyframe",
    );
    assert_invariant(
        chain.apply(&mut image, &step(3, 1, (3, 2), Vec::new())?, Vec::new()),
        "native checkpoint delta chain size differs",
    );
    assert_invariant(
        chain.apply(&mut image, &step(3, 1, (2, 3), Vec::new())?, Vec::new()),
        "native checkpoint delta chain size differs",
    );
    Ok(())
}

#[test]
fn delta_chain_charges_an_empty_seal_one_row_and_one_byte() -> TestResult {
    let (mut chain, mut image) = keyframe()?;
    assert_invariant(
        chain.apply(&mut image, &step(2, 1, (0, 0), Vec::new())?, Vec::new()),
        "native checkpoint delta chain size differs",
    );
    chain.apply(&mut image, &step(2, 1, (1, 1), Vec::new())?, Vec::new())?;
    chain.apply(&mut image, &step(3, 1, (2, 2), Vec::new())?, Vec::new())?;
    assert_eq!(image.totals(), (2, 11));
    Ok(())
}

#[test]
fn delta_chain_refuses_duplicate_rows_and_unmatched_tombstones() -> TestResult {
    let (mut chain, mut image) = keyframe()?;
    assert_invariant(
        chain.apply(
            &mut image,
            &step(2, 1, (1, 4), Vec::new())?,
            vec![(0, b"kept".to_vec())],
        ),
        "native checkpoint image repeats a row",
    );
    let (mut chain, mut image) = keyframe()?;
    assert_invariant(
        chain.apply(
            &mut image,
            &step(2, 1, (1, 6), vec![tombstone(b"absent")])?,
            Vec::new(),
        ),
        "native checkpoint tombstone has no exact row",
    );
    let (mut chain, mut image) = keyframe()?;
    let mut short = tombstone(b"removed");
    short.encoded_bytes = 3;
    assert_invariant(
        chain.apply(&mut image, &step(2, 1, (1, 3), vec![short])?, Vec::new()),
        "native checkpoint tombstone length differs",
    );
    Ok(())
}

#[test]
fn delta_metadata_refuses_unordered_tombstones_and_late_bases() -> TestResult {
    let repeated = delta(
        1,
        (2, 14),
        vec![tombstone(b"removed"), tombstone(b"removed")],
        &[],
    )?;
    assert_invariant(
        repeated.validate(2, 4, 64),
        "native checkpoint tombstones are malformed",
    );
    let late = Delta {
        base: 2,
        ..delta(1, (1, 1), Vec::new(), &[])?
    };
    assert_invariant(
        late.validate(2, 4, 64),
        "native checkpoint delta metadata is malformed",
    );
    delta(1, (1, 1), Vec::new(), &[])?.validate(2, 4, 64)?;
    Ok(())
}

/// A persisted chain whose keyframe plus changes would read past twice the
/// image it commits to is refused before any row is read: a 10-row keyframe
/// and 9 tombstones leave one row but would read ten.
#[test]
fn delta_metadata_refuses_a_chain_past_the_row_budget() -> TestResult {
    let mut removed = (0..9_u8)
        .map(|index| tombstone(&[b'r', index]))
        .collect::<Vec<_>>();
    removed.sort_by(|left, right| left.digest.cmp(&right.digest));
    let mut overlong = delta(1, (9, 18), removed, &[])?;
    overlong.base_rows = 10;
    overlong.base_bytes = 20;
    assert_invariant(
        overlong.validate(2, 1, 2),
        "native checkpoint delta exceeds its read budget",
    );
    overlong.validate(2, 10, 20)?;
    Ok(())
}

#[test]
fn delta_metadata_refuses_a_chain_past_the_byte_budget() -> TestResult {
    let mut heavy = delta(1, (1, 4_000), Vec::new(), &[])?;
    heavy.base_rows = 4;
    heavy.base_bytes = 1_000;
    assert_invariant(
        heavy.validate(2, 4, 1_000),
        "native checkpoint delta exceeds its read budget",
    );
    heavy.chain_bytes = 1_000;
    heavy.validate(2, 4, 1_000)?;
    Ok(())
}

#[test]
fn delta_metadata_refuses_a_charge_larger_than_its_chain() -> TestResult {
    let undercharged = delta(1, (1, 1), Vec::new(), &[b"added-row"])?;
    assert_invariant(
        undercharged.validate(2, 8, 64),
        "native checkpoint delta exceeds its read budget",
    );
    let charged = delta(1, (1, 9), Vec::new(), &[b"added-row"])?;
    charged.validate(2, 8, 64)?;
    Ok(())
}

#[test]
fn added_digest_binds_table_order_and_length() -> TestResult {
    let digest = |rows: &[(usize, &str)]| {
        added_digest(rows.iter().map(|(table, row)| (*table, row.as_bytes())))
    };
    let committed = digest(&[(0, "first"), (1, "second")])?;
    assert_eq!(committed, digest(&[(0, "first"), (1, "second")])?);
    for altered in [
        digest(&[(0, "second"), (1, "first")])?,
        digest(&[(1, "first"), (1, "second")])?,
        digest(&[(0, "firs"), (1, "tsecond")])?,
        digest(&[(0, "first")])?,
    ] {
        assert_ne!(committed, altered);
    }
    Ok(())
}

#[test]
fn seal_plan_takes_a_keyframe_when_the_chain_reaches_the_row_budget() -> TestResult {
    let before = image(&[
        b"kept".to_vec(),
        b"removed".to_vec(),
        b"other-a".to_vec(),
        b"other-b".to_vec(),
    ])?;
    let after = image(&[
        b"kept".to_vec(),
        b"added".to_vec(),
        b"other-a".to_vec(),
        b"other-b".to_vec(),
    ])?;
    assert!(matches!(plan(None, &after)?, Seal::Keyframe));
    let base = keyframe_of(&before)?;
    let Seal::Delta { delta, added } = plan(Some((&base, &before)), &after)? else {
        return Err("small change stored a keyframe".into());
    };
    assert_eq!(
        (
            delta.base,
            delta.base_rows,
            delta.chain_rows,
            delta.chain_bytes,
            delta.removed.len()
        ),
        (1, 4, 2, 12, 1)
    );
    assert_eq!(added, vec![(0, b"added".to_vec())]);
    assert_eq!(
        delta.added_digest,
        added_digest([(0, b"added".as_slice())])?
    );
    let mut long = step(2, 1, (5, 12), Vec::new())?;
    if let Some(delta) = long.delta.as_mut() {
        (delta.base_rows, delta.base_bytes) = before.totals();
    }
    assert!(matches!(
        plan(Some((&long, &before)), &after)?,
        Seal::Keyframe
    ));
    Ok(())
}

/// Replacing a large row moves few rows but many bytes, so the byte budget
/// alone forces a keyframe.
#[test]
fn seal_plan_takes_a_keyframe_when_replaced_bytes_exceed_the_budget() -> TestResult {
    let before = image(&[b"kept".to_vec(), vec![b'a'; 1_000]])?;
    let after = image(&[b"kept".to_vec(), vec![b'b'; 1_000]])?;
    let base = keyframe_of(&before)?;
    assert!(matches!(
        plan(Some((&base, &before)), &after)?,
        Seal::Keyframe
    ));
    let small = image(&[b"kept".to_vec(), vec![b'a'; 1_000], b"x".to_vec()])?;
    assert!(matches!(
        plan(Some((&base, &before)), &small)?,
        Seal::Delta { .. }
    ));
    Ok(())
}

/// More removals than one record may carry force a keyframe; the largest
/// permitted burst still fits the canonical record bound.
#[test]
fn seal_plan_takes_a_keyframe_for_a_tombstone_burst() -> TestResult {
    let rows = (0..1_024_u32)
        .map(|index| format!("row-{index:04}").into_bytes())
        .collect::<Vec<_>>();
    let before = image(&rows)?;
    let base = keyframe_of(&before)?;
    let burst = image(&rows[MAX_TOMBSTONES + 1..])?;
    assert!(matches!(
        plan(Some((&base, &before)), &burst)?,
        Seal::Keyframe
    ));
    let largest = image(&rows[MAX_TOMBSTONES..])?;
    let Seal::Delta { delta, .. } = plan(Some((&base, &before)), &largest)? else {
        return Err("a permitted burst stored a keyframe".into());
    };
    assert_eq!(delta.removed.len(), MAX_TOMBSTONES);
    let mut sealed = record(2, Some(delta))?;
    sealed.tables = super::super::super::schema::TABLES
        .iter()
        .map(|table| rows::Fingerprint {
            table: table.source.into(),
            row_count: 65_536,
            encoded_bytes: 67_108_864,
            digest: "f".repeat(64),
        })
        .collect();
    let bytes = sealed.bytes()?.len();
    assert!(
        bytes < 65_536,
        "a {MAX_TOMBSTONES}-tombstone delta record is {bytes} bytes"
    );
    Ok(())
}
