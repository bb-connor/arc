//! Actual image scans remain authenticated with the cost observer installed.
use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Images {
    walks: Mutex<Vec<(&'static str, u64)>>,
}

impl Images {
    fn observe(&self, kind: &'static str, visited: u64) {
        let mut walks = self
            .walks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if visited == 0 {
            walks.push((kind, 0));
        } else {
            let walk = walks
                .last_mut()
                .unwrap_or_else(|| panic!("image visit lacks traversal"));
            assert_eq!(walk.0, kind);
            assert_eq!(walk.1.checked_add(1), Some(visited));
            walk.1 = visited;
        }
    }

    fn counts(&self, kind: &str) -> Vec<u64> {
        self.walks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(tag, _)| *tag == kind)
            .map(|(_, count)| *count)
            .collect()
    }

    fn clear(&self) {
        self.walks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

fn observe(fixture: &Fixture) -> AnchoredTestResult<Arc<Images>> {
    let images = Arc::new(Images::default());
    fixture.store.observe_native_image_visits_for_test({
        let images = images.clone();
        move |kind, visited| images.observe(kind, visited)
    })?;
    Ok(images)
}

fn current_rows(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
) -> AnchoredTestResult<u64> {
    let connection = fixture.store.connection()?;
    let mut total = 0_u64;
    for table in native::schema::TABLES {
        let count: i64 = connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE security_authority_id = ?1",
                table.native
            ),
            [initialized.security_authority_id().as_str()],
            |row| row.get(0),
        )?;
        total = total
            .checked_add(u64::try_from(count)?)
            .ok_or("current row total overflow")?;
    }
    Ok(total)
}

#[test]
fn image_counter_measures_actual_current_copy_and_sealed_row_visits() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let images = observe(&fixture)?;
    let (mut context, _) = mutations::request("image-probe")?;
    let original = join(&fixture, &initialized, &mut context, "image-probe-original")?;
    let expected = current_rows(&fixture, &initialized)?;
    assert!(expected > 0);
    images.clear();
    fixture
        .store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("current state disappeared")?;
    let current = images.counts("current");
    assert!(
        !current.is_empty(),
        "current-image verification was not observed"
    );
    assert!(
        current.iter().all(|count| *count == expected),
        "{current:?}, actual rows {expected}"
    );

    images.clear();
    let archived_before = archived(&fixture)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    assert_eq!(images.counts("copy"), vec![expected]);
    let sealed_rows: i64 = fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_checkpoint_rows WHERE security_authority_id = ?1",
        [initialized.security_authority_id().as_str()], |row| row.get(0),
    )?;
    assert_eq!(u64::try_from(sealed_rows)?, expected);
    assert_eq!(archived(&fixture)?, archived_before);

    images.clear();
    fixture
        .store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("sealed state disappeared")?;
    let snapshot = images.counts("snapshot");
    let current = images.counts("current");
    assert!(
        !snapshot.is_empty(),
        "snapshot fingerprint verification was not observed"
    );
    assert!(
        !current.is_empty(),
        "current-image equality verification was not observed"
    );
    assert!(
        snapshot.iter().all(|count| *count == expected),
        "{snapshot:?}, actual sealed rows {expected}"
    );
    assert!(
        current.iter().all(|count| *count == expected),
        "{current:?}, actual rows {expected}"
    );
    fixture
        .store
        .load_security_participant_flow_join(&original, &fixture.fence, now_ms())?
        .ok_or("original custody was pruned by sealing")?;
    Ok(())
}

#[test]
fn image_observer_preserves_typed_fence_refusal_without_checkpoint_writes() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let images = observe(&fixture)?;
    let before: (i64, String) = fixture.store.connection()?.query_row(
        "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut stale = fixture.fence.clone();
    stale.owner_epoch = stale
        .owner_epoch
        .checked_add(1)
        .ok_or("fence epoch overflow")?;
    assert!(matches!(
        fixture
            .store
            .checkpoint_security_participant_history(&initialized, &stale, now_ms()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert_eq!(events(&fixture)?, 0);
    assert_eq!(images.counts("copy"), Vec::<u64>::new());
    let after: (i64, String) = fixture.store.connection()?.query_row(
        "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn image_observer_preserves_snapshot_corruption_refusal() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let images = observe(&fixture)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    assert_eq!(events(&fixture)?, 1);
    assert!(images.counts("copy").iter().any(|count| *count > 0));
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(
            "DROP TRIGGER security_participant_checkpoint_rows_no_update;
             UPDATE security_participant_checkpoint_rows SET canonical_row = X'7b7d'
             WHERE rowid = (SELECT MIN(rowid) FROM security_participant_checkpoint_rows);",
        )?;
        connection.execute_batch(native::checkpoint::sql())?;
    }
    assert!(matches!(
        fixture.store.load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms()
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    Ok(())
}
