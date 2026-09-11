use super::*;

#[test]
fn imports_complete_inventory_inactive_with_anchored_read_only_retries() -> AnchoredTestResult {
    for empty in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, empty)?;
        let before = global_count(&fixture);
        let expected = pin(&fixture, &source)?;
        assert_eq!(expected.event_sequence(), 1);
        assert!(!expected.is_imported());
        assert_eq!(counts(&fixture), [0, 1, 1]);
        assert_eq!(pin(&fixture, &source)?, expected);
        assert_eq!(source.calls(), ["preview"]);
        let imported = import(&fixture, &source, &expected)?;
        assert!(imported.imported_inactive());
        assert_eq!(imported.snapshot(), expected.snapshot());
        assert_eq!(counts(&fixture), [if empty { 0 } else { 3 }, 2, 1]);
        assert_eq!(global_count(&fixture), before + 2);
        assert_eq!(import(&fixture, &source, &expected)?, imported);
        assert_eq!(pin(&fixture, &source)?, imported);
        assert_eq!(load(&fixture)?, Some(imported.clone()));
        assert_eq!(source.calls(), ["preview", "seal", "verify", "verify"]);
        assert_eq!(global_count(&fixture), before + 2);
        let inventory = imported.snapshot().inventory();
        assert_eq!(
            (
                &*inventory.wall_clock_high_water,
                &*inventory.pruned_through,
                &*inventory.capacity
            ),
            ("100", "50", "8")
        );
        if !empty {
            assert!(inventory.markers[0].is_legacy_unscoped());
            assert_eq!(inventory.markers[0].expires_at, "1");
            assert!(inventory.markers[1].dispatch_reservation_id.is_none());
            assert_eq!(
                inventory.markers[2]
                    .dispatch_reservation_id
                    .as_ref()
                    .map(AdmissionIdentifier::as_str),
                Some("private-owner")
            );
        }
        let legacy = SqliteGovernedApprovalReplayStore::open(&source.path)?;
        use chio_kernel::GovernedApprovalReplayStore;
        assert!(legacy
            .reserve_for_dispatch("subject", "new", "intent", now_ms() / 1000 + 100, "owner")
            .is_err());
    }
    Ok(())
}

#[test]
fn pending_pin_and_import_survive_reopen_without_source_clock_or_inventory_changes(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    let source_path = source.path.clone();
    drop(source);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
        _temp,
        database,
        lock_root,
    };
    let source = Source::reopen(source_path.clone(), &fixture.store)?;
    assert!(fixture
        .store
        .load_governed_approval_replay_migration(
            &identifier("authority", AUTHORITY_ID),
            &fence,
            now_ms()
        )
        .is_err());
    assert_eq!(pin(&fixture, &source)?, expected);
    assert!(source.calls().is_empty());
    let imported = import(&fixture, &source, &expected)?;
    drop(source);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
        _temp,
        database,
        lock_root,
    };
    let source = Source::reopen(source_path, &fixture.store)?;
    assert_eq!(load(&fixture)?, Some(imported.clone()));
    assert_eq!(import(&fixture, &source, &expected)?, imported);
    assert_eq!(source.calls(), ["verify"]);
    Ok(())
}

#[test]
fn stale_fences_wrong_generations_and_changed_inventory_cannot_seal() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(fixture
        .store
        .expect_governed_approval_replay_source(
            &identifier("source", SOURCE_ID),
            &identifier("authority", AUTHORITY_ID),
            &source,
            &stale,
            now_ms()
        )
        .is_err());
    assert!(source.calls().is_empty());
    let expected = pin(&fixture, &source)?;
    assert!(fixture
        .store
        .import_governed_approval_replay_source(
            &identifier("authority", AUTHORITY_ID),
            &identifier("expectation", "wrong"),
            &source,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert_eq!(source.calls(), ["preview"]);
    Connection::open(&source.path)?.execute("UPDATE chio_governed_approval_replay_entries SET dispatch_reservation_id = 'changed' WHERE request_id = 'reserved'", [])?;
    assert!(import(&fixture, &source, &expected).is_err());
    assert_eq!(load(&fixture)?, Some(expected.clone()));
    assert_eq!(counts(&fixture), [0, 1, 1]);
    assert!(source
        .raw
        .preview_unsealed(expected.snapshot().binding())
        .is_ok());
    Ok(())
}

#[test]
fn a_source_cannot_be_pinned_twice_under_different_authorities() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    assert!(fixture
        .store
        .expect_governed_approval_replay_source(
            &identifier("source", "second-source"),
            &identifier("authority", "second-authority"),
            &source,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert_eq!(counts(&fixture), [0, 1, 1]);
    assert!(source
        .raw
        .preview_unsealed(expected.snapshot().binding())
        .is_ok());
    Ok(())
}

#[test]
fn lost_seal_acknowledgement_and_source_panics_resume_exactly_once() -> AnchoredTestResult {
    for failure in ["preview", "seal", "verify", "lost-ack"] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        if failure == "preview" {
            source.state.lock().expect("state").panic_on = Some("preview");
            assert!(pin(&fixture, &source).is_err());
            assert_eq!(counts(&fixture), [0, 0, 0]);
            source.state.lock().expect("state").panic_on = None;
        }
        let expected = pin(&fixture, &source)?;
        if failure != "preview" {
            if failure == "lost-ack" {
                source.state.lock().expect("state").lose_seal_ack_once = true;
            } else {
                source.state.lock().expect("state").panic_on = Some(failure);
            }
            assert!(import(&fixture, &source, &expected).is_err());
            assert_eq!(load(&fixture)?, Some(expected.clone()));
            source.state.lock().expect("state").panic_on = None;
        }
        assert!(import(&fixture, &source, &expected)?.imported_inactive());
        assert_eq!(counts(&fixture), [3, 2, 1]);
    }
    Ok(())
}
