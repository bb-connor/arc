//! Release request display names cannot replace authenticated request owners.
use super::*;

#[test]
fn artifacts_release_request_id_is_partitioned_by_authenticated_actor() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let bytes = b"public-two-request-owners";
    let reference = f.publish("independent-release-owner-control", bytes)?;
    assert_eq!(f.metadata(&reference)?.label, InformationLabel::bottom());
    let other = super::release_audience::install_read_actor(
        &f,
        224,
        "independent-release-request-owner",
        restricted_label(),
    )?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let first_handle = f.runtime.handle(&f.f.control, &reference, &recipient)?;
    let second_handle = f.runtime.handle(&other, &reference, &recipient)?;
    assert_ne!(first_handle.handle, second_handle.handle);
    let request = RequestId::new("same-display-release-request")?;
    let first_sink = f.sink();
    let second_sink = f.sink();
    let first = f.runtime.release_into(
        &f.f.control,
        &request,
        f.runtime.prepare_read(&f.f.control, &first_handle)?,
        &first_sink,
    )?;
    assert_eq!(
        first_sink
            .delivered
            .lock()
            .map_err(|_| "first sink")?
            .as_slice(),
        &[bytes.to_vec()]
    );
    // The second actor can use its own handle and a fresh request without
    // adopting the first actor's custody. This positive control reaches the
    // release path independently of publication identifier squatting.
    f.runtime.release_into(
        &other,
        &RequestId::new("second-owner-fresh-request-control")?,
        f.runtime.prepare_read(&other, &second_handle)?,
        &second_sink,
    )?;
    let second = f
        .runtime
        .release_into(
            &other,
            &request,
            f.runtime.prepare_read(&other, &second_handle)?,
            &second_sink,
        )
        .map_err(|error| {
            format!("release actor partition: independent same-display request: {error}")
        })?;
    assert_ne!(first.release, second.release);
    let event_count: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    for (capability, handle, sink, expected) in [
        (&f.f.control, &first_handle, &first_sink, &first.release),
        (&other, &second_handle, &second_sink, &second.release),
    ] {
        let replay = f.runtime.release_into(
            capability,
            &request,
            f.runtime.prepare_read(capability, handle)?,
            sink,
        )?;
        assert_eq!(&replay.release, expected);
    }
    let after: i64 = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        after, event_count,
        "exact actor-owned redelivery must not mint custody again"
    );
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        first_sink
            .delivered
            .lock()
            .map_err(|_| "first sink")?
            .as_slice(),
        &[bytes.to_vec(), bytes.to_vec()]
    );
    assert_eq!(
        second_sink
            .delivered
            .lock()
            .map_err(|_| "second sink")?
            .as_slice(),
        &[bytes.to_vec(), bytes.to_vec(), bytes.to_vec()]
    );
    Ok(())
}
