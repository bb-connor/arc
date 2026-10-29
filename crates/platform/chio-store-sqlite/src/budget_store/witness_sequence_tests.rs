use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn populate(store: &SqliteBudgetStore) -> TestResult {
    assert!(store.try_charge_cost_with_ids_and_authority(
        "cap",
        0,
        Some(10),
        5,
        None,
        None,
        None,
        Some("event"),
        None,
    )?);
    Ok(())
}

#[test]
fn standalone_witness_preserves_sequence_without_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteBudgetStore::open(directory.path().join("budget.db"))?;
    populate(&store)?;
    let (sequence, authority, epoch) = store
        .mutation_event_witness_for_event_id("event")?
        .ok_or("written event must have a witness")?;
    assert!(sequence > 0);
    assert_eq!(authority, None);
    assert_eq!(epoch, None);
    assert_eq!(store.mutation_event_witness_for_event_id("absent")?, None);
    Ok(())
}

#[test]
fn retained_witness_refuses_missing_or_nonpositive_sequence_without_repair() -> TestResult {
    for malformed in [None, Some(0_i64), Some(-1_i64)] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("budget.db");
        let store = SqliteBudgetStore::open(&path)?;
        populate(&store)?;
        let original = store
            .mutation_event_witness_for_event_id("event")?
            .ok_or("written event must have a witness")?;
        let connection = Connection::open(&path)?;
        assert_eq!(
            connection.execute(
                "UPDATE budget_mutation_events SET event_seq = ?1 WHERE event_id = 'event'",
                [malformed],
            )?,
            1
        );
        let result = store.mutation_event_witness_for_event_id("event");
        assert!(
            matches!(&result, Err(BudgetStoreError::Invariant(reason))
                if reason == "budget mutation witness has no positive event sequence"),
            "malformed sequence {malformed:?}: {result:?}"
        );
        let retained: Option<i64> = connection.query_row(
            "SELECT event_seq FROM budget_mutation_events WHERE event_id = 'event'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(retained, malformed);
        connection.execute(
            "UPDATE budget_mutation_events SET event_seq = ?1 WHERE event_id = 'event'",
            [i64::try_from(original.0)?],
        )?;
        assert_eq!(
            store.mutation_event_witness_for_event_id("event")?,
            Some(original)
        );
    }
    Ok(())
}
