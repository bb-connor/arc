use super::*;

fn replay_entry(webhook_id: &str) -> AgentWebReplayEntry {
    let Ok(scope) = AgentWebReplayScope::parse(format!("{:064x}", 1)) else {
        panic!("test replay scope must parse");
    };
    let Ok(entry) = AgentWebReplayEntry::new(scope, webhook_id, 20) else {
        panic!("test replay entry must validate");
    };
    entry
}

#[test]
fn one_external_subject_is_reserved_once_across_envelopes() {
    let mut subjects = BTreeMap::new();
    let mut entries = Vec::new();

    assert!(retain_replay_entry_for_subject(
        &mut subjects,
        &mut entries,
        "subject-one",
        replay_entry("webhook-one"),
    )
    .is_ok());
    assert!(retain_replay_entry_for_subject(
        &mut subjects,
        &mut entries,
        "subject-one",
        replay_entry("webhook-one"),
    )
    .is_ok());
    assert_eq!(entries.len(), 1);
}

#[test]
fn one_replay_key_cannot_name_distinct_external_subjects() {
    let mut subjects = BTreeMap::new();
    let mut entries = Vec::new();

    assert!(retain_replay_entry_for_subject(
        &mut subjects,
        &mut entries,
        "subject-one",
        replay_entry("webhook-one"),
    )
    .is_ok());
    let error = retain_replay_entry_for_subject(
        &mut subjects,
        &mut entries,
        "subject-two",
        replay_entry("webhook-one"),
    );
    assert!(error.is_err_and(|error| error
        .to_string()
        .contains("reused across external subjects")));
}
