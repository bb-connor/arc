use super::*;

#[test]
fn response_domain_commitments_preserve_wire_ids() {
    let (machine, initial) = machine_with_plan(1);
    let changed = machine
        .transition(&initial, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("transition rejected: {failure}"));
    let snapshot = decode_response_record(&changed)
        .unwrap_or_else(|failure| panic!("snapshot rejected: {failure}"));
    // Literal known answers, independently reproduced with Python SHA-256 over
    // canonical commitments and the v1 domain bytes. Do not derive expected
    // values from the production constants: they must detect byte drift.
    assert_eq!(
        hex::encode(snapshot.plan.affected_set_hash.as_bytes()),
        "72d1daff620e3630f198f66893175b0a08f03f17af7478cc83ad95c0637d6de1"
    );
    assert_eq!(
        snapshot.plan.effects.as_slice()[0].effect_id.as_str(),
        "response_effect_7047b23dfb89bd2318ee8dd2d6036ed6a0619df1506e0958477e256bedcdac78"
    );
    assert_eq!(
        snapshot.mutations.as_slice()[0].transition_id().as_str(),
        "response_request_c9b4f8b25f446039fc288c8669345141b5c519ad84a8daabc9eed0ec07e6235a"
    );
    assert_eq!(
        snapshot.mutations.as_slice()[1].transition_id().as_str(),
        "response_transition_6a146800d58751dbbcbe21223e286ec68cc298111efdbf7b084598bff56c4dcd"
    );
}
