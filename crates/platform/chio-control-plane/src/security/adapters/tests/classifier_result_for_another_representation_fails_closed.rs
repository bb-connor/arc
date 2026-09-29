use super::*;

#[test]
fn classifier_result_for_another_representation_fails_closed() {
    let adapter = StructuredClassificationAdapter::new(Arc::new(WrongRepresentation));
    let error = require_error(adapter.classify(&request(b"payload")));
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}
