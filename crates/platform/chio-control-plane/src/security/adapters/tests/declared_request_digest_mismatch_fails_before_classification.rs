use super::*;


    #[test]
    fn declared_request_digest_mismatch_fails_before_classification() {
        let classifier = RegexStructuredClassifier::new("classifier.local", "1", vec![])
            .unwrap_or_else(|error| panic!("classifier: {error}"));
        let adapter = StructuredClassificationAdapter::new(Arc::new(classifier));
        let mut request = request(b"payload");
        request.payload_digest = Digest32::new([9; 32]);
        let error = require_error(adapter.classify(&request));
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
