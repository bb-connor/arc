use std::collections::BTreeSet;

use chio_security_types::ports::{BackendName, BackendNameError};

#[test]
fn a_backend_name_refuses_what_the_outbox_cannot_store() {
    assert_eq!(BackendName::new(""), Err(BackendNameError::Empty));
    for untrimmed in [" pagerduty", "pagerduty\n", "   "] {
        assert_eq!(
            BackendName::new(untrimmed),
            Err(BackendNameError::Untrimmed)
        );
    }
    assert_eq!(
        BackendName::new("pager\0duty"),
        Err(BackendNameError::ContainsNul)
    );
    let names: BTreeSet<BackendName> = BackendName::new("pagerduty").into_iter().collect();
    assert!(names.contains("pagerduty"));
    assert_eq!(names.first().map(BackendName::as_str), Some("pagerduty"));
}
