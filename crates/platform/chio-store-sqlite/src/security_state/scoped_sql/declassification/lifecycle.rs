//! Explicit authority-scoped declassification lifecycle queries.

use super::super::{ReadQuery, WriteQuery};

pub(in crate::security_state) const LIFECYCLE_SCHEMA: ReadQuery = ReadQuery {
    parameters: 0,
    legacy: r#"SELECT schema_version, readiness_cursor, reconciliation_active,
                   live_dispatch_sealed, compaction_active
            FROM security_declassification_lifecycle WHERE singleton = 1"#,
    native: r#"SELECT schema_version, readiness_cursor, reconciliation_active,
                   live_dispatch_sealed, compaction_active
            FROM security_participant_state_declassification_lifecycle WHERE security_authority_id = ?1 AND singleton = 1"#,
};

pub(in crate::security_state) const BEGIN_RECONCILIATION: WriteQuery = WriteQuery {
    parameters: 0,
    legacy: r#"UPDATE security_declassification_lifecycle
                SET reconciliation_active = 1
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 0 AND compaction_active = 0"#,
    native: r#"UPDATE security_participant_state_declassification_lifecycle
                SET reconciliation_active = 1
                WHERE security_authority_id = ?1 AND singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 0 AND compaction_active = 0"#,
};

pub(in crate::security_state) const END_RECONCILIATION: WriteQuery = WriteQuery {
    parameters: 0,
    legacy: r#"UPDATE security_declassification_lifecycle
                SET reconciliation_active = 0
                WHERE singleton = 1 AND reconciliation_active = 1
                  AND live_dispatch_sealed = 0 AND compaction_active = 0"#,
    native: r#"UPDATE security_participant_state_declassification_lifecycle
                SET reconciliation_active = 0
                WHERE security_authority_id = ?1 AND singleton = 1 AND reconciliation_active = 1
                  AND live_dispatch_sealed = 0 AND compaction_active = 0"#,
};

pub(in crate::security_state) const SEAL_DISPATCH: WriteQuery = WriteQuery {
    parameters: 0,
    legacy: r#"UPDATE security_declassification_lifecycle
                SET live_dispatch_sealed = 1
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 0 AND compaction_active = 0"#,
    native: r#"UPDATE security_participant_state_declassification_lifecycle
                SET live_dispatch_sealed = 1
                WHERE security_authority_id = ?1 AND singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 0 AND compaction_active = 0"#,
};

pub(in crate::security_state) const RESET_LIFECYCLE: WriteQuery = WriteQuery {
    parameters: 0,
    legacy: r#"UPDATE security_declassification_lifecycle
                SET reconciliation_active = 0,
                    live_dispatch_sealed = 0,
                    compaction_active = 0
                WHERE singleton = 1"#,
    native: r#"UPDATE security_participant_state_declassification_lifecycle
                SET reconciliation_active = 0,
                    live_dispatch_sealed = 0,
                    compaction_active = 0
                WHERE security_authority_id = ?1 AND singleton = 1"#,
};
