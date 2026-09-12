mod capability_set_suspension;
#[cfg(test)]
mod deadline_tests;
mod declassification;
mod flow_state;
mod issuance_freeze;
mod native_declassification;
mod native_egress;
pub(crate) use native_declassification::NativeDeclassificationOutcome;
mod native_mutation;
mod participant_source;
mod scoped_sql;
mod transaction;
pub(crate) use declassification::verify_native_declassification_state;
pub(crate) use declassification::verify_native_pending_declassification;
use flow_state::load_flow_snapshot;
pub(crate) use flow_state::{
    observe_native_flow_state, resolve_native_input_join, resolve_native_label_join,
    verify_native_flow_state,
};
pub(crate) use native_egress::{NativeEgressCommand, NativeEgressResult};
pub(crate) use native_mutation::{
    deny_native_mutations, is_native_flow_join_table, join_native_flow,
    join_native_nonce_preflight, join_native_output, mutate_native_egress, NativeRowChange,
};
#[cfg(all(test, unix))]
pub(crate) use participant_source::seeded_security_history;
pub(crate) use participant_source::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
    RetainedSecuritySourceRows, TableHasher,
};
use transaction::{trusted_time_in_transaction, SecurityStateWriteTransaction};

pub use participant_source::{
    SecurityParticipantSourceBinding, SecurityParticipantSourceError,
    SecurityParticipantSourceSeal, SecurityParticipantSourceSnapshot,
    SqliteSecurityParticipantSource,
};

include!("security_state_parts/part_01.rs");
include!("security_state_parts/part_02.rs");
include!("security_state_parts/part_03.rs");
include!("security_state_parts/part_04.rs");
include!("security_state_parts/part_05.rs");
include!("security_state_parts/part_06.rs");
include!("security_state_parts/part_07.rs");
include!("security_state_parts/part_08.rs");
include!("security_state_parts/part_09.rs");
include!("security_state_parts/part_10.rs");
