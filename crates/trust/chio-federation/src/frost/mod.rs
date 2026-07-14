//! Strict FROST Ed25519 authorization contracts.

mod action;
mod registry;
mod roster;
mod types;
mod verify;

pub use action::{
    FrostActionPreimageV1, FrostChannelCloseActionV1, FrostClearingRoundFinalizeActionV1,
    FrostCredentialsPassportRevokeActionV1, FrostGovernanceCaseEnforceSanctionActionV1,
    FrostPouncerRevokeCredentialActionV1, FrostRosterRotateActionV1, FrostSettleCommitmentActionV1,
    CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA, CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA,
    CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA,
    CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA,
    CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA, CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA,
    CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
};
pub use registry::{frost_action_registration, registered_frost_actions, FrostActionRegistration};
pub use roster::{
    ActiveFrostRosterResolver, FrostAnchorError, FrostEpochAnchor, FrostEpochCheckpointV1,
    FrostHistoricalRosterResolver, FrostParticipantV1, FrostRosterError,
    FrostRosterResolutionError, FrostRosterV1, VerifiedActiveFrostRoster,
    CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA, CHIO_FROST_ROSTER_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
pub use types::{
    FrostAuthorizationBodyV1, FrostAuthorizationDomain, FrostAuthorizationError,
    CHIO_FROST_AUTHORIZATION_BODY_SCHEMA, CHIO_FROST_AUTHORIZATION_SIGNING_PREFIX,
};
pub use verify::{
    frost_authorization_session_id, frost_authorization_slot_id,
    resolve_active_roster_for_execution, verify_for_execution, verify_historical_evidence,
    ExpectedFrostAuthorization, FrostAnchoredAuthorizationSlot, FrostAuthorizationSlotAnchor,
    FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState, FrostAuthorizationV1,
    FrostVerificationError, HistoricalFrostEvidence, VerifiedFrostAuthorization,
    CHIO_FROST_AUTHORIZATION_SCHEMA, CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA,
};
