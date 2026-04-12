//! ARC-Wall core contracts layered on ARC receipt and guard truth.

pub mod control_path;

pub use control_path::{
    ArcWallArtifact, ArcWallArtifactKind, ArcWallAuthorizationContext, ArcWallBuyerMotion,
    ArcWallBuyerReviewPackage, ArcWallContractError, ArcWallControlPackage, ArcWallControlProfile,
    ArcWallControlSurface, ArcWallDeniedAccessRecord, ArcWallGuardDecision, ArcWallGuardOutcome,
    ArcWallInformationDomain, ArcWallPolicySnapshot, ARC_WALL_AUTHORIZATION_CONTEXT_SCHEMA,
    ARC_WALL_BUYER_REVIEW_PACKAGE_SCHEMA, ARC_WALL_CONTROL_PACKAGE_SCHEMA,
    ARC_WALL_CONTROL_PROFILE_SCHEMA, ARC_WALL_DENIED_ACCESS_RECORD_SCHEMA,
    ARC_WALL_GUARD_OUTCOME_SCHEMA, ARC_WALL_POLICY_SNAPSHOT_SCHEMA,
};
