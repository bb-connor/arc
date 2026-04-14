use arc_wall_core::{
    ArcWallBuyerMotion, ArcWallControlProfile, ArcWallControlSurface, ArcWallInformationDomain,
    ARC_WALL_CONTROL_PROFILE_SCHEMA,
};

#[test]
fn wall_control_profile_validates_fail_closed_boundary() {
    let profile = ArcWallControlProfile {
        schema: ARC_WALL_CONTROL_PROFILE_SCHEMA.to_string(),
        profile_id: "wall-profile".to_string(),
        workflow_id: "wf-1".to_string(),
        buyer_motion: ArcWallBuyerMotion::ControlRoomBarrierReview,
        control_surface: ArcWallControlSurface::ToolAccessDomainBoundary,
        source_domain: ArcWallInformationDomain::Research,
        protected_domain: ArcWallInformationDomain::Execution,
        retained_artifact_policy: "retain-minimum".to_string(),
        intended_use: "boundary review".to_string(),
        fail_closed: true,
    };
    assert!(profile.validate().is_ok());

    let invalid = ArcWallControlProfile {
        protected_domain: ArcWallInformationDomain::Research,
        ..profile
    };
    assert!(invalid.validate().is_err());
}
