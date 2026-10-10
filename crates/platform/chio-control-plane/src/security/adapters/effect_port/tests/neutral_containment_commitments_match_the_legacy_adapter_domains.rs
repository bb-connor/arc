use super::*;

#[test]
fn neutral_containment_commitments_match_the_legacy_adapter_domains() {
    #[derive(Serialize)]
    struct LegacyOverlayCommitment<'a> {
        schema_version: u8,
        target: &'a TenantScopedId,
        generation: u64,
        effective_posture_rank: u32,
        active_contributions: &'a OverlayContributions,
    }

    #[derive(Serialize)]
    struct LegacyInstalledCommitment<'a> {
        schema_version: u8,
        target: &'a TenantScopedId,
        effect_id: &'a str,
        posture_rank: u32,
        contribution_hash: Digest32,
        expires_at_unix_ms: Option<u64>,
    }

    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("target: {error}"));
    let contribution = OverlayContribution {
        effect_id: EffectId::new("compatibility-effect")
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        posture_rank: 7,
        contribution_hash: Digest32::new([41_u8; 32]),
        expires_at_unix_ms: Some(90_000),
    };
    let contributions = OverlayContributions::new(vec![contribution.clone()])
        .unwrap_or_else(|error| panic!("contributions: {error}"));
    let snapshot = OverlaySnapshot {
        target: target.clone(),
        generation: 1,
        effective_posture_rank: 7,
        active_contributions: contributions,
        highest_fencing_token: 9,
    };
    let legacy_overlay = super::super::domain_hash(
        b"chio.response-effect-overlay-state.v1\0",
        &LegacyOverlayCommitment {
            schema_version: 1,
            target: &target,
            generation: 1,
            effective_posture_rank: 7,
            active_contributions: &snapshot.active_contributions,
        },
    )
    .unwrap_or_else(|error| panic!("legacy overlay hash: {error}"));
    assert_eq!(
        containment_overlay_version_hash(&snapshot),
        Ok(legacy_overlay)
    );

    let legacy_installed = super::super::domain_hash(
        b"chio.response-effect-overlay-contribution.v1\0",
        &LegacyInstalledCommitment {
            schema_version: 1,
            target: &target,
            effect_id: contribution.effect_id.as_str(),
            posture_rank: contribution.posture_rank,
            contribution_hash: contribution.contribution_hash,
            expires_at_unix_ms: contribution.expires_at_unix_ms,
        },
    )
    .unwrap_or_else(|error| panic!("legacy installed hash: {error}"));
    assert_eq!(
        containment_installed_version_hash(&target, &contribution),
        Ok(legacy_installed)
    );
}
