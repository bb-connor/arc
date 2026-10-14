use chio_cage_plan::{
    EnforcementEvidenceError, EnforcementPrepared, NONO_PATCH_VERSION, PINNED_NONO_VERSION,
    PINNED_SECCOMPILER_VERSION,
};

const PREPARED: &str = include_str!(
    "../../../../tests/bindings/vectors/security/cage/positive/cage-enforcement-prepared-v1.json"
);

fn reviewed() -> Result<EnforcementPrepared, serde_json::Error> {
    let mut prepared: EnforcementPrepared = serde_json::from_str(PREPARED)?;
    prepared.nono_version = PINNED_NONO_VERSION.to_string();
    prepared.nono_patch_version = NONO_PATCH_VERSION.to_string();
    prepared.seccompiler_version = PINNED_SECCOMPILER_VERSION.to_string();
    Ok(prepared)
}

#[test]
fn reviewed_enforcement_versions_validate() -> Result<(), Box<dyn std::error::Error>> {
    reviewed()?.validate()?;
    Ok(())
}

#[test]
fn unreviewed_enforcement_versions_are_refused() -> Result<(), serde_json::Error> {
    let reviewed = reviewed()?;
    let mutations: [fn(&mut EnforcementPrepared); 3] = [
        |prepared| prepared.nono_version = "0.52.0".to_string(),
        |prepared| prepared.nono_patch_version = "chio.2".to_string(),
        |prepared| prepared.seccompiler_version = "0.4.0".to_string(),
    ];
    for mutate in mutations {
        let mut prepared = reviewed.clone();
        mutate(&mut prepared);
        assert!(matches!(
            prepared.validate(),
            Err(EnforcementEvidenceError::InvalidEnforcementVersion)
        ));
    }
    Ok(())
}
