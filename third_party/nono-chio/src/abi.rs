//! Minimal ABI probe extracted from the reviewed nono 0.53.0 Linux backend.
//! Probe order and HardRequirement filesystem/network/scope checks are unchanged.
use super::Error;
use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr, Scope, ABI,
};
use std::sync::OnceLock;

/// ABI probe order: highest to lowest.
const ABI_PROBE_ORDER: [ABI; 6] = [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1];

/// Detect the highest Landlock ABI supported by the running kernel.
///
/// Probes from V6 down to V1 using `HardRequirement` compatibility mode.
/// Returns the highest ABI for which a full ruleset can be created.
///
/// The result is cached after the first call since the kernel ABI does not
/// change at runtime.
///
/// # Errors
///
/// Returns an error if no ABI version is supported (Landlock not available).
pub(super) fn detect_abi() -> Result<ABI, Error> {
    static CACHED: OnceLock<ABI> = OnceLock::new();

    if let Some(abi) = CACHED.get() {
        return Ok(*abi);
    }

    let abi = detect_abi_uncached()?;
    let _ = CACHED.set(abi);
    Ok(abi)
}

fn detect_abi_uncached() -> Result<ABI, Error> {
    let mut last_error = None;

    for &abi in &ABI_PROBE_ORDER {
        match probe_abi_candidate(abi) {
            Ok(()) => return Ok(abi),
            Err(err) => {
                last_error = Some(format!("ABI {:?}: {}", abi, err));
            }
        }
    }

    Err(Error::AbiProbe(format!(
        "No supported Landlock ABI detected{}",
        last_error
            .as_ref()
            .map(|e| format!(" (last error: {})", e))
            .unwrap_or_default()
    )))
}

/// Probe whether a specific ABI version is supported using `HardRequirement`.
fn probe_abi_candidate(abi: ABI) -> std::result::Result<(), String> {
    let mut ruleset = Ruleset::default().set_compatibility(CompatLevel::HardRequirement);

    ruleset = ruleset
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("filesystem access probe failed: {}", e))?;

    let handled_net = AccessNet::from_all(abi);
    if !handled_net.is_empty() {
        ruleset = ruleset
            .handle_access(handled_net)
            .map_err(|e| format!("network access probe failed: {}", e))?;
    }

    let scopes = Scope::from_all(abi);
    if !scopes.is_empty() {
        ruleset = ruleset
            .scope(scopes)
            .map_err(|e| format!("scope probe failed: {}", e))?;
    }

    ruleset
        .create()
        .map_err(|e| format!("ruleset creation probe failed: {}", e))?;

    Ok(())
}
