use chio_core::crypto::PublicKey;
use chio_core::receipt::body::ChioReceipt;
use serde::Deserialize;

use crate::{
    verify_signed_cage_receipt_with_trusted_key, CageEnforcementState, ConfinementBackendKind,
    ConfinementDisclosure,
};

/// Receipt metadata key the kernel binds from the prepared launch at dispatch.
pub const NATIVE_LAUNCH_METADATA_KEY: &str = "native_launch";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeLaunchReference {
    receipt_id: String,
    receipt_sha256: String,
}

/// Render a tool-call receipt's tool-server confinement.
///
/// Confined only when the receipt verifies under `trusted_kernel_key` and its
/// kernel-bound `native_launch` reference names `launch` exactly: same id,
/// same canonical digest, same tool server, signed by `trusted_launch_signer`,
/// and in state `FullyEnforced`. Every other case renders unconfined with the
/// reason taken from the receipt's signed `tool_origin`.
#[must_use]
pub fn render_tool_confinement(
    receipt: &ChioReceipt,
    launch: Option<&ChioReceipt>,
    trusted_kernel_key: &PublicKey,
    trusted_launch_signer: &PublicKey,
) -> ConfinementDisclosure {
    let unconfined = ConfinementDisclosure::Unconfined(receipt.tool_origin.into());
    match launch {
        Some(launch)
            if bound_launch_is_fully_enforced(
                receipt,
                launch,
                trusted_kernel_key,
                trusted_launch_signer,
            ) =>
        {
            ConfinementDisclosure::Confined(ConfinementBackendKind::LinuxCage)
        }
        _ => unconfined,
    }
}

fn bound_launch_is_fully_enforced(
    receipt: &ChioReceipt,
    launch: &ChioReceipt,
    trusted_kernel_key: &PublicKey,
    trusted_launch_signer: &PublicKey,
) -> bool {
    if &receipt.kernel_key != trusted_kernel_key
        || !receipt.verify_integrity_embedded_key().unwrap_or(false)
    {
        return false;
    }
    let Some(reference) = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(NATIVE_LAUNCH_METADATA_KEY))
        .and_then(|value| NativeLaunchReference::deserialize(value).ok())
    else {
        return false;
    };
    let Ok(launch_bytes) = chio_core::canonical_json_bytes(launch) else {
        return false;
    };
    reference.receipt_id == launch.id
        && reference.receipt_sha256 == chio_core::sha256_hex(&launch_bytes)
        && launch.tool_server == receipt.tool_server
        && verify_signed_cage_receipt_with_trusted_key(launch, trusted_launch_signer)
            .is_ok_and(|body| body.enforcement_record.state == CageEnforcementState::FullyEnforced)
}
