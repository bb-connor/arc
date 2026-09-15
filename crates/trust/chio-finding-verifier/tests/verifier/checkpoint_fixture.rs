//! Shared historical checkpoint fixture without changing signed production code.
use super::*;

pub(super) fn checkpoint_at(
    mut checkpoint: KernelCheckpoint,
    issued_at: u64,
    signer: &Keypair,
) -> Result<KernelCheckpoint, Box<dyn Error>> {
    checkpoint.body.issued_at = issued_at;
    checkpoint.signature = signer.sign(&canonical_json_bytes(&checkpoint.body)?);
    Ok(checkpoint)
}
