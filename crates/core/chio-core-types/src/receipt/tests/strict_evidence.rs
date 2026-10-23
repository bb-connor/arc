use super::*;
use crate::crypto::{PublicKey, Signature};

fn identity_forgery() -> crate::error::Result<(PublicKey, Signature)> {
    Ok((
        PublicKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")?,
        Signature::from_hex(concat!(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))?,
    ))
}

#[test]
fn tool_receipt_rejects_identity_key_forgery() -> crate::error::Result<()> {
    let keypair = Keypair::generate();
    let mut receipt = ChioReceipt::sign(make_receipt_body(&keypair), &keypair)?;
    (receipt.kernel_key, receipt.signature) = identity_forgery()?;
    receipt.id = chio_receipt_id(&receipt.body())?;
    assert!(!receipt.verify_signature()?);
    Ok(())
}

#[test]
fn child_receipt_rejects_identity_key_forgery() -> crate::error::Result<()> {
    let keypair = Keypair::generate();
    let mut receipt = ChildRequestReceipt::sign(make_child_receipt_body(&keypair), &keypair)?;
    (receipt.kernel_key, receipt.signature) = identity_forgery()?;
    assert!(!receipt.verify_signature()?);
    Ok(())
}

#[test]
fn export_envelope_rejects_identity_key_forgery() -> crate::error::Result<()> {
    #[derive(Clone, serde::Serialize)]
    struct ForgedExport {
        count: u32,
    }
    impl crate::receipt::lineage::SignedExportPayload for ForgedExport {
        const SCHEMA_ID: &'static str = crate::CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA;
    }
    let mut envelope = SignedExportEnvelope::sign(ForgedExport { count: 3 }, &Keypair::generate())?;
    (envelope.signer_key, envelope.signature) = identity_forgery()?;
    assert!(!envelope.verify_signature(&envelope.signer_key)?);
    Ok(())
}
