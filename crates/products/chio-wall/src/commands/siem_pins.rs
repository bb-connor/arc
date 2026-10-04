//! Operator-owned signer policy shared by SIEM ingestion and paging dispatch.
use std::collections::BTreeSet;
use std::env::VarError;
use std::path::Path;

use chio_core::crypto::PublicKey;
use chio_siem::SiemConfig;

use super::CliError;

pub(super) const ENV: &str = "CHIO_SIEM_TRUSTED_KERNEL_KEYS";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_KEYS: usize = 64;

/// Validate independent pins before opening the manager or polling receipts.
pub(super) fn configuration(
    receipt_db: &Path,
    cursor_db: &Path,
    paging: bool,
    value: Result<String, VarError>,
) -> Result<(SiemConfig, Vec<PublicKey>), CliError> {
    let keys = parse(value, paging)?;
    let config = SiemConfig {
        db_path: receipt_db.to_path_buf(),
        cursor_db_path: Some(cursor_db.to_path_buf()),
        trusted_kernel_keys: keys.iter().map(PublicKey::to_hex).collect(),
        ..SiemConfig::default()
    };
    Ok((config, keys))
}

fn invalid(reason: &str) -> CliError {
    CliError::cli_other_error(format!("{ENV}: {reason}"))
}

fn parse(value: Result<String, VarError>, paging: bool) -> Result<Vec<PublicKey>, CliError> {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) if !paging => return Ok(Vec::new()),
        Err(VarError::NotPresent) => {
            return Err(invalid(
                "independent kernel signer pins are required for paging",
            ));
        }
        Err(VarError::NotUnicode(_)) => return Err(invalid("must be Unicode JSON")),
    };
    if value.len() > MAX_CONFIG_BYTES {
        return Err(invalid("configuration exceeds 1 MiB"));
    }
    let encoded: Vec<String> = serde_json::from_str(&value)
        .map_err(|_| invalid("expected a JSON array of public-key strings"))?;
    if encoded.is_empty() || encoded.len() > MAX_KEYS {
        return Err(invalid("expected 1 through 64 kernel signer keys"));
    }
    let mut identities = BTreeSet::new();
    let mut keys = Vec::with_capacity(encoded.len());
    for wire in encoded {
        let key = PublicKey::from_hex(&wire).map_err(|_| invalid("invalid public-key encoding"))?;
        if key.is_weak_ed25519() {
            return Err(invalid("weak Ed25519 keys cannot identify kernel signers"));
        }
        if !identities.insert(key.to_hex()) {
            return Err(invalid("duplicate kernel signer identity"));
        }
        keys.push(key);
    }
    Ok(keys)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_siem::{Alert, AlertBackend, ExportError, Exporter};
    use std::sync::{Arc, Mutex};

    fn configured(
        value: Result<String, VarError>,
        paging: bool,
    ) -> Result<(SiemConfig, Vec<PublicKey>), CliError> {
        configuration(
            Path::new("unused-receipts.db"),
            Path::new("unused-cursor.db"),
            paging,
            value,
        )
    }

    fn encoded_keys(keys: &[PublicKey]) -> String {
        serde_json::to_string(&keys.iter().map(PublicKey::to_hex).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn paging_requires_pins_while_soc_only_can_omit_them() {
        assert!(configured(Err(VarError::NotPresent), true).is_err());
        let (config, keys) = configured(Err(VarError::NotPresent), false).unwrap();
        assert!(keys.is_empty());
        assert!(config.trusted_kernel_keys.is_empty());
    }

    #[test]
    fn rejects_malformed_explicit_config_even_without_paging() {
        for value in [
            "",
            " ",
            "null",
            "{}",
            "[]",
            "[42]",
            "[\"bad\"]",
            "[\"00\"]",
            "[\"p256:04\"]",
        ] {
            for paging in [false, true] {
                assert!(
                    configured(Ok(value.into()), paging).is_err(),
                    "accepted {value}"
                );
            }
        }
        assert!(configured(Err(VarError::NotUnicode("invalid".into())), false).is_err());
    }

    #[test]
    fn bounds_bytes_and_key_count_before_accepting_pins() {
        let key = Keypair::from_seed(&[43; 32]).public_key();
        let oversized = format!("{}{}", " ".repeat(1024 * 1024), encoded_keys(&[key]));
        assert!(configured(Ok(oversized), true).is_err());
        let sixty_four: Vec<_> = (0..64)
            .map(|seed| Keypair::from_seed(&[seed; 32]).public_key())
            .collect();
        assert_eq!(
            configured(Ok(encoded_keys(&sixty_four)), true)
                .unwrap()
                .1
                .len(),
            64
        );
        let sixty_five: Vec<_> = (0..65)
            .map(|seed| Keypair::from_seed(&[seed; 32]).public_key())
            .collect();
        assert!(configured(Ok(encoded_keys(&sixty_five)), true).is_err());
    }

    #[test]
    fn rejects_weak_and_normalized_duplicate_keys() {
        let mut weak = [0_u8; 32];
        weak[0] = 1;
        assert!(configured(
            Ok(encoded_keys(&[PublicKey::from_bytes(&weak).unwrap()])),
            true
        )
        .is_err());
        let key = Keypair::from_seed(&[43; 32]).public_key().to_hex();
        let duplicates = serde_json::json!([key, format!("0x{}", key.to_uppercase())]);
        assert!(configured(Ok(duplicates.to_string()), true).is_err());
    }

    #[test]
    fn canonical_operator_pins_reach_manager_and_exporter_policy() {
        let key = Keypair::from_seed(&[43; 32]).public_key();
        let rotated = Keypair::from_seed(&[44; 32]).public_key();
        let value = serde_json::json!([
            format!("0x{}", key.to_hex().to_uppercase()),
            rotated.to_hex()
        ]);
        let (config, keys) = configured(Ok(value.to_string()), true).unwrap();
        assert_eq!(keys, vec![key.clone(), rotated.clone()]);
        assert_eq!(
            config.trusted_kernel_keys,
            BTreeSet::from([key.to_hex(), rotated.to_hex()])
        );
        assert_eq!(config.db_path, Path::new("unused-receipts.db"));
        assert_eq!(
            config.cursor_db_path.as_deref(),
            Some(Path::new("unused-cursor.db"))
        );
    }

    #[test]
    fn operator_pins_accept_existing_algorithm_aware_wire_formats() {
        // SEC1 encodings of the P-256 and P-384 standard generator points.
        let p256 = "p256:046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let p384 = "p384:04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
        let (_, keys) = configured(Ok(serde_json::json!([p256, p384]).to_string()), true).unwrap();
        assert_eq!(keys[0].to_hex(), p256);
        assert_eq!(keys[1].to_hex(), p384);
    }

    struct Receiver(Arc<Mutex<Vec<String>>>);
    impl AlertBackend for Receiver {
        fn name(&self) -> &str {
            "pin-wiring-receiver"
        }
        fn dispatch<'a>(
            &'a self,
            alert: &'a Alert,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.0.lock().unwrap().push(alert.receipt_id.clone());
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn production_builder_pages_only_the_independent_operator_signer() {
        let key = Keypair::from_seed(&[43; 32]).public_key();
        let (config, keys) = configured(Ok(encoded_keys(&[key])), true).unwrap();
        assert_eq!(config.trusted_kernel_keys.len(), 1);
        let received = Arc::new(Mutex::new(Vec::new()));
        let (exporter, _) = crate::commands::build_serve_alerting_exporter(
            vec![Box::new(Receiver(received.clone()))],
            chio_siem::metrics_sink::noop_metrics_sink(),
            keys,
        )
        .unwrap();
        let valid = crate::commands::tests::serve_deny_event("SecretLeakGuard");
        let attacker = Keypair::from_seed(&[44; 32]);
        let mut body = valid.receipt.body();
        body.kernel_key = attacker.public_key();
        let mut untrusted = valid.clone();
        untrusted.receipt = chio_core::receipt::body::ChioReceipt::sign(body, &attacker).unwrap();
        untrusted.authoritative = true;
        untrusted.signer_trusted = true;
        untrusted.signature_valid = true;
        untrusted.receipt_id_valid = true;
        untrusted.parameter_hash_valid = true;
        untrusted.authorized = true;
        let id = valid.receipt.id.clone();
        assert_eq!(exporter.export_batch(&[untrusted, valid]).await.unwrap(), 2);
        assert_eq!(*received.lock().unwrap(), vec![id]);
    }
}
