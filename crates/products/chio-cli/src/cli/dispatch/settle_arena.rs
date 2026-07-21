// Dispatch handlers for the `chio settle` and `chio arena` command groups.

use super::*;

struct SettlementDriveCredentials {
    iou_issuer: chio_core::Keypair,
    trusted_iou_issuer_keys: Vec<chio_core::PublicKey>,
    trusted_kernel_keys: Vec<chio_core::PublicKey>,
}

const MAX_SETTLEMENT_TRUST_ROOTS: usize = 256;

fn load_settlement_drive_credentials(
    iou_issuer_seed_file: &Path,
    trusted_iou_issuer_pubkeys: &[PathBuf],
    trusted_kernel_pubkeys: &[PathBuf],
) -> Result<SettlementDriveCredentials, CliError> {
    if trusted_kernel_pubkeys.is_empty() {
        return Err(CliError::Other(
            "settle drive: at least one --trusted-kernel-pubkey is required".to_string(),
        ));
    }
    if trusted_kernel_pubkeys.len() > MAX_SETTLEMENT_TRUST_ROOTS
        || trusted_iou_issuer_pubkeys.len() >= MAX_SETTLEMENT_TRUST_ROOTS
    {
        return Err(CliError::Other(format!(
            "settle drive: each trust domain is limited to {MAX_SETTLEMENT_TRUST_ROOTS} keys"
        )));
    }

    let iou_issuer = crate::load_existing_authority_keypair(iou_issuer_seed_file).map_err(|error| {
        CliError::Other(format!(
            "settle drive: failed to load existing IOU issuer seed {}: {error}",
            iou_issuer_seed_file.display()
        ))
    })?;
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted_kernel_keys = Vec::with_capacity(trusted_kernel_pubkeys.len());
    for path in trusted_kernel_pubkeys {
        let key = crate::load_trusted_kernel_pubkey(path).map_err(|error| {
            CliError::Other(format!(
                "settle drive: failed to load trusted kernel public key {}: {error}",
                path.display()
            ))
        })?;
        if !seen.insert(key.to_hex()) {
            return Err(CliError::Other(format!(
                "settle drive: duplicate trusted kernel public key at {}",
                path.display()
            )));
        }
        trusted_kernel_keys.push(key);
    }

    let mut seen_iou_issuers = std::collections::BTreeSet::new();
    let current_iou_issuer = iou_issuer.public_key();
    seen_iou_issuers.insert(current_iou_issuer.to_hex());
    let mut trusted_iou_issuer_keys = Vec::with_capacity(
        trusted_iou_issuer_pubkeys.len().saturating_add(1),
    );
    trusted_iou_issuer_keys.push(current_iou_issuer);
    for path in trusted_iou_issuer_pubkeys {
        let key = crate::load_trusted_kernel_pubkey(path).map_err(|error| {
            CliError::Other(format!(
                "settle drive: failed to load trusted IOU issuer public key {}: {error}",
                path.display()
            ))
        })?;
        if !seen_iou_issuers.insert(key.to_hex()) {
            return Err(CliError::Other(format!(
                "settle drive: duplicate trusted IOU issuer public key at {}",
                path.display()
            )));
        }
        trusted_iou_issuer_keys.push(key);
    }
    if trusted_iou_issuer_keys
        .iter()
        .any(|issuer| trusted_kernel_keys.contains(issuer))
    {
        return Err(CliError::Other(
            "settle drive: IOU issuer and kernel receipt signer trust domains must be disjoint"
                .to_string(),
        ));
    }

    Ok(SettlementDriveCredentials {
        iou_issuer,
        trusted_iou_issuer_keys,
        trusted_kernel_keys,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_settle(
    command: SettleCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    settlement_driver: &str,
) -> Result<(), CliError> {
    match command {
        SettleCommands::Status { store, json, limit } => {
            let resolved = store.or_else(|| receipt_db.clone());
            match resolved {
                Some(path) => match settle::cmd_settle_status(
                    &path,
                    limit,
                    json || json_output,
                ) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(CliError::Other(format!("settle status: {err}"))),
                },
                None => Err(CliError::Other(
                    "settle status: no store path supplied; pass --store or set --receipt-db"
                        .to_string(),
                )),
            }
        }
        SettleCommands::Drive {
            store,
            iou_issuer_seed_file,
            trusted_kernel_pubkeys,
            trusted_iou_issuer_pubkeys,
            batch,
            json,
        } => {
            match settlement_driver {
                "ops" => {}
                "none" => {
                    return Err(CliError::Other(
                        "settle drive: the settlement driver is disabled; pass \
                         --settlement-driver ops to run the reference driver"
                            .to_string(),
                    ))
                }
                other => {
                    return Err(CliError::Other(format!(
                        "settle drive: unknown settlement driver `{other}` \
                         (expected `none` or `ops`)"
                    )))
                }
            }
            if batch == 0 || batch > crate::types_cli::MAX_SETTLEMENT_CLI_ROWS {
                return Err(CliError::Other(format!(
                    "settle drive: batch must be in 1..={}",
                    crate::types_cli::MAX_SETTLEMENT_CLI_ROWS
                )));
            }
            // Resolve all private signing custody and public trust roots before
            // opening or mutating the receipt database. A malformed or
            // duplicate trust configuration must leave the target store
            // untouched.
            let credentials = load_settlement_drive_credentials(
                &iou_issuer_seed_file,
                &trusted_iou_issuer_pubkeys,
                &trusted_kernel_pubkeys,
            )?;
            let resolved = store.or_else(|| receipt_db.clone());
            match resolved {
                Some(path) => settle::cmd_settle_drive(
                    &path,
                    batch,
                    json || json_output,
                    &credentials.iou_issuer,
                    &credentials.trusted_iou_issuer_keys,
                    &credentials.trusted_kernel_keys,
                )
                .map(|_| ())
                .map_err(|err| CliError::Other(format!("settle drive: {err}"))),
                None => Err(CliError::Other(
                    "settle drive: no store path supplied; pass --store or set --receipt-db"
                        .to_string(),
                )),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod settlement_drive_credentials_tests {
    use super::*;

    fn existing_seed(path: &Path) -> chio_core::Keypair {
        crate::load_or_create_authority_keypair(path).expect("create strict test seed")
    }

    fn drive_command(
        store: PathBuf,
        iou_issuer_seed_file: PathBuf,
        trusted_kernel_pubkeys: Vec<PathBuf>,
    ) -> SettleCommands {
        SettleCommands::Drive {
            store: Some(store),
            iou_issuer_seed_file,
            trusted_kernel_pubkeys,
            trusted_iou_issuer_pubkeys: Vec::new(),
            batch: 1,
            json: false,
        }
    }

    fn dispatch_error(command: SettleCommands) -> CliError {
        match dispatch_settle(command, false, None, "ops") {
            Err(error) => error,
            Ok(()) => panic!("invalid settlement credentials must fail"),
        }
    }

    fn sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }

    fn assert_store_was_not_created(path: &Path) {
        assert!(!path.exists(), "credential failure created the target DB");
        assert!(!sidecar(path, "-wal").exists(), "credential failure created WAL");
        assert!(!sidecar(path, "-shm").exists(), "credential failure created SHM");
    }

    #[test]
    fn duplicate_trusted_kernel_keys_are_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let _issuer = existing_seed(&seed_path);
        let trusted = chio_core::Keypair::from_seed(&[41_u8; 32]).public_key();
        let first_trusted_path = directory.path().join("kernel-current.pub");
        let second_trusted_path = directory.path().join("kernel-duplicate.pub");
        std::fs::write(&first_trusted_path, trusted.to_hex()).expect("write first public key");
        std::fs::write(&second_trusted_path, trusted.to_hex()).expect("write second public key");

        let error = dispatch_error(drive_command(
            store_path.clone(),
            seed_path,
            vec![first_trusted_path, second_trusted_path],
        ));
        assert!(error.to_string().contains("duplicate trusted kernel public key"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn malformed_trusted_kernel_key_is_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let _issuer = existing_seed(&seed_path);
        let trusted_path = directory.path().join("kernel.pub");
        std::fs::write(&trusted_path, "not-a-public-key").expect("write malformed key");

        let error = dispatch_error(drive_command(
            store_path.clone(),
            seed_path,
            vec![trusted_path],
        ));
        assert!(error
            .to_string()
            .contains("failed to load trusted kernel public key"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn missing_trust_root_is_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let _issuer = existing_seed(&seed_path);

        let error = dispatch_error(drive_command(
            store_path.clone(),
            seed_path,
            Vec::new(),
        ));
        assert!(error
            .to_string()
            .contains("at least one --trusted-kernel-pubkey is required"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn missing_iou_issuer_seed_is_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let missing_seed_path = directory.path().join("missing-iou-issuer.seed");
        let trusted_path = directory.path().join("kernel.pub");
        let trusted = chio_core::Keypair::from_seed(&[42_u8; 32]).public_key();
        std::fs::write(&trusted_path, trusted.to_hex()).expect("write public key");

        let error = dispatch_error(drive_command(
            store_path.clone(),
            missing_seed_path,
            vec![trusted_path],
        ));
        assert!(error
            .to_string()
            .contains("failed to load existing IOU issuer seed"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn overlapping_iou_and_kernel_signer_is_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let issuer = existing_seed(&seed_path);
        let trusted_path = directory.path().join("kernel.pub");
        std::fs::write(&trusted_path, issuer.public_key().to_hex()).expect("write public key");

        let error = dispatch_error(drive_command(
            store_path.clone(),
            seed_path,
            vec![trusted_path],
        ));
        assert!(error.to_string().contains("trust domains must be disjoint"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn oversized_public_key_file_is_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let _issuer = existing_seed(&seed_path);
        let trusted_path = directory.path().join("kernel.pub");
        std::fs::write(&trusted_path, vec![b'a'; 16_385]).expect("write oversized key");

        let error = dispatch_error(drive_command(
            store_path.clone(),
            seed_path,
            vec![trusted_path],
        ));
        assert!(error.to_string().contains("exceeds 16384 bytes"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn excessive_trust_roots_are_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let _issuer = existing_seed(&seed_path);
        let trusted_path = directory.path().join("kernel.pub");
        let roots = vec![trusted_path; MAX_SETTLEMENT_TRUST_ROOTS + 1];

        let error = dispatch_error(drive_command(store_path.clone(), seed_path, roots));
        assert!(error.to_string().contains("limited to 256 keys"));
        assert_store_was_not_created(&store_path);
    }

    #[test]
    fn invalid_programmatic_batch_is_rejected_before_store_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store_path = directory.path().join("must-not-exist.sqlite3");
        let seed_path = directory.path().join("iou-issuer.seed");
        let _issuer = existing_seed(&seed_path);
        let trusted_path = directory.path().join("kernel.pub");
        let trusted = chio_core::Keypair::from_seed(&[43_u8; 32]).public_key();
        std::fs::write(&trusted_path, trusted.to_hex()).expect("write public key");
        let mut command = drive_command(store_path.clone(), seed_path, vec![trusted_path]);
        if let SettleCommands::Drive { batch, .. } = &mut command {
            *batch = 0;
        }

        let error = dispatch_error(command);
        assert!(error.to_string().contains("batch must be in"));
        assert_store_was_not_created(&store_path);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_arena(command: ArenaCommands, json_output: bool) -> Result<(), CliError> {
    match command {
        ArenaCommands::Run {
            scenario,
            output_root,
            json,
        } => cmd_arena_run(&scenario, output_root.as_deref(), json || json_output),
        ArenaCommands::Replay {
            scenario_id,
            output_root,
            bundle_dir,
            json,
        } => cmd_arena_replay(
            &scenario_id,
            output_root.as_deref(),
            bundle_dir.as_deref(),
            json || json_output,
        ),
        ArenaCommands::Evolve {
            seed,
            generations,
            wall_seconds,
            output_root,
            json,
        } => cmd_arena_evolve(
            &seed,
            generations,
            wall_seconds,
            output_root.as_deref(),
            json || json_output,
        ),
    }
}
