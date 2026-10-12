use super::*;
use crate::formal_mirrors::{check_entries, compute_from_source, RecordedSymbolDigest};

fn entries() -> Vec<MirrorEntry> {
    // Several coverage groups can constrain the same model/source pair.
    // The manifest permits only one entry for that pair, with the union
    // of its required symbols. Fixtures must obey the same contract.
    let mut entries = std::collections::BTreeMap::new();
    for (model, sources) in REQUIRED_COVERAGE {
        for source in *sources {
            let entry = entries
                .entry((*model, source.path))
                .or_insert_with(|| MirrorEntry {
                    model_file: (*model).to_owned(),
                    model_kind: ModelKind::Tla,
                    relationship: MirrorRelationship::AbstractionAnchor,
                    rust_source: source.path.to_owned(),
                    rust_symbols: Vec::new(),
                    normalized_sha256: String::new(),
                    symbol_sha256: Vec::new(),
                });
            for symbol in source.symbols {
                if !entry.rust_symbols.iter().any(|name| name == symbol) {
                    entry.rust_symbols.push((*symbol).to_owned());
                }
            }
        }
    }
    entries.into_values().collect()
}

#[test]
fn overlapping_coverage_groups_require_one_complete_manifest_entry() -> Result<(), String> {
    let entries = entries();
    let mut pairs = std::collections::BTreeSet::new();
    for entry in &entries {
        assert!(pairs.insert((&entry.model_file, &entry.rust_source)));
    }
    let entry = entries
        .iter()
        .find(|entry| {
            entry.model_file == "formal/apalache/PostAdmissionDropGuard.tla"
                && entry.rust_source
                    == "crates/kernel/chio-kernel/src/kernel/credential_reservation.rs"
        })
        .ok_or("shared credential source is missing")?;
    for required in [
        "DispatchCredentialReservation::requires_post_reservation_revalidation",
        "DispatchCredentialReservation::rollback_entries",
    ] {
        assert!(entry.rust_symbols.iter().any(|symbol| symbol == required));
    }
    Ok(())
}

#[test]
fn complete_dispatch_coverage_is_accepted() {
    assert!(validate(&entries()).is_ok());
}

#[test]
fn checked_in_manifest_covers_required_dispatch_implementations() -> Result<(), String> {
    let root = crate::workspace_root().map_err(|error| error.to_string())?;
    let raw = std::fs::read_to_string(root.join(super::super::MANIFEST_PATH))
        .map_err(|error| error.to_string())?;
    validate(&super::super::parse_manifest(&raw)?)
}

#[test]
fn required_dispatch_anchors_resolve_production_symbols() -> Result<(), String> {
    let root = crate::workspace_root().map_err(|error| error.to_string())?;
    // A manifest and its coverage contract can drift together after a source
    // deletion. Resolve every required symbol against the current Rust body.
    for entry in entries() {
        super::super::compute_entry(&entry, &root)?;
    }
    Ok(())
}

#[test]
fn standalone_nonce_ownership_and_reservation_body_edits_drift() -> Result<(), String> {
    let root = crate::workspace_root().map_err(|error| error.to_string())?;
    for (path, symbol, before, after) in [
        (
            "crates/kernel/chio-kernel/src/execution_nonce/store.rs",
            "InMemoryExecutionNonceStore::reserve_signed",
            "if retain_until <= now {",
            "if retain_until < now {",
        ),
        (
            "crates/kernel/chio-kernel/src/execution_nonce/store.rs",
            "InMemoryExecutionNonceStore::rollback_dispatch_reservation",
            "entry.reservation_id.as_deref() == Some(owner)",
            "entry.reservation_id.is_some()",
        ),
        (
            "crates/platform/chio-store-sqlite/src/execution_nonce_store.rs",
            "SqliteExecutionNonceStore::try_reserve_entry_with_clock_policy",
            "if signed_expires_at <= updated_high_water {",
            "if signed_expires_at < updated_high_water {",
        ),
        (
            "crates/platform/chio-store-sqlite/src/execution_nonce_store.rs",
            "SqliteExecutionNonceStore::rollback_dispatch_reservation",
            "WHERE nonce_id = ?1 AND dispatch_reservation_id = ?2",
            "WHERE nonce_id = ?1",
        ),
    ] {
        let mut entry = entries()
            .into_iter()
            .find(|entry| {
                entry.rust_source == path && entry.rust_symbols.iter().any(|name| name == symbol)
            })
            .ok_or_else(|| format!("standalone nonce implementation anchor missing: {path}"))?;
        let source = std::fs::read_to_string(root.join(path)).map_err(|error| error.to_string())?;
        assert_eq!(
            source.matches(before).count(),
            1,
            "mutation site: {path}::{symbol}"
        );
        let original = compute_from_source(&entry, &source)?;
        entry.normalized_sha256 = original.normalized_sha256;
        entry.symbol_sha256 = original
            .symbols
            .iter()
            .map(|digest| RecordedSymbolDigest {
                symbol: digest.symbol.clone(),
                sha256: digest.sha256.clone(),
            })
            .collect();
        let changed = compute_from_source(&entry, &source.replacen(before, after, 1))?;
        let Err(error) = check_entries(&[entry], &[changed]) else {
            panic!("standalone nonce implementation drift must reject: {path}::{symbol}");
        };
        assert!(
            error.contains(&format!("changed symbol:  {symbol}")),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn extracted_validators_and_drop_clock_failures_remain_drift_guarded() -> Result<(), String> {
    let root = crate::workspace_root().map_err(|error| error.to_string())?;
    for (path, symbol, before, after) in [
        (
            "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/delta.rs",
            "READ_FACTOR",
            "const READ_FACTOR: u64 = 2;",
            "const READ_FACTOR: u64 = 3;",
        ),
        (
            "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/delta.rs",
            "MAX_TOMBSTONES",
            "const MAX_TOMBSTONES: usize = 256;",
            "const MAX_TOMBSTONES: usize = 512;",
        ),
        (
            "crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs",
            "PostAdmissionDropGuard::record_pre_dispatch_cleanup_fault_receipt",
            "trusted_now_millis().and_then(|now| {",
            "trusted_now_millis().or_else(|_| Ok(UnixMillis::new(0))).and_then(|now| {",
        ),
        (
            "crates/kernel/chio-kernel/src/kernel/effect_obligation.rs",
            "PostEffectObligation::fail",
            "read_authority_time()",
            "read_authority_time().or_else(|_| Ok(UnixMillis::new(0)))",
        ),
        (
            "crates/kernel/chio-kernel/src/kernel/clock.rs",
            "read",
            "Ok(read_fenced(clock, fence)?.unix_millis())",
            "Ok(UnixMillis::new(0))",
        ),
        (
            "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/record.rs",
            "Record::validate_initialized",
            "if self.authority != initialized.authority {",
            "if false {",
        ),
        (
            "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/record.rs",
            "Record::validate_initialized",
            "if self.authority != initialized.authority {",
            "if false {",
        ),
        (
            "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/record.rs",
            "Record::validate_initialized",
            "if self.authority != initialized.authority {",
            "if false {",
        ),
    ] {
        let mut entry = entries()
            .into_iter()
            .find(|entry| {
                entry.rust_source == path && entry.rust_symbols.iter().any(|name| name == symbol)
            })
            .ok_or_else(|| format!("implementation anchor missing: {path}"))?;
        let source =
            std::fs::read_to_string(root.join(path)).map_err(|error| error.to_string())?;
        assert!(source.contains(before), "mutation site: {path}::{symbol}");
        let original = compute_from_source(&entry, &source)?;
        entry.normalized_sha256 = original.normalized_sha256;
        entry.symbol_sha256 = original
            .symbols
            .iter()
            .map(|digest| RecordedSymbolDigest {
                symbol: digest.symbol.clone(),
                sha256: digest.sha256.clone(),
            })
            .collect();
        let changed = compute_from_source(&entry, &source.replace(before, after))?;
        let Err(error) = check_entries(&[entry], &[changed]) else {
            panic!("implementation drift must reject: {path}::{symbol}");
        };
        assert!(error.contains(&format!("changed symbol:  {symbol}")), "{error}");
    }
    Ok(())
}

#[test]
fn every_required_symbol_is_independently_enforced() {
    let original = entries();
    for (index, entry) in original.iter().enumerate() {
        for symbol in &entry.rust_symbols {
            let mut mutated = original.clone();
            mutated[index].rust_symbols.retain(|name| name != symbol);
            let Err(error) = validate(&mutated) else {
                panic!("missing implementation must reject");
            };
            assert!(error.contains(&entry.model_file), "{error}");
            assert!(error.contains(&entry.rust_source), "{error}");
            assert!(error.contains(symbol), "{error}");
        }
    }
}

#[test]
fn wrong_model_source_or_relationship_cannot_satisfy_coverage() {
    #[derive(Debug)]
    enum Field {
        Model,
        Source,
        Relationship,
        Kind,
    }
    for field in [
        Field::Model,
        Field::Source,
        Field::Relationship,
        Field::Kind,
    ] {
        let mut mutated = entries();
        match field {
            Field::Model => mutated[0].model_file.push_str(".other"),
            Field::Source => mutated[0].rust_source.push_str(".other"),
            Field::Relationship => {
                mutated[0].relationship = MirrorRelationship::Transliteration;
            }
            Field::Kind => mutated[0].model_kind = ModelKind::Lean,
        }
        assert!(validate(&mutated).is_err(), "accepted mismatched {field:?}");
    }
}

#[test]
fn implementation_edits_drift_even_when_forwarder_is_unchanged() -> Result<(), String> {
    let forwarder = entries()
        .into_iter()
        .find(|entry| {
            entry.model_file == "formal/tla/RevocationPropagation.tla"
                && entry.rust_source
                    == "crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_entry.rs"
        })
        .ok_or("async evaluation forwarding anchor missing")?;
    let mut entry = entries()
        .into_iter()
        .find(|entry| {
            entry.model_file == "formal/tla/RevocationPropagation.tla"
                && entry.rust_source
                    == "crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs"
        })
        .ok_or("async evaluation implementation anchor missing")?;
    let original = r#"
        struct ChioKernel;
        impl ChioKernel {
            async fn evaluate_tool_call_async_with_session_context(&self) -> bool {
                self.evaluate_tool_call_async_with_session_context_scoped().await
            }
            async fn evaluate_tool_call_async_with_session_context_scoped(&self) -> bool {
                true
            }
        }
    "#;
    let before = compute_from_source(&entry, original)?;
    entry.normalized_sha256 = before.normalized_sha256;
    entry.symbol_sha256 = before
        .symbols
        .iter()
        .map(|digest| RecordedSymbolDigest {
            symbol: digest.symbol.clone(),
            sha256: digest.sha256.clone(),
        })
        .collect();
    let after = compute_from_source(&entry, &original.replace("true", "false"))?;
    assert_eq!(
        compute_from_source(&forwarder, original)?.normalized_sha256,
        compute_from_source(&forwarder, &original.replace("true", "false"))?.normalized_sha256,
    );
    let Err(error) = check_entries(&[entry], &[after]) else {
        panic!("implementation drift must reject");
    };
    assert!(error.contains(
        "changed symbol:  ChioKernel::evaluate_tool_call_async_with_session_context_scoped"
    ));
    Ok(())
}
