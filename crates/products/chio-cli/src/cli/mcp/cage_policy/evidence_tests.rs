//! Synthetic signed fixtures check composition, not actual kernel enforcement.
use super::super::tests::{policy, signed_policy};
use super::*;
use chio_cage::*;
use chio_core::{canonical_json_bytes, Ed25519Backend, Keypair};
use chio_manifest::NativeSyscallProfile;
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fixture() -> Result<(NativeLaunchEvidence, McpCageLaunchPolicy, Keypair)> {
    let policy = policy(
        NativeSyscallProfile::NativeMinimalV1,
        NativeSyscallProfile::NativeMinimalV1,
    );
    let signer = Keypair::from_seed(&[91; 32]);
    let registry = resolve_launch_manifest_registry(
        &policy,
        chio_manifest::RuntimeToolTopology::local(),
        None,
        "test",
    )?;
    let manifest = registry.authorize_cage_manifest("cage-policy-test")?;
    let identity = serde_json::from_value(
        json!({"device":1,"inode":2,"mount_id":3,"mode":0o100700,"uid":10001,"gid":10001,"kind":"regular_file"}),
    )?;
    let prepared = EnforcementPrepared {
        schema: ENFORCEMENT_PREPARED_SCHEMA.into(),
        process_id: 42,
        manifest_digest: manifest.manifest_digest().into(),
        profile_digest: "3".repeat(64),
        plan_digest: "4".repeat(64),
        fd_table_digest: "5".repeat(64),
        helper_binding_digest: policy.runtime.cage_init_binding_digest.clone(),
        target_binding_digest: policy.runtime.target_binding_digest.clone(),
        target_identity: identity,
        applied_execution_identity: policy.runtime.execution_identity.clone(),
        nono_version: PINNED_NONO_VERSION.into(),
        nono_patch_version: NONO_PATCH_VERSION.into(),
        landlock_abi: 4,
        landlock_filesystem_status: ObservedRulesetStatus::FullyEnforced,
        landlock_network_status: ObservedRulesetStatus::FullyEnforced,
        seccompiler_version: PINNED_SECCOMPILER_VERSION.into(),
        seccomp_status: SeccompEnforcementStatus::FullyEnforced,
        seccomp_architecture: SandboxArchitecture::X86_64,
        seccomp_filter_digest: "6".repeat(64),
        trace_session_digest: "7".repeat(64),
        prepared_at_unix_ms: 1100,
    };
    let full = FullyEnforcedEvidence::new(
        prepared,
        ExecTransitionObserved {
            schema: EXEC_TRANSITION_OBSERVED_SCHEMA.into(),
            process_id: 42,
            trace_session_digest: "7".repeat(64),
            target_binding_digest: policy.runtime.target_binding_digest.clone(),
            target_identity: identity,
            observed_at_unix_ms: 1200,
        },
        true,
    )?;
    let signed_policy = String::from_utf8(canonical_json_bytes(&signed_policy(
        policy.clone(),
        &signer,
    ))?)?;
    let context = CageReceiptSigningContext::new(
        policy.receipt.capability_id.clone(),
        "cage-policy-test",
        "cage-launch",
        "3".repeat(64),
        policy.receipt.tenant_id.clone(),
    )?
    .with_admitted_policy_digest(chio_core::sha256_hex(signed_policy.as_bytes()))?;
    let backend = Ed25519Backend::new(signer.clone());
    let enforcement = sign_cage_receipt(
        CageReceiptBody::new(
            "attempt-1",
            None,
            CageEnforcementRecord::fully_enforced(full.clone())?,
            1000,
            1300,
        )?,
        &context,
        &backend,
    )?;
    let terminal = sign_cage_receipt(
        CageReceiptBody::new(
            "attempt-1",
            None,
            CageEnforcementRecord::exited(
                full,
                ProcessExitEvidence {
                    process_id: 42,
                    exit_code: Some(0),
                    signal: None,
                    exited_at_unix_ms: 2000,
                },
            )?,
            1000,
            2100,
        )?,
        &context,
        &backend,
    )?;
    Ok((
        NativeLaunchEvidence {
            signed_policy,
            enforcement,
            terminal,
        },
        policy,
        signer,
    ))
}

#[test]
fn native_run_evidence_requires_external_policy_pin_and_same_observed_launch() -> Result {
    let (evidence, policy, signer) = fixture()?;
    let verify = |evidence: &NativeLaunchEvidence| {
        verify_native_launch_evidence(evidence, "cage-policy-test", &signer.public_key())
    };
    let window = verify(&evidence)?;
    assert_eq!(window.started_at_unix_ms, 1300);
    assert_eq!(window.exited_at_unix_ms, 2000);
    assert_eq!(window.tools, BTreeSet::from(["echo".into()]));
    assert!(verify_native_launch_evidence(
        &evidence,
        "cage-policy-test",
        &Keypair::from_seed(&[92; 32]).public_key()
    )
    .is_err());
    assert!(
        verify_native_launch_evidence(&evidence, "other-server", &signer.public_key()).is_err()
    );
    for field in ["helper", "target", "identity", "stage"] {
        let mut policy = policy.clone();
        match field {
            "helper" => policy.runtime.cage_init_binding_digest = "a".repeat(64),
            "target" => policy.runtime.target_binding_digest = "b".repeat(64),
            "identity" => {
                policy.runtime.execution_identity = ExecutionIdentity::new(20001, 20001, vec![])?
            }
            _ => {
                policy.enterprise_migration.stage =
                    chio_security_types::EnterpriseMigrationStage::Disabled
            }
        }
        let mut changed = evidence.clone();
        changed.signed_policy =
            String::from_utf8(canonical_json_bytes(&signed_policy(policy, &signer))?)?;
        assert!(verify(&changed).is_err(), "accepted substituted {field}");
    }
    let mut changed = evidence.clone();
    let mut terminal = verify_signed_cage_receipt(&evidence.terminal)?;
    terminal.attempt_id = "another-launch".into();
    let context = CageReceiptSigningContext::new(
        policy.receipt.capability_id.clone(),
        "cage-policy-test",
        "cage-launch",
        "3".repeat(64),
        policy.receipt.tenant_id.clone(),
    )?
    .with_admitted_policy_digest(chio_core::sha256_hex(evidence.signed_policy.as_bytes()))?;
    // The complete-policy commitment supplements the observed executable and
    // execution-identity checks. A matching policy tag alone is insufficient.
    for field in ["helper", "target", "identity"] {
        let mut observed = verify_signed_cage_receipt(&evidence.enforcement)?;
        let full = observed
            .enforcement_record
            .fully_enforced
            .as_mut()
            .ok_or("full enforcement")?;
        match field {
            "helper" => full.prepared.helper_binding_digest = "a".repeat(64),
            "target" => {
                full.prepared.target_binding_digest = "b".repeat(64);
                full.exec_transition.target_binding_digest = "b".repeat(64);
            }
            _ => {
                full.prepared.applied_execution_identity =
                    ExecutionIdentity::new(20001, 20001, vec![])?;
            }
        }
        observed.bindings = Some(CageReceiptBindings::from_prepared(&full.prepared));
        let receipt = sign_cage_receipt(observed, &context, &Ed25519Backend::new(signer.clone()))?;
        let error = verify_policy_bound_enforcement(
            &evidence.signed_policy,
            &receipt,
            "cage-policy-test",
            &signer.public_key(),
            false,
        )
        .err()
        .ok_or("accepted mismatched observed launch")?;
        assert!(
            error.to_string().contains("observed launch differs"),
            "{field}: {error}"
        );
    }
    changed.terminal = sign_cage_receipt(terminal, &context, &Ed25519Backend::new(signer.clone()))?;
    assert!(verify(&changed).is_err());
    Ok(())
}

#[test]
fn native_start_verification_binds_original_receipt_without_claiming_exit() -> Result {
    let (evidence, policy, signer) = fixture()?;
    let directory = tempfile::tempdir()?;
    let policy_path = directory.path().join("policy.json");
    let receipt_path = directory.path().join("receipt.json");
    std::fs::write(&policy_path, &evidence.signed_policy)?;
    std::fs::write(&receipt_path, canonical_json_bytes(&evidence.enforcement)?)?;
    let pin = signer.public_key().to_hex();
    let target = &policy.runtime.target_binding_digest;
    let verify = |server: &str, key: &str, id: &str, target: &str| {
        verify_native_start_file(&policy_path, &receipt_path, server, key, id, target)
    };
    verify("cage-policy-test", &pin, &evidence.enforcement.id, target)?;
    assert!(verify("other-server", &pin, &evidence.enforcement.id, target).is_err());
    assert!(verify(
        "cage-policy-test",
        &Keypair::from_seed(&[92; 32]).public_key().to_hex(),
        &evidence.enforcement.id,
        target,
    )
    .is_err());
    assert!(verify("cage-policy-test", &pin, &"a".repeat(64), target).is_err());
    assert!(verify(
        "cage-policy-test",
        &pin,
        &evidence.enforcement.id,
        &"b".repeat(64)
    )
    .is_err());

    // A valid signed exit is not the selected original enforcement receipt.
    std::fs::write(&receipt_path, canonical_json_bytes(&evidence.terminal)?)?;
    assert!(verify("cage-policy-test", &pin, &evidence.terminal.id, target).is_err());
    let mut changed = serde_json::to_value(&evidence.enforcement)?;
    changed["invented_field"] = json!(true);
    std::fs::write(&receipt_path, serde_json::to_vec(&changed)?)?;
    assert!(verify("cage-policy-test", &pin, &evidence.enforcement.id, target).is_err());
    Ok(())
}

#[test]
fn native_policy_substitutions_by_the_same_operator_fail_all_verifiers() -> Result {
    let (evidence, policy, signer) = fixture()?;
    let directory = tempfile::tempdir()?;
    let policy_path = directory.path().join("policy.json");
    let receipt_path = directory.path().join("receipt.json");
    let original_receipt = canonical_json_bytes(&evidence.enforcement)?;
    std::fs::write(&receipt_path, &original_receipt)?;
    for field in [
        "argv",
        "cwd",
        "limits",
        "timeout",
        "ceilings",
        "receipt",
        "migration",
    ] {
        let mut alternate = policy.clone();
        match field {
            "argv" => alternate
                .runtime
                .target_argv
                .push("--different-behavior".into()),
            "cwd" => alternate.runtime.working_directory = "/different-directory".into(),
            "limits" => {
                alternate.limits.nofile_soft = 32;
                alternate.limits.nofile_hard = 32;
            }
            "timeout" => alternate.limits.launch_timeout_ms += 1,
            "ceilings" => {
                alternate
                    .operator_ceilings
                    .forbidden_paths
                    .insert("/another-path".into());
            }
            "receipt" => alternate.receipt.database_path = "/another-receipt-store".into(),
            _ => {
                alternate.enterprise_migration.state_database_path =
                    "/another-migration-store".into()
            }
        }
        let mut changed = evidence.clone();
        changed.signed_policy =
            String::from_utf8(canonical_json_bytes(&signed_policy(alternate, &signer))?)?;
        // A valid signature by the same trusted operator must not authorize
        // associating a different configuration with this unchanged launch.
        decode_cage_policy(
            &policy_path,
            changed.signed_policy.as_bytes(),
            &signer.public_key(),
        )?;
        std::fs::write(&policy_path, &changed.signed_policy)?;
        let error = verify_native_start_file(
            &policy_path,
            &receipt_path,
            "cage-policy-test",
            &signer.public_key().to_hex(),
            &evidence.enforcement.id,
            &policy.runtime.target_binding_digest,
        )
        .err()
        .ok_or("accepted alternate policy")?;
        assert!(
            error
                .to_string()
                .contains("complete admitted signed policy"),
            "{field}: {error}"
        );
        assert!(
            verify_native_launch_evidence(&changed, "cage-policy-test", &signer.public_key())
                .is_err(),
            "{field}"
        );
        let observed = NativeLaunchObservation {
            signed_policy: changed.signed_policy,
            enforcement: changed.enforcement,
            terminal: None,
        };
        assert!(
            verify_native_launch_observation(&observed, "cage-policy-test", &signer.public_key())
                .is_err(),
            "{field}"
        );
        assert_eq!(std::fs::read(&receipt_path)?, original_receipt);
    }
    // A fresh policy signer also cannot relabel the original signed launch.
    let replacement = Keypair::from_seed(&[93; 32]);
    let mut changed = evidence.clone();
    changed.signed_policy =
        String::from_utf8(canonical_json_bytes(&signed_policy(policy, &replacement))?)?;
    assert!(
        verify_native_launch_evidence(&changed, "cage-policy-test", &replacement.public_key())
            .is_err()
    );
    Ok(())
}

#[test]
fn native_policy_verification_rejects_legacy_and_mismatched_terminal_commitments() -> Result {
    let (mut evidence, policy, signer) = fixture()?;
    let legacy_context = CageReceiptSigningContext::new(
        policy.receipt.capability_id,
        "cage-policy-test",
        "cage-launch",
        "3".repeat(64),
        policy.receipt.tenant_id,
    )?;
    let backend = Ed25519Backend::new(signer.clone());
    let mut terminal = verify_signed_cage_receipt(&evidence.terminal)?;
    terminal.admitted_policy_digest = None;
    evidence.terminal = sign_cage_receipt(terminal.clone(), &legacy_context, &backend)?;
    assert!(
        verify_native_launch_evidence(&evidence, "cage-policy-test", &signer.public_key()).is_err()
    );
    let alternate = legacy_context
        .clone()
        .with_admitted_policy_digest("a".repeat(64))?;
    evidence.terminal = sign_cage_receipt(terminal, &alternate, &backend)?;
    assert!(
        verify_native_launch_evidence(&evidence, "cage-policy-test", &signer.public_key()).is_err()
    );
    let mut legacy = verify_signed_cage_receipt(&evidence.enforcement)?;
    legacy.admitted_policy_digest = None;
    evidence.enforcement = sign_cage_receipt(legacy, &legacy_context, &backend)?;
    let error = verify_policy_bound_enforcement(
        &evidence.signed_policy,
        &evidence.enforcement,
        "cage-policy-test",
        &signer.public_key(),
        false,
    )
    .err()
    .ok_or("legacy receipt proved complete policy")?;
    assert!(error
        .to_string()
        .contains("complete admitted signed policy"));
    Ok(())
}

#[test]
fn native_observation_keeps_missing_exit_distinct_and_rejects_substituted_terminal() -> Result {
    let (evidence, policy, signer) = fixture()?;
    let mut observed = NativeLaunchObservation {
        signed_policy: evidence.signed_policy,
        enforcement: evidence.enforcement,
        terminal: None,
    };
    let verify = |value: &NativeLaunchObservation| {
        verify_native_launch_observation(value, "cage-policy-test", &signer.public_key())
    };
    let start = verify(&observed)?;
    assert_eq!(start.started_at_unix_ms, 1300);
    assert_eq!(start.exited_at_unix_ms, None);
    assert!(verify_native_launch_observation(
        &observed,
        "cage-policy-test",
        &Keypair::from_seed(&[92; 32]).public_key()
    )
    .is_err());
    observed.terminal = Some(evidence.terminal.clone());
    assert_eq!(verify(&observed)?.exited_at_unix_ms, Some(2000));

    let mut terminal = verify_signed_cage_receipt(&evidence.terminal)?;
    terminal.attempt_id = "unrelated-attempt".into();
    let context = CageReceiptSigningContext::new(
        policy.receipt.capability_id,
        "cage-policy-test",
        "cage-launch",
        "3".repeat(64),
        policy.receipt.tenant_id,
    )?
    .with_admitted_policy_digest(chio_core::sha256_hex(observed.signed_policy.as_bytes()))?;
    observed.terminal = Some(sign_cage_receipt(
        terminal,
        &context,
        &Ed25519Backend::new(signer.clone()),
    )?);
    assert!(verify(&observed).is_err());
    observed.terminal = Some(observed.enforcement.clone());
    assert!(verify(&observed).is_err());
    Ok(())
}
