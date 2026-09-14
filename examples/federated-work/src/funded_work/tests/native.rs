use super::*;
use crate::funded_work::{
    agreement::*,
    native::Native,
    observer::{FundingSource, Observation},
};
use chio_core_types::Keypair;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

pub(super) struct Source(pub Mutex<Observation>, pub AtomicBool);
impl FundingSource for Source {
    fn observe(&self, _allocation: &str) -> Result<Observation> {
        if !self.1.load(Ordering::SeqCst) {
            return Err("observer unavailable".into());
        }
        Ok(self.0.lock().map_err(|_| "poisoned fixture")?.clone())
    }
}

pub(super) struct Fixture {
    pub directory: tempfile::TempDir,
    pub native: Native,
    pub source: Arc<Source>,
    pub agreement: SignedAgreement,
    pub request: chio_kernel::ToolCallRequest,
    pub buyer: Keypair,
}

pub(super) fn fixture() -> Result<Fixture> {
    let (domain, terms, observation, _) = super::observer::fixture()?;
    let directory = tempfile::tempdir()?;
    let buyer = Keypair::generate();
    Native::provision(directory.path(), buyer.public_key(), domain.clone())?;
    let source = Arc::new(Source(Mutex::new(observation), AtomicBool::new(true)));
    let native = Native::open(directory.path(), source.clone())?;
    let request = native.request(
        "funded-native-1",
        include_str!("../../../fixtures/openapi.json"),
        terms.submit_by,
    )?;
    let agreement = Agreement {
        schema: AGREEMENT_SCHEMA.into(),
        policy_sha256: crate::common::digest(&native.policy)?,
        authority_uuid: native.policy.authority_uuid.clone(),
        buyer_key: buyer.public_key(),
        provider_key: native.policy.provider_key.clone(),
        request_id: request.request_id.clone(),
        request_sha256: crate::common::digest(&request)?,
        domain: domain.clone(),
        work: WorkTerms {
            payer: terms.payer,
            beneficiary: terms.beneficiary,
            verifier: terms.verifier,
            amount: "100".into(),
            submit_by: terms.submit_by,
            challenge_until: terms.challenge_until,
            resolve_by: terms.resolve_by,
            refund_after: terms.refund_after,
        },
    }
    .sign(&buyer, &crate::common::key(directory.path())?)?;
    bind_observation(&source, &agreement)?;
    Ok(Fixture {
        directory,
        native,
        source,
        agreement,
        request,
        buyer,
    })
}

fn bind_observation(source: &Source, agreement: &SignedAgreement) -> Result<()> {
    let domain = &agreement.body.domain;
    let terms = agreement.body.terms()?;
    let id = allocation_id(&domain.chain_id, &domain.escrow, &terms)?;
    {
        use alloy_sol_types::SolValue;
        let mut observed = source.0.lock().map_err(|_| "poisoned fixture")?;
        observed.receipt.logs[0].topics[1] = id.clone();
        observed.receipt.logs[0].topics[2] = terms.agreement_digest.clone();
        let bytes = alloy_primitives::hex::decode(&observed.work.return_data[2..])?;
        let mut work = AbiWork::abi_decode_validate(&bytes)?;
        work.terms = terms.abi(&domain.escrow)?;
        observed.work.return_data =
            format!("0x{}", alloy_primitives::hex::encode(work.abi_encode()));
        observed.work.call_data.replace_range(10.., &id[2..]);
    }
    Ok(())
}

#[test]
fn verified_funding_creates_one_native_operation_and_hold() -> Result<()> {
    let f = fixture()?;
    let result = f.native.execute(&f.agreement, &f.request)?;
    assert_eq!(result["executions"], 1);
    assert_eq!(result["paymentState"], "pending");
    assert!(result["operationId"]
        .as_str()
        .is_some_and(|id| id.len() == 64));
    assert!(result["holdId"].as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(result["externalFundsTransferred"], false);
    assert_eq!(native_counts(&f)?, (1, 1));
    Ok(())
}

fn native_counts(f: &Fixture) -> Result<(i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        f.directory.path().join("authority.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok((
        connection.query_row("SELECT count(*) FROM admission_operations", [], |r| {
            r.get(0)
        })?,
        connection.query_row("SELECT count(*) FROM budget_authorization_holds", [], |r| {
            r.get(0)
        })?,
    ))
}

#[test]
fn observation_lost_during_authorization_keeps_original_native_identity() -> Result<()> {
    use std::sync::atomic::AtomicUsize;
    struct Once(Arc<Source>, AtomicUsize);
    impl FundingSource for Once {
        fn observe(&self, allocation: &str) -> Result<Observation> {
            if self.1.fetch_add(1, Ordering::SeqCst) == 0 {
                self.0.observe(allocation)
            } else {
                Err("lost observation during native authorization".into())
            }
        }
    }
    let f = fixture()?;
    let Fixture {
        directory,
        native,
        source,
        agreement,
        request,
        ..
    } = f;
    drop(native);
    let native = Native::open(
        directory.path(),
        Arc::new(Once(source.clone(), AtomicUsize::new(0))),
    )?;
    let first = native.execute(&agreement, &request)?;
    assert_eq!(first["executions"], 0);
    assert_eq!(first["fundingCorrelation"], "not_authorized");
    assert!(first["authorizationId"].is_null());
    assert!(first["holdId"].is_string());
    drop(native);
    let native = Native::open(directory.path(), source)?;
    let replay = native.execute(&agreement, &request)?;
    assert_eq!(replay["operationId"], first["operationId"]);
    assert_eq!(replay["holdId"], first["holdId"]);
    assert_eq!(replay["executions"], 0);
    assert_eq!(replay["nativePaymentState"], "Closed");
    assert!(replay["nativeAuthorizationId"].is_null());
    assert_eq!(replay["paymentState"], "not_authorized");
    Ok(())
}

#[test]
fn admission_without_a_payment_participant_remains_inspectable() -> Result<()> {
    let mut f = fixture()?;
    f.native.execute(&f.agreement, &f.request)?;
    // A separately funded request cannot spend the same one-invocation native
    // capability again. Exercise the real budget refusal after native begin.
    f.request.request_id = "funded-but-budget-exhausted".into();
    let mut body = f.agreement.body.clone();
    body.request_id = f.request.request_id.clone();
    body.request_sha256 = crate::common::digest(&f.request)?;
    f.agreement = body.sign(&f.buyer, &crate::common::key(f.directory.path())?)?;
    bind_observation(&f.source, &f.agreement)?;
    let first = f.native.execute(&f.agreement, &f.request)?;
    assert!(first["operationId"].is_string());
    assert!(first["holdId"].is_null());
    assert!(first["nativePaymentState"].is_null());
    assert!(first["authorizationId"].is_null());
    assert_eq!(first["fundingCorrelation"], "not_authorized");
    assert_eq!(first["executions"], 1);
    assert_eq!(native_counts(&f)?, (2, 1));
    drop(f.native);
    let native = Native::open(f.directory.path(), f.source)?;
    let replay = native.execute(&f.agreement, &f.request)?;
    assert_eq!(replay["operationId"], first["operationId"]);
    assert_eq!(replay["executions"], 1);
    assert!(replay["holdId"].is_null());
    Ok(())
}

#[test]
fn invalid_observations_deny_before_any_native_operation_hold_or_dispatch() -> Result<()> {
    use alloy_primitives::U256;
    use alloy_sol_types::SolValue;
    let f = fixture()?;
    let valid = f.source.0.lock().map_err(|_| "fixture lock")?.clone();
    for case in 0..22 {
        let mut changed = valid.clone();
        let label = match case {
            0 => {
                changed.chain_id = "1".into();
                "wrong chain"
            }
            1 => {
                changed.genesis_hash = format!("0x{}", "c".repeat(64));
                "wrong genesis"
            }
            2 => {
                changed.escrow_code = "0x6001".into();
                "changed escrow code"
            }
            3 => {
                changed.token_code = "0x6001".into();
                "changed token code"
            }
            4 => {
                changed.ancestry.pop();
                "unconfirmed deposit"
            }
            5 => {
                changed.receipt.status = 0;
                "reverted deposit"
            }
            6 => {
                changed.receipt.from = f.agreement.body.work.beneficiary.clone();
                "wrong payer"
            }
            7 => {
                changed.receipt.to = f.agreement.body.domain.token.clone();
                "wrong contract"
            }
            8 => {
                changed.receipt.block_number += 1;
                "wrong receipt block"
            }
            9 => {
                changed.receipt.logs[0].topics[1] = format!("0x{}", "d".repeat(64));
                "another allocation"
            }
            10 => {
                changed.receipt.logs[0].topics[2] = format!("0x{}", "d".repeat(64));
                "another agreement"
            }
            11 => {
                changed.receipt.logs[1].data = format!("0x{:064x}", 99);
                "short token transfer"
            }
            12 => {
                changed.receipt.logs[0].address = f.agreement.body.domain.token.clone();
                "forged event emitter"
            }
            13 => {
                changed.work.block_hash = format!("0x{}", "d".repeat(64));
                "unpinned state"
            }
            14 => {
                changed.work.return_data.push_str("00");
                "trailing ABI bytes"
            }
            15 => {
                changed.balance.return_data = format!("0x{:064x}", 99);
                "underbacked allocation"
            }
            16 => {
                changed.ancestry[1].parent_hash = format!("0x{}", "d".repeat(64));
                "broken ancestry"
            }
            17 => {
                changed.independent_head.hash = format!("0x{}", "d".repeat(64));
                "changed head"
            }
            18 => {
                for b in &mut changed.ancestry {
                    b.timestamp -= 120;
                }
                changed.independent_head.timestamp -= 120;
                "stale chain with fresh observation"
            }
            19 => {
                changed.work.call_data.replace_range(..10, "0x70a08231");
                "substituted state call"
            }
            20 | 21 => {
                let bytes = alloy_primitives::hex::decode(&changed.work.return_data[2..])?;
                let mut work = AbiWork::abi_decode_validate(&bytes)?;
                if case == 20 {
                    work.terms.amount = U256::from(101);
                } else {
                    work.state = 2;
                }
                changed.work.return_data =
                    format!("0x{}", alloy_primitives::hex::encode(work.abi_encode()));
                if case == 20 {
                    "wrong state amount"
                } else {
                    "already claimed allocation"
                }
            }
            _ => return Err("unknown case".into()),
        };
        *f.source.0.lock().map_err(|_| "fixture lock")? = changed;
        assert!(
            f.native.execute(&f.agreement, &f.request).is_err(),
            "accepted {label}"
        );
        assert_eq!(native_counts(&f)?, (0, 0), "reserved for {label}");
        assert_eq!(
            f.native.journal.execution_count()?,
            0,
            "dispatched for {label}"
        );
    }
    *f.source.0.lock().map_err(|_| "fixture lock")? = valid;
    assert_eq!(f.native.execute(&f.agreement, &f.request)?["executions"], 1);
    Ok(())
}

#[test]
fn changed_request_and_unavailable_observer_cannot_reserve() -> Result<()> {
    let f = fixture()?;
    let mut changed = f.request.clone();
    changed.request_id = "another-native-request".into();
    assert!(f.native.execute(&f.agreement, &changed).is_err());
    changed = f.request.clone();
    changed.arguments["input"] = serde_json::json!("{}");
    assert!(f.native.execute(&f.agreement, &changed).is_err());
    f.source.1.store(false, Ordering::SeqCst);
    assert!(f.native.execute(&f.agreement, &f.request).is_err());
    assert_eq!(native_counts(&f)?, (0, 0));
    assert_eq!(f.native.journal.execution_count()?, 0);
    Ok(())
}

#[test]
fn fresh_native_authority_cannot_inherit_funded_agreement() -> Result<()> {
    let f = fixture()?;
    let fresh = tempfile::tempdir()?;
    Native::provision(
        fresh.path(),
        f.buyer.public_key(),
        f.agreement.body.domain.clone(),
    )?;
    // Copy the original receiver policy and key, keeping the freshly provisioned
    // native database intact. Failure must be the authoritative store identity.
    for name in ["funding-policy.json", "key.seed"] {
        std::fs::copy(f.directory.path().join(name), fresh.path().join(name))?;
    }
    let error = Native::open(fresh.path(), f.source.clone())
        .err()
        .ok_or("fresh authority was accepted")?;
    assert!(
        error.to_string().contains("does not bind this authority"),
        "{error}"
    );
    assert_eq!(native_counts(&f)?, (0, 0));
    Ok(())
}

#[test]
fn restart_and_replay_preserve_one_operation_and_original_hold() -> Result<()> {
    let f = fixture()?;
    let first = f.native.execute(&f.agreement, &f.request)?;
    let replay = f.native.execute(&f.agreement, &f.request)?;
    for field in ["operationId", "holdId", "authorizationId"] {
        assert_eq!(first[field], replay[field]);
    }
    assert_eq!(replay["executions"], 1);
    let Fixture {
        directory,
        native,
        source,
        agreement,
        request,
        ..
    } = f;
    drop(native);
    source.1.store(false, Ordering::SeqCst);
    let recovered = Native::open(directory.path(), source)?;
    let replay = recovered.execute(&agreement, &request)?;
    for field in ["operationId", "holdId", "authorizationId"] {
        assert_eq!(first[field], replay[field]);
    }
    assert_eq!(replay["executions"], 1);
    assert_eq!(replay["paymentState"], "pending");
    Ok(())
}

#[test]
fn resigning_another_request_cannot_reuse_the_original_deposit() -> Result<()> {
    let f = fixture()?;
    f.native.execute(&f.agreement, &f.request)?;
    let mut changed = f.request.clone();
    changed.request_id = "another-signed-request".into();
    let mut body = f.agreement.body.clone();
    body.request_id = changed.request_id.clone();
    body.request_sha256 = crate::common::digest(&changed)?;
    let agreement = body.sign(&f.buyer, &crate::common::key(f.directory.path())?)?;
    agreement.validate(&f.native.policy, &changed)?;
    assert!(f.native.execute(&agreement, &changed).is_err());
    assert_eq!(native_counts(&f)?, (1, 1));
    assert_eq!(f.native.journal.execution_count()?, 1);
    Ok(())
}

#[test]
fn retention_capacity_denies_before_an_additional_native_reservation() -> Result<()> {
    let f = fixture()?;
    let provider = crate::common::key(f.directory.path())?;
    for index in 0..=63 {
        let request = f.native.request(
            &format!("capacity-{index}"),
            include_str!("../../../fixtures/openapi.json"),
            f.agreement.body.work.submit_by,
        )?;
        let mut body = f.agreement.body.clone();
        body.request_id = request.request_id.clone();
        body.request_sha256 = crate::common::digest(&request)?;
        let agreement = body.sign(&f.buyer, &provider)?;
        let terms = agreement.validate(&f.native.policy, &request)?;
        bind_observation(&f.source, &agreement)?;
        let observed = f.source.0.lock().map_err(|_| "fixture lock")?.clone();
        let now = crate::common::now()?;
        let verified = crate::funded_work::observer::verify(
            &f.native.policy.domain,
            &terms,
            &observed,
            now,
            now,
        )?;
        if index < 63 {
            f.native.journal.stage(&verified, &agreement, &request)?;
        } else {
            let error = f
                .native
                .execute(&agreement, &request)
                .err()
                .ok_or("capacity overflow admitted")?;
            assert!(
                error.to_string().contains("retention capacity exhausted"),
                "{error}"
            );
            assert_eq!(native_counts(&f)?, (0, 0));
            assert_eq!(f.native.journal.execution_count()?, 0);
        }
    }
    Ok(())
}

#[test]
fn original_capability_expiry_and_scope_deny_before_reservation() -> Result<()> {
    use chio_core_types::capability::token::CapabilityToken;
    let f = fixture()?;
    let provider = crate::common::key(f.directory.path())?;
    for case in 0..3 {
        let mut request = f.request.clone();
        let mut body = request.capability.body();
        match case {
            0 => {
                body.issued_at = crate::common::now()? - 20;
                body.expires_at = crate::common::now()? - 1;
            }
            1 => body.expires_at = f.agreement.body.work.submit_by + 1,
            2 => body.scope.grants[0].max_invocations = Some(2),
            _ => return Err("unknown expiry case".into()),
        }
        request.capability = CapabilityToken::sign(body, &provider)?;
        let mut agreement = f.agreement.body.clone();
        agreement.request_sha256 = crate::common::digest(&request)?;
        let agreement = agreement.sign(&f.buyer, &provider)?;
        agreement.validate(&f.native.policy, &request)?;
        let error = f
            .native
            .execute(&agreement, &request)
            .err()
            .ok_or("invalid original authority admitted")?;
        assert!(
            error.to_string().contains(if case == 2 {
                "request profile"
            } else {
                "capability"
            }),
            "{error}"
        );
        assert_eq!(native_counts(&f)?, (0, 0));
    }
    Ok(())
}

#[test]
fn signed_agreement_rejects_identity_and_signature_substitution() -> Result<()> {
    let f = fixture()?;
    let mut changed = f.agreement.clone();
    changed.buyer_signature = Keypair::generate().sign(b"another agreement");
    let error = f
        .native
        .execute(&changed, &f.request)
        .err()
        .ok_or("signature accepted")?;
    assert!(error.to_string().contains("signature invalid"));
    changed = f.agreement.clone();
    changed.body.authority_uuid = "another-authority".into();
    let error = f
        .native
        .execute(&changed, &f.request)
        .err()
        .ok_or("identity accepted")?;
    assert!(error
        .to_string()
        .contains("pinned native funding authority"));
    assert_eq!(native_counts(&f)?, (0, 0));
    Ok(())
}

#[test]
fn concurrent_retries_cannot_duplicate_native_dispatch_or_hold() -> Result<()> {
    let f = fixture()?;
    std::thread::scope(|scope| {
        let handles = (0..3)
            .map(|_| scope.spawn(|| f.native.execute(&f.agreement, &f.request)))
            .collect::<Vec<_>>();
        for handle in handles {
            let _ = handle.join().map_err(|_| "concurrent retry panicked")?;
        }
        Ok::<_, crate::common::Error>(())
    })?;
    let report = f.native.execute(&f.agreement, &f.request)?;
    assert_eq!(report["executions"], 1);
    assert_eq!(native_counts(&f)?, (1, 1));
    Ok(())
}
