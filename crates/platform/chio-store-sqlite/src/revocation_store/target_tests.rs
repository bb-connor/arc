//! Atomicity of a target revocation: a failure part way through the fan-out
//! leaves no entry, no tag row and no revoked root.

use chio_core::root_authority::{RevocationReason, RevocationTarget};
use chio_core::tenant_index::KeyedIndexValue;
use chio_kernel::RevocationStoreError;

use super::targets::FAN_OUT_FAILS_AFTER;
use crate::root_exchange_store::support::{digest, Admit, Case, Env, TestResult, NOW};
use crate::root_exchange_store::RootTags;

fn subject(value: u8) -> KeyedIndexValue {
    KeyedIndexValue {
        key_id: digest(0xa1),
        value: digest(value),
    }
}

fn count(env: &Env, table: &str) -> TestResult<i64> {
    Ok(env
        .fixture
        .raw()?
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?)
}

#[test]
fn a_fan_out_failure_after_the_first_root_rolls_back_everything() -> TestResult {
    let env = Env::new()?;
    for (capability_id, seed) in [("cap-a", 1_u8), ("cap-b", 2)] {
        let mut case = Case::id_jag(capability_id)?;
        case.replay = 0x30 + seed;
        case.request = 0x50 + seed;
        case.artifact = 0x70 + seed;
        case.tags = RootTags {
            subject: subject(0xb1),
            tenant: subject(0xc0 + seed),
        };
        case.candidates = vec![case.tags];
        env.minted(&case, &Admit, NOW)?;
    }
    let store = env.owner.revocation_store();
    let target = RevocationTarget::subject_tag(digest(0xb1));
    FAN_OUT_FAILS_AFTER.with(|limit| limit.set(Some(1)));
    let failed = store.revoke_target(
        &target,
        &[subject(0xb1)],
        Some(&digest(0xa1)),
        RevocationReason::IncidentResponse,
    );
    FAN_OUT_FAILS_AFTER.with(|limit| limit.set(None));
    assert!(
        matches!(&failed, Err(RevocationStoreError::Sync(detail)) if detail == "injected fan-out failure"),
        "{failed:?}"
    );
    for table in [
        "revocation_entries",
        "revocation_entry_tags",
        "revoked_capabilities",
        "revocation_delta_log",
    ] {
        assert_eq!(count(&env, table)?, 0, "{table}");
    }
    let revocation = store.revoke_target(
        &target,
        &[subject(0xb1)],
        Some(&digest(0xa1)),
        RevocationReason::IncidentResponse,
    )?;
    assert!(revocation.newly_revoked);
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (2, 2));
    Ok(())
}

#[test]
fn an_unanswered_mint_check_carries_the_store_error() {
    let refusal = super::targets::unavailable(RevocationStoreError::Fenced {
        expected_epoch: 7,
        actual_epoch: Some(8),
    });
    let crate::root_exchange_store::MintRevocationRefusal::Unavailable(error) = refusal else {
        panic!("an unanswered check is unavailable, got {refusal:?}");
    };
    assert!(
        matches!(
            error.store_error(),
            RevocationStoreError::Fenced {
                expected_epoch: 7,
                actual_epoch: Some(8)
            }
        ),
        "{error:?}"
    );
}
