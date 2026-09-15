use crate::{
    common::{self, Result},
    funded_work::{
        lifecycle,
        observer::{FundingSource, Observation},
        rail::FundingRail,
        settlement::{self, Action, Prepared},
        settlement_observer,
        smoke::{setup, Scenario},
    },
};
use alloy_primitives::{B256, U256};
use alloy_sol_types::SolValue;
use chio_kernel::payment::{PaymentAdapter, RailSettlementStatus};
use serde_json::json;
use std::sync::Arc;

#[test]
#[ignore = "requires the owned Node chain and CHIO_FUNDED_PYTHON; exercised by lifecycle qualification"]
fn payout_rejects_altered_observations_and_adapter_identities() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    } = setup(directory.path())?;
    chain.request(json!({"method":"pin-verifier","key":native.policy.verifier_key.to_hex()}))?;
    native.execute(&agreement, &request)?;
    let checkpoint: crate::funded_work::Checkpoint = Arc::new(|_| Ok(()));
    lifecycle::progress(
        directory.path(),
        &native,
        &request,
        "pay",
        &checkpoint,
        &|phase| {
            chain.request(
                json!({"method":"advance","allocation":funding["allocationId"],"phase":phase}),
            )?;
            Ok(())
        },
    )?;
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("missing original entry")?;
    let prepared: Prepared = native
        .journal
        .retained(&entry.allocation, "pay")?
        .ok_or("missing payout transaction")?;
    let action = settlement::request(&entry, Action::Pay, &native.policy, &native.journal)?;
    let valid = chain.observe_transaction(&prepared)?;
    let now = common::now()?;
    settlement_observer::verify(&native.policy, &action, &prepared, &valid, now, now)?;
    for case in 0..25 {
        let mut changed = valid.clone();
        match case {
            0 => changed.chain_id = "1".into(),
            1 => changed.genesis_hash = format!("0x{}", "f".repeat(64)),
            2 => changed.escrow_code = "0x6001".into(),
            3 => changed.token_code = "0x6001".into(),
            4 => {
                changed.ancestry.pop();
            }
            5 => changed.receipt.status = 0,
            6 => changed.receipt.from = action.terms.payer.clone(),
            7 => changed.receipt.to = action.terms.token.clone(),
            8 => changed.receipt.transaction_hash = format!("0x{}", "f".repeat(64)),
            9 => changed.receipt.block_number += 1,
            10 => changed.independent_head.hash = format!("0x{}", "f".repeat(64)),
            11 => changed.ancestry[1].parent_hash = format!("0x{}", "f".repeat(64)),
            12 => changed.work.block_hash = format!("0x{}", "f".repeat(64)),
            13 => changed.work.call_data.replace_range(..10, "0x70a08231"),
            14 => changed.work.return_data.push_str("00"),
            15 => changed
                .receipt
                .logs
                .retain(|log| log.address != native.policy.domain.escrow),
            16 => changed
                .receipt
                .logs
                .retain(|log| log.address != native.policy.domain.token),
            17 => {
                for log in &mut changed.receipt.logs {
                    if log.address == native.policy.domain.token {
                        log.data = format!("0x{:064x}", 99);
                    }
                }
            }
            18..=24 => {
                let bytes = crate::funded_work::observer::data(&changed.work.return_data, 1024)?;
                let mut work =
                    crate::funded_work::allocation::AbiWork::abi_decode_validate(&bytes)?;
                match case {
                    18 => work.terms.amount = U256::from(101),
                    19 => work.commitment = B256::ZERO,
                    20 => work.decisionDigest = B256::ZERO,
                    21 => work.accepted = false,
                    22 => work.paid = U256::from(99),
                    23 => work.refunded = U256::from(100),
                    _ => work.state = 3,
                }
                changed.work.return_data =
                    format!("0x{}", alloy_primitives::hex::encode(work.abi_encode()));
            }
            _ => return Err("invalid mutation case".into()),
        }
        assert!(
            settlement_observer::verify(&native.policy, &action, &prepared, &changed, now, now)
                .is_err(),
            "accepted mutation {case}"
        );
    }
    assert!(
        settlement_observer::verify(&native.policy, &action, &prepared, &valid, now, now + 31)
            .is_err()
    );
    assert!(
        settlement_observer::verify(&native.policy, &action, &prepared, &valid, now, now - 1)
            .is_err()
    );
    let rail = |source: Arc<dyn FundingSource>| FundingRail {
        journal: native.journal.clone(),
        operations: native.authority.admission_operation_store(),
        fence: native.authority.mutation_fence(),
        policy: native.policy.clone(),
        source,
        checkpoint: checkpoint.clone(),
    };
    let adapter = rail(chain.clone());
    let id = crate::funded_work::rail::authorization_id(&entry.allocation)?;
    let reference = entry.operation.as_deref().ok_or("operation missing")?;
    assert_eq!(
        adapter
            .capture(&id, 100, "XTS", reference)?
            .settlement_status,
        RailSettlementStatus::Settled
    );
    assert!(adapter
        .capture("replacement", 100, "XTS", reference)
        .is_err());
    assert!(adapter.capture(&id, 99, "XTS", reference).is_err());
    assert!(adapter.capture(&id, 100, "USD", reference).is_err());
    assert!(adapter.capture(&id, 100, "XTS", "replacement").is_err());
    assert!(adapter.release(&id, reference).is_err());
    struct Unavailable;
    impl FundingSource for Unavailable {
        fn observe(&self, _: &str) -> Result<Observation> {
            Err("observer unavailable".into())
        }
    }
    assert!(rail(Arc::new(Unavailable))
        .capture(&id, 100, "XTS", reference)
        .is_err());
    assert_eq!(native.report(&request)?["executions"], 1);
    Ok(())
}
