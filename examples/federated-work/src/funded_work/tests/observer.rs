use super::*;
use crate::funded_work::observer::*;
use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolValue;

pub(super) fn fixture() -> Result<(Domain, Terms, Observation, u64)> {
    let now = crate::common::now()?;
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../contracts/scripts/fixtures/work-claim-vectors.json"
    ))?;
    let mut terms: Terms = serde_json::from_value(vector["terms"].clone())?;
    terms.submit_by = now + 600;
    terms.challenge_until = now + 700;
    terms.resolve_by = now + 800;
    terms.refund_after = now + 900;
    let escrow = "0xe78a0f7e598cc8b0bb87894b0f60dd2a88d6a8ab";
    let code = "0x6000";
    let domain = Domain {
        profile: PROFILE.into(),
        chain_id: "31337".into(),
        genesis_hash: format!("0x{}", "a".repeat(64)),
        escrow: escrow.into(),
        escrow_code_hash: format!("{:#x}", keccak256([0x60, 0])),
        token: terms.token.clone(),
        token_code_hash: format!("{:#x}", keccak256([0x60, 0])),
    };
    let id = allocation_id(&domain.chain_id, escrow, &terms)?;
    let blocks = (10..=12)
        .map(|number| Block {
            number,
            hash: format!("0x{number:064x}"),
            parent_hash: format!("0x{:064x}", number - 1),
            timestamp: now,
        })
        .collect::<Vec<_>>();
    let head = blocks.last().ok_or("no block")?.clone();
    let data = AbiWork {
        terms: terms.abi(escrow)?,
        state: 1,
        commitment: B256::ZERO,
        decisionDigest: B256::ZERO,
        accepted: false,
        paid: U256::ZERO,
        refunded: U256::ZERO,
    }
    .abi_encode();
    let read = |contract: &str, call_data: String, bytes: Vec<u8>| Read {
        contract: contract.into(),
        block_number: head.number,
        block_hash: head.hash.clone(),
        call_data,
        return_data: format!("0x{}", alloy_primitives::hex::encode(bytes)),
    };
    let topic_address = |value: &str| format!("0x{:0>64}", &value[2..]);
    let observation = Observation {
        chain_id: "31337".into(),
        genesis_hash: domain.genesis_hash.clone(),
        escrow_code: code.into(),
        token_code: code.into(),
        receipt: Receipt {
            transaction_hash: format!("0x{}", "b".repeat(64)),
            from: terms.payer.clone(),
            to: escrow.into(),
            status: 1,
            block_number: 10,
            block_hash: format!("0x{:064x}", 10),
            logs: vec![
                Log {
                    address: escrow.into(),
                    topics: vec![
                        format!("{:#x}", keccak256(b"Funded(bytes32,bytes32,address)")),
                        id.clone(),
                        terms.agreement_digest.clone(),
                        topic_address(&terms.payer),
                    ],
                    data: "0x".into(),
                },
                Log {
                    address: terms.token.clone(),
                    topics: vec![
                        format!("{:#x}", keccak256(b"Transfer(address,address,uint256)")),
                        topic_address(&terms.payer),
                        topic_address(escrow),
                    ],
                    data: format!("0x{:064x}", 100),
                },
            ],
        },
        work: read(
            escrow,
            format!(
                "0x{}{}",
                alloy_primitives::hex::encode(&keccak256(b"getWork(bytes32)")[..4]),
                &id[2..]
            ),
            data,
        ),
        balance: read(
            &terms.token,
            format!("0x70a08231{:0>64}", &escrow[2..]),
            U256::from(100).abi_encode(),
        ),
        ancestry: blocks,
        independent_head: head,
    };
    Ok((domain, terms, observation, now))
}

#[test]
fn receiver_verifies_exact_funded_state_and_confirmed_ancestry() -> Result<()> {
    let (domain, terms, observation, now) = fixture()?;
    let verified = verify(&domain, &terms, &observation, now, now)?;
    assert_eq!(
        verified.id,
        allocation_id(&domain.chain_id, &domain.escrow, &terms)?
    );
    Ok(())
}

#[test]
fn stale_chain_time_cannot_be_refreshed_by_a_new_receiver_timestamp() -> Result<()> {
    let (domain, terms, observation, now) = fixture()?;
    assert!(verify(&domain, &terms, &observation, now + 120, now + 120).is_err());
    assert!(verify(&domain, &terms, &observation, now, now + 31).is_err());
    Ok(())
}
