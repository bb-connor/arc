use crate::common::Result;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{sol, SolValue};
use serde::{Deserialize, Serialize};

pub const MAX_UNITS: u64 = (1 << 53) - 1;

sol! {
    struct AbiTerms {
        bytes32 agreementDigest;
        address payer;
        address beneficiary;
        address verifier;
        address token;
        uint256 amount;
        uint64 submitBy;
        uint64 challengeUntil;
        uint64 resolveBy;
        uint64 refundAfter;
    }

    struct AbiWork {
        AbiTerms terms;
        uint8 state;
        bytes32 commitment;
        bytes32 decisionDigest;
        bool accepted;
        uint256 paid;
        uint256 refunded;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Terms {
    pub agreement_digest: String,
    pub payer: String,
    pub beneficiary: String,
    pub verifier: String,
    pub token: String,
    pub amount: String,
    pub submit_by: u64,
    pub challenge_until: u64,
    pub resolve_by: u64,
    pub refund_after: u64,
}

/// Exact decimal conversion, without accepting signs, whitespace or leading zeros.
pub fn units(value: &str) -> Result<u64> {
    if value.is_empty()
        || value.len() > 16
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("noncanonical decimal units".into());
    }
    let parsed: u64 = value.parse()?;
    if parsed == 0 || parsed > MAX_UNITS {
        return Err("units outside safe positive integer range".into());
    }
    Ok(parsed)
}

pub fn hex_bytes(value: &str, length: usize) -> Result<Vec<u8>> {
    let body = value.strip_prefix("0x").ok_or("hex prefix missing")?;
    if body.len() != length * 2
        || !body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical hexadecimal value".into());
    }
    Ok(alloy_primitives::hex::decode(body)?)
}

pub fn hash(value: &str) -> Result<B256> {
    let parsed = B256::from_slice(&hex_bytes(value, 32)?);
    if parsed == B256::ZERO {
        return Err("zero hash".into());
    }
    Ok(parsed)
}

pub fn address(value: &str) -> Result<Address> {
    let parsed = Address::from_slice(&hex_bytes(value, 20)?);
    if parsed == Address::ZERO {
        return Err("zero address".into());
    }
    Ok(parsed)
}

impl Terms {
    pub fn abi(&self, escrow: &str) -> Result<AbiTerms> {
        let actors = [
            address(&self.payer)?,
            address(&self.beneficiary)?,
            address(&self.verifier)?,
            address(escrow)?,
        ];
        for (index, actor) in actors.iter().enumerate() {
            if actors[..index].contains(actor) {
                return Err("funding actor collision".into());
            }
        }
        if self.submit_by == 0
            || self.submit_by >= self.challenge_until
            || self.challenge_until >= self.resolve_by
            || self.resolve_by >= self.refund_after
            || self.refund_after > MAX_UNITS
        {
            return Err("invalid funding deadlines".into());
        }
        Ok(AbiTerms {
            agreementDigest: hash(&self.agreement_digest)?,
            payer: actors[0],
            beneficiary: actors[1],
            verifier: actors[2],
            token: address(&self.token)?,
            amount: U256::from(units(&self.amount)?),
            submitBy: self.submit_by,
            challengeUntil: self.challenge_until,
            resolveBy: self.resolve_by,
            refundAfter: self.refund_after,
        })
    }
}

pub fn allocation_id(chain_id: &str, escrow: &str, terms: &Terms) -> Result<String> {
    Ok(format!(
        "{:#x}",
        keccak256(
            (
                U256::from(units(chain_id)?),
                address(escrow)?,
                terms.abi(escrow)?
            )
                .abi_encode()
        )
    ))
}
