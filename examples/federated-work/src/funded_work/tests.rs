use super::allocation::*;
use crate::common::Result;
mod evidence;
mod execution;
mod execution_authority;
mod native;
mod observer;
mod resolution;
mod settlement;
mod successors;
mod wire;

#[test]
fn allocation_matches_the_independent_contract_vector() -> Result<()> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/scripts/fixtures/work-claim-vectors.json"
    ))?;
    let terms: Terms = serde_json::from_value(vector["terms"].clone())?;
    assert_eq!(
        allocation_id(
            "31337",
            "0xe78a0f7e598cc8b0bb87894b0f60dd2a88d6a8ab",
            &terms
        )?,
        "0x2d47eebb8e6cbeec1b78ee266bf5540826afe1f9d3e80b1dabb8d35aeb9a228b"
    );
    Ok(())
}

#[test]
fn allocation_rejects_lossy_or_ambiguous_money() {
    for value in [
        "0",
        "01",
        " 100",
        "+100",
        "100.0",
        "1e2",
        "9007199254740992",
        "18446744073709551616",
    ] {
        assert!(units(value).is_err(), "accepted {value}");
    }
    assert_eq!(units("9007199254740991").ok(), Some(9_007_199_254_740_991));
}
mod authority_enrollment;
mod checkpoint_handoff;
mod verifier_handoff;
