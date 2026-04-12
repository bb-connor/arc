use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use reqwest::Url;

use crate::config::ChainlinkNetworkConfig;
use crate::PriceOracleError;

sol! {
    #[sol(rpc)]
    contract AggregatorV3Interface {
        function latestRoundData() external view returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencerAvailability {
    Up,
    Down,
    Recovering,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerStatus {
    pub chain_id: u64,
    pub feed_address: String,
    pub checked_at: u64,
    pub status_started_at: u64,
    pub availability: SequencerAvailability,
}

pub async fn read_sequencer_status(
    chain: &ChainlinkNetworkConfig,
    now: u64,
) -> Result<Option<SequencerStatus>, PriceOracleError> {
    let Some(feed_address) = chain.sequencer_uptime_feed.as_ref() else {
        return Ok(None);
    };
    let url = chain.rpc_endpoint.parse::<Url>().map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!(
            "invalid RPC endpoint {} for chain {}: {err}",
            chain.rpc_endpoint, chain.chain_id
        ))
    })?;
    let address = feed_address.parse::<Address>().map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!(
            "invalid sequencer uptime feed {} for chain {}: {err}",
            feed_address, chain.chain_id
        ))
    })?;
    let provider = ProviderBuilder::new().connect_http(url);
    let contract = AggregatorV3Interface::new(address, &provider);
    let latest = contract.latestRoundData().call().await.map_err(|err| {
        PriceOracleError::Unavailable(format!(
            "sequencer uptime read failed for chain {} at {}: {err}",
            chain.chain_id, feed_address
        ))
    })?;
    let answer = u8::try_from(latest.answer).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "sequencer uptime answer was invalid for chain {} at {}",
            chain.chain_id, feed_address
        ))
    })?;
    if answer > 1 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "sequencer uptime answer {} was unsupported for chain {} at {}",
            answer, chain.chain_id, feed_address
        )));
    }
    let status_started_at = u64::try_from(latest.startedAt).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "sequencer startedAt overflowed for chain {} at {}",
            chain.chain_id, feed_address
        ))
    })?;
    let availability = if answer == 1 {
        SequencerAvailability::Down
    } else if status_started_at > 0
        && now.saturating_sub(status_started_at) < chain.sequencer_grace_period_seconds
    {
        SequencerAvailability::Recovering
    } else {
        SequencerAvailability::Up
    };
    Ok(Some(SequencerStatus {
        chain_id: chain.chain_id,
        feed_address: feed_address.clone(),
        checked_at: now,
        status_started_at,
        availability,
    }))
}
