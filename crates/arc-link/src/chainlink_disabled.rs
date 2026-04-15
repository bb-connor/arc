use crate::config::{ChainlinkNetworkConfig, PairConfig};
use crate::{OracleBackend, OracleBackendKind, OracleFuture, PriceOracleError};

pub struct ChainlinkFeedReader {
    // Kept so the disabled backend preserves the same constructor/config shape
    // as the web3-enabled implementation.
    #[allow(dead_code)]
    networks: Vec<ChainlinkNetworkConfig>,
}

impl ChainlinkFeedReader {
    #[must_use]
    pub fn new(networks: Vec<ChainlinkNetworkConfig>) -> Self {
        Self { networks }
    }
}

impl OracleBackend for ChainlinkFeedReader {
    fn kind(&self) -> OracleBackendKind {
        OracleBackendKind::Chainlink
    }

    fn read_rate<'a>(&'a self, _pair: &'a PairConfig, _now: u64) -> OracleFuture<'a> {
        Box::pin(async {
            Err(PriceOracleError::UnsupportedBackend(
                "Chainlink backend requires the `web3` feature".to_string(),
            ))
        })
    }
}
