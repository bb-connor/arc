use reqwest::{Client, Url};
use serde::Deserialize;

use crate::config::{PairConfig, PythFeedConfig};
use crate::{ExchangeRate, OracleBackend, OracleBackendKind, OracleFuture, PriceOracleError};

#[derive(Debug)]
pub struct PythHermesClient {
    base_url: String,
    http_client: Client,
}

impl PythHermesClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, PriceOracleError> {
        let base_url = base_url.into();
        let http_client = Client::builder().build().map_err(|err| {
            PriceOracleError::Unavailable(format!("building Hermes client failed: {err}"))
        })?;
        Ok(Self {
            base_url,
            http_client,
        })
    }
}

impl OracleBackend for PythHermesClient {
    fn kind(&self) -> OracleBackendKind {
        OracleBackendKind::Pyth
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, now: u64) -> OracleFuture<'a> {
        Box::pin(async move {
            let feed = pair
                .pyth
                .as_ref()
                .ok_or_else(|| PriceOracleError::NoPairAvailable {
                    base: pair.base.clone(),
                    quote: pair.quote.clone(),
                })?;
            read_pyth_rate(&self.http_client, &self.base_url, pair, feed, now).await
        })
    }
}

async fn read_pyth_rate(
    http_client: &Client,
    base_url: &str,
    pair: &PairConfig,
    feed: &PythFeedConfig,
    now: u64,
) -> Result<ExchangeRate, PriceOracleError> {
    let url = build_latest_price_url(base_url, &feed.id)?;
    let response = http_client.get(url).send().await.map_err(|err| {
        PriceOracleError::Unavailable(format!(
            "Hermes request failed for {} id {}: {err}",
            pair.pair(),
            feed.id
        ))
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PriceOracleError::Unavailable(format!(
            "Hermes returned HTTP {} for {} id {}",
            status,
            pair.pair(),
            feed.id
        )));
    }
    let feeds: Vec<PythLatestPriceFeed> = response.json().await.map_err(|err| {
        PriceOracleError::InvalidFeed(format!(
            "Hermes JSON decode failed for {} id {}: {err}",
            pair.pair(),
            feed.id
        ))
    })?;
    let latest = feeds.into_iter().next().ok_or_else(|| {
        PriceOracleError::InvalidFeed(format!(
            "Hermes returned no price feeds for {} id {}",
            pair.pair(),
            feed.id
        ))
    })?;
    let expected = canonicalize_pyth_feed_id(&feed.id);
    let actual = canonicalize_pyth_feed_id(&latest.id);
    if expected != actual {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Hermes returned feed id {} but {} was requested for {}",
            latest.id,
            feed.id,
            pair.pair()
        )));
    }
    build_exchange_rate(pair, feed, latest.price, now)
}

fn build_latest_price_url(base_url: &str, id: &str) -> Result<Url, PriceOracleError> {
    let trimmed = base_url.trim_end_matches('/');
    let base = format!("{trimmed}/api/latest_price_feeds");
    Url::parse_with_params(
        &base,
        [(String::from("ids[]"), canonicalize_pyth_feed_id(id))],
    )
    .map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!("invalid Hermes base URL {base_url}: {err}"))
    })
}

fn build_exchange_rate(
    pair: &PairConfig,
    feed: &PythFeedConfig,
    price: PythPriceComponent,
    now: u64,
) -> Result<ExchangeRate, PriceOracleError> {
    let (rate_numerator, rate_denominator) =
        decimal_components_to_ratio(&price.price, price.expo, pair, feed)?;
    let confidence = decimal_components_to_ratio(&price.conf, price.expo, pair, feed).ok();
    let rate = ExchangeRate {
        base: pair.base.clone(),
        quote: pair.quote.clone(),
        rate_numerator,
        rate_denominator,
        updated_at: price.publish_time,
        fetched_at: now,
        source: "pyth".to_string(),
        feed_reference: feed.id.clone(),
        max_age_seconds: pair.policy.max_age_seconds,
        conversion_margin_bps: pair.policy.exchange_rate_margin_bps,
        confidence_numerator: confidence.as_ref().map(|value| value.0),
        confidence_denominator: confidence.as_ref().map(|value| value.1),
    };
    rate.ensure_fresh(now)?;
    Ok(rate)
}

fn decimal_components_to_ratio(
    raw_value: &str,
    expo: i32,
    pair: &PairConfig,
    feed: &PythFeedConfig,
) -> Result<(u128, u128), PriceOracleError> {
    let signed = raw_value.parse::<i128>().map_err(|err| {
        PriceOracleError::InvalidFeed(format!(
            "Pyth value parse failed for {} id {}: {err}",
            pair.pair(),
            feed.id
        ))
    })?;
    let value = u128::try_from(signed).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "Pyth returned a negative value for {} id {}",
            pair.pair(),
            feed.id
        ))
    })?;
    if value == 0 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Pyth returned zero for {} id {}",
            pair.pair(),
            feed.id
        )));
    }
    if expo >= 0 {
        let scale = 10_u128.checked_pow(expo as u32).ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "Pyth positive exponent overflowed for {} id {}",
                pair.pair(),
                feed.id
            ))
        })?;
        let numerator = value.checked_mul(scale).ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "Pyth numerator overflowed for {} id {}",
                pair.pair(),
                feed.id
            ))
        })?;
        return Ok((numerator, 1));
    }
    let denominator = 10_u128.checked_pow(expo.unsigned_abs()).ok_or_else(|| {
        PriceOracleError::ArithmeticOverflow(format!(
            "Pyth denominator overflowed for {} id {}",
            pair.pair(),
            feed.id
        ))
    })?;
    Ok((value, denominator))
}

fn canonicalize_pyth_feed_id(id: &str) -> String {
    id.trim_start_matches("0x").to_ascii_lowercase()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythLatestPriceFeed {
    id: String,
    price: PythPriceComponent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythPriceComponent {
    price: String,
    conf: String,
    expo: i32,
    publish_time: u64,
}

#[cfg(test)]
mod tests {
    use crate::config::{PairConfig, PairPolicy, PythFeedConfig, BASE_MAINNET_CHAIN_ID};

    use super::{build_exchange_rate, canonicalize_pyth_feed_id, PythPriceComponent};

    fn pair() -> PairConfig {
        PairConfig {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            chain_id: BASE_MAINNET_CHAIN_ID,
            chainlink: None,
            pyth: Some(PythFeedConfig {
                id: "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
                    .to_string(),
            }),
            policy: PairPolicy::volatile_default(),
        }
    }

    #[test]
    fn normalizes_pyth_decimal_components() {
        let rate = build_exchange_rate(
            &pair(),
            pair().pyth.as_ref().expect("feed"),
            PythPriceComponent {
                price: "184136023127".to_string(),
                conf: "177166324".to_string(),
                expo: -8,
                publish_time: 1_743_292_740,
            },
            1_743_292_780,
        )
        .expect("exchange rate");
        assert_eq!(rate.rate_numerator, 184_136_023_127);
        assert_eq!(rate.rate_denominator, 100_000_000);
        assert_eq!(rate.confidence_numerator, Some(177_166_324));
    }

    #[test]
    fn canonicalizes_feed_ids() {
        assert_eq!(
            canonicalize_pyth_feed_id(
                "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
            ),
            "ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
        );
    }
}
