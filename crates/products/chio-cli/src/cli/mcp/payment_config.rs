//! CLI selection of the kernel payment adapter. Sim is the safe default; the
//! http variants delegate to an external facilitator. No custody or broadcast
//! variant is exposed (custody-neutral).

use std::sync::Arc;

use chio_kernel::payment::SimPaymentAdapter;
use chio_kernel::{
    AcpPaymentAdapter, PaymentAdapter, X402Network, X402PaymentAdapter, X402RailConfig,
    DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
};
use chio_store_sqlite::SqliteExecutionNonceStore;

#[derive(Debug, Clone)]
pub enum PaymentAdapterConfig {
    Sim,
    HttpX402 {
        adapter: X402PaymentAdapter,
    },
    HttpAcp {
        base_url: String,
        bearer_token: Option<String>,
    },
}

impl PaymentAdapterConfig {
    #[must_use]
    pub fn default_safe() -> Self {
        Self::Sim
    }

    /// Read the payment adapter config from environment variables.
    ///
    /// `CHIO_PAYMENT_ADAPTER`: `sim` (default), `http-x402`, `http-acp`.
    /// `CHIO_PAYMENT_BASE_URL`: required when the adapter is `http-x402` or `http-acp`.
    /// `CHIO_PAYMENT_BEARER_TOKEN`: optional bearer token for http adapters.
    ///
    /// `http-x402` also requires the rail it settles to:
    /// `CHIO_PAYMENT_X402_NETWORK` (CAIP-2, testnet allowlist only),
    /// `CHIO_PAYMENT_X402_ASSET` (EIP-3009 token contract),
    /// `CHIO_PAYMENT_X402_TOKEN_SYMBOL` (the charge currency on this rail),
    /// `CHIO_PAYMENT_X402_TOKEN_DECIMALS` (ERC-20 `decimals`),
    /// `CHIO_PAYMENT_X402_PAY_TO` (payee address), and
    /// `CHIO_PAYMENT_X402_REPLAY_DB` (SQLite file of the durable store that
    /// holds each accepted EIP-3009 authorization for single use; empty,
    /// in-memory and temporary database paths are refused). The
    /// facilitator URL, the rail and the replay store are validated here, at
    /// load.
    ///
    /// Returns `Ok(None)` when `CHIO_PAYMENT_ADAPTER` is absent or set to `sim`
    /// (the caller then uses the documented default). Returns `Err` when the
    /// variable is present but its value is not a recognized adapter kind -
    /// an unrecognized value would otherwise silently mask a misconfigured
    /// real payment rail.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// [`Self::from_env`] over an explicit variable lookup.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let Some(kind) = lookup("CHIO_PAYMENT_ADAPTER") else {
            return Ok(None);
        };
        let base_url = lookup("CHIO_PAYMENT_BASE_URL").unwrap_or_default();
        let bearer_token = lookup("CHIO_PAYMENT_BEARER_TOKEN");
        match kind.as_str() {
            "sim" | "" => Ok(None),
            "http-x402" => {
                let required =
                    |name: &str| lookup(name).ok_or_else(|| format!("http-x402 requires {name}"));
                let network = X402Network::allowlisted(&required("CHIO_PAYMENT_X402_NETWORK")?)
                    .map_err(|error| format!("CHIO_PAYMENT_X402_NETWORK: {error}"))?;
                let token_decimals = required("CHIO_PAYMENT_X402_TOKEN_DECIMALS")?
                    .parse::<u8>()
                    .map_err(|_| "CHIO_PAYMENT_X402_TOKEN_DECIMALS must be 0-255".to_string())?;
                let rail = X402RailConfig::new(
                    network,
                    &required("CHIO_PAYMENT_X402_ASSET")?,
                    &required("CHIO_PAYMENT_X402_TOKEN_SYMBOL")?,
                    token_decimals,
                    &required("CHIO_PAYMENT_X402_PAY_TO")?,
                )
                .map_err(|error| format!("http-x402 rail: {error}"))?;
                let clock = crate::input::time::clock();
                let replay_db = required("CHIO_PAYMENT_X402_REPLAY_DB")?;
                let replay_db = durable_replay_db_path(&replay_db)
                    .map_err(|error| format!("CHIO_PAYMENT_X402_REPLAY_DB: {error}"))?;
                let replay = SqliteExecutionNonceStore::open_with_clock(
                    replay_db,
                    DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
                    clock.clone(),
                )
                .map_err(|error| format!("CHIO_PAYMENT_X402_REPLAY_DB: {error}"))?;
                let mut adapter =
                    X402PaymentAdapter::new(base_url, rail, clock, Arc::new(replay))
                        .map_err(|error| format!("CHIO_PAYMENT_BASE_URL: {error}"))?;
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token);
                }
                Ok(Some(Self::HttpX402 { adapter }))
            }
            "http-acp" => Ok(Some(Self::HttpAcp {
                base_url,
                bearer_token,
            })),
            other => Err(format!(
                "CHIO_PAYMENT_ADAPTER: unrecognized adapter kind {:?}; \
                 expected one of: sim, http-x402, http-acp",
                other
            )),
        }
    }

    /// Load-time config-consistency check (house rule: invalid policies reject
    /// at load time). This is a config-shape check only; the authoritative
    /// fail-closed enforcement is the kernel runtime MustPrepay gate.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Sim | Self::HttpX402 { .. } => Ok(()),
            Self::HttpAcp { base_url, .. } => {
                if base_url.trim().is_empty() {
                    return Err("http payment adapter requires a non-empty base_url".to_string());
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn build_adapter(&self) -> Box<dyn PaymentAdapter> {
        match self {
            Self::Sim => Box::new(SimPaymentAdapter::new()),
            Self::HttpX402 { adapter } => Box::new(adapter.clone()),
            Self::HttpAcp {
                base_url,
                bearer_token,
            } => {
                let mut adapter = AcpPaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
        }
    }
}

/// Why a configured x402 replay store path cannot hold spent nonces across a
/// restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum X402ReplayStorePathError {
    #[error("x402 replay store path is empty")]
    Empty,
    #[error("x402 replay store path names a non-durable SQLite database")]
    NonDurable,
}

/// The configured replay store path, refused unless SQLite would open it as a
/// durable file.
pub fn durable_replay_db_path(path: &str) -> Result<&str, X402ReplayStorePathError> {
    if path.trim().is_empty() {
        return Err(X402ReplayStorePathError::Empty);
    }
    if chio_store_sqlite::is_in_memory_sqlite_path(path) || names_a_temporary_database(path) {
        return Err(X402ReplayStorePathError::NonDurable);
    }
    Ok(path)
}

/// SQLite opens a private temporary database for an empty URI filename,
/// including `file://` and `file://localhost` with no path, and refuses any
/// URI authority other than empty or `localhost`.
fn names_a_temporary_database(path: &str) -> bool {
    let Some(uri) = path.strip_prefix("file:") else {
        return false;
    };
    let uri = uri.split(['?', '#']).next().unwrap_or_default();
    let name = match uri.strip_prefix("//") {
        Some(authority_and_path) => {
            let (authority, name) = authority_and_path
                .split_once('/')
                .unwrap_or((authority_and_path, ""));
            if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
                return true;
            }
            name
        }
        None => uri,
    };
    name.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn default_is_sim_and_safe() {
        assert!(matches!(
            PaymentAdapterConfig::default_safe(),
            PaymentAdapterConfig::Sim
        ));
    }

    #[test]
    fn unknown_adapter_kind_errors_at_load_time_not_silently_downgrades() {
        // A present-but-unrecognized CHIO_PAYMENT_ADAPTER must produce an error,
        // not silently fall back to Sim. This prevents a misconfigured real rail
        // from being masked by a silent default.
        std::env::set_var("CHIO_PAYMENT_ADAPTER", "mystery-rail");
        let result = PaymentAdapterConfig::from_env();
        std::env::remove_var("CHIO_PAYMENT_ADAPTER");
        let error = result.test_expect_err("unknown adapter kind must fail at load time");
        assert!(
            error.contains("mystery-rail") && error.contains("unrecognized"),
            "error must identify the unknown kind: {error}"
        );
    }

    #[test]
    fn http_x402_holds_an_adapter_validated_at_load() {
        let rail = X402RailConfig::new(
            X402Network::allowlisted("eip155:84532").test_unwrap(),
            "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
            "USDC",
            6,
            "0x2000000000000000000000000000000000000002",
        )
        .test_unwrap();
        let cfg = PaymentAdapterConfig::HttpX402 {
            adapter: X402PaymentAdapter::new(
                "https://facilitator.example",
                rail,
                crate::input::time::clock(),
                Arc::new(chio_kernel::InMemoryExecutionNonceStore::default()),
            )
            .test_unwrap(),
        };
        cfg.validate().test_unwrap();
        assert_eq!(cfg.build_adapter().rail_id(), "x402");
    }

    #[test]
    fn valid_variants_pass_validation_and_build() {
        let sim = PaymentAdapterConfig::Sim;
        sim.validate().test_unwrap();
        let _ = sim.build_adapter();
        let http = PaymentAdapterConfig::HttpAcp {
            base_url: "https://facilitator.example".to_string(),
            bearer_token: Some("tok".to_string()),
        };
        http.validate().test_unwrap();
        let _ = http.build_adapter();
    }

    #[test]
    fn replay_store_path_refuses_an_empty_path() {
        for path in ["", "   "] {
            assert_eq!(
                durable_replay_db_path(path),
                Err(X402ReplayStorePathError::Empty),
                "{path:?}"
            );
        }
    }

    #[test]
    fn replay_store_path_refuses_non_durable_databases() {
        for path in [
            ":memory:",
            ":MEMORY:",
            "file::memory:",
            "file::memory:?cache=shared",
            "file:x402?mode=memory&cache=shared",
            "file:x402?vfs=memdb",
            "file:",
            "file:?cache=shared",
            "file:#fragment",
            "file://",
            "file://localhost",
            "file://LOCALHOST",
            "file://?cache=shared",
            "file://localhost?mode=rwc",
            "file://localhost#fragment",
            "file://example.com/var/lib/chio/x402-replay.sqlite3",
        ] {
            assert_eq!(
                durable_replay_db_path(path),
                Err(X402ReplayStorePathError::NonDurable),
                "{path:?}"
            );
        }
    }

    #[test]
    fn replay_store_path_accepts_durable_files() {
        for path in [
            "/var/lib/chio/x402-replay.sqlite3",
            "x402-replay.sqlite3",
            "file:/var/lib/chio/x402-replay.sqlite3",
            "file:x402-replay.sqlite3?mode=rwc",
            "file:///var/lib/chio/x402-replay.sqlite3",
            "file://localhost/var/lib/chio/x402-replay.sqlite3",
        ] {
            assert_eq!(durable_replay_db_path(path), Ok(path), "{path:?}");
        }
    }

    #[test]
    fn http_x402_refuses_a_non_durable_replay_store_at_load() {
        let variables = |replay_db: &'static str| {
            move |name: &str| {
                match name {
                    "CHIO_PAYMENT_ADAPTER" => Some("http-x402"),
                    "CHIO_PAYMENT_BASE_URL" => Some("https://facilitator.example"),
                    "CHIO_PAYMENT_X402_NETWORK" => Some("eip155:84532"),
                    "CHIO_PAYMENT_X402_ASSET" => Some("0x036cbd53842c5426634e7929541ec2318f3dcf7e"),
                    "CHIO_PAYMENT_X402_TOKEN_SYMBOL" => Some("USDC"),
                    "CHIO_PAYMENT_X402_TOKEN_DECIMALS" => Some("6"),
                    "CHIO_PAYMENT_X402_PAY_TO" => Some("0x2000000000000000000000000000000000000002"),
                    "CHIO_PAYMENT_X402_REPLAY_DB" => Some(replay_db),
                    _ => None,
                }
                .map(str::to_owned)
            }
        };
        for (replay_db, refusal) in [
            ("", X402ReplayStorePathError::Empty),
            (":memory:", X402ReplayStorePathError::NonDurable),
            ("file://localhost", X402ReplayStorePathError::NonDurable),
        ] {
            let error = PaymentAdapterConfig::from_lookup(variables(replay_db))
                .test_expect_err("a non-durable replay store is refused at load");
            assert_eq!(error, format!("CHIO_PAYMENT_X402_REPLAY_DB: {refusal}"));
        }
    }
}
