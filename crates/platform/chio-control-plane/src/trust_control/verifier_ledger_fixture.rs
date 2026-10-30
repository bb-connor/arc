//! Verifier ledgers for tests that build a service state directly.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_federation::verifier_ledger::VerifierLedger;
use chio_test_support::prelude::*;

use super::{TrustServiceConfig, TrustServiceState, VerifierLedgerSource};
use crate::CliError;

fn open_sqlite(database: &Path) -> Result<Arc<dyn VerifierLedger>, CliError> {
    Ok(Arc::new(
        chio_store_sqlite::SqlitePassportVerifierStore::open(database)?,
    ))
}

/// A SQLite verifier ledger in `database`.
pub(crate) fn source(database: PathBuf) -> VerifierLedgerSource {
    VerifierLedgerSource {
        database,
        open: open_sqlite,
    }
}

/// Opens the configured ledger the way service startup does.
pub(crate) fn open(config: &TrustServiceConfig) -> Option<Arc<dyn VerifierLedger>> {
    config
        .verifier_ledger
        .as_ref()
        .map(|source| (source.open)(&source.database).test_unwrap())
}

/// Configures and opens a ledger in `database` on an already built state and
/// returns the handle the state now shares.
pub(crate) fn attach(state: &mut TrustServiceState, database: PathBuf) -> Arc<dyn VerifierLedger> {
    state.config.verifier_ledger = Some(source(database));
    let ledger = open(&state.config).test_unwrap();
    state.verifier_ledger = Some(Arc::clone(&ledger));
    ledger
}
