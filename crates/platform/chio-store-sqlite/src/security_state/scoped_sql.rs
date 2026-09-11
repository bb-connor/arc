//! Data scoping, not admission authority. No raw-SQL or connection escape hatch.
//!
//! Native inspection cannot construct a writer. Native monotone joins require
//! the affine admission-owned transaction and its bounded row-change capture.
//! Other production mutations still require the legacy transaction owner.

use super::*;
use rusqlite::{params_from_iter, Row, Statement, ToSql};

pub(super) mod declassification;
pub(super) mod flow;

pub(super) struct ReadQuery {
    parameters: usize,
    legacy: &'static str,
    native: &'static str,
}

pub(super) struct WriteQuery {
    parameters: usize,
    legacy: &'static str,
    native: &'static str,
}

#[derive(Clone, Copy)]
pub(super) struct ScopedReader<'a> {
    connection: &'a Connection,
    authority: Option<&'a str>,
}

impl<'a> ScopedReader<'a> {
    pub(super) fn legacy(connection: &'a Connection) -> Self {
        Self {
            connection,
            authority: None,
        }
    }

    pub(super) fn native(connection: &'a Connection, authority: &'a str) -> Self {
        Self {
            connection,
            authority: Some(authority),
        }
    }

    fn prepare(
        self,
        legacy: &str,
        native: &str,
        parameters: usize,
        supplied: usize,
        readonly: bool,
    ) -> rusqlite::Result<Statement<'a>> {
        if supplied != parameters {
            return Err(rusqlite::Error::InvalidParameterCount(supplied, parameters));
        }
        let statement = self.connection.prepare(if self.authority.is_some() {
            native
        } else {
            legacy
        })?;
        let expected = parameters + usize::from(self.authority.is_some());
        if statement.parameter_count() != expected || statement.readonly() != readonly {
            return Err(rusqlite::Error::InvalidQuery);
        }
        // Require a dense, explicit numbered binding. A stray named or anonymous
        // parameter must not silently shift the security authority or domain IDs.
        for index in 1..=expected {
            if statement.parameter_name(index) != Some(format!("?{index}").as_str()) {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        Ok(statement)
    }

    pub(super) fn query_row<T>(
        self,
        query: ReadQuery,
        parameters: &[&dyn ToSql],
        read: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let mut statement = self.prepare(
            query.legacy,
            query.native,
            query.parameters,
            parameters.len(),
            true,
        )?;
        let authority = self.authority;
        let bindings = authority
            .as_ref()
            .map(|id| id as &dyn ToSql)
            .into_iter()
            .chain(parameters.iter().copied());
        statement.query_row(params_from_iter(bindings), read)
    }

    pub(super) fn visit(
        self,
        query: ReadQuery,
        read: impl FnMut(&Row<'_>) -> PortResult<()>,
    ) -> PortResult<()> {
        self.scan(query, &[], read)
    }

    pub(super) fn scan(
        self,
        query: ReadQuery,
        parameters: &[&dyn ToSql],
        mut read: impl FnMut(&Row<'_>) -> PortResult<()>,
    ) -> PortResult<()> {
        let mut statement = self
            .prepare(
                query.legacy,
                query.native,
                query.parameters,
                parameters.len(),
                true,
            )
            .map_err(sqlite_error)?;
        let authority = self.authority;
        let bindings = authority
            .as_ref()
            .map(|id| id as &dyn ToSql)
            .into_iter()
            .chain(parameters.iter().copied());
        let mut rows = statement
            .query(params_from_iter(bindings))
            .map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            read(row)?;
        }
        Ok(())
    }

    pub(super) fn collect<T>(
        self,
        query: ReadQuery,
        parameters: &[&dyn ToSql],
        read: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<Vec<T>> {
        let mut statement = self.prepare(
            query.legacy,
            query.native,
            query.parameters,
            parameters.len(),
            true,
        )?;
        let authority = self.authority;
        let bindings = authority
            .as_ref()
            .map(|id| id as &dyn ToSql)
            .into_iter()
            .chain(parameters.iter().copied());
        let result = statement
            .query_map(params_from_iter(bindings), read)?
            .collect();
        result
    }
}

/// A borrow of an already owned write transaction. Domain operations cannot
/// commit, select another scope, or obtain the underlying SQLite connection.
pub(super) struct ScopedMutation<'a> {
    reader: ScopedReader<'a>,
}

impl<'a> ScopedMutation<'a> {
    pub(super) fn native(owner: &'a super::native_mutation::NativeFlowOwner<'_>) -> Self {
        Self {
            reader: ScopedReader::native(owner.transaction(), owner.authority()),
        }
    }

    pub(super) fn legacy(transaction: &'a Transaction<'_>) -> Self {
        Self {
            reader: ScopedReader::legacy(transaction),
        }
    }

    pub(super) fn native_egress(owner: &'a super::native_mutation::NativeEgressOwner<'_>) -> Self {
        Self {
            reader: ScopedReader::native(owner.transaction(), owner.authority()),
        }
    }

    /// SQL-semantic test fixture only. Never an activation or operation owner.
    #[cfg(all(test, unix))]
    pub(super) fn native_for_test(transaction: &'a Transaction<'_>, authority: &'a str) -> Self {
        Self {
            reader: ScopedReader::native(transaction, authority),
        }
    }

    pub(super) fn reader(&self) -> ScopedReader<'a> {
        self.reader
    }

    pub(super) fn query_row<T>(
        &self,
        query: ReadQuery,
        parameters: &[&dyn ToSql],
        read: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.reader.query_row(query, parameters, read)
    }

    pub(super) fn execute(
        &self,
        query: WriteQuery,
        parameters: &[&dyn ToSql],
    ) -> rusqlite::Result<usize> {
        let mut statement = self.reader.prepare(
            query.legacy,
            query.native,
            query.parameters,
            parameters.len(),
            false,
        )?;
        let authority = self.reader.authority;
        let bindings = authority
            .as_ref()
            .map(|id| id as &dyn ToSql)
            .into_iter()
            .chain(parameters.iter().copied());
        statement.execute(params_from_iter(bindings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn scope_binding_is_first_and_domain_arity_is_exact() -> TestResult {
        let connection = Connection::open_in_memory()?;
        const QUERY: ReadQuery = ReadQuery {
            parameters: 2,
            legacy: "SELECT ?1, ?2, 'legacy'",
            native: "SELECT ?2, ?3, ?1",
        };
        let decode = |row: &Row<'_>| -> rusqlite::Result<(String, i64, String)> {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        };
        assert_eq!(
            ScopedReader::legacy(&connection).query_row(QUERY, params!["tenant", 7], decode)?,
            ("tenant".into(), 7, "legacy".into())
        );
        assert_eq!(
            ScopedReader::native(&connection, "authority").query_row(
                QUERY,
                params!["tenant", 7],
                decode
            )?,
            ("tenant".into(), 7, "authority".into())
        );
        for reader in [
            ScopedReader::legacy(&connection),
            ScopedReader::native(&connection, "authority"),
        ] {
            assert!(reader.query_row(QUERY, params!["tenant"], decode).is_err());
            assert!(reader
                .query_row(QUERY, params!["authority", "tenant", 7], decode)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn malformed_catalog_bindings_and_read_write_mismatch_fail_closed() -> TestResult {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE fixture (value INTEGER)")?;
        for sql in [
            "SELECT ?",
            "SELECT :named",
            "SELECT ?2",
            "SELECT ?1, ?3",
            "INSERT INTO fixture VALUES (?1)",
        ] {
            let query = ReadQuery {
                parameters: 1,
                legacy: sql,
                native: sql,
            };
            assert!(
                ScopedReader::legacy(&connection)
                    .query_row(query, params![9], |row| row.get::<_, i64>(0))
                    .is_err(),
                "{sql}"
            );
        }
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM fixture", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }
}
