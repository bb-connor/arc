//! Payment catalog comparison preserves every token and quoted byte.

/// Collapse ASCII whitespace only outside SQL string and identifier quotes.
/// A whitespace run remains one separator, so tokens and operators never join.
/// SQL containing a comment outside quotes retains its original bytes.
pub(super) fn normalize_sql(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut quote_terminator = None;
    let mut pending_space = false;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote_terminator {
            normalized.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped_terminator) = characters.next() {
                        normalized.push(escaped_terminator);
                    }
                } else {
                    quote_terminator = None;
                }
            }
            continue;
        }
        if (character == '-' && characters.peek() == Some(&'-'))
            || (character == '/' && characters.peek() == Some(&'*'))
        {
            return value.to_owned();
        }
        if character.is_ascii_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        normalized.push(character);
        quote_terminator = match character {
            '\'' | '"' | '`' => Some(character),
            '[' => Some(']'),
            _ => None,
        };
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::normalize_sql;

    #[test]
    fn preserves_quoted_whitespace_and_escaped_delimiters() {
        for (input, expected) in [
            (
                " \t SELECT \n'a  b''c \t d'\r FROM \t payment_journal \n",
                "SELECT 'a  b''c \t d' FROM payment_journal",
            ),
            (
                " SELECT \t\"a  b\"\"c \t d\" \nFROM payment_journal",
                "SELECT \"a  b\"\"c \t d\" FROM payment_journal",
            ),
            (
                " SELECT \t`a  b``c \t d` \nFROM payment_journal",
                "SELECT `a  b``c \t d` FROM payment_journal",
            ),
            (
                " SELECT \t[a  b] \nFROM payment_journal",
                "SELECT [a  b] FROM payment_journal",
            ),
        ] {
            assert_eq!(normalize_sql(input), expected);
        }
    }

    #[test]
    fn preserves_separators_operators_and_non_ascii_identifier_bytes() {
        assert_eq!(normalize_sql("\tIS \n NOT \r NULL\n"), "IS NOT NULL");
        assert_ne!(normalize_sql("IS NOT NULL"), normalize_sql("ISNOTNULL"));
        assert_ne!(
            normalize_sql("value < = 512"),
            normalize_sql("value <= 512")
        );
        assert_eq!(normalize_sql("SELECT foo\u{a0}bar"), "SELECT foo\u{a0}bar");
        assert_eq!(normalize_sql("SELECT 'a  b"), "SELECT 'a  b");
    }

    #[test]
    fn line_comment_newline_keeps_different_check_constraints_distinct() -> rusqlite::Result<()> {
        let enforced = "CREATE TABLE sample (value INTEGER -- boundary\n CHECK (value > 0)\n);";
        let omitted = "CREATE TABLE sample (value INTEGER -- boundary CHECK (value > 0)\n);";
        let with_check = rusqlite::Connection::open_in_memory()?;
        with_check.execute_batch(enforced)?;
        assert!(matches!(
            with_check.execute("INSERT INTO sample VALUES (-1)", []),
            Err(rusqlite::Error::SqliteFailure(code, Some(message)))
                if code.code == rusqlite::ErrorCode::ConstraintViolation
                    && code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK
                    && message == "CHECK constraint failed: value > 0"
        ));
        let without_check = rusqlite::Connection::open_in_memory()?;
        without_check.execute_batch(omitted)?;
        without_check.execute("INSERT INTO sample VALUES (-1)", [])?;
        assert_ne!(normalize_sql(enforced), normalize_sql(omitted));
        Ok(())
    }

    #[test]
    fn comments_preserve_all_bytes_and_quoted_markers_remain_literals() {
        for input in [
            " CREATE TABLE sample (value INTEGER /* a  b\n c */ CHECK (value > 0)); ",
            " CREATE TABLE sample (value INTEGER -- a  b\n CHECK (value > 0)); ",
        ] {
            assert_eq!(normalize_sql(input), input);
        }
        assert_eq!(
            normalize_sql(" SELECT\n'--  a\n b'\t"),
            "SELECT '--  a\n b'"
        );
        assert_eq!(
            normalize_sql(" SELECT\n'/*  a\n b */'\t"),
            "SELECT '/*  a\n b */'"
        );
    }
}
