// Replay subcommand handler for the `chio` CLI.
//
// This file is included into `main.rs` via `include!` and reuses the shared
// `use` declarations from `cli/types.rs`. The clap parser surface landed in
// M04.P4.T1; the handler logic (log reader, signature re-verify, Merkle root
// recompute, divergence reporting, JSON output, bless gate) is implemented
// incrementally in M04.P4.T2 through M04.P4.T7. Until those tickets land the
// handler returns a stub message and exits cleanly so the parser surface can
// be tooled and gated end-to-end without depending on unimplemented logic.
//
// Reference: `.planning/trajectory/04-deterministic-replay.md` Phase 4 and
// the "chio replay subcommand surface" section of that document.

/// Dispatch entry-point for `chio replay`.
///
/// For T1 this prints a stub notice describing which downstream ticket owns
/// the missing logic, then exits with status 0 so the parser surface alone
/// can be exercised by gate checks (`chio replay --help | grep expect-root`).
/// Subsequent tickets replace the stub body with the real reader, verifier,
/// Merkle recompute, divergence reporter, and bless gate.
fn cmd_replay(args: &ReplayArgs) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "chio replay: parser surface only (M04.P4.T1)",
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    writeln!(
        stdout,
        "  log:           {}",
        args.log.display(),
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    writeln!(
        stdout,
        "  from_tee:      {}",
        args.from_tee,
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    writeln!(
        stdout,
        "  expect_root:   {}",
        args.expect_root.as_deref().unwrap_or("<none>"),
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    writeln!(
        stdout,
        "  json:          {}",
        args.json,
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    writeln!(
        stdout,
        "  bless:         {}",
        args.bless,
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    writeln!(
        stdout,
        "TODO: implement reader/verify/merkle/report in M04.P4.T2 through M04.P4.T7",
    )
    .map_err(|error| {
        CliError::Other(format!("failed to write replay stub notice: {error}"))
    })?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_parser_tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn replay_parses_log_argument() {
        let cli = Cli::try_parse_from(["chio", "replay", "./receipts/"]).unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert_eq!(args.log, PathBuf::from("./receipts/"));
                assert!(!args.from_tee);
                assert!(args.expect_root.is_none());
                assert!(!args.json);
                assert!(!args.bless);
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_expect_root_flag() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "./receipts/",
            "--expect-root",
            "7af9deadbeef",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert_eq!(args.expect_root.as_deref(), Some("7af9deadbeef"));
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_from_tee_and_json_flags() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "capture.ndjson",
            "--from-tee",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.from_tee);
                assert!(args.json);
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_bless_flag() {
        let cli =
            Cli::try_parse_from(["chio", "replay", "./receipts/", "--bless"]).unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.bless);
            }
            _ => panic!("expected replay subcommand"),
        }
    }
}
