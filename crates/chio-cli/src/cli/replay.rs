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
///
/// M10.P2.T1 hook: when the optional `traffic` sub-subcommand is supplied
/// the dispatch routes through [`cmd_replay_traffic`], leaving the M04
/// stub body below untouched. The legacy `chio replay <log>` surface is
/// preserved verbatim.
fn cmd_replay(args: &ReplayArgs) -> Result<(), CliError> {
    if let Some(ReplaySubcommand::Traffic(traffic)) = args.command.as_ref() {
        return cmd_replay_traffic(traffic);
    }

    // Legacy M04 surface requires the positional `log` path. Emit a
    // structured CliError when it is absent so the help text guides the
    // caller toward either supplying a path or the `traffic` arm.
    let Some(log) = args.log.as_ref() else {
        return Err(CliError::Other(
            "chio replay requires a positional <log> path or the `traffic` sub-subcommand"
                .to_string(),
        ));
    };

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
        log.display(),
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
                assert_eq!(args.log.as_deref(), Some(Path::new("./receipts/")));
                assert!(!args.from_tee);
                assert!(args.expect_root.is_none());
                assert!(!args.json);
                assert!(!args.bless);
                assert!(args.command.is_none());
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

    #[test]
    fn replay_parses_traffic_subcommand() {
        // M10.P2.T1: `chio replay traffic --from <ndjson>` is additive
        // alongside the legacy positional surface. The positional `log`
        // is absent in this shape and the `Traffic` variant carries the
        // structured arguments.
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "traffic",
            "--from",
            "capture.ndjson",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.log.is_none(), "positional <log> absent under traffic");
                match args.command.as_ref() {
                    Some(ReplaySubcommand::Traffic(t)) => {
                        assert_eq!(t.from, PathBuf::from("capture.ndjson"));
                        assert_eq!(t.schema, "chio-tee-frame.v1");
                        assert!(t.tenant_pubkey.is_none());
                        assert!(!t.json);
                    }
                    _ => panic!("expected traffic sub-subcommand"),
                }
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_traffic_full_flag_set() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "traffic",
            "--from",
            "capture.ndjson",
            "--schema",
            "chio-tee-frame.v1",
            "--tenant-pubkey",
            "/etc/chio/tenant.pub",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => match args.command.as_ref() {
                Some(ReplaySubcommand::Traffic(t)) => {
                    assert_eq!(t.from, PathBuf::from("capture.ndjson"));
                    assert_eq!(t.schema, "chio-tee-frame.v1");
                    assert_eq!(
                        t.tenant_pubkey.as_deref(),
                        Some(Path::new("/etc/chio/tenant.pub"))
                    );
                    assert!(t.json);
                    assert!(t.against.is_none());
                    assert!(t.run_id.is_none());
                }
                _ => panic!("expected traffic sub-subcommand"),
            },
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_traffic_against_and_run_id_flags() {
        // M10.P2.T2: `--against <policy-ref>` and `--run-id <id>` are
        // additive optional flags. When both are present the dispatcher
        // routes through `run_traffic_replay` and namespaces receipt
        // ids under `replay:<run_id>:<frame_id>`.
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "traffic",
            "--from",
            "capture.ndjson",
            "--against",
            "path:/etc/chio/policy.yaml",
            "--run-id",
            "ci-2026-04-25",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => match args.command.as_ref() {
                Some(ReplaySubcommand::Traffic(t)) => {
                    assert_eq!(t.against.as_deref(), Some("path:/etc/chio/policy.yaml"));
                    assert_eq!(t.run_id.as_deref(), Some("ci-2026-04-25"));
                }
                _ => panic!("expected traffic sub-subcommand"),
            },
            _ => panic!("expected replay subcommand"),
        }
    }
}
