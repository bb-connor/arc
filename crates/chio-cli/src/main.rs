// Chio CLI -- command-line interface for the Chio runtime kernel.
//
// Provides commands for:
//
// - `arc run --policy <path> -- <command> [args...]`
//   Spawn an agent subprocess, set up the length-prefixed transport over
//   stdin/stdout pipes, and run the kernel message loop.
//
// - `arc check --policy <path> --tool <name> --params <json>`
//   Load a policy, create a kernel, and evaluate a single tool call.
//
// - `arc mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//   Wrap an MCP server subprocess with the Chio kernel and expose an
//   MCP-compatible edge over stdio for stock MCP clients.

mod admin;
mod cert;
mod did;
mod guard;
mod guards;
mod passport;
mod policies;
mod scaffold;

include!("cli/types.rs");
include!("cli/dispatch.rs");
include!("cli/runtime.rs");
include!("cli/trust_commands.rs");
include!("cli/session.rs");

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod cli_entrypoint_tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn format_json_flag_enables_json_output() {
        let cli = Cli::try_parse_from(["chio", "--format", "json", "init", "demo"]).unwrap();
        assert!(cli.json_output());
    }

    #[test]
    fn legacy_json_flag_still_enables_json_output() {
        let cli = Cli::try_parse_from(["chio", "--json", "init", "demo"]).unwrap();
        assert!(cli.json_output());
    }

    #[test]
    fn api_protect_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "api",
            "protect",
            "--upstream",
            "http://127.0.0.1:8080",
        ])
        .unwrap();

        match cli.command {
            Commands::Api {
                command:
                    ApiCommands::Protect {
                        upstream,
                        spec,
                        listen,
                        receipt_store,
                    },
            } => {
                assert_eq!(upstream, "http://127.0.0.1:8080");
                assert!(spec.is_none());
                assert_eq!(listen, "127.0.0.1:9090");
                assert!(receipt_store.is_none());
            }
            _ => panic!("expected api protect subcommand"),
        }
    }

    #[test]
    fn write_cli_error_emits_structured_json() {
        let error = CliError::Kernel(chio_kernel::KernelError::OutOfScope {
            tool: "read_file".to_string(),
            server: "fs".to_string(),
        });
        let mut output = Vec::new();

        write_cli_error(&mut output, &error, true).unwrap();

        let rendered: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(rendered["code"], "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
        assert_eq!(rendered["context"]["tool"], "read_file");
        assert!(rendered["suggested_fix"]
            .as_str()
            .expect("suggested_fix string")
            .contains("Issue a capability"));
    }

    #[test]
    fn write_cli_error_emits_human_report() {
        let error = CliError::Other("bad inputs".to_string());
        let mut output = Vec::new();

        write_cli_error(&mut output, &error, false).unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("error [CHIO-CLI-OTHER]: bad inputs"));
        assert!(rendered.contains("context:"));
        assert!(rendered.contains("suggested fix:"));
    }
}
