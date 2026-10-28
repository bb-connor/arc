//! `chio-verify <BUNDLE_DIR> --trust <FILE> [--json]`

use std::path::PathBuf;
use std::process::ExitCode;

use chio_bundle_verify::{read_trust_file, verify_bundle, BundleVerifyError, ExitClass};
use clap::Parser;

/// Verify an exported Chio evidence bundle offline.
#[derive(Debug, Parser)]
#[command(name = "chio-verify", version)]
struct Args {
    /// Exported package directory.
    bundle_dir: PathBuf,
    /// The verifier's `chio.verifier-trust.v1` file.
    #[arg(long)]
    trust: PathBuf,
    /// Print `chio.bundle-verify-report.v1` on stdout and rejections as JSON
    /// on stderr.
    #[arg(long)]
    json: bool,
}

fn exit(class: ExitClass) -> ExitCode {
    ExitCode::from(u8::try_from(class.code()).unwrap_or(1))
}

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "A command-line verifier prints its report and rejections."
)]
fn reject(error: &BundleVerifyError, json: bool) -> ExitCode {
    if json {
        let body = serde_json::json!({
            "code": error.code_urn(),
            "message": error.message(),
            "exit_class": error.exit_class().code(),
        });
        eprintln!("{body}");
    } else {
        match error.code_urn() {
            Some(code) => eprintln!("error [{code}]: {error}"),
            None => eprintln!("error: {error}"),
        }
    }
    exit(error.exit_class())
}

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "A command-line verifier prints its report and rejections."
)]
fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            let usage = error.use_stderr();
            let _ = error.print();
            return if usage {
                exit(ExitClass::Usage)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    let trust = match read_trust_file(&args.trust) {
        Ok(trust) => trust,
        Err(error) => return reject(&error, args.json),
    };
    let report = match verify_bundle(&args.bundle_dir, &trust, None) {
        Ok(verified) => verified.report,
        Err(error) => return reject(&error, args.json),
    };
    let class = report.exit_class(&trust);
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("error: cannot render the report: {error}");
                return exit(ExitClass::Unclassified);
            }
        }
    } else {
        println!("bundle verified: {} receipt(s)", report.receipts.len());
        for receipt in &report.receipts {
            let columns = &receipt.columns;
            println!(
                "{} identity_root={:?} delegation_chain={:?} decision={:?} content={:?} settlement={:?}",
                receipt.receipt_id,
                columns.identity_root.class,
                columns.delegation_chain.class,
                columns.decision.class,
                columns.content.class,
                columns.settlement.class,
            );
        }
        if class != ExitClass::Verified {
            eprintln!("error: a required column is not verified");
        }
    }
    exit(class)
}
