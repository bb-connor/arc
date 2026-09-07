//! Offline signature verification for original worker receipt exports.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use super::CliError;

const MAX_LINE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECEIPTS: usize = 10_000;

pub(crate) fn cmd_receipt_verify(
    input: &Path,
    key_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let fail = |message: String| CliError::cli_other_error(message);
    let key = super::load_trusted_kernel_pubkey(key_path)
        .map_err(|error| fail(format!("invalid trusted kernel key: {error}")))?;
    let file = std::fs::File::open(input)
        .map_err(|error| fail(format!("cannot open receipt input: {error}")))?;
    if !file
        .metadata()
        .map_err(|error| fail(error.to_string()))?
        .is_file()
    {
        return Err(fail("receipt input must be a regular file".to_string()));
    }
    let mut reader = BufReader::new(file);
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    let mut line_number = 0usize;
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_LINE_BYTES + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| fail(format!("cannot read receipt input: {error}")))?;
        if read == 0 {
            break;
        }
        line_number += 1;
        total_bytes += read as u64;
        if total_bytes > MAX_INPUT_BYTES {
            return Err(fail("receipt input exceeds 64 MiB".to_string()));
        }
        if read as u64 > MAX_LINE_BYTES {
            return Err(fail(format!("receipt line {line_number} exceeds 8 MiB")));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if count == MAX_RECEIPTS {
            return Err(fail("receipt input exceeds 10000 receipts".to_string()));
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| fail(format!("invalid receipt JSON at line {line_number}")))?;
        let canonical = chio_core::canonical::canonical_json_string_from_str(text)
            .map_err(|_| fail(format!("non-I-JSON receipt at line {line_number}")))?;
        let value: serde_json::Value = serde_json::from_str(&canonical)
            .map_err(|_| fail(format!("invalid receipt JSON at line {line_number}")))?;
        let receipt: chio_core::receipt::body::ChioReceipt = serde_json::from_value(value.clone())
            .map_err(|_| fail(format!("invalid receipt schema at line {line_number}")))?;
        let supported = chio_core::canonical::canonical_json_string(&receipt)
            .map_err(|_| fail(format!("invalid receipt schema at line {line_number}")))?;
        if canonical != supported {
            return Err(fail(format!(
                "receipt fields differ from the supported signed schema at line {line_number}"
            )));
        }
        let outcome = super::replay_cli::verify_receipt(&value, Some(&key));
        if !outcome.ok {
            return Err(fail(format!(
                "receipt verification failed at line {line_number}: {}",
                outcome
                    .error
                    .unwrap_or_else(|| "invalid signature".to_string())
            )));
        }
        count += 1;
    }
    if count == 0 {
        return Err(fail("receipt input is empty".to_string()));
    }
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "schema": "chio.receipt.signatures.v1",
                "receipts_verified": count,
                "trusted_kernel_key": key.to_hex(),
                "checks": ["signature", "signer_pin", "action_parameter_hash"],
            })
        );
    } else {
        println!("Verified {count} receipt signatures, signer pins and action hashes.");
    }
    Ok(())
}
