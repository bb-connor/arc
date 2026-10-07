//! Model-free bounded projection worker. Cage policy, not this executable,
//! prevents filesystem/network/process escapes. Failure emits no error body.
#![forbid(unsafe_code)]
use chio_core_types::recovery::{decode_confined_input, project_confined_boolean};
use std::io::{Read, Write};
use std::process::ExitCode;
use zeroize::Zeroizing;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut packet = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut packet)?;
    let input = decode_confined_input(&packet)?;
    let output = Zeroizing::new(project_confined_boolean(input.observation, input.field)?);
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
