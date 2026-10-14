//! Linux acceptance adversary. Build each image with CHIO_CONFINED_CANARY_MODE; that
//! measured image has no runtime mode/argument/environment escape hatch.
#![forbid(unsafe_code)]
use chio_core_types::recovery::{decode_confined_input, project_confined_boolean};
use std::io::{Read, Write};
use std::process::ExitCode;
use zeroize::Zeroizing;

const BUILD_MODE: Option<&str> = option_env!("CHIO_CONFINED_CANARY_MODE");
const MODE_RECORD_PREFIX: &[u8] = b"CHIO-CONFINED-CANARY-MODE-V1:";
const MODE_FIELD_BYTES: usize = 32;

const fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn mode_record() -> [u8; MODE_RECORD_PREFIX.len() + MODE_FIELD_BYTES] {
    let mode = match BUILD_MODE {
        Some(value) => {
            let bytes = value.as_bytes();
            if !(same_bytes(bytes, b"error")
                || same_bytes(bytes, b"log")
                || same_bytes(bytes, b"progress")
                || same_bytes(bytes, b"stream")
                || same_bytes(bytes, b"file")
                || same_bytes(bytes, b"callback")
                || same_bytes(bytes, b"wrong-predicate")
                || same_bytes(bytes, b"overflow")
                || same_bytes(bytes, b"hang"))
            {
                panic!("CHIO_CONFINED_CANARY_MODE must name a registered fixture");
            }
            bytes
        }
        None => b"unconfigured",
    };
    let mut record = [0; MODE_RECORD_PREFIX.len() + MODE_FIELD_BYTES];
    let mut index = 0;
    while index < MODE_RECORD_PREFIX.len() {
        record[index] = MODE_RECORD_PREFIX[index];
        index += 1;
    }
    index = 0;
    while index < mode.len() {
        record[MODE_RECORD_PREFIX.len() + index] = mode[index];
        index += 1;
    }
    record
}

// The record is part of the measured executable, not a self-issued attestation.
// Runtime mode, arguments, and inherited environment cannot change it.
#[used]
static MODE_RECORD: [u8; MODE_RECORD_PREFIX.len() + MODE_FIELD_BYTES] = mode_record();

fn run() -> Result<(), Box<dyn std::error::Error>> {
    std::hint::black_box(&MODE_RECORD);
    // Ordinary workspace/example builds remain valid, but an unconfigured
    // fixture refuses before reading input or acting on any return channel.
    let mode = BUILD_MODE.ok_or("acceptance fixture has no explicit build mode")?;
    let mut packet = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut packet)?;
    let input = decode_confined_input(&packet)?;
    let field = input.field;
    let observation = input.observation;
    let data: serde_json::Value = serde_json::from_slice(observation)?;
    let canary = data
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or("canary fixture")?
        .as_bytes();
    match mode {
        "error" => {
            std::io::stderr().write_all(canary)?;
            return Err("classified failure".into());
        }
        "log" => std::io::stderr().write_all(canary)?,
        "progress" | "stream" => {
            for b in canary {
                std::io::stdout().write_all(core::slice::from_ref(b))?;
            }
            return Ok(());
        }
        "file" => {
            let path = data
                .get("probe_file")
                .and_then(|v| v.as_str())
                .ok_or("file fixture")?;
            if std::fs::write(path, canary).is_ok() {
                return Err("filesystem confinement failed".into());
            }
        }
        "callback" => {
            #[cfg(unix)]
            {
                let path = data
                    .get("probe_socket")
                    .and_then(|v| v.as_str())
                    .ok_or("callback fixture")?;
                if let Ok(mut socket) = std::os::unix::net::UnixStream::connect(path) {
                    socket.write_all(canary)?;
                }
            }
            return Err("callback attempted".into());
        }
        "wrong-predicate" => {
            std::io::stdout().write_all(b"false")?;
            return Ok(());
        }
        "overflow" => {
            std::io::stderr().write_all(&vec![b'x'; 16385])?;
            return Ok(());
        }
        "hang" => loop {
            std::hint::spin_loop();
        },
        _ => return Err("unregistered fixture mode".into()),
    }
    let value = Zeroizing::new(project_confined_boolean(observation, field)?);
    std::io::stdout().write_all(&value)?;
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
