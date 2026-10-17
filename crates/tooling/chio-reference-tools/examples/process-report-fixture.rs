//! Real caged report effects and deterministic crash cutpoints for host qualification.
#![forbid(unsafe_code)]

use chio_reference_tools::{serve, ToolDescriptor, ToolError, ToolOutput, ToolServer};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

/// Reads of the control file before a hold fails. The native syscall profile
/// grants no sleep, so each poll is one file read.
const HOLD_POLLS: u32 = 50_000_000;

struct Reports {
    publications: PathBuf,
}

impl Reports {
    fn control(&self) -> Result<String, ToolError> {
        fs::read_to_string(self.publications.with_extension("control"))
            .map_err(|_| ToolError::Failed("fixture control unavailable".into()))
    }

    /// Under control `mode`, record the `.held` marker and block until the
    /// control reads `ready`, so a test can kill the host at this cutpoint.
    fn hold(&self, mode: &str) -> Result<(), ToolError> {
        if self.control()? != mode {
            return Ok(());
        }
        OpenOptions::new()
            .write(true)
            .open(self.publications.with_extension("held"))
            .and_then(|mut marker| {
                marker
                    .write_all(mode.as_bytes())
                    .and_then(|()| marker.sync_all())
            })
            .map_err(|_| ToolError::Failed("fixture hold marker unavailable".into()))?;
        for _ in 0..HOLD_POLLS {
            if self.control()? == "ready" {
                return Ok(());
            }
            std::hint::spin_loop();
        }
        Err(ToolError::Failed("fixture hold was not released".into()))
    }
}

impl ToolServer for Reports {
    fn name(&self) -> &str {
        "report-tools"
    }
    fn version(&self) -> &str {
        "1"
    }

    fn tools(&self) -> Vec<ToolDescriptor> {
        let Ok(control) = self.control() else {
            return Vec::new();
        };
        let changed = control == "changed";
        [
            (if changed { "readchanged" } else { "read" }, true),
            (if changed { "appendchanged" } else { "append" }, false),
        ]
        .into_iter()
        .map(|(name, read_only)| ToolDescriptor {
            name,
            description: "Report tool",
            input_schema: json!({"type":"object"}),
            read_only,
        })
        .collect()
    }

    fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
        match name {
            "read" if arguments["path"] == "source.txt" => {
                let source = fs::read_to_string(self.publications.with_extension("source.txt"))
                    .map_err(|_| ToolError::Failed("fixture source unavailable".into()))?;
                Ok(ToolOutput::structured(json!({"source":source})))
            }
            "append" => {
                self.hold("hold-before")?;
                let mut file = OpenOptions::new()
                    .append(true)
                    .open(&self.publications)
                    .map_err(|_| ToolError::Failed("fixture output unavailable".into()))?;
                writeln!(file, "{arguments}")
                    .and_then(|()| file.sync_all())
                    .map_err(|_| ToolError::Failed("fixture publication failed".into()))?;
                if self.control()? == "pause" {
                    // The host must retain uncertain-effect custody when killed here.
                    loop {
                        std::thread::park();
                    }
                }
                self.hold("hold-after")?;
                Ok(ToolOutput::structured(json!({"published":true})))
            }
            _ => Err(ToolError::InvalidArguments(
                "unknown report operation".into(),
            )),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let publications = PathBuf::from(arguments.next().ok_or("publication path is required")?);
    if arguments.next().is_some() || !publications.is_absolute() {
        return Err("expected one absolute publication path".into());
    }
    serve(
        Reports { publications },
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )?;
    Ok(())
}
