//! Qualification fixture that attempts OS effects without application path checks.
//! Build explicitly as an example; this is not a supported end-user tool.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;

use chio_reference_tools::{
    serve, string_argument, ToolDescriptor, ToolError, ToolOutput, ToolServer,
};
use serde_json::{json, Value};

struct EnforcementProbe;

fn observed(result: std::io::Result<Value>) -> ToolOutput {
    ToolOutput::structured(match result {
        Ok(value) => json!({"effect": "succeeded", "value": value}),
        Err(error) => json!({"effect": "refused", "os_errno": error.raw_os_error()}),
    })
}

impl ToolServer for EnforcementProbe {
    fn name(&self) -> &str {
        "chio-enforcement-probe"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn tools(&self) -> Vec<ToolDescriptor> {
        [
            ("read_file", "path", true),
            ("write_file", "path", false),
            ("append_and_wait", "path", false),
            ("connect_socket", "address", false),
        ]
        .into_iter()
        .map(|(name, argument, read_only)| ToolDescriptor {
            name,
            description: "Qualification only: attempt the named OS operation directly",
            input_schema: json!({
                "type": "object", "properties": {argument: {"type": "string"}},
                "required": [argument], "additionalProperties": false,
            }),
            read_only,
        })
        .collect()
    }
    fn call(&mut self, name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
        match name {
            "read_file" => {
                let path = string_argument(arguments, "path")?;
                Ok(observed(std::fs::File::open(path).and_then(|file| {
                    let mut bytes = Vec::new();
                    file.take(65_536).read_to_end(&mut bytes)?;
                    Ok(json!({"bytes_hex": hex::encode(bytes)}))
                })))
            }
            "write_file" => {
                let path = string_argument(arguments, "path")?;
                Ok(observed(
                    std::fs::write(path, b"probe-effect\n").map(|()| json!(null)),
                ))
            }
            "append_and_wait" => {
                let path = string_argument(arguments, "path")?;
                let result = std::fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .and_then(|mut file| file.write_all(b"probe-effect\n"));
                if let Err(error) = result {
                    return Ok(observed(Err(error)));
                }
                // The external harness kills the host after observing this
                // write. Never return an outcome or issue a second effect.
                loop {
                    std::thread::yield_now();
                }
            }
            "connect_socket" => {
                let address = string_argument(arguments, "address")?;
                Ok(observed(TcpStream::connect(address).and_then(
                    |mut socket| {
                        socket.write_all(b"probe-effect\n")?;
                        Ok(json!(null))
                    },
                )))
            }
            _ => Err(ToolError::InvalidArguments("unknown probe".into())),
        }
    }
}

fn main() -> ExitCode {
    match serve(
        EnforcementProbe,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("enforcement probe: {error}");
            ExitCode::FAILURE
        }
    }
}
