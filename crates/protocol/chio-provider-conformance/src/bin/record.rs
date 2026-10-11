#[path = "record/anthropic.rs"]
mod anthropic;
#[path = "record/bedrock.rs"]
mod bedrock;
#[path = "record/cli.rs"]
mod cli;
#[path = "record/credentials.rs"]
mod credentials;
#[path = "record/fixture.rs"]
mod fixture;
#[path = "record/http.rs"]
mod http;
#[path = "record/invoke.rs"]
mod invoke;
#[path = "record/openai.rs"]
mod openai;
#[path = "record/process.rs"]
mod process;
#[path = "record/record.rs"]
mod record;
#[path = "record/util.rs"]
mod util;

use std::path::PathBuf;

use thiserror::Error;

fn main() {
    cli::main();
}

#[derive(Debug, Error)]
pub(crate) enum RecordError {
    #[error("{0}")]
    Provider(#[from] chio_tool_call_fabric::ProviderError),
    #[error("{0}")]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
    #[error("capture I/O failed")]
    CaptureIo(#[from] std::io::Error),
    #[error("{0}")]
    Transport(#[from] chio_provider_adapter_core::http::HttpTransportError),
    #[error("capture process exceeded its deadline")]
    ProcessTimeout,
    #[error("capture process output exceeded its byte limit")]
    ProcessOutputLimit,
    #[error("capture process failed with exit status {code:?}")]
    ProcessFailed { code: Option<i32> },
    #[error("invalid scenario id `{0}`: use the fixture id without path separators")]
    InvalidScenario(String),
    #[error("scenario fixture does not exist: {path}")]
    ScenarioNotFound { path: PathBuf },
    #[error("read fixture {path}: {source}")]
    ReadFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("create fixture directory {path}: {source}")]
    CreateFixtureDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("write fixture {path}: {source}")]
    WriteFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("replace fixture {path}: {source}")]
    ReplaceFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse fixture {path} line {line}: {source}")]
    ParseFixtureLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: chio_core::canonical::UntrustedJsonError,
    },
    #[error("invalid fixture {path}: {message}")]
    InvalidFixture { path: PathBuf, message: String },
    #[error("missing environment for {provider}: set {vars}")]
    MissingEnv {
        provider: &'static str,
        vars: &'static str,
    },
    #[error("{provider} captured payload did not contain expected tool invocations: {message}")]
    CaptureShape {
        provider: &'static str,
        message: String,
    },
    #[error("JSON error while recording fixture: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bedrock AWS CLI command failed: {message}")]
    AwsCli { message: String },
    #[error("bedrock streaming re-record requires a Bedrock SDK event-stream capture path; use a non-streaming scenario for this CLI revision")]
    BedrockStreamUnsupported,
}
