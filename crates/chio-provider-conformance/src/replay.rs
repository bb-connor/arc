//! Replay OpenAI provider captures through the native adapter surface.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chio_tool_call_fabric::{
    DenyReason, Principal, ProviderError, ProviderId, ProviderRequest, ReceiptId, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::assertions::{
    assert_canonical_json_eq, assert_verdict_eq, canonical_json_bytes_for, AssertionError,
};

const CAPTURE_SCHEMA: &str = "chio-provider-conformance.capture.v1";

/// Replay error with fixture path context.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// A fixture file could not be read.
    #[error("read fixture {path:?}: {source}")]
    ReadFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A fixture directory could not be read.
    #[error("read fixture directory {path:?}: {source}")]
    ReadFixtureDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A fixture line was not valid JSON.
    #[error("parse fixture {path:?} line {line}: {source}")]
    ParseLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    /// A capture field had an unsupported value.
    #[error("invalid fixture {path:?}: {message}")]
    InvalidFixture { path: PathBuf, message: String },
    /// Canonical JSON or equality assertion failed.
    #[error(transparent)]
    Assertion(#[from] AssertionError),
    /// Provider adapter replay failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// JSON encoding or decoding failed while reconstructing replay inputs.
    #[error("JSON error during replay: {0}")]
    Json(#[from] serde_json::Error),
}

/// Loaded provider capture fixture.
#[derive(Debug, Clone)]
pub struct ProviderCaptureFixture {
    /// Fixture id embedded in every capture record.
    pub fixture_id: String,
    /// Source file path.
    pub path: PathBuf,
    records: Vec<CaptureRecord>,
}

/// Replay mode selected from the capture shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMode {
    /// Batch `upstream_response` payloads were lifted.
    Batch,
    /// Streaming `upstream_event` payloads were replayed as SSE.
    Stream,
    /// No tool call crossed the adapter boundary.
    NoToolCall,
}

/// Summary returned after a fixture replay completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Fixture id.
    pub fixture_id: String,
    /// Source fixture path.
    pub path: PathBuf,
    /// Replay mode used for this fixture.
    pub mode: ReplayMode,
    /// Number of NDJSON records loaded.
    pub records: usize,
    /// Number of adapter invocations reconstructed.
    pub invocations: usize,
    /// Number of kernel verdict records asserted.
    pub verdicts: usize,
    /// Number of lowered provider responses asserted.
    pub lowered_responses: usize,
}

/// Captured verdict record normalized into the fabric verdict type.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedVerdict {
    /// Invocation id from the capture record.
    pub invocation_id: String,
    /// Fabric verdict reconstructed from the capture.
    pub verdict: VerdictResult,
    /// Captured invocation body used for canonical JSON byte assertions.
    pub invocation: ComparableInvocation,
}

/// Tool invocation representation used for stable capture comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparableInvocation {
    pub provider: ProviderId,
    pub tool_name: String,
    pub arguments: Value,
    pub provenance: ComparableProvenance,
}

/// Provenance representation used for stable capture comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparableProvenance {
    pub provider: ProviderId,
    pub request_id: String,
    pub api_version: String,
    pub principal: Principal,
    pub received_at: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct CaptureRecord {
    schema: String,
    fixture_id: String,
    direction: CaptureDirection,
    provider: String,
    #[serde(default)]
    invocation_id: Option<String>,
    #[serde(default)]
    verdict: Option<CapturedVerdictKind>,
    #[serde(default)]
    receipt_id: Option<String>,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CaptureDirection {
    UpstreamRequest,
    UpstreamResponse,
    UpstreamEvent,
    KernelVerdict,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CapturedVerdictKind {
    Allow,
    Deny,
}

/// Return the OpenAI fixture corpus path.
pub fn openai_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/openai")
}

/// Return all OpenAI NDJSON fixture paths in deterministic order.
pub fn openai_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    let root = openai_fixture_dir();
    let entries = fs::read_dir(&root).map_err(|source| ReplayError::ReadFixtureDir {
        path: root.clone(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ReplayError::ReadFixtureDir {
            path: root.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Load an NDJSON fixture from disk.
pub fn load_fixture(path: impl AsRef<Path>) -> Result<ProviderCaptureFixture, ReplayError> {
    let path = path.as_ref().to_path_buf();
    let body = fs::read_to_string(&path).map_err(|source| ReplayError::ReadFixture {
        path: path.clone(),
        source,
    })?;
    let mut records = Vec::new();

    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str::<CaptureRecord>(line).map_err(|source| {
            ReplayError::ParseLine {
                path: path.clone(),
                line: line_index + 1,
                source,
            }
        })?;
        validate_record(&path, &record)?;
        records.push(record);
    }

    let Some(first) = records.first() else {
        return Err(invalid_fixture(
            &path,
            "fixture did not contain any records",
        ));
    };
    let fixture_id = first.fixture_id.clone();
    if records
        .iter()
        .any(|record| record.fixture_id.as_str() != fixture_id.as_str())
    {
        return Err(invalid_fixture(
            &path,
            "fixture_id changed within one NDJSON file",
        ));
    }

    Ok(ProviderCaptureFixture {
        fixture_id,
        path,
        records,
    })
}

/// Replay an OpenAI fixture through the OpenAI provider adapter.
#[cfg(feature = "fixtures-openai")]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    use chio_openai::OpenAiAdapter;

    let fixture = load_fixture(path)?;
    fixture.ensure_openai()?;
    let captured = fixture.captured_verdicts()?;
    let org_id = fixture.openai_org_id()?;
    let adapter = OpenAiAdapter::new(org_id);

    let (mode, invocations, verdicts) = if fixture.has_stream_tool_events() {
        let (invocations, verdicts) = replay_openai_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else if captured.is_empty() {
        (ReplayMode::NoToolCall, Vec::new(), Vec::new())
    } else {
        let invocations = replay_openai_batch(&fixture, &adapter)?;
        let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
        (ReplayMode::Batch, invocations, verdicts)
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_openai_lowered_responses(&fixture, &adapter, &captured)?;

    Ok(ReplayOutcome {
        fixture_id: fixture.fixture_id,
        path: fixture.path,
        mode,
        records: fixture.records.len(),
        invocations: invocations.len(),
        verdicts: verdicts.len(),
        lowered_responses,
    })
}

/// Stub that explains which feature is needed for OpenAI replay.
#[cfg(not(feature = "fixtures-openai"))]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "OpenAI replay requires the fixtures-openai feature",
    ))
}

impl ProviderCaptureFixture {
    fn ensure_openai(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "openai")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "OpenAI replay received a non-openai provider record",
        ))
    }

    fn captured_verdicts(&self) -> Result<Vec<CapturedVerdict>, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::KernelVerdict)
            .map(|record| self.captured_verdict(record))
            .collect()
    }

    fn captured_verdict(&self, record: &CaptureRecord) -> Result<CapturedVerdict, ReplayError> {
        let invocation_id =
            required_field(&self.path, record.invocation_id.as_deref(), "invocation_id")?;
        let receipt_id = required_field(&self.path, record.receipt_id.as_deref(), "receipt_id")?;
        let kind = record.verdict.ok_or_else(|| {
            invalid_fixture(&self.path, "kernel_verdict record was missing verdict")
        })?;
        let invocation_value = record.payload.get("invocation").ok_or_else(|| {
            invalid_fixture(&self.path, "kernel_verdict payload was missing invocation")
        })?;
        let invocation = serde_json::from_value::<ComparableInvocation>(invocation_value.clone())?;

        if invocation.provenance.request_id != invocation_id {
            return Err(invalid_fixture(
                &self.path,
                "kernel_verdict invocation_id did not match provenance.request_id",
            ));
        }

        let verdict = match kind {
            CapturedVerdictKind::Allow => VerdictResult::Allow {
                redactions: captured_redactions(&record.payload)?,
                receipt_id: ReceiptId(receipt_id.to_string()),
            },
            CapturedVerdictKind::Deny => VerdictResult::Deny {
                reason: captured_deny_reason(&self.path, &record.payload)?,
                receipt_id: ReceiptId(receipt_id.to_string()),
            },
        };

        Ok(CapturedVerdict {
            invocation_id: invocation_id.to_string(),
            verdict,
            invocation,
        })
    }

    fn openai_org_id(&self) -> Result<String, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamRequest)
            .find_map(|record| org_id_from_payload(&record.payload))
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "OpenAI fixture did not include an organization header",
                )
            })
    }

    fn has_stream_tool_events(&self) -> bool {
        self.records.iter().any(|record| {
            if record.direction != CaptureDirection::UpstreamEvent {
                return false;
            }

            event_name(&record.payload).is_some_and(|event| {
                event == "response.function_call_arguments.delta"
                    || stream_event_item(&record.payload)
                        .and_then(|item| item.get("type"))
                        .and_then(Value::as_str)
                        == Some("function_call")
            })
        })
    }

    fn upstream_responses(&self) -> impl Iterator<Item = &CaptureRecord> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamResponse)
    }

    fn lowered_tool_output_requests(&self) -> Vec<&CaptureRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.direction == CaptureDirection::UpstreamRequest
                    && record
                        .payload
                        .get("body")
                        .and_then(|body| body.get("tool_outputs"))
                        .is_some()
            })
            .collect()
    }
}

#[cfg(feature = "fixtures-openai")]
fn replay_openai_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-openai")]
fn replay_openai_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let sse = fixture_sse_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&sse, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "OpenAI stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("OpenAI stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}

fn assert_replayed_invocations(
    fixture: &ProviderCaptureFixture,
    captured: &[CapturedVerdict],
    invocations: &[ToolInvocation],
) -> Result<(), ReplayError> {
    let mut expected = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.invocation.clone()))
        .collect::<BTreeMap<_, _>>();

    for invocation in invocations {
        let request_id = invocation.provenance.request_id.as_str();
        let expected_invocation = expected.remove(request_id).ok_or_else(|| {
            invalid_fixture(
                &fixture.path,
                format!("adapter produced unexpected invocation {request_id}"),
            )
        })?;
        let actual = comparable_invocation(
            invocation,
            expected_invocation.provenance.received_at.clone(),
        )?;
        assert_canonical_json_eq(
            format!("{} invocation {request_id}", fixture.fixture_id),
            &expected_invocation,
            &actual,
        )?;
    }

    if let Some((request_id, _)) = expected.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("adapter did not replay expected invocation {request_id}"),
        ));
    }

    Ok(())
}

fn assert_replayed_verdicts(
    fixture: &ProviderCaptureFixture,
    captured: &[CapturedVerdict],
    verdicts: &[VerdictResult],
) -> Result<(), ReplayError> {
    if captured.len() != verdicts.len() {
        return Err(invalid_fixture(
            &fixture.path,
            format!(
                "captured {} verdicts but replay produced {}",
                captured.len(),
                verdicts.len()
            ),
        ));
    }

    for (captured, actual) in captured.iter().zip(verdicts) {
        assert_verdict_eq(
            format!("{} verdict {}", fixture.fixture_id, captured.invocation_id),
            &captured.verdict,
            actual,
        )?;
    }

    Ok(())
}

#[cfg(feature = "fixtures-openai")]
fn assert_openai_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    use chio_tool_call_fabric::ProviderAdapter;

    let lower_verdict = shared_lower_verdict(&fixture.path, captured)?;
    let mut lowered = 0;

    for record in fixture.lowered_tool_output_requests() {
        let expected_body = record.payload.get("body").ok_or_else(|| {
            invalid_fixture(
                &fixture.path,
                "lowered upstream_request payload was missing body",
            )
        })?;
        let Some(verdict) = lower_verdict.clone() else {
            return Err(invalid_fixture(
                &fixture.path,
                "lowered tool output request appeared without captured verdict",
            ));
        };
        let result = ToolResult(canonical_json_bytes_for(
            format!("{} captured tool result", fixture.fixture_id),
            expected_body,
        )?);
        let response = futures_lite_block_on(adapter.lower(verdict, result))?;
        let actual_body = serde_json::from_slice::<Value>(&response.0)?;

        assert_canonical_json_eq(
            format!("{} lowered OpenAI tool_outputs", fixture.fixture_id),
            expected_body,
            &actual_body,
        )?;
        lowered += 1;
    }

    Ok(lowered)
}

#[cfg(not(feature = "fixtures-openai"))]
fn assert_openai_lowered_responses(
    fixture: &ProviderCaptureFixture,
    _adapter: &(),
    _captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    if !fixture.lowered_tool_output_requests().is_empty() {
        return Err(invalid_fixture(
            &fixture.path,
            "OpenAI lowering requires the fixtures-openai feature",
        ));
    }
    Ok(0)
}

fn validate_record(path: &Path, record: &CaptureRecord) -> Result<(), ReplayError> {
    if record.schema != CAPTURE_SCHEMA {
        return Err(invalid_fixture(
            path,
            format!("unsupported capture schema {}", record.schema),
        ));
    }

    if record.provider.is_empty() {
        return Err(invalid_fixture(path, "provider was empty"));
    }

    Ok(())
}

fn comparable_invocation(
    invocation: &ToolInvocation,
    received_at: Value,
) -> Result<ComparableInvocation, ReplayError> {
    Ok(ComparableInvocation {
        provider: invocation.provider,
        tool_name: invocation.tool_name.clone(),
        arguments: serde_json::from_slice(&invocation.arguments)?,
        provenance: ComparableProvenance {
            provider: invocation.provenance.provider,
            request_id: invocation.provenance.request_id.clone(),
            api_version: invocation.provenance.api_version.clone(),
            principal: invocation.provenance.principal.clone(),
            received_at,
        },
    })
}

fn captured_redactions(payload: &Value) -> Result<Vec<Redaction>, ReplayError> {
    let Some(redactions) = payload.get("redactions") else {
        return Ok(Vec::new());
    };
    serde_json::from_value(redactions.clone()).map_err(ReplayError::from)
}

fn captured_deny_reason(path: &Path, payload: &Value) -> Result<DenyReason, ReplayError> {
    let reason = payload
        .get("reason")
        .ok_or_else(|| invalid_fixture(path, "deny kernel_verdict payload was missing reason"))?;
    serde_json::from_value(reason.clone()).map_err(ReplayError::from)
}

fn shared_lower_verdict(
    path: &Path,
    captured: &[CapturedVerdict],
) -> Result<Option<VerdictResult>, ReplayError> {
    let mut verdicts = captured.iter().map(|entry| entry.verdict.clone());
    let Some(first) = verdicts.next() else {
        return Ok(None);
    };

    for verdict in verdicts {
        if verdict_kind(&first) != verdict_kind(&verdict) {
            return Err(invalid_fixture(
                path,
                "one lowered tool_outputs payload cannot represent mixed verdict kinds",
            ));
        }
    }

    Ok(Some(first))
}

fn verdict_kind(verdict: &VerdictResult) -> &'static str {
    match verdict {
        VerdictResult::Allow { .. } => "allow",
        VerdictResult::Deny { .. } => "deny",
    }
}

fn response_has_no_tool_calls(payload: &Value) -> bool {
    let output = payload.get("output").and_then(Value::as_array);
    let Some(output) = output else {
        return true;
    };

    !output.iter().any(|item| {
        item.get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "function_call")
    })
}

fn fixture_sse_bytes(fixture: &ProviderCaptureFixture) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = Vec::new();

    for record in &fixture.records {
        if record.direction != CaptureDirection::UpstreamEvent {
            continue;
        }

        let event = event_name(&record.payload).ok_or_else(|| {
            invalid_fixture(&fixture.path, "upstream_event payload was missing event")
        })?;
        let data = record.payload.get("data").ok_or_else(|| {
            invalid_fixture(&fixture.path, "upstream_event payload was missing data")
        })?;
        bytes.extend_from_slice(b"event: ");
        bytes.extend_from_slice(event.as_bytes());
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(b"data: ");
        bytes.extend_from_slice(serde_json::to_string(data)?.as_bytes());
        bytes.extend_from_slice(b"\n\n");
    }

    Ok(bytes)
}

fn event_name(payload: &Value) -> Option<&str> {
    payload.get("event").and_then(Value::as_str)
}

fn stream_event_item(payload: &Value) -> Option<&Value> {
    payload
        .get("data")
        .and_then(|data| data.get("item"))
        .or_else(|| payload.get("data").and_then(|data| data.get("output_item")))
}

fn org_id_from_payload(payload: &Value) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if is_openai_org_header(key) {
            header_value(value)
        } else {
            None
        }
    })
}

fn is_openai_org_header(key: &str) -> bool {
    key.eq_ignore_ascii_case("openai-organization")
        || key.eq_ignore_ascii_case("openai-org-id")
        || key.eq_ignore_ascii_case("x-openai-organization")
}

fn header_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => non_empty(value),
        Value::Array(values) => values.iter().find_map(header_value),
        _ => None,
    }
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn required_field<'a>(
    path: &Path,
    value: Option<&'a str>,
    field: &str,
) -> Result<&'a str, ReplayError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_fixture(path, format!("record was missing {field}")))
}

fn invalid_fixture(path: impl AsRef<Path>, message: impl Into<String>) -> ReplayError {
    ReplayError::InvalidFixture {
        path: path.as_ref().to_path_buf(),
        message: message.into(),
    }
}

fn futures_lite_block_on<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
