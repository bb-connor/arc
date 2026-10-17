use super::*;
use chio_guards::SanitizerHook;
use chio_kernel::PipelineOutcome;
use std::sync::{mpsc, Barrier};
use std::time::Duration;

const THREADS: usize = 8;
const CALLS_PER_THREAD: usize = 24;
const CANARY: &str = "tripwire-canary";

struct CanaryDetector;

impl TripwireDetectorPort for CanaryDetector {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision> {
        let content =
            std::str::from_utf8(input.content.as_bytes()).map_err(|_| PortError::invalid_data())?;
        if content.contains(CANARY) {
            Ok(TripwireDecision::Match {
                artifact_id_hash: input.content_digest,
                artifact_version_hash: input.canonical_context_digest,
            })
        } else {
            Ok(TripwireDecision::Clear)
        }
    }
}

#[derive(Default)]
struct RecordingPostFlow {
    observed: Mutex<Vec<(String, serde_json::Value)>>,
}

impl FlowPostInvocationPort for RecordingPostFlow {
    fn evaluate(&self, input: &FlowPostInvocationInput<'_>) -> Result<(), FlowDenial> {
        self.observed
            .lock()
            .map_err(|_| FlowDenial::StateChanged)?
            .push((input.request.request_id.clone(), input.response.clone()));
        Ok(())
    }
}

struct Harness {
    pipeline: PostInvocationPipeline,
    flow: Arc<RecordingPostFlow>,
    events: Arc<FakeEvents>,
}

fn harness() -> Harness {
    let flow = Arc::new(RecordingPostFlow::default());
    let events = Arc::new(FakeEvents::new(false));
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(SanitizerHook::new()));
    pipeline.add(Box::new(FlowPostInvocationHook::new(
        flow.clone(),
        MissingContextPolicy::Deny,
    )));
    pipeline.add(Box::new(RawOutputTripwireHook::new(
        Arc::new(CanaryDetector),
        tripwire_publisher(events.clone()),
        MissingContextPolicy::Deny,
    )));
    Harness {
        pipeline,
        flow,
        events,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallKind {
    Redacted,
    Tripwire,
    RedactedThenTripwire,
}

struct Call {
    kind: CallKind,
    request: ToolCallRequest,
    response: serde_json::Value,
}

fn calls(base: &ToolCallRequest) -> Vec<Call> {
    (0..THREADS * CALLS_PER_THREAD)
        .map(|index| {
            let mut request = base.clone();
            request.request_id = format!("request-{index}");
            let token = format!("ghp_{:0>36}", index);
            let (kind, response) = match index % 3 {
                0 => (
                    CallKind::Redacted,
                    serde_json::json!({"call": index, "contact": format!("user{index}@example.com")}),
                ),
                1 => (
                    CallKind::Tripwire,
                    serde_json::json!({"call": index, "note": format!("{CANARY} {index}")}),
                ),
                _ => (
                    CallKind::RedactedThenTripwire,
                    serde_json::json!({"call": index, "token": token, "note": CANARY}),
                ),
            };
            Call {
                kind,
                request,
                response,
            }
        })
        .collect()
}

fn evaluate(
    pipeline: &PostInvocationPipeline,
    call: &Call,
    security: &SecurityInvocationContext,
) -> PipelineOutcome {
    let context = PostInvocationContext::from_request_with_security_context(
        &call.request,
        Some(0),
        Some(security),
    );
    pipeline.evaluate_with_context_and_evidence(&context, &call.response)
}

fn assert_outcome_belongs_to_call(index: usize, call: &Call, outcome: &PipelineOutcome) {
    let names = outcome
        .evidence
        .iter()
        .map(|evidence| evidence.guard_name.as_str())
        .collect::<Vec<_>>();
    match call.kind {
        CallKind::Redacted => {
            let PostInvocationVerdict::Redact(value) = &outcome.verdict else {
                panic!("call {index} expected Redact, got {:?}", outcome.verdict);
            };
            assert_eq!(value["call"], serde_json::json!(index));
            assert!(!value.to_string().contains(&format!("user{index}@")));
            assert_eq!(names, ["output-sanitizer"], "call {index}");
        }
        CallKind::Tripwire => {
            assert!(
                matches!(outcome.verdict, PostInvocationVerdict::Block(_)),
                "call {index} expected Block, got {:?}",
                outcome.verdict
            );
            assert_eq!(names, ["chio-watermark-tripwire"], "call {index}");
        }
        CallKind::RedactedThenTripwire => {
            assert!(
                matches!(outcome.verdict, PostInvocationVerdict::Block(_)),
                "call {index} expected Block, got {:?}",
                outcome.verdict
            );
            assert_eq!(
                names,
                ["output-sanitizer", "chio-watermark-tripwire"],
                "call {index}"
            );
        }
    }
}

#[test]
fn concurrent_pipeline_calls_keep_their_own_results_and_evidence() {
    let base = request();
    let security = security_context(&base);
    let calls = calls(&base);

    let oracle = harness();
    let expected = calls
        .iter()
        .map(|call| evaluate(&oracle.pipeline, call, &security))
        .collect::<Vec<_>>();

    let shared = Arc::new(harness());
    let calls = Arc::new(calls);
    let security = Arc::new(security);
    let start = Arc::new(Barrier::new(THREADS));
    let (sender, receiver) = mpsc::channel();
    let workers = (0..THREADS)
        .map(|thread| {
            let shared = Arc::clone(&shared);
            let calls = Arc::clone(&calls);
            let security = Arc::clone(&security);
            let start = Arc::clone(&start);
            let sender = sender.clone();
            std::thread::spawn(move || {
                start.wait();
                for round in 0..CALLS_PER_THREAD {
                    let index = round * THREADS + thread;
                    let outcome = evaluate(&shared.pipeline, &calls[index], &security);
                    if sender.send((index, outcome)).is_err() {
                        return;
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    drop(sender);

    let mut seen = vec![false; calls.len()];
    for _ in 0..calls.len() {
        let (index, outcome) = match receiver.recv_timeout(Duration::from_secs(60)) {
            Ok(received) => received,
            Err(error) => panic!("post-invocation pipeline call did not complete: {error}"),
        };
        assert!(!seen[index], "call {index} reported twice");
        seen[index] = true;
        assert_outcome_belongs_to_call(index, &calls[index], &outcome);
        assert_eq!(
            format!("{:?}", outcome.verdict),
            format!("{:?}", expected[index].verdict),
            "call {index} verdict differs from its isolated evaluation"
        );
        assert_eq!(
            outcome.evidence, expected[index].evidence,
            "call {index} evidence differs from its isolated evaluation"
        );
        assert_eq!(outcome.escalations, expected[index].escalations);
    }
    for worker in workers {
        if worker.join().is_err() {
            panic!("post-invocation worker panicked");
        }
    }

    let observed = shared
        .flow
        .observed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(observed.len(), calls.len());
    for (request_id, response) in observed {
        let index = request_id
            .strip_prefix("request-")
            .and_then(|index| index.parse::<usize>().ok())
            .test_unwrap();
        assert_eq!(response["call"], serde_json::json!(index));
    }
    let tripwire_calls = calls
        .iter()
        .filter(|call| call.kind != CallKind::Redacted)
        .count();
    assert_eq!(shared.events.appends.load(Ordering::SeqCst), tripwire_calls);
    assert_eq!(oracle.events.appends.load(Ordering::SeqCst), tripwire_calls);
}
