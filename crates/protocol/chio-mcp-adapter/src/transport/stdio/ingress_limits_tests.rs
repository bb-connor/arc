//! Real child streams exercise shared ingress retention and stderr draining.
use super::*;
use chio_core::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, RequestId, RootDefinition,
};
use chio_kernel::KernelError;
use chio_test_support::prelude::*;
use std::sync::atomic::AtomicUsize;

const CHILD: &str = r#"
import json
import os
import sys

mode = sys.argv[1]

def emit(value):
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
    sys.stdout.flush()

def notify(count, size):
    payload = 'x' * size
    for index in range(count):
        emit({'jsonrpc':'2.0', 'method':'notifications/message',
              'params':{'index':index, 'data':payload}})

for line in sys.stdin:
    request = json.loads(line)
    method = request.get('method')
    if method == 'initialize':
        emit({'jsonrpc':'2.0', 'id':request['id'], 'result':{
            'protocolVersion':'2025-11-25', 'capabilities':{'tools':{}},
            'serverInfo':{'name':'ingress-budget-fixture', 'version':'1'}}})
    elif method == 'fixture/notify':
        notify(20, 512 * 1024)
    elif method == 'tools/call':
        result = {'content':[], 'structuredContent':{'ok':True}}
        if mode in ('blocked', 'blocked-count'):
            emit({'jsonrpc':'2.0', 'id':'held-roots', 'method':'roots/list', 'params':{}})
            notify(20, 512 * 1024) if mode == 'blocked' else notify(300, 64)
        elif mode == 'nodes':
            result['structuredContent'] = {'items':[0] * 1048576}
        elif mode in ('stderr', 'stderr-long'):
            if mode == 'stderr':
                os.write(2, b'\xff\n')
            block = b'x' * 65536
            for _ in range(8 if mode == 'stderr' else 1024):
                remaining = memoryview(block)
                while remaining:
                    remaining = remaining[os.write(2, remaining):]
        elif mode == 'drain':
            notify(8, 512 * 1024)
        elif mode == 'broker':
            result['structuredContent'] = {'body':[255] * 524288}
        emit({'jsonrpc':'2.0', 'id':request['id'], 'result':result})
    elif method == 'fixture/probe':
        emit({'jsonrpc':'2.0', 'id':request['id'], 'result':{'ok':True}})
"#;

struct CountedStdout {
    inner: std::process::ChildStdout,
    read_bytes: Arc<AtomicUsize>,
}

impl Read for CountedStdout {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let size = self.inner.read(buffer)?;
        self.read_bytes.fetch_add(size, Ordering::Release);
        Ok(size)
    }
}

fn spawn(mode: &str) -> (StdioMcpTransport, Arc<AtomicUsize>) {
    let read_bytes = Arc::new(AtomicUsize::new(0));
    let reader_bytes = Arc::clone(&read_bytes);
    let transport = StdioMcpTransport::spawn_test_process_with_stdout(
        "python3",
        &["-c", CHILD, mode],
        StdioRequestTimeouts {
            initialization: Duration::from_secs(5),
            discovery: Duration::from_secs(5),
            request: Duration::from_secs(5),
        },
        |inner| {
            Box::new(CountedStdout {
                inner,
                read_bytes: reader_bytes,
            })
        },
    )
    .test_expect("initialize real ingress fixture");
    (transport, read_bytes)
}

fn wait_for_overload_or_unbounded_retention(
    transport: &StdioMcpTransport,
    read_bytes: &AtomicUsize,
    initial_bytes: usize,
    read_threshold: usize,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let lifecycle = transport
            .child_lifecycle
            .lock()
            .test_expect("inspect child cleanup");
        if !matches!(lifecycle.terminal, ChildTerminalState::Running) {
            return lifecycle.child.is_none();
        }
        drop(lifecycle);
        // Each test sets a byte threshold beyond its expected queue capacity.
        // Actual reads establish arrival; elapsed sleep does not stand in for it.
        if read_bytes.load(Ordering::Acquire) >= initial_bytes + read_threshold
            || Instant::now() >= deadline
        {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn nc3_unsolicited_notifications_share_retained_byte_budget() {
    let (transport, read_bytes) = spawn("idle");
    let initial_bytes = read_bytes.load(Ordering::Acquire);
    transport
        .send_notification_with_timeout("fixture/notify", json!({}), Duration::from_secs(5))
        .test_expect("request unsolicited fixture traffic");
    let terminal = wait_for_overload_or_unbounded_retention(
        &transport,
        &read_bytes,
        initial_bytes,
        9 * 1024 * 1024,
    );
    // Releasing retained notifications must not resurrect an overloaded session.
    drop(transport.drain_notifications());
    let probe = transport.send_request("fixture/probe", json!({}));
    transport
        .shutdown()
        .test_expect("cleanup unsolicited child");
    assert!(terminal, "overload must terminate and reap the producer");
    assert!(
        probe.is_err(),
        "draining must not revive the failed transport"
    );
}

struct HeldRoots {
    parent: RequestId,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

impl NestedFlowBridge for HeldRoots {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        self.entered
            .send(())
            .test_expect("signal active consumer hold");
        self.release
            .recv_timeout(Duration::from_secs(10))
            .test_expect("release active consumer");
        Ok(Vec::new())
    }

    fn create_message(
        &mut self,
        _: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        panic!("fixture did not request sampling")
    }

    fn create_elicitation(
        &mut self,
        _: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        panic!("fixture did not request elicitation")
    }

    fn notify_elicitation_completed(&mut self, _: &str) -> Result<(), KernelError> {
        panic!("fixture did not emit elicitation completion")
    }

    fn notify_resource_updated(&mut self, _: &str) -> Result<(), KernelError> {
        panic!("fixture did not emit resource changes")
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        panic!("fixture did not emit resource list changes")
    }
}

fn assert_stalled_consumer_overload_is_terminal(mode: &str, read_threshold: usize) {
    let (transport, read_bytes) = spawn(mode);
    let transport = Arc::new(transport);
    let initial_bytes = read_bytes.load(Ordering::Acquire);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let request_transport = Arc::clone(&transport);
    let request = std::thread::spawn(move || {
        let mut bridge = HeldRoots {
            parent: RequestId::new("nc3-active-parent"),
            entered: entered_tx,
            release: release_rx,
        };
        request_transport.send_request_with_nested_flow(
            "tools/call",
            json!({"name":"held", "arguments":{}}),
            Some(&mut bridge),
        )
    });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .test_expect("observe the real request consumer waiting in its bridge");
    let terminal = wait_for_overload_or_unbounded_retention(
        &transport,
        &read_bytes,
        initial_bytes,
        read_threshold,
    );
    release_tx.send(()).test_expect("release held roots bridge");
    let response = request.join().test_expect("join actual request caller");
    let probe = transport.send_request("fixture/probe", json!({}));
    transport.shutdown().test_expect("cleanup active child");
    assert!(
        terminal,
        "reader must clean up while the consumer is blocked"
    );
    assert!(response.is_err(), "overloaded request must not succeed");
    assert!(probe.is_err(), "subsequent requests must remain denied");
}

#[test]
fn nc3_active_request_queue_shares_retained_byte_budget() {
    assert_stalled_consumer_overload_is_terminal("blocked", 9 * 1024 * 1024);
}

#[test]
fn nc3_full_active_queue_cannot_discard_terminal_overload() {
    // The caller remains in its bridge while 300 small frames arrive. Any
    // attempt to report overload only through the 128-entry request channel
    // would lose the terminal decision behind these messages.
    assert_stalled_consumer_overload_is_terminal("blocked-count", 32 * 1024);
}

#[test]
fn nc3_expanding_frame_cannot_return_an_unadmitted_json_tree() {
    let (transport, _) = spawn("nodes");
    let response = transport.send_request("tools/call", json!({"name":"nodes", "arguments":{}}));
    let probe = transport.send_request("fixture/probe", json!({}));
    transport.shutdown().test_expect("cleanup expanding child");
    let error = response.test_expect_err("node expansion must be refused before handoff");
    assert!(
        error.to_string().contains("ingress"),
        "must reject for ingress admission, not merely time out: {error}"
    );
    assert!(probe.is_err(), "single-frame overload must be terminal");
}

#[test]
fn nc3_non_utf8_stderr_does_not_block_valid_stdout_response() {
    let (transport, _) = spawn("stderr");
    let response = transport.send_request("tools/call", json!({"name":"stderr", "arguments":{}}));
    transport.shutdown().test_expect("cleanup stderr child");
    let response = response.test_expect("keep draining stderr after invalid UTF-8");
    assert_eq!(response["structuredContent"]["ok"], true);
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").test_expect("read own RSS");
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .test_expect("Linux reports own resident bytes");
    let kib = value
        .split_whitespace()
        .next()
        .test_expect("RSS numeric field")
        .parse::<usize>()
        .test_expect("RSS is a nonnegative integer");
    kib.checked_mul(1024).test_expect("RSS byte conversion")
}

#[test]
#[cfg(target_os = "linux")]
fn nc3_unterminated_stderr_retention_is_bounded() {
    const ISOLATED: &str = "CHIO_NC3_STDERR_RETENTION_TEST_CHILD";
    if std::env::var_os(ISOLATED).is_none() {
        // The measurement owns its process so other test allocators and freed
        // JSON arenas cannot hide or manufacture retained stderr growth.
        let module = module_path!()
            .strip_prefix("chio_mcp_adapter::")
            .test_expect("unit test module prefix");
        let output = std::process::Command::new(std::env::current_exe().test_expect("test binary"))
            .args([
                "--exact",
                &format!("{module}::nc3_unterminated_stderr_retention_is_bounded"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ISOLATED, "1")
            .output()
            .test_expect("run isolated stderr allocation control");
        assert!(
            output.status.success(),
            "isolated stderr allocation control failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let (transport, _) = spawn("stderr-long");
    let before = resident_bytes();
    let response = transport.send_request("tools/call", json!({"name":"stderr", "arguments":{}}));
    let retained = resident_bytes().saturating_sub(before);
    // Measure before shutdown closes stderr: an unbounded lines() reader still
    // owns the complete unterminated record at this point.
    transport
        .shutdown()
        .test_expect("cleanup long stderr producer");
    let response = response.test_expect("valid stdout follows a 64 MiB unterminated stderr record");
    assert_eq!(response["structuredContent"]["ok"], true);
    assert!(
        retained < 32 * 1024 * 1024,
        "bounded stderr must not retain the attacker's entire record: grew by {retained} bytes"
    );
}

#[test]
fn nc3_notification_draining_releases_ingress_capacity() {
    let (transport, _) = spawn("drain");
    for _ in 0..3 {
        let result = transport
            .send_request("tools/call", json!({"name":"batch", "arguments":{}}))
            .test_expect("ordinary batch below the shared limit");
        assert_eq!(result["structuredContent"]["ok"], true);
        let notifications = transport.drain_notifications();
        assert_eq!(notifications.len(), 8);
        for notification in &notifications {
            assert_eq!(
                notification["params"]["data"]
                    .as_str()
                    .test_expect("notification payload")
                    .len(),
                512 * 1024
            );
        }
        drop(notifications);
    }
    transport.shutdown().test_expect("cleanup ordinary batches");
}

#[test]
fn nc3_real_broker_sized_structured_response_remains_admitted() {
    let (transport, _) = spawn("broker");
    let response = transport
        .send_request("tools/call", json!({"name":"broker", "arguments":{}}))
        .test_expect("admit the 524288-byte broker body as a JSON array");
    let body = response["structuredContent"]["body"]
        .as_array()
        .test_expect("structured broker body");
    assert_eq!(body.len(), 524_288);
    assert!(body.iter().all(|byte| byte.as_u64() == Some(255)));
    transport.shutdown().test_expect("cleanup broker response");
}
