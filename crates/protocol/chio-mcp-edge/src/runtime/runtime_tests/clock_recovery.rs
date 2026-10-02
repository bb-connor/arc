#![cfg(test)]
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct MessageWriter {
    pending: Vec<u8>,
    sender: mpsc::Sender<Value>,
}

impl Write for MessageWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        for byte in bytes {
            if *byte == b'\n' {
                let message = serde_json::from_slice(&self.pending)?;
                self.pending.clear();
                self.sender.send(message).map_err(std::io::Error::other)?;
            } else {
                self.pending.push(*byte);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn response(
    receiver: &mpsc::Receiver<Value>,
    id: u64,
) -> Result<Value, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let message =
            receiver.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))?;
        if message["id"] == id {
            return Ok(message);
        }
    }
}

#[test]
fn background_without_pending_work_does_not_require_time() -> TestResult {
    let clock = Arc::new(ProtocolClock::new());
    let mut edge = edge_with_clock(clock.clone());
    clock.fail();
    assert!(!edge.process_background_tasks()?);
    let (_tx, mut rx) = mpsc::channel();
    let (_cancel_tx, mut cancel_rx) = mpsc::channel();
    assert!(!edge.process_background_tasks_with_channel(
        &mut rx,
        &mut cancel_rx,
        &mut Vec::new()
    )?);
    Ok(())
}

#[test]
fn serve_loop_preserves_idle_session_across_clock_failure() -> TestResult {
    serve_through_clock_failure(false)
}

#[test]
fn serve_loop_preserves_pending_work_and_recovers_without_reconnecting() -> TestResult {
    serve_through_clock_failure(true)
}

fn serve_through_clock_failure(pending: bool) -> TestResult {
    let clock = Arc::new(ProtocolClock::new());
    let mut edge = edge_with_clock(clock.clone());
    let task = pending.then(|| queue_task(&mut edge));
    clock.fail();
    std::thread::scope(|scope| -> TestResult {
        let (client_tx, client_rx) = mpsc::channel();
        let (output_tx, output_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let edge = &mut edge;
        let serve = scope.spawn(move || {
            let result = edge.serve_message_channels(
                client_rx,
                MessageWriter {
                    pending: Vec::new(),
                    sender: output_tx,
                },
            );
            let _ = done_tx.send(());
            result
        });
        let exercise = (|| -> TestResult {
            // Exercise actual idle ticks before sending any request. The completion
            // channel detects premature session termination without an unbounded wait.
            assert!(matches!(
                done_rx.recv_timeout(CLIENT_IDLE_POLL_INTERVAL * 4),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            client_tx.send(json!({"jsonrpc":"2.0","id":11,"method":"ping"}))?;
            assert_eq!(response(&output_rx, 11)?["result"], json!({}));
            client_tx.send(json!({"jsonrpc":"2.0","id":12,"method":"tasks/list","params":{}}))?;
            assert_eq!(
                response(&output_rx, 12)?["error"]["data"]["chioError"],
                "urn:chio:error:kernel:clock-unavailable"
            );

            clock.advance(5);
            client_tx.send(json!({"jsonrpc":"2.0","id":13,"method":"ping"}))?;
            assert_eq!(response(&output_rx, 13)?["result"], json!({}));
            if let Some(task) = &task {
                client_tx.send(json!({"jsonrpc":"2.0","id":14,"method":"tasks/result","params":{"taskId":task}}))?;
                let completed = response(&output_rx, 14)?;
                assert!(completed.get("error").is_none(), "{completed}");
                assert_eq!(completed["result"]["isError"], false);
            }
            Ok(())
        })();
        drop(client_tx);
        let served = serve.join().map_err(|_| "serve loop panicked")?;
        exercise?;
        served?;
        Ok(())
    })?;
    if let Some(task) = task {
        assert!(edge.pending_background_tasks.is_empty());
        assert!(edge.tasks[&task].is_terminal());
    }
    Ok(())
}
