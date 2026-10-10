#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::sync::Mutex;
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn protocol_boundary_expired_writer_never_enqueues() {
    let (tx, rx) = mpsc::sync_channel(1);
    let mut writer =
        BoundedStdioWriter::new(tx, Arc::new(AtomicBool::new(false)), Duration::from_secs(1))
            .unwrap();
    writer.write_all(b"effect").unwrap();
    writer.deadline = Instant::now();
    assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}
#[test]
fn protocol_boundary_writer_supervisor_refuses_expired_queue_entry() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::sync_channel(1);
    let (complete_tx, complete_rx) = mpsc::sync_channel(1);
    tx.send(WriterCommand {
        bytes: b"effect".to_vec(),
        deadline: Some(Instant::now()),
        completion: Some(complete_tx),
    })
    .unwrap();
    drop(tx);
    run_stdio_writer(Box::new(Capture(bytes.clone())), rx);
    assert!(bytes.lock().unwrap().is_empty());
    assert_eq!(
        complete_rx.recv().unwrap().unwrap_err(),
        "MCP stdin command expired before dispatch"
    );
}

#[test]
fn review_regression_writer_expiry_does_not_disconnect_healthy_commands() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::sync_channel(2);
    let (expired_tx, expired_rx) = mpsc::sync_channel(1);
    let (healthy_tx, healthy_rx) = mpsc::sync_channel(1);
    tx.send(WriterCommand {
        bytes: b"expired".to_vec(),
        deadline: Some(Instant::now()),
        completion: Some(expired_tx),
    })
    .unwrap();
    tx.send(WriterCommand {
        bytes: b"healthy".to_vec(),
        deadline: Instant::now().checked_add(Duration::from_secs(10)),
        completion: Some(healthy_tx),
    })
    .unwrap();
    drop(tx);
    run_stdio_writer(Box::new(Capture(bytes.clone())), rx);
    assert_eq!(&*bytes.lock().unwrap(), b"healthy");
    assert_eq!(
        expired_rx.recv().unwrap().unwrap_err(),
        "MCP stdin command expired before dispatch"
    );
    assert_eq!(healthy_rx.recv().unwrap(), Ok(()));
}
