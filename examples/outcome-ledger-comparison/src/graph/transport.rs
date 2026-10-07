use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use chio_core_types::receipt::decision::Decision;
use serde_json::{json, Value};

use super::model::{hash, Endpoint, Reply, Rpc};
use crate::Result;

static REQUESTS: AtomicUsize = AtomicUsize::new(0);

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl OwnedChild {
    fn wait(&mut self) -> Result<std::process::ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("receiver process did not exit".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub enum Attempt {
    Reply(Box<Reply>),
    Killed,
}

pub fn call(endpoint: &Endpoint, tool: &str, arguments: Value, fault: &str) -> Result<Attempt> {
    let rpc = Rpc {
        tool: tool.into(),
        arguments,
    };
    if let Some(socket) = &endpoint.socket {
        if fault != "none" {
            return Err("socket clients cannot select receiver fault injection".into());
        }
        let reply = super::isolation::socket_call(socket, &rpc)?;
        verify_reply(endpoint, &rpc, &reply)?;
        return Ok(Attempt::Reply(Box::new(reply)));
    }
    call_process(endpoint, rpc, fault, false)
}

pub(super) fn call_process(
    endpoint: &Endpoint,
    rpc: Rpc,
    fault: &str,
    isolated: bool,
) -> Result<Attempt> {
    let mut command = if isolated {
        super::isolation::receiver_command(&endpoint.directory)?
    } else {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg("--graph-worker").arg(&endpoint.directory);
        command
    };
    let mut child = OwnedChild(
        command
            .arg(fault)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let mut stdin = child.0.stdin.take().ok_or("receiver stdin missing")?;
    stdin.write_all(&serde_json::to_vec(&rpc)?)?;
    drop(stdin);
    let stdout = child.0.stdout.take().ok_or("receiver stdout missing")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .take(4 * 1024 * 1024 + 1)
            .read_line(&mut line)
            .map(|_| line);
        let _ = sender.send(result);
    });
    let line = receiver.recv_timeout(Duration::from_secs(20))??;
    if line.len() > 4 * 1024 * 1024 {
        return Err("receiver response exceeds fixture bound".into());
    }
    let sequence = REQUESTS.fetch_add(1, Ordering::Relaxed);
    let trace = endpoint
        .directory
        .join(format!("rpc-{}-{sequence:04}.json", std::process::id()));
    if line.trim() == format!("GRAPH_CHECKPOINT {fault}") && fault != "none" {
        let children = if isolated {
            super::isolation::descendants(child.0.id())?
        } else {
            Vec::new()
        };
        child.0.kill()?;
        let status = child.wait()?;
        if isolated {
            super::isolation::require_terminated(&children)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        assert!(!status.success());
        eprintln!(
            "GRAPH_KILL receiver={} boundary={fault} exit={status}",
            endpoint.role
        );
        std::fs::write(
            trace,
            serde_json::to_vec_pretty(
                &json!({"request":rpc,"checkpoint":fault,"exit":status.to_string()}),
            )?,
        )?;
        return Ok(Attempt::Killed);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("{} receiver failed: {status}", endpoint.role).into());
    }
    let reply: Reply = serde_json::from_str(&line)?;
    verify_reply(endpoint, &rpc, &reply)?;
    std::fs::write(
        trace,
        serde_json::to_vec_pretty(&json!({"request":rpc,"reply":reply}))?,
    )?;
    Ok(Attempt::Reply(Box::new(reply)))
}

fn verify_reply(endpoint: &Endpoint, rpc: &Rpc, reply: &Reply) -> Result<()> {
    if reply.receipt.kernel_key != endpoint.key
        || !reply.receipt.verify_signature()?
        || !reply.receipt.action.verify_hash()?
        || reply.receipt.tool_server != endpoint.role
        || reply.receipt.tool_name != rpc.tool
        || reply.receipt.action.parameters != rpc.arguments
        || reply.allowed != (reply.receipt.decision == Some(Decision::Allow))
    {
        return Err("receiver reply failed pinned receipt or request binding".into());
    }
    if reply.allowed {
        let output = reply.output.as_ref().ok_or("allowed reply has no output")?;
        if reply.receipt.content_hash != hash(output)? {
            return Err("receiver result differs from signed content hash".into());
        }
    }
    Ok(())
}

pub fn invoke(endpoint: &Endpoint, tool: &str, arguments: Value) -> Result<Reply> {
    match call(endpoint, tool, arguments, "none")? {
        Attempt::Reply(reply) => Ok(*reply),
        Attempt::Killed => Err("unexpected receiver termination".into()),
    }
}

pub fn allowed(endpoint: &Endpoint, tool: &str, arguments: Value) -> Result<Value> {
    let reply = invoke(endpoint, tool, arguments)?;
    if !reply.allowed {
        return Err(format!(
            "{} {tool} unexpectedly denied: {:?}",
            endpoint.role, reply.receipt.decision
        )
        .into());
    }
    reply.output.ok_or_else(|| "allowed output absent".into())
}

pub fn courier(job_path: &std::path::Path, kill_after_publisher: bool) -> Result<Option<Value>> {
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("--graph-courier").arg(job_path);
    courier_command(command, kill_after_publisher)
}

pub(super) fn courier_command(
    mut command: Command,
    kill_after_publisher: bool,
) -> Result<Option<Value>> {
    let isolated = command.get_program() == std::ffi::OsStr::new("/usr/bin/bwrap");
    let mut child = OwnedChild(
        command
            .arg(if kill_after_publisher {
                "after_publisher"
            } else {
                "none"
            })
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("courier stdout missing")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .take(4 * 1024 * 1024 + 1)
            .read_line(&mut line)
            .map(|_| line);
        let _ = sender.send(result);
    });
    let line = receiver.recv_timeout(Duration::from_secs(45))??;
    if line.len() > 4 * 1024 * 1024 {
        return Err("courier response exceeds fixture bound".into());
    }
    if kill_after_publisher {
        if line.trim() != "GRAPH_COURIER_CHECKPOINT" {
            return Err("courier checkpoint missing".into());
        }
        let children = if isolated {
            super::isolation::descendants(child.0.id())?
        } else {
            Vec::new()
        };
        child.0.kill()?;
        let status = child.wait()?;
        if isolated {
            super::isolation::require_terminated(&children)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        assert!(!status.success());
        eprintln!("GRAPH_COURIER_KILL boundary=after_publisher exit={status}");
        Ok(None)
    } else {
        let status = child.wait()?;
        if !status.success() {
            return Err("replacement courier failed".into());
        }
        Ok(Some(serde_json::from_str(&line)?))
    }
}
