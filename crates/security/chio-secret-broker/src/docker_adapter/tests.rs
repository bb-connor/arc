use super::*;
use std::io::BufRead;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

#[test]
fn restart_during_exec_creation_or_completion_never_certifies_success(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for before_start in [true, false] {
        let directory = crate::private_tempdir()?;
        let path = directory.path().join("docker.sock");
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let container_id = "a".repeat(64);
        let exec_id = "b".repeat(64);
        let container = json!({"Id":container_id,"State":{"Running":true,"Paused":false,"StartedAt":"original-start"},
            "HostConfig":{"Privileged":false,"NetworkMode":"none","ReadonlyRootfs":true},
            "Config":{"User":"65534:65534"},"Mounts":[],"Image":"immutable"});
        let mut changed = container.clone();
        changed["State"]["StartedAt"] = json!("new-start");
        let config = DockerAdapterConfig {
            socket_path: path,
            peer: chio_secure_ipc::PeerIdentity {
                process_id: std::process::id(),
                user_id: rustix::process::geteuid().as_raw(),
                group_id: rustix::process::getegid().as_raw(),
            },
            api_version: "v1.52".into(),
            daemon_id: "engine".into(),
            container_id: container_id.clone(),
            container_started_at: "original-start".into(),
            container_configuration_sha256: container_configuration_digest(&container)?,
            timeout_ms: 5000,
            maximum_output_bytes: 1024,
        };
        let json_reply = |status, value: Value| {
            let body = value.to_string().into_bytes();
            let mut reply = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            reply.extend(body);
            reply
        };
        let info = || {
            (
                "GET /v1.52/info".to_string(),
                json_reply(200, json!({"ID":"engine"})),
            )
        };
        let inspect = |value| {
            (
                format!("GET /v1.52/containers/{container_id}/json"),
                json_reply(200, value),
            )
        };
        let mut exchange = vec![
            info(),
            inspect(container.clone()),
            info(),
            inspect(container.clone()),
            (
                format!("POST /v1.52/containers/{container_id}/exec"),
                json_reply(201, json!({"Id":exec_id})),
            ),
            info(),
            inspect(if before_start {
                changed.clone()
            } else {
                container
            }),
        ];
        if !before_start {
            let mut output =
                b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n".to_vec();
            output.extend([1, 0, 0, 0, 0, 0, 0, 2]);
            output.extend(b"ok");
            exchange.extend([
                (format!("POST /v1.52/exec/{exec_id}/start"),output),
                (format!("GET /v1.52/exec/{exec_id}/json"),json_reply(200,json!({"ID":exec_id,"ContainerID":container_id,"Running":false,"ExitCode":0}))),
                info(),inspect(changed),
            ]);
        }
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(10);
            for (expected, response) in exchange {
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                assert_eq!(line.trim(), format!("{expected} HTTP/1.1"));
                let mut length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line)?;
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.strip_prefix("Content-Length: ") {
                        length = value.trim().parse().map_err(std::io::Error::other)?;
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body)?;
                reader.get_mut().write_all(&response)?;
            }
            Ok(())
        });
        let adapter = DockerAdapter::new(config)?;
        let result = adapter.execute(&DockerCommand {
            command: "effect".into(),
            tool_call_id: None,
        });
        if before_start {
            assert!(matches!(result, Err(BrokerError::AuthorizationDenied(_))));
        } else {
            assert!(matches!(result, Err(BrokerError::Upstream(_))));
        }
        server
            .join()
            .map_err(|_| "engine fixture thread failed")??;
    }
    Ok(())
}
