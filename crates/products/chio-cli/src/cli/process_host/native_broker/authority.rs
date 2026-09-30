//! One authenticated authority RPC endpoint per installed broker route.
use super::*;

pub(crate) struct AuthorityService {
    _endpoints: Vec<AuthorityEndpoint>,
}

/// Keeps the authenticated authority RPC live for the same host lifetime.
/// It reads original custody; it is not another admission or quota writer.
struct AuthorityEndpoint {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    socket: PathBuf,
    identity: (u64, u64),
}

impl AuthorityService {
    pub fn start(
        host: &HostConfig,
        directory: &Path,
        authority: &DurableAdmissionRuntime,
        kernel: Arc<ChioKernel>,
    ) -> Result<Self, CliError> {
        let config = host
            .native_broker
            .as_ref()
            .ok_or_else(|| error("missing broker host configuration"))?;
        let selected = components(host)?;
        let store = authority
            .local_authority_store()
            .ok_or_else(|| error("native broker requires the host's local authority"))?;
        let native = native_binding(config, directory, &store, false)?;
        let mut endpoints = Vec::with_capacity(config.routes.len());
        for route in &config.routes {
            let participant = selected
                .routes
                .participant(&route.quota.server_id, &route.quota.tool_name)
                .map_err(error)?;
            let handler = Arc::new(
                BrokerKernelAuthorityHandler::new(
                    &store,
                    native.clone(),
                    participant,
                    kernel.clone(),
                )
                .map_err(error)?,
            );
            endpoints.push(AuthorityEndpoint::start(
                config,
                route,
                directory,
                handler,
                kernel.clone(),
            )?);
        }
        Ok(Self {
            _endpoints: endpoints,
        })
    }
}

impl AuthorityEndpoint {
    fn start(
        config: &Config,
        route: &RouteConfig,
        directory: &Path,
        handler: Arc<BrokerKernelAuthorityHandler>,
        kernel: Arc<ChioKernel>,
    ) -> Result<Self, CliError> {
        let socket = directory.join(&route.authority_socket_name);
        // The host lease excludes another owner. Refuse live or substituted
        // paths; only a dead socket in this private directory can be removed.
        if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != std::fs::metadata(directory)?.uid()
            {
                return Err(error(
                    "broker authority socket path has another owner or type",
                ));
            }
            match std::os::unix::net::UnixStream::connect(&socket) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&socket)?
                }
                _ => {
                    return Err(error(
                        "broker authority socket is live or cannot be safely recovered",
                    ));
                }
            }
        }
        let server = AuthorityRpcServer::bind(
            &socket,
            route.broker_identity.clone(),
            config.authority_signer()?,
            handler,
            30,
        )
        .map_err(error)?;
        server.set_nonblocking(true).map_err(error)?;
        let metadata = std::fs::symlink_metadata(&socket)?;
        let identity = (metadata.dev(), metadata.ino());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = std::thread::Builder::new()
            .name("chio-broker-authority".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    match server.try_serve_one() {
                        Ok(true) => {}
                        Ok(false) => std::thread::park_timeout(Duration::from_millis(10)),
                        Err(error) => {
                            tracing::error!(error = %error, "broker authority service failed");
                            let _ = kernel.emergency_stop("broker authority service failed");
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            socket,
            identity,
        })
    }
}

impl Drop for AuthorityEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        if std::fs::symlink_metadata(&self.socket).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}
