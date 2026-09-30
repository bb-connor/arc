//! Pinned Docker execution behind the common authenticated host endpoint.
use super::*;
use crate::host_https::{private_bytes, HostHttpsServer, HttpsEndpoint, JsonAdapter};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerHttpsConfig {
    pub schema: String,
    pub bind: std::net::SocketAddr,
    pub certificate_der: Vec<u8>,
    pub private_key_file: PathBuf,
    pub bearer_file: PathBuf,
    pub docker: DockerAdapterConfig,
}

pub struct DockerHttpsServer(HostHttpsServer);

impl DockerHttpsConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = private_bytes(path, 65_536)?;
        chio_core_types::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
            .and_then(|text| text.decode_signed())
            .map_err(|_| denied())
    }
}

impl DockerHttpsServer {
    pub fn bind(config: DockerHttpsConfig) -> Result<Self> {
        if config.schema != "chio.docker-https-adapter.v1" {
            return Err(denied());
        }
        HostHttpsServer::bind(
            HttpsEndpoint {
                bind: config.bind,
                certificate_der: config.certificate_der,
                private_key_file: config.private_key_file,
                bearer_file: config.bearer_file,
            },
            DockerAdapter::new(config.docker)?,
        )
        .map(Self)
    }
    pub fn serve(self) -> Result<()> {
        self.0.serve()
    }
}

impl JsonAdapter for DockerAdapter {
    fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }
    fn execute_json(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let command: DockerCommand =
            chio_core_types::canonical::UntrustedJsonText::from_wire(bytes, 131_072)
                .and_then(|text| text.decode_signed())
                .map_err(|_| denied())?;
        canonical_json_bytes(&self.execute(&command)?)
    }
}
