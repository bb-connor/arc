//! What "ready" means for a supervised service.

pub use chio_egress_contract::OperatorReadinessError as ReadinessError;
use chio_egress_contract::OperatorReadinessProbe;
use std::path::PathBuf;

/// The condition the supervisor waits for before it reports readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Ready as soon as the service has been started.
    Immediate,
    /// Ready once a GET of `url` answers with a success status.
    Http { url: String, bearer: Option<String> },
    /// Ready once the Unix socket is listening in the supervised child.
    UnixSocket(PathBuf),
}

impl Readiness {
    pub fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    /// The condition, for status lines; never the bearer.
    pub fn describe(&self) -> String {
        match self {
            Self::Immediate => "start".to_string(),
            Self::Http { url, .. } => format!("GET {url}"),
            Self::UnixSocket(path) => format!("socket {}", path.display()),
        }
    }

    /// Validate the operator's target and bind the client before service launch.
    pub fn prepare(&self) -> Result<PreparedReadiness, ReadinessError> {
        let condition = match self {
            Self::Immediate => PreparedCondition::Immediate,
            Self::Http { url, bearer } => PreparedCondition::Http(Box::new(
                OperatorReadinessProbe::prepare(url, bearer.as_deref())?,
            )),
            Self::UnixSocket(path) => PreparedCondition::UnixSocket(path.clone()),
        };
        Ok(PreparedReadiness { condition })
    }
}

/// A probe prepared before child launch, with no per-attempt target replacement.
pub struct PreparedReadiness {
    condition: PreparedCondition,
}

enum PreparedCondition {
    Immediate,
    Http(Box<OperatorReadinessProbe>),
    UnixSocket(PathBuf),
}

impl PreparedReadiness {
    /// One bounded attempt. Transport, redirect and response-limit errors deny readiness.
    #[cfg(test)]
    pub async fn probe(&self) -> bool {
        self.probe_inner(None).await
    }

    /// Bind socket readiness to the unreaped child, not merely a pathname.
    pub(crate) async fn probe_for_child(&self, child_id: u32) -> bool {
        self.probe_inner(Some(child_id)).await
    }

    async fn probe_inner(&self, child_id: Option<u32>) -> bool {
        match &self.condition {
            PreparedCondition::Immediate => true,
            PreparedCondition::Http(probe) => probe.probe().await,
            PreparedCondition::UnixSocket(path) => {
                let Ok(stream) = tokio::net::UnixStream::connect(path).await else {
                    return false;
                };
                child_id.is_none_or(|expected| {
                    stream
                        .peer_cred()
                        .ok()
                        .and_then(|peer| peer.pid())
                        .and_then(|pid| u32::try_from(pid).ok())
                        == Some(expected)
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_socket_is_ready_only_once_something_listens() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("service.sock");
        let readiness = Readiness::UnixSocket(path.clone());
        let probe = readiness
            .prepare()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!probe.probe().await);
        let _listener =
            tokio::net::UnixListener::bind(&path).unwrap_or_else(|error| panic!("{error}"));
        assert!(probe.probe().await);
    }

    #[tokio::test]
    async fn an_http_endpoint_is_ready_only_on_a_success_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            for status in ["503 Service Unavailable", "200 OK"] {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let mut request = vec![0_u8; 4096];
                let length = stream
                    .read(&mut request)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                seen.push(String::from_utf8_lossy(&request[..length]).into_owned());
                let response =
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
            }
            seen
        });
        let readiness = Readiness::Http {
            url: format!("http://{address}/health"),
            bearer: Some("admin-token".to_string()),
        };
        let probe = readiness
            .prepare()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!probe.probe().await);
        assert!(probe.probe().await);
        let seen = server.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(seen.iter().all(
            |request| request.contains("authorization: Bearer admin-token")
                || request.contains("Authorization: Bearer admin-token")
        ));
        assert_eq!(readiness.describe(), format!("GET http://{address}/health"));
    }
}

#[cfg(test)]
#[path = "readiness_security_tests.rs"]
mod security_tests;
