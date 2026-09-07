//! What "ready" means for a supervised service.

use std::path::PathBuf;
use std::time::Duration;

/// The condition the supervisor waits for before it reports readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Ready as soon as the service has been started.
    Immediate,
    /// Ready once a GET of `url` answers with a success status.
    Http { url: String, bearer: Option<String> },
    /// Ready once the Unix socket at the path accepts a connection.
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

    /// One attempt at the condition.
    pub async fn probe(&self, http: &reqwest::Client) -> bool {
        match self {
            Self::Immediate => true,
            Self::Http { url, bearer } => {
                let mut request = http.get(url);
                if let Some(bearer) = bearer {
                    request = request.bearer_auth(bearer);
                }
                matches!(request.send().await, Ok(response) if response.status().is_success())
            }
            Self::UnixSocket(path) => tokio::net::UnixStream::connect(path).await.is_ok(),
        }
    }
}

/// The client readiness probes use: a short deadline per attempt and no
/// proxy, because the probe targets the service on this host.
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_socket_is_ready_only_once_something_listens() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("service.sock");
        let readiness = Readiness::UnixSocket(path.clone());
        let http = http_client().unwrap_or_else(|error| panic!("{error}"));
        assert!(!readiness.probe(&http).await);
        let _listener = tokio::net::UnixListener::bind(&path).unwrap_or_else(|error| panic!("{error}"));
        assert!(readiness.probe(&http).await);
    }

    #[tokio::test]
    async fn an_http_endpoint_is_ready_only_on_a_success_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener.local_addr().unwrap_or_else(|error| panic!("{error}"));
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            for status in ["503 Service Unavailable", "200 OK"] {
                let (mut stream, _) = listener.accept().await.unwrap_or_else(|error| panic!("{error}"));
                let mut request = vec![0_u8; 4096];
                let length = stream.read(&mut request).await.unwrap_or_else(|error| panic!("{error}"));
                seen.push(String::from_utf8_lossy(&request[..length]).into_owned());
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream.write_all(response.as_bytes()).await.unwrap_or_else(|error| panic!("{error}"));
            }
            seen
        });
        let readiness = Readiness::Http {
            url: format!("http://{address}/health"),
            bearer: Some("admin-token".to_string()),
        };
        let http = http_client().unwrap_or_else(|error| panic!("{error}"));
        assert!(!readiness.probe(&http).await);
        assert!(readiness.probe(&http).await);
        let seen = server.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(seen.iter().all(|request| request.contains("authorization: Bearer admin-token")
            || request.contains("Authorization: Bearer admin-token")));
        assert_eq!(readiness.describe(), format!("GET http://{address}/health"));
    }
}
