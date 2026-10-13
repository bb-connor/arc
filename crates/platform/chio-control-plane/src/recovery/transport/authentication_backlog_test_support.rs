//! Genuine bounded native authentication backlog without replacing decisions.
use super::*;
use axum::{body::Body, http::Request};
use chio_core_types::capability::token::CapabilityToken;
use chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore;
use std::{sync::mpsc, thread, time::Duration};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error>;
type NativeReply = tokio::task::JoinHandle<
    Result<chio_kernel::recovery::AuthenticatedRecoveryActor, RecoveryRuntimeError>,
>;

pub(in crate::recovery) struct NativeAuthenticationBacklog {
    release: Option<mpsc::Sender<()>>,
    holder: Option<
        thread::JoinHandle<
            Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError>,
        >,
    >,
    replies: Vec<NativeReply>,
}
impl NativeAuthenticationBacklog {
    pub(in crate::recovery) async fn start(
        authentication: Arc<AuthenticationLane>,
        runtime: Arc<RecoveryRuntime>,
        capability: CapabilityToken,
        permission: RecoveryPermission,
        store: SqliteAdmissionOperationStore,
    ) -> Result<Self, TestError> {
        let (entered, observation) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::channel();
        let holder = thread::Builder::new()
            .name("native-authentication-backlog".into())
            .spawn(move || store.hold_current_connection_for_authentication_test(entered, wait))?;
        let mut backlog = Self {
            release: Some(release),
            holder: Some(holder),
            replies: Vec::new(),
        };
        // The feature-only observer has acquired the actual shared connection
        // and verified its current owner and anchor before signaling entry.
        observation.recv_timeout(Duration::from_secs(2))?;
        for _ in 0..2 {
            let authentication = authentication.clone();
            let runtime = runtime.clone();
            let capability = capability.clone();
            backlog.replies.push(tokio::spawn(async move {
                authentication
                    .authenticate(runtime, &capability, permission)
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while authentication.outstanding_jobs_for_test() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "genuine native authentication backlog did not reach its bound")?;
        Ok(backlog)
    }

    pub(in crate::recovery) async fn finish(mut self) -> Result<(), TestError> {
        if let Some(release) = self.release.take() {
            release.send(())?;
        }
        if let Some(holder) = self.holder.take() {
            holder
                .join()
                .map_err(|_| "native authentication backlog holder panicked")??;
        }
        for reply in self.replies.drain(..) {
            // Both genuine verification jobs must authenticate successfully
            // after the real connection is released. No decision is mocked.
            reply.await??;
        }
        Ok(())
    }
}
impl Drop for NativeAuthenticationBacklog {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

pub(crate) async fn call_with_native_authentication_backlog(
    runtime: Arc<RecoveryRuntime>,
    capability: &CapabilityToken,
    store: SqliteAdmissionOperationStore,
    route: &str,
    bytes: Vec<u8>,
) -> Result<axum::response::Response, TestError> {
    let host = RecoveryHost::new(runtime.clone())?;
    let (authentication, permission) = match route {
        "/v1/recovery/commands" => (
            host.existing_authentication.clone(),
            RecoveryPermission::Inspect,
        ),
        "/v1/recovery/review" => (
            host.existing_authentication.clone(),
            RecoveryPermission::Approve,
        ),
        "/v1/recovery/settle" => (
            host.settlement_authentication.clone(),
            RecoveryPermission::Settle,
        ),
        _ => return Err("unsupported native authentication backlog route".into()),
    };
    let backlog = NativeAuthenticationBacklog::start(
        authentication,
        runtime,
        capability.clone(),
        permission,
        store,
    )
    .await?;
    let router = Router::new()
        .route("/v1/recovery/commands", post(command))
        .route("/v1/recovery/review", post(review))
        .route("/v1/recovery/settle", post(settle))
        .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
        .with_state(host);
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        router.oneshot(
            Request::builder()
                .method("POST")
                .uri(route)
                .body(Body::from(bytes))?,
        ),
    )
    .await;
    // Finish authenticating the queued jobs before returning the response.
    backlog.finish().await?;
    Ok(response.map_err(|_| "forged token waited for genuine native authentication backlog")??)
}
