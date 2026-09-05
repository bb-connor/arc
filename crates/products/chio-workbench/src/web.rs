//! Loopback HTTP interface. The per-start key authorizes the local operator.
use crate::{Error, Workbench};
use axum::{
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct Access {
    token: String,
    origin: String,
    host: String,
}

pub fn router(workbench: Arc<Workbench>, token: String, address: std::net::SocketAddr) -> Router {
    let access = Access {
        token,
        origin: format!("http://{address}"),
        host: address.to_string(),
    };
    let api = Router::new()
        .route("/api/config", get(config))
        .route("/api/runs", get(list).post(start))
        .route("/api/runs/{id}", get(detail))
        .route("/api/runs/{id}/stop", post(stop))
        .layer(middleware::from_fn_with_state(access.clone(), authorize));
    Router::new()
        .merge(api)
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(20 * 1024))
        .layer(middleware::from_fn_with_state(access, boundary))
        .with_state(workbench)
}

async fn boundary(State(access): State<Access>, request: Request, next: Next) -> Response {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(access.host.as_str())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if request
        .headers()
        .get(header::ORIGIN)
        .is_some_and(|origin| origin.as_bytes() != access.origin.as_bytes())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn authorize(State(access): State<Access>, request: Request, next: Next) -> Response {
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let authorized = provided.is_some_and(|provided| {
        use subtle::ConstantTimeEq;
        bool::from(provided.as_bytes().ct_eq(access.token.as_bytes()))
    });
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

async fn config(State(workbench): State<Arc<Workbench>>) -> Json<serde_json::Value> {
    Json(
        json!({"workspace":workbench.workspace(),"model":workbench.model(),"roles":["investigator","editor","reviewer"]}),
    )
}
async fn list(
    State(workbench): State<Arc<Workbench>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(json!(workbench.list()?.into_iter().map(|run| json!({"id":run.id,"prompt":run.prompt,"status":run.status,"started_at":run.started_at})).collect::<Vec<_>>())))
}
async fn detail(
    State(workbench): State<Arc<Workbench>>,
    Path(id): Path<String>,
) -> Result<Json<crate::Run>, ApiError> {
    Ok(Json(workbench.get(&id)?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    prompt: String,
    call_limit: u32,
}
async fn start(
    State(workbench): State<Arc<Workbench>>,
    Json(body): Json<Start>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let id = workbench.start(body.prompt, body.call_limit)?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id":id}))))
}
async fn stop(
    State(workbench): State<Arc<Workbench>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    workbench.stop(&id)?;
    Ok(StatusCode::ACCEPTED)
}

struct ApiError(Error);
impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, message) = match self.0 {
            Error::Busy => (
                StatusCode::CONFLICT,
                "another task is already running".into(),
            ),
            Error::NotFound => (StatusCode::NOT_FOUND, "run not found".into()),
            Error::Invalid(message) => (StatusCode::BAD_REQUEST, message),
            error => {
                eprintln!("workbench request failed: {error}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "workbench could not complete this request".into(),
                )
            }
        };
        (code, Json(json!({"error":message}))).into_response()
    }
}
