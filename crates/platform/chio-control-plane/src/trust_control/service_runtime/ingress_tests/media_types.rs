//! Original-byte validation must cover every media type the Json extractor accepts.
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Spellings around the extractor's rule: an `application` type whose subtype
/// before the last `+` is `json`, or whose suffix after it is `json`.
const MEDIA_TYPES: [&str; 13] = [
    "application/json",
    "application/json; charset=utf-8",
    "APPLICATION/JSON",
    "application/vnd.chio+json",
    "application/json+chio",
    "application/json+",
    "Application/Json+Chio; charset=utf-8",
    "application/json+a+b",
    "application/+json",
    "application/json ; charset=utf-8",
    "application/jsonx",
    "text/json",
    "text/plain",
];

async fn status(
    router: &Router,
    media_type: Option<&str>,
    body: &'static str,
) -> TestResult<StatusCode> {
    let mut request = Request::builder().method("POST").uri(CERTIFICATIONS_PATH);
    if let Some(media_type) = media_type {
        request = request.header(CONTENT_TYPE, media_type);
    }
    Ok(router
        .clone()
        .oneshot(request.body(Body::from(body))?)
        .await?
        .status())
}

#[tokio::test]
async fn ingress_validates_every_media_type_the_json_extractor_accepts() -> TestResult {
    let extractor = Router::new().route(
        CERTIFICATIONS_PATH,
        post(|Json(_): Json<serde_json::Value>| async {}),
    );
    let guarded = extractor.clone().route_layer(axum::middleware::from_fn(
        crate::trust_control::json_ingress::validate,
    ));
    let mut accepted = Vec::new();
    for media_type in MEDIA_TYPES.into_iter().map(Some).chain([None]) {
        let extracted = status(&extractor, media_type, r#"{"field":1}"#).await? == StatusCode::OK;
        if extracted {
            accepted.push(media_type);
        }
        let honest = status(&guarded, media_type, r#"{"field":1}"#).await?;
        assert_eq!(honest == StatusCode::OK, extracted, "{media_type:?}");
        for hostile in [
            r#"{"field":1,"field":2}"#,
            r#"{"field":0.10000000000000001}"#,
        ] {
            let observed = status(&guarded, media_type, hostile).await?;
            if extracted {
                assert_eq!(
                    observed,
                    StatusCode::BAD_REQUEST,
                    "{media_type:?} {hostile}"
                );
            } else {
                assert!(
                    matches!(
                        observed,
                        StatusCode::BAD_REQUEST | StatusCode::UNSUPPORTED_MEDIA_TYPE
                    ),
                    "{media_type:?} {hostile} {observed}"
                );
            }
        }
    }
    assert_eq!(
        accepted,
        [
            Some("application/json"),
            Some("application/json; charset=utf-8"),
            Some("APPLICATION/JSON"),
            Some("application/vnd.chio+json"),
            Some("application/json+chio"),
            Some("application/json+"),
            Some("Application/Json+Chio; charset=utf-8"),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn ingress_verifier_policy_rejects_lossy_numbers_under_json_subtype_spellings() -> TestResult
{
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("policies.json");
    let mut state = metrics_state("service-secret");
    state.config.verifier_policies_file = Some(path.clone());
    let router = super::super::super::build_router(state);
    let uri = PASSPORT_VERIFIER_POLICY_PATH.replace("{policy_id}", "ingress-policy");
    let honest = serde_json::to_string(&policy()?)?;
    let response = send(
        &router,
        "PUT",
        &uri,
        "application/json",
        "service-secret",
        honest.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let before = std::fs::read(&path)?;
    let lossy = honest.replace(
        "\"minCompositeScore\":0.1",
        "\"minCompositeScore\":0.10000000000000001",
    );
    assert_ne!(lossy, honest);
    for media_type in [
        "application/json+chio",
        "application/json+",
        "Application/Json+Chio; charset=utf-8",
    ] {
        let response = send(
            &router,
            "PUT",
            &uri,
            media_type,
            "service-secret",
            lossy.clone(),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{media_type}");
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}
