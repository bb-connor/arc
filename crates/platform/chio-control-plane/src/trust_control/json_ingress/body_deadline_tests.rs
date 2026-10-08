use std::time::Duration;

use super::{body_read_deadline, read_body_by, Body, InputError, IntoResponse, StatusCode};

#[tokio::test]
async fn a_stalled_json_body_ends_at_its_read_deadline() {
    let stalled = Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());

    let read = tokio::time::timeout(
        Duration::from_secs(10),
        read_body_by(stalled, 1024, Duration::from_millis(50)),
    )
    .await
    .unwrap_or_else(|_| panic!("the body read ignored its deadline"));

    assert!(matches!(read, Err(InputError::TimedOut)), "{read:?}");
    assert_eq!(
        InputError::TimedOut.into_response().status(),
        StatusCode::REQUEST_TIMEOUT
    );
}

#[tokio::test]
async fn a_complete_json_body_is_read_within_its_deadline() {
    let read = read_body_by(Body::from("{}"), 1024, Duration::from_secs(1)).await;

    assert!(matches!(read.as_deref(), Ok(b"{}")), "{read:?}");
}

#[test]
fn read_deadlines_allow_one_second_per_mebibyte_of_the_bound() {
    assert_eq!(body_read_deadline(4 * 1024), Duration::from_secs(10));
    assert_eq!(body_read_deadline(1024 * 1024), Duration::from_secs(11));
    assert_eq!(
        body_read_deadline(128 * 1024 * 1024),
        Duration::from_secs(138)
    );
}
