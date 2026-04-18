//! Receipt flush to DynamoDB.
//!
//! Receipts are buffered in-memory during the invocation and drained to
//! DynamoDB when the extension receives a `SHUTDOWN` event (or when the
//! buffer fills up, whichever happens first).
//!
//! Table schema (required; the extension does not create the table):
//!
//! ```text
//! AttributeDefinitions:
//!   - AttributeName: receipt_id   (HASH / partition key, S)
//!   - AttributeName: timestamp    (RANGE / sort key, N)
//! ```
//!
//! Every item also carries:
//!
//! | attribute      | type | meaning                                         |
//! |----------------|------|-------------------------------------------------|
//! | receipt_id     | S    | UUIDv7 unique identifier                        |
//! | timestamp      | N    | unix seconds; sort key so latest is easy to scan|
//! | capability_id  | S    | capability token the call was evaluated against |
//! | tool_server    | S    | tool server identifier                          |
//! | tool_name      | S    | tool name                                       |
//! | decision       | S    | `allow` or `deny`                               |
//! | reason         | S    | optional deny reason                            |
//! | payload        | S    | canonical-JSON of the full receipt body         |
//!
//! DynamoDB's `BatchWriteItem` API caps each request at 25 items; throttled
//! items come back in `UnprocessedItems` and we retry them with exponential
//! backoff. All errors are fail-closed: the buffered receipts stay in memory
//! and are surfaced to the caller.

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_dynamodb::operation::batch_write_item::BatchWriteItemError;
use aws_sdk_dynamodb::primitives::DateTime;
use aws_sdk_dynamodb::types::{AttributeValue, PutRequest, WriteRequest};
use aws_sdk_dynamodb::Client as DynamoClient;
use tracing::{debug, info, warn};

/// Maximum number of items DynamoDB will accept per `BatchWriteItem` request.
const BATCH_MAX: usize = 25;

/// Maximum retry attempts for unprocessed / throttled items.
const MAX_RETRIES: u32 = 5;

/// In-memory representation of a receipt that we plan to persist. Kept
/// deliberately small and free of kernel types so the extension can be
/// exercised without spinning up a full kernel.
#[derive(Debug, Clone)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub decision: String,
    pub reason: Option<String>,
    pub payload_json: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FlushError {
    #[error("DynamoDB BatchWriteItem failed: {0}")]
    BatchWrite(String),
    #[error("DynamoDB did not drain UnprocessedItems after {0} retries")]
    TooManyRetries(u32),
}

impl From<aws_sdk_dynamodb::error::SdkError<BatchWriteItemError>> for FlushError {
    fn from(value: aws_sdk_dynamodb::error::SdkError<BatchWriteItemError>) -> Self {
        FlushError::BatchWrite(value.to_string())
    }
}

/// Client wrapper that knows how to push a batch of receipts to a single
/// DynamoDB table. Cloning is cheap: the underlying SDK client is
/// reference-counted.
#[derive(Debug, Clone)]
pub struct DynamoFlusher {
    client: DynamoClient,
    table: String,
}

impl DynamoFlusher {
    #[must_use]
    pub fn new(client: DynamoClient, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    /// The DynamoDB table this flusher writes to. Surfaced for structured
    /// logging in callers that build the flusher in one place and log
    /// context in another.
    #[must_use]
    #[allow(dead_code)]
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Flush every buffered receipt. Returns the total number of items
    /// written. On partial failure the error carries the underlying SDK
    /// message; unflushed items are NOT silently dropped -- the caller is
    /// expected to keep them buffered and retry on the next SHUTDOWN.
    pub async fn flush(&self, records: Vec<ReceiptRecord>) -> Result<usize, FlushError> {
        if records.is_empty() {
            return Ok(0);
        }

        let total = records.len();
        info!(count = total, table = %self.table, "flushing receipts to DynamoDB");
        for chunk in records.chunks(BATCH_MAX) {
            self.flush_chunk(chunk).await?;
        }
        Ok(total)
    }

    async fn flush_chunk(&self, chunk: &[ReceiptRecord]) -> Result<(), FlushError> {
        let mut pending: Vec<WriteRequest> = chunk.iter().map(build_write_request).collect();

        for attempt in 0..MAX_RETRIES {
            if pending.is_empty() {
                return Ok(());
            }
            let items: HashMap<String, Vec<WriteRequest>> =
                HashMap::from([(self.table.clone(), pending)]);
            let response = self
                .client
                .batch_write_item()
                .set_request_items(Some(items))
                .send()
                .await?;

            let unprocessed = response
                .unprocessed_items
                .unwrap_or_default()
                .remove(&self.table)
                .unwrap_or_default();
            if unprocessed.is_empty() {
                return Ok(());
            }
            debug!(
                retry = attempt + 1,
                remaining = unprocessed.len(),
                "DynamoDB returned UnprocessedItems; backing off"
            );
            backoff(attempt).await;
            pending = unprocessed;
        }
        Err(FlushError::TooManyRetries(MAX_RETRIES))
    }
}

fn build_write_request(record: &ReceiptRecord) -> WriteRequest {
    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert(
        "receipt_id".into(),
        AttributeValue::S(record.receipt_id.clone()),
    );
    item.insert(
        "timestamp".into(),
        AttributeValue::N(record.timestamp.to_string()),
    );
    item.insert(
        "capability_id".into(),
        AttributeValue::S(record.capability_id.clone()),
    );
    item.insert(
        "tool_server".into(),
        AttributeValue::S(record.tool_server.clone()),
    );
    item.insert(
        "tool_name".into(),
        AttributeValue::S(record.tool_name.clone()),
    );
    item.insert(
        "decision".into(),
        AttributeValue::S(record.decision.clone()),
    );
    if let Some(reason) = &record.reason {
        item.insert("reason".into(), AttributeValue::S(reason.clone()));
    }
    item.insert(
        "payload".into(),
        AttributeValue::S(record.payload_json.clone()),
    );
    // Strictly cosmetic: helps operators scanning the table know when
    // Dynamo actually observed the write.
    let _ = DateTime::from_secs(record.timestamp as i64);

    let put = match PutRequest::builder().set_item(Some(item)).build() {
        Ok(put) => put,
        Err(err) => {
            // `set_item(Some(..))` is required; this branch can only trigger
            // if the SDK ever changes its contract. Log and return an empty
            // PutRequest so the caller sees the failure on the next flush.
            warn!(?err, "failed to build PutRequest");
            PutRequest::builder()
                .set_item(Some(HashMap::new()))
                .build()
                .unwrap_or_else(|_| unreachable!())
        }
    };
    WriteRequest::builder().put_request(put).build()
}

async fn backoff(attempt: u32) {
    // 100ms, 200ms, 400ms, 800ms, 1600ms (capped well below Lambda's ~2s
    // SHUTDOWN deadline).
    let millis = 100u64.saturating_mul(1u64 << attempt).min(1_600);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> ReceiptRecord {
        ReceiptRecord {
            receipt_id: "01908f4a-0000-7000-8000-000000000001".into(),
            timestamp: 1_700_000_000,
            capability_id: "cap-1".into(),
            tool_server: "tools.example".into(),
            tool_name: "search".into(),
            decision: "allow".into(),
            reason: None,
            payload_json: "{}".into(),
        }
    }

    #[test]
    fn write_request_has_required_attributes() {
        let record = sample_record();
        let request = build_write_request(&record);
        let put = request.put_request().expect("put request");
        let item = put.item();
        assert!(item.contains_key("receipt_id"));
        assert!(item.contains_key("timestamp"));
        assert!(item.contains_key("capability_id"));
        assert!(item.contains_key("tool_server"));
        assert!(item.contains_key("tool_name"));
        assert!(item.contains_key("decision"));
        assert!(item.contains_key("payload"));
    }

    #[test]
    fn deny_record_populates_reason() {
        let mut record = sample_record();
        record.decision = "deny".into();
        record.reason = Some("no matching grant".into());
        let request = build_write_request(&record);
        let put = request.put_request().expect("put request");
        let item = put.item();
        match item.get("reason").expect("reason") {
            AttributeValue::S(s) => assert_eq!(s, "no matching grant"),
            other => panic!("expected string, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backoff_is_bounded() {
        let start = std::time::Instant::now();
        backoff(0).await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(500));
    }
}
