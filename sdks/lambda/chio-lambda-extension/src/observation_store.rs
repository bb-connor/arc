//! Write-through observation storage in DynamoDB.
//!
//! Every evaluate request writes its observation with one `PutItem` before
//! the evaluator answers. A failed or timed-out write fails the request, so
//! no observation is answered without a stored record and nothing is held in
//! memory between requests. Items are unsigned observation records, not Chio
//! receipts.
//!
//! Table schema (required; the extension does not create the table):
//!
//! ```text
//! AttributeDefinitions:
//!   - AttributeName: observation_id (HASH / partition key, S)
//!   - AttributeName: timestamp      (RANGE / sort key, N)
//! ```
//!
//! Every item also carries:
//!
//! | attribute      | type | meaning                                         |
//! |----------------|------|-------------------------------------------------|
//! | observation_id | S    | UUIDv7 unique identifier                        |
//! | timestamp      | N    | unix seconds from the trusted clock             |
//! | capability_id  | S    | capability token the call was evaluated against |
//! | tool_server    | S    | tool server identifier                          |
//! | tool_name      | S    | tool name                                       |
//! | decision       | S    | observed `allow` or `deny`                      |
//! | reason         | S    | optional deny reason                            |
//! | payload        | S    | JSON of the full observation response           |

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;

/// Upper bound on one observation write, including SDK retries. The
/// evaluator applies it to every store.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// One observation as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRecord {
    pub observation_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub decision: String,
    pub reason: Option<String>,
    pub payload_json: String,
}

#[derive(Debug, thiserror::Error)]
#[error("observation write failed: {0}")]
pub struct StoreError(pub String);

pub type StoreFuture<'a> = Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>>;

/// Durable destination for observations. `put` resolves only after the
/// record is stored.
pub trait ObservationStore: Send + Sync {
    fn put<'a>(&'a self, record: &'a ObservationRecord) -> StoreFuture<'a>;
}

/// Writes each observation to one DynamoDB table.
#[derive(Debug, Clone)]
pub struct DynamoStore {
    client: DynamoClient,
    table: String,
}

impl DynamoStore {
    #[must_use]
    pub fn new(client: DynamoClient, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }
}

impl ObservationStore for DynamoStore {
    fn put<'a>(&'a self, record: &'a ObservationRecord) -> StoreFuture<'a> {
        Box::pin(async move {
            self.client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item(record)))
                .send()
                .await
                .map(|_| ())
                .map_err(|err| StoreError(err.to_string()))
        })
    }
}

fn item(record: &ObservationRecord) -> HashMap<String, AttributeValue> {
    let mut item = HashMap::from([
        (
            "observation_id".to_string(),
            AttributeValue::S(record.observation_id.clone()),
        ),
        (
            "timestamp".to_string(),
            AttributeValue::N(record.timestamp.to_string()),
        ),
        (
            "capability_id".to_string(),
            AttributeValue::S(record.capability_id.clone()),
        ),
        (
            "tool_server".to_string(),
            AttributeValue::S(record.tool_server.clone()),
        ),
        (
            "tool_name".to_string(),
            AttributeValue::S(record.tool_name.clone()),
        ),
        (
            "decision".to_string(),
            AttributeValue::S(record.decision.clone()),
        ),
        (
            "payload".to_string(),
            AttributeValue::S(record.payload_json.clone()),
        ),
    ]);
    if let Some(reason) = &record.reason {
        item.insert("reason".to_string(), AttributeValue::S(reason.clone()));
    }
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> ObservationRecord {
        ObservationRecord {
            observation_id: "01908f4a-0000-7000-8000-000000000001".into(),
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
    fn item_has_required_attributes() {
        let item = item(&sample_record());
        for key in [
            "observation_id",
            "timestamp",
            "capability_id",
            "tool_server",
            "tool_name",
            "decision",
            "payload",
        ] {
            assert!(item.contains_key(key), "{key}");
        }
        assert!(!item.contains_key("reason"));
    }

    #[test]
    fn deny_record_populates_reason() {
        let mut record = sample_record();
        record.decision = "deny".into();
        record.reason = Some("no matching grant".into());
        match item(&record).get("reason") {
            Some(AttributeValue::S(s)) => assert_eq!(s, "no matching grant"),
            other => panic!("expected string, got {other:?}"),
        }
    }
}
