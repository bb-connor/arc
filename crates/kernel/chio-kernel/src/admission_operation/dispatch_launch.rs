//! Launch evidence of the evaluation that committed dispatch.

use serde::{Deserialize, Deserializer, Serialize};

use super::AdmissionOperationError;
use super::AdmittedReceiptMetadata;

const NATIVE_LAUNCH: &str = "native_launch";
const PROCESS: &str = "chio_process";
const WORKER_PROFILE: &str = "worker_profile";

/// The native launch and worker launch that presented the attempt committing
/// dispatch. An absent entry means that attempt presented no such launch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdmissionDispatchLaunchV1 {
    native_launch: Option<serde_json::Value>,
    worker_profile: Option<serde_json::Value>,
}

impl<'de> Deserialize<'de> for AdmissionDispatchLaunchV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let object = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        if object.len() != 2
            || !object.contains_key(NATIVE_LAUNCH)
            || !object.contains_key(WORKER_PROFILE)
        {
            return Err(serde::de::Error::custom(
                "dispatch launch must name exactly native_launch and worker_profile",
            ));
        }
        let entry = |key: &str| object.get(key).filter(|value| !value.is_null()).cloned();
        let launch = Self {
            native_launch: entry(NATIVE_LAUNCH),
            worker_profile: entry(WORKER_PROFILE),
        };
        launch.validate().map_err(serde::de::Error::custom)?;
        Ok(launch)
    }
}

impl AdmissionDispatchLaunchV1 {
    /// The attempt-scoped launch entries of a presenting caller's metadata.
    pub fn from_admitted_metadata(
        metadata: Option<&AdmittedReceiptMetadata>,
    ) -> Result<Self, AdmissionOperationError> {
        let launch = Self {
            native_launch: metadata
                .and_then(|metadata| metadata.get(NATIVE_LAUNCH))
                .cloned(),
            worker_profile: metadata
                .and_then(|metadata| metadata.get(PROCESS))
                .and_then(|process| process.get(WORKER_PROFILE))
                .cloned(),
        };
        launch.validate()?;
        Ok(launch)
    }

    #[must_use]
    pub fn native_launch(&self) -> Option<&serde_json::Value> {
        self.native_launch.as_ref()
    }

    #[must_use]
    pub fn worker_profile(&self) -> Option<&serde_json::Value> {
        self.worker_profile.as_ref()
    }

    /// Replace the attempt-scoped entries of signed refusal metadata with the
    /// launches that committed dispatch.
    pub(crate) fn apply_to(&self, metadata: &mut serde_json::Map<String, serde_json::Value>) {
        match &self.native_launch {
            Some(launch) => {
                metadata.insert(NATIVE_LAUNCH.to_owned(), launch.clone());
            }
            None => {
                metadata.remove(NATIVE_LAUNCH);
            }
        }
        if let Some(process) = metadata
            .get_mut(PROCESS)
            .and_then(serde_json::Value::as_object_mut)
        {
            match &self.worker_profile {
                Some(profile) => {
                    process.insert(WORKER_PROFILE.to_owned(), profile.clone());
                }
                None => {
                    process.remove(WORKER_PROFILE);
                }
            }
        }
    }

    fn validate(&self) -> Result<(), AdmissionOperationError> {
        if self
            .native_launch
            .as_ref()
            .is_some_and(|launch| !is_native_launch(launch))
        {
            return Err(AdmissionOperationError::InvalidDispatchLaunch {
                entry: NATIVE_LAUNCH,
            });
        }
        if self
            .worker_profile
            .as_ref()
            .is_some_and(|profile| !is_worker_profile(profile))
        {
            return Err(AdmissionOperationError::InvalidDispatchLaunch {
                entry: WORKER_PROFILE,
            });
        }
        Ok(())
    }
}

fn is_lower_sha256_hex(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// A native launch names one launch receipt by id and content digest.
pub(crate) fn is_native_launch(launch: &serde_json::Value) -> bool {
    launch.as_object().is_some_and(|object| object.len() == 2)
        && launch.get("receipt_id").is_some_and(is_lower_sha256_hex)
        && launch
            .get("receipt_sha256")
            .is_some_and(is_lower_sha256_hex)
}

/// A worker profile names one container launch record and its attempt.
pub(crate) fn is_worker_profile(profile: &serde_json::Value) -> bool {
    let reference = profile.get("launch_ref");
    profile.as_object().is_some_and(|object| object.len() == 3)
        && profile.get("kind").and_then(serde_json::Value::as_str) == Some("container")
        && profile
            .get("launch_attempt")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|attempt| (1..=u64::from(u32::MAX)).contains(&attempt))
        && reference
            .and_then(serde_json::Value::as_object)
            .is_some_and(|object| object.len() == 2)
        && reference
            .and_then(|reference| reference.get("record_id"))
            .is_some_and(is_lower_sha256_hex)
        && reference
            .and_then(|reference| reference.get("record_sha256"))
            .is_some_and(is_lower_sha256_hex)
}

#[cfg(test)]
#[path = "dispatch_launch_tests.rs"]
mod tests;
