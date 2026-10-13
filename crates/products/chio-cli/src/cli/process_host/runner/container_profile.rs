//! The engine-reported configuration that must equal the fixed worker profile.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::state::error;
use crate::CliError;

pub(super) const PROCESS_SOCKET: &str = "/run/chio/process.sock";

/// Inspection template whose output decodes as [`EffectiveConfig`].
pub(super) const INSPECT_TEMPLATE: &str = r#"{"image":{{json .Image}},"user":{{json .Config.User}},"volumes":{{json .Config.Volumes}},"host":{{json .HostConfig}}}"#;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct EffectiveConfig {
    image: String,
    user: String,
    volumes: Option<BTreeMap<String, serde_json::Value>>,
    host: HostProfile,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
struct HostProfile {
    binds: Option<Vec<String>>,
    volumes_from: Option<Vec<String>>,
    cap_add: Option<Vec<String>>,
    cap_drop: Option<Vec<String>>,
    group_add: Option<Vec<String>>,
    devices: Option<Vec<serde_json::Value>>,
    security_opt: Option<Vec<String>>,
    privileged: bool,
    readonly_rootfs: bool,
    network_mode: String,
    ipc_mode: String,
    pid_mode: String,
    cgroupns_mode: String,
    userns_mode: String,
    #[serde(rename = "UTSMode")]
    uts_mode: String,
    memory: i64,
    memory_swap: i64,
    nano_cpus: i64,
    pids_limit: Option<i64>,
    shm_size: i64,
    ulimits: Option<Vec<Ulimit>>,
    tmpfs: Option<BTreeMap<String, String>>,
    mounts: Option<Vec<Mount>>,
    init: Option<bool>,
    restart_policy: RestartPolicy,
    log_config: LogConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Ulimit {
    name: String,
    hard: i64,
    soft: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    #[serde(rename = "Type")]
    kind: String,
    source: String,
    target: String,
    read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RestartPolicy {
    name: String,
    maximum_retry_count: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
struct LogConfig {
    #[serde(rename = "Type")]
    kind: String,
}

fn present<T>(values: Option<Vec<T>>) -> Option<Vec<T>> {
    values.filter(|values| !values.is_empty())
}

impl EffectiveConfig {
    /// Engines report absent and empty collections interchangeably.
    pub(super) fn normalized(mut self) -> Self {
        self.volumes = self.volumes.filter(|volumes| !volumes.is_empty());
        let host = &mut self.host;
        host.binds = present(host.binds.take());
        host.volumes_from = present(host.volumes_from.take());
        host.cap_add = present(host.cap_add.take());
        host.group_add = present(host.group_add.take());
        host.devices = present(host.devices.take());
        host.ulimits = present(host.ulimits.take()).map(|mut ulimits| {
            ulimits.sort();
            ulimits
        });
        self
    }

    pub(super) fn digest(&self) -> Result<String, CliError> {
        Ok(chio_core::sha256_hex(
            &chio_core::canonical_json_bytes(self).map_err(error)?,
        ))
    }
}

/// The configuration `create` requests, as the engine reports it.
pub(super) fn fixed(image: &str, uid: u32, gid: u32, socket: &str) -> EffectiveConfig {
    let ulimit = |name: &str, limit: i64| Ulimit {
        name: name.to_owned(),
        hard: limit,
        soft: limit,
    };
    EffectiveConfig {
        image: image.to_owned(),
        user: format!("{uid}:{gid}"),
        volumes: None,
        host: HostProfile {
            binds: None,
            volumes_from: None,
            cap_add: None,
            cap_drop: Some(vec!["ALL".to_owned()]),
            group_add: None,
            devices: None,
            security_opt: Some(vec!["no-new-privileges:true".to_owned()]),
            privileged: false,
            readonly_rootfs: true,
            network_mode: "none".to_owned(),
            ipc_mode: "private".to_owned(),
            pid_mode: String::new(),
            cgroupns_mode: "private".to_owned(),
            userns_mode: String::new(),
            uts_mode: String::new(),
            memory: 512 * 1024 * 1024,
            memory_swap: 512 * 1024 * 1024,
            nano_cpus: 1_000_000_000,
            pids_limit: Some(64),
            shm_size: 8 * 1024 * 1024,
            ulimits: Some(vec![
                ulimit("core", 0),
                ulimit("fsize", 16_777_216),
                ulimit("nofile", 128),
            ]),
            tmpfs: Some(BTreeMap::from([
                (
                    "/tmp".to_owned(),
                    "rw,noexec,nosuid,nodev,size=16m,mode=1777".to_owned(),
                ),
                (
                    "/work".to_owned(),
                    format!("rw,noexec,nosuid,nodev,size=64m,uid={uid},gid={gid},mode=0700"),
                ),
            ])),
            mounts: Some(vec![Mount {
                kind: "bind".to_owned(),
                source: socket.to_owned(),
                target: PROCESS_SOCKET.to_owned(),
                read_only: true,
            }]),
            init: Some(true),
            restart_policy: RestartPolicy {
                name: "no".to_owned(),
                maximum_retry_count: 0,
            },
            log_config: LogConfig {
                kind: "none".to_owned(),
            },
        },
    }
}
