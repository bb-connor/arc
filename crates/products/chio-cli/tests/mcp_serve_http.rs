#![allow(clippy::expect_used, clippy::too_many_arguments, clippy::unwrap_used)]

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chio_core::crypto::Keypair;
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair as RcgenKeyPair,
};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};

#[path = "support/mcp_security.rs"]
mod mcp_security;

static UNIQUE_TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
const SERVER_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const SERVER_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STATIC_AUTH_ADMIN_TOKEN: &str = "static-auth-admin-token";

include!("mcp_serve_http_parts/part_01.inc");
include!("mcp_serve_http_parts/part_02.inc");
include!("mcp_serve_http_parts/part_03.inc");
include!("mcp_serve_http_parts/part_04.inc");
