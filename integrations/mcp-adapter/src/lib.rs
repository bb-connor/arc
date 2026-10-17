//! Distribution integration for Chio's registry-listed MCP server.
//!
//! This crate extends the existing `chio-mcp-edge` transport contract with
//! the Streamable HTTP, OAuth 2.1 + PKCE, and RFC9728 Protected Resource
//! Metadata surfaces used by the MCP listing lane. Receipts are produced by the
//! Chio kernel, not by this crate.

#![forbid(unsafe_code)]

pub mod oauth;
pub mod prm;
pub mod transport;

pub use oauth::{
    authorization_url, pkce_challenge, AuthorizationRequest, OAuthError, PkceChallenge,
};
pub use prm::{PrmError, ProtectedResourceMetadata};
pub use transport::{
    StreamableHttpExchange, StreamableHttpTransport, StreamableHttpTransportBuilder,
};
