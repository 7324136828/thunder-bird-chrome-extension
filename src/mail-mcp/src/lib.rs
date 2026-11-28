//! `mail-mcp`: an MCP (Model Context Protocol) stdio server for the
//! Thunderbird-style mail extension.
//!
//! The server holds no credentials and persists nothing. Every tool is a
//! proxy to the local `mail-backend` HTTP API (`MAIL_BACKEND_URL`, default
//! `http://127.0.0.1:48101`), so it can only act on accounts the user has
//! already unlocked in the extension.
//!
//! - [`backend`]: HTTP client for the backend API (original FastAPI routes).
//! - [`tools`]: the tool implementations.
//! - [`params`]: tool argument types (JSON schemas for `tools/list`).
//! - [`server`]: the `rmcp` server handler and stdio entry point.

pub mod backend;
pub mod error;
pub mod params;
pub mod server;
pub mod tools;

pub use backend::BackendClient;
pub use error::ToolError;
pub use server::{serve_stdio, MailMcpServer};
pub use tools::MailTools;
