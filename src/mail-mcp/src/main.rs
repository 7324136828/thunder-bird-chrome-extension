//! mail-mcp entry point: MCP over stdio, proxying to the local mail-backend.
//!
//! Configuration (environment):
//! - `MAIL_BACKEND_URL` (default `http://127.0.0.1:48101`)
//! - `MAIL_MCP_ALLOW_NON_LOOPBACK=1` to allow a non-loopback backend host
//! - `MAIL_BACKEND_TIMEOUT_SECS` (default 300)
//! - `RUST_LOG` for stderr logging (default `warn`)
//!
//! stdout carries only MCP protocol messages; all logs go to stderr.

use mail_mcp::{serve_stdio, BackendClient};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let client = match BackendClient::from_env() {
        Ok(client) => client,
        Err(message) => {
            eprintln!("mail-mcp: {message}");
            return std::process::ExitCode::from(2);
        }
    };
    tracing::info!("mail-mcp proxying to {}", client.base_url());

    match serve_stdio(client).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mail-mcp: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
