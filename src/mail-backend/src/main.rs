//! mail-backend entry point: CLI parsing, start-up, graceful shutdown.
//!
//! Replaces the uvicorn launchers of the original project (`run.py`,
//! `backend/packaged.py`): it binds loopback only (non-loopback addresses are
//! refused: the API serves unlocked mailboxes and a LAN client could forge
//! the `Host` header and omit `Origin`), prints where it
//! listens and which settings/profile files it uses, and on Ctrl+C stops
//! accepting requests and locks every account (clears the in-memory
//! `SessionStore`), like main.py's lifespan `finally:` block.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mail_backend::{build_app, AppState, DEFAULT_PORT};
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Environment variable equivalent to `--addr`.
const ADDR_ENV: &str = "MAIL_BACKEND_ADDR";

const USAGE: &str = "\
mail-backend - local mail service for the Thunderbird-style mail extension

USAGE:
    mail-backend [--port PORT] [--addr HOST:PORT]

OPTIONS:
    -p, --port PORT       Port to listen on (default 48101, address 127.0.0.1)
    -a, --addr HOST:PORT  Loopback listen address, e.g. 127.0.0.1:48101 or [::1]:48101
                          (a bare port also works; non-loopback addresses are refused)
    -h, --help            Show this help
    -V, --version         Show the version

ENVIRONMENT:
    MAIL_BACKEND_ADDR     Same as --addr (command-line flags win)
    MAIL_BACKEND_EXTENSION_IDS
                          Comma-separated browser-extension ids allowed to call the
                          backend, replacing the built-in id of this extension (needed
                          for Firefox, whose ids are random per install); \"*\" allows
                          every extension (INSECURE, development only)
    PUBLIC_BACKEND_URL    Base URL for Inbox Doctor OAuth redirects
                          (default: http://localhost:<listen port>)
    WEBMAIL_SETTINGS_PATH Full path of settings.json (default: webmail-thunderbird\\settings.json
                          under %APPDATA%, or $XDG_CONFIG_HOME / ~/.config elsewhere)
    MAIL_SERVERS_PATH     Server-profile file (default: mail-servers.json in the app data folder)
    DATA_DIRECTORY        Data folder for Inbox Doctor, retention and trash archives
    RUST_LOG              Log filter, e.g. info or mail_backend=debug

Mailbox passwords are kept in memory only: every restart locks all accounts.
Only the browser extension (and local tools without an Origin header, such as
the MCP server) can use this service; requests from web pages are refused.";

#[derive(Debug, PartialEq, Eq)]
enum Cli {
    Run(SocketAddr),
    Help,
    Version,
}

/// Parse "48101", "127.0.0.1:48101", "localhost:48101", "[::1]:48101",
/// "localhost" or "127.0.0.1" into a socket address.
fn parse_addr(text: &str) -> Result<SocketAddr, String> {
    let text = text.trim();
    let bad = || {
        format!(
            "invalid address {text:?} (expected e.g. 127.0.0.1:{DEFAULT_PORT} or just a port number)"
        )
    };
    if text.is_empty() {
        return Err(bad());
    }
    if text.chars().all(|c| c.is_ascii_digit()) {
        let port: u16 = text.parse().map_err(|_| bad())?;
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = text
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| bad())?),
        None => (text, DEFAULT_PORT),
    };
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    Err(bad())
}

fn parse_cli(args: &[String], env_addr: Option<&str>) -> Result<Cli, String> {
    let mut addr: Option<SocketAddr> = None;
    let mut port: Option<u16> = None;
    let mut iter = args.iter();
    while let Some(argument) = iter.next() {
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_string())),
            _ => (argument.as_str(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            inline
                .clone()
                .or_else(|| iter.next().cloned())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag {
            "-h" | "--help" | "/?" => return Ok(Cli::Help),
            "-V" | "--version" => return Ok(Cli::Version),
            "-p" | "--port" => {
                let text = value("--port")?;
                port = Some(
                    text.trim()
                        .parse()
                        .map_err(|_| format!("invalid port {text:?}"))?,
                );
            }
            "-a" | "--addr" => addr = Some(parse_addr(&value("--addr")?)?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let mut address = match addr {
        Some(address) => address,
        None => match env_addr.map(str::trim).filter(|text| !text.is_empty()) {
            Some(text) => parse_addr(text).map_err(|message| format!("{ADDR_ENV}: {message}"))?,
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
        },
    };
    if let Some(port) = port {
        address.set_port(port);
    }
    if !address.ip().is_loopback() {
        return Err(format!(
            "refusing to listen on non-loopback address {address}: the backend serves \
             unlocked mailboxes and must only be reachable from this computer \
             (use 127.0.0.1 or [::1])"
        ));
    }
    Ok(Cli::Run(address))
}

fn friendly_bind_error(addr: SocketAddr, error: &std::io::Error) -> String {
    let port = addr.port();
    let next = port.wrapping_add(1).max(1024);
    match error.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "Port {port} is already in use - is mail-backend already running?\n\
             Check http://127.0.0.1:{port}/api/health in your browser. To use another port run:\n    \
             mail-backend --port {next}\n\
             and point the extension's backend URL at http://127.0.0.1:{next}"
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "Not allowed to listen on {addr} ({error}). The port may be reserved by the system; \
             try another one, e.g.\n    mail-backend --port {next}"
        ),
        std::io::ErrorKind::AddrNotAvailable => format!(
            "The address {addr} is not available on this machine ({error}). \
             Use 127.0.0.1 (the default)."
        ),
        _ => format!("Could not listen on {addr}: {error}"),
    }
}

/// `http://127.0.0.1:PORT` for the 127.0.0.1 listener (packaged.py
/// `listener_url`), otherwise the literal (loopback) address.
fn listener_url(local: SocketAddr) -> String {
    if local.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        format!("http://127.0.0.1:{}", local.port())
    } else {
        format!("http://{local}")
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .try_init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    println!("[run] Stopping mail-backend...");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env_addr = std::env::var(ADDR_ENV).ok();
    let addr = match parse_cli(&args, env_addr.as_deref()) {
        Ok(Cli::Run(addr)) => addr,
        Ok(Cli::Help) => {
            println!("{USAGE}");
            return;
        }
        Ok(Cli::Version) => {
            println!("mail-backend {VERSION}");
            return;
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    init_tracing();
    // One readable line per panic (the request itself still gets a JSON 500).
    std::panic::set_hook(Box::new(|info| {
        tracing::error!("internal error (recovered): {info}");
    }));

    // Bind first so the actual port (also for `--port 0`) is known when the
    // state is built: Inbox Doctor's OAuth redirect URI follows it.
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("[run] ERROR: {}", friendly_bind_error(addr, &error));
            std::process::exit(1);
        }
    };
    let local = listener.local_addr().unwrap_or(addr);

    let state = match AppState::initialize_listening_on(Some(local.port())) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("[run] ERROR: {error}");
            std::process::exit(1);
        }
    };

    let url = listener_url(local);
    println!("Starting mail-backend {VERSION}");
    println!(
        "Allowed extension ids: {}",
        mail_backend::security::allowed_extension_ids().describe()
    );
    println!("Backend:  {url} (health: {url}/api/health)");
    println!(
        "Settings: {}",
        mail_core::settings::settings_path().display()
    );
    println!("Profiles: {}", state.mail_servers_path.display());
    println!("Data:     {}", state.data_directory.display());
    println!("[run] Press Ctrl+C to stop.");

    let app = build_app(state.clone());
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    // Lock every account: passwords must not outlive the serving phase.
    state.shutdown();
    if let Err(error) = result {
        eprintln!("[run] ERROR: server stopped: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn cli_parsing() {
        assert_eq!(
            parse_cli(&strings(&[]), None),
            Ok(Cli::Run(loopback(48101)))
        );
        assert_eq!(
            parse_cli(&strings(&["--port", "5000"]), None),
            Ok(Cli::Run(loopback(5000)))
        );
        assert_eq!(
            parse_cli(&strings(&["--port=5001"]), None),
            Ok(Cli::Run(loopback(5001)))
        );
        assert_eq!(
            parse_cli(&strings(&["-p", "5002"]), Some("127.0.0.1:9")),
            Ok(Cli::Run(loopback(5002)))
        );
        assert_eq!(
            parse_cli(&strings(&[]), Some("5003")),
            Ok(Cli::Run(loopback(5003)))
        );
        assert_eq!(
            parse_cli(&strings(&[]), Some("localhost:5004")),
            Ok(Cli::Run(loopback(5004)))
        );
        assert_eq!(
            parse_cli(&strings(&[]), Some("  ")),
            Ok(Cli::Run(loopback(48101)))
        );
        assert_eq!(
            parse_cli(&strings(&["--addr", "[::1]:5005"]), None),
            Ok(Cli::Run("[::1]:5005".parse().unwrap()))
        );
        assert_eq!(
            parse_cli(&strings(&["-a", "localhost"]), None),
            Ok(Cli::Run(loopback(48101)))
        );
        assert_eq!(parse_cli(&strings(&["--help"]), None), Ok(Cli::Help));
        assert_eq!(parse_cli(&strings(&["-V"]), None), Ok(Cli::Version));
        assert!(parse_cli(&strings(&["--port", "abc"]), None).is_err());
        assert!(parse_cli(&strings(&["--port"]), None).is_err());
        assert!(parse_cli(&strings(&["--bogus"]), None).is_err());
        let env_error = parse_cli(&strings(&[]), Some("nonsense:host:x")).unwrap_err();
        assert!(env_error.starts_with("MAIL_BACKEND_ADDR:"), "{env_error}");
        // Loopback only: wildcard and LAN addresses are refused, from flags
        // and from the environment alike.
        for address in [
            "0.0.0.0:48101",
            "[::]:48101",
            "192.168.1.20:48101",
            "0.0.0.0",
        ] {
            let error = parse_cli(&strings(&["--addr", address]), None).unwrap_err();
            assert!(error.contains("non-loopback"), "{error}");
            assert!(parse_cli(&strings(&[]), Some(address)).is_err());
        }
        assert_eq!(
            parse_cli(&strings(&["--addr", "127.0.0.2:5006"]), None),
            Ok(Cli::Run("127.0.0.2:5006".parse().unwrap()))
        );
    }

    #[test]
    fn bind_errors_are_helpful() {
        let message = friendly_bind_error(
            loopback(48101),
            &std::io::Error::from(std::io::ErrorKind::AddrInUse),
        );
        assert!(
            message.contains("already in use") && message.contains("--port 48102"),
            "{message}"
        );
        let message = friendly_bind_error(
            "10.9.9.9:1".parse().unwrap(),
            &std::io::Error::from(std::io::ErrorKind::AddrNotAvailable),
        );
        assert!(message.contains("127.0.0.1"), "{message}");
    }

    #[test]
    fn listener_urls() {
        assert_eq!(listener_url(loopback(48101)), "http://127.0.0.1:48101");
        assert_eq!(listener_url("[::1]:7".parse().unwrap()), "http://[::1]:7");
    }
}
