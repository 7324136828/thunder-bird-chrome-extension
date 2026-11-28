//! mail-backend: loopback HTTP backend for the Thunderbird-style mail
//! extension (port of `backend/app/main.py`, `backend/app/doctor/router.py`
//! and `backend/app/doctor/metrics_router.py`).
//!
//! All mail logic is synchronous `mail-core` / `mail-doctor` code; handlers
//! call it through [`error::run_blocking`] (FastAPI ran the same `def`
//! endpoints in its threadpool). Passwords live only in
//! [`state::AppState::sessions`] and are cleared on shutdown.
//!
//! Module map:
//!
//! | Module       | Purpose                                                        |
//! |--------------|----------------------------------------------------------------|
//! | `state`      | `AppState` (`app.state.*` of main.py's lifespan)               |
//! | `security`   | loopback Host / extension Origin guard, CORS                   |
//! | `error`      | `ApiError`, JSON 404/405/500, exception-handler mapping         |
//! | `extract`    | FastAPI-compatible JSON body / query extractors                |
//! | `limits`     | request size limits (`*UploadLimitMiddleware`s + global default) |
//! | `routes`     | one sub-router per route group                                 |

use std::time::Instant;

use axum::extract::{DefaultBodyLimit, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;

pub mod error;
pub mod extract;
pub mod limits;
pub mod routes;
pub mod security;
pub mod state;

pub use error::{run_blocking, ApiError, ApiResult};
pub use state::AppState;

/// Default listen port (final; supersedes 8741 from agent.md).
pub const DEFAULT_PORT: u16 = 48101;

/// The complete application: every API route plus the middleware stack.
/// Integration tests drive it with `tower::ServiceExt::oneshot`.
pub fn build_app(state: AppState) -> Router {
    apply_middleware(routes::api_router().with_state(state))
}

/// Wrap a stateless router in the production middleware stack (exposed so
/// tests can mount extra routes behind the same layers).
///
/// Order, outermost first:
/// 1. request log (method, path, status, duration — never the query string,
///    which carries account emails and OAuth codes);
/// 2. [`security::guard`] (Host / Origin / Sec-Fetch-Site → 403);
/// 3. [`security::cors_layer`] (preflight + headers for extension origins);
/// 4. [`error::normalize_error_responses`] (JSON bodies for every error);
/// 5. panic catcher → JSON 500;
/// 6. [`limits::default_body_limit`]: a default request body cap (4 MiB;
///    64 MiB for `/api/audit/eml`) on every route without its own
///    [`limits::RequestSizeLimitLayer`] (deviation: Python had no cap);
///    axum's `DefaultBodyLimit` is disabled so the per-route layers decide;
/// 7. JSON 404 fallback.
pub fn apply_middleware(router: Router) -> Router {
    router
        .fallback(error::not_found_fallback)
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn(limits::default_body_limit))
        .layer(CatchPanicLayer::custom(error::panic_response))
        .layer(middleware::from_fn(error::normalize_error_responses))
        .layer(security::cors_layer())
        .layer(middleware::from_fn(security::guard))
        .layer(middleware::from_fn(log_requests))
}

/// One log line per request: `METHOD PATH STATUS MS`.
async fn log_requests(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    tracing::info!(
        "{method} {path} {} {}ms",
        response.status().as_u16(),
        started.elapsed().as_millis()
    );
    response
}
