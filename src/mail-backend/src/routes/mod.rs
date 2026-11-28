//! HTTP routes, one sub-router per group of `backend/app/main.py`,
//! `backend/app/doctor/router.py` and `backend/app/doctor/metrics_router.py`.
//!
//! Each module's doc comment lists the exact routes it holds (method, path,
//! parameters, success shape and error statuses); together with
//! `mail-backend/API_MATRIX.md` this is the API checklist. Paths and JSON
//! shapes must stay identical to the Python backend so the copied React
//! frontend works unchanged.
//!
//! Conventions for route code:
//! * Parse inputs with [`crate::extract`] (`QueryParams` + `QueryValidator`,
//!   `JsonObject`) so validation errors are FastAPI-shaped.
//! * Call synchronous mail-core code through [`crate::error::run_blocking`].
//! * Return `ApiResult<T>`; `MailError` converts into `ApiError` with `?`.
//! * Apply [`crate::limits::RequestSizeLimitLayer`] to the upload routes.
//! * No route group may register a path owned by another group.

use axum::Router;

use crate::state::AppState;

pub mod accounts;
pub mod audit;
pub mod classifier;
pub mod doctor;
pub mod health;
pub mod images;
pub mod mail;
pub mod metrics;
pub mod retention;
pub mod send;
pub mod servers;
pub mod settings;
pub mod signature;
pub mod trash;

/// Every API route, merged from the per-group routers.
pub fn api_router() -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(settings::router())
        .merge(accounts::router())
        .merge(servers::router())
        .merge(signature::router())
        .merge(mail::router())
        .merge(retention::router())
        .merge(classifier::router())
        .merge(images::router())
        .merge(trash::router())
        .merge(send::router())
        .merge(audit::router())
        .merge(doctor::router())
        .merge(metrics::router())
}
