//! Historical audit metrics and the weekly audit schedule (port of
//! `backend/app/doctor/metrics_router.py` and main.py `audit_schedule`).
//! Neither route needs mailbox credentials.
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | GET    | `/api/email-metrics` | query `account: str(max 320)|None` (stripped, lowercased; non-empty must have exactly one `@`, no whitespace/control chars) | 200 `{"runs": [...], "domains": [str], "accounts": [str]}` (no credentials needed) | 400 `"Enter a valid account email address"`, 422 |
//! | GET    | `/api/email-metrics/schedule` | — | 200 `{"enabled": true, "timezone", "weekday": 5, "hour": 18, "minute": 0, "accounts": [{"email", "next_run_at", "last_run_at", "pending_runs", "unlocked", "last_error"}]}` | — |

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use mail_doctor::metrics::{validate_account_query, MetricsResponse};
use mail_doctor::scheduler::ScheduleStatus;

use crate::error::{run_blocking, ApiResult};
use crate::extract::QueryParams;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/email-metrics", get(email_metrics))
        .route("/api/email-metrics/schedule", get(audit_schedule))
}

/// `GET /api/email-metrics?account=`.
async fn email_metrics(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<MetricsResponse>> {
    let mut q = query.validator();
    let account = q.string("account").max_length(320).optional();
    q.finish()?;
    let account = validate_account_query(account.as_deref())?;
    let doctor = state.doctor.clone();
    let metrics = run_blocking(move || doctor.metrics().list_metrics(account.as_deref())).await?;
    Ok(Json(metrics))
}

/// `GET /api/email-metrics/schedule` (main.py `audit_schedule`).
async fn audit_schedule(State(state): State<AppState>) -> ApiResult<Json<ScheduleStatus>> {
    let scheduler = state.audit_scheduler.clone();
    Ok(Json(
        run_blocking(move || scheduler.get_status(None)).await?,
    ))
}
