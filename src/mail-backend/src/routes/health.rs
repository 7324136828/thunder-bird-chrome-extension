//! Health check (main.py `health`).
//!
//! | Method | Path          | Params | Success                 | Errors |
//! |--------|---------------|--------|-------------------------|--------|
//! | GET    | `/api/health` | —      | 200 `{"status":"ok"}`   | —      |

use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/health", get(health))
}

/// `GET /api/health` → `{"status": "ok"}`.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
