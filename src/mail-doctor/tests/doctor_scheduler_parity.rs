//! Weekly schedule arithmetic compared with the original Python
//! (`backend/app/doctor/scheduler.py` with zoneinfo `America/New_York`):
//! `tests/fixtures/doctor/schedule_vectors.json` holds `next_saturday`,
//! `weekly_window`, the one-week advance of `_reconcile` and the
//! `pending_runs` of `get_status` computed by CPython across both 2026 DST
//! transitions.

use chrono::{DateTime, Duration, Utc};
use mail_core::SessionStore;
use mail_doctor::config::DoctorSettings;
use mail_doctor::db::isoformat;
use mail_doctor::runner::JobRunner;
use mail_doctor::scheduler::{
    next_saturday, parse_schedule_time, weekly_window, WeeklyAuditScheduler,
};
use std::sync::Arc;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/doctor/schedule_vectors.json")).unwrap()
}

fn moment(text: &str) -> DateTime<Utc> {
    parse_schedule_time(text).unwrap()
}

#[test]
fn next_saturday_and_windows_match_python_zoneinfo() {
    let vectors = vectors();
    for case in vectors["next"].as_array().unwrap() {
        let now = moment(case[0].as_str().unwrap());
        let due = next_saturday(now);
        assert_eq!(
            isoformat(&due),
            case[1].as_str().unwrap(),
            "next_saturday({now})"
        );
        let (start, end) = weekly_window(due);
        assert_eq!(
            isoformat(&start),
            case[2].as_str().unwrap(),
            "window start of {due}"
        );
        assert_eq!(
            isoformat(&end),
            case[3].as_str().unwrap(),
            "window end of {due}"
        );
        // `_reconcile` advances a completed week by seven local days, which
        // is the next Saturday after the due time.
        assert_eq!(
            isoformat(&next_saturday(due)),
            case[4].as_str().unwrap(),
            "advance {due}"
        );
    }
}

#[test]
fn pending_runs_match_python_get_status() {
    let directory = tempfile::tempdir().unwrap();
    let settings = DoctorSettings::with_defaults(directory.path());
    let runner = JobRunner::new(settings);
    runner.initialize().unwrap();
    let scheduler = WeeklyAuditScheduler::new(Arc::new(runner), SessionStore::new());
    let vectors = vectors();
    let mut registered = std::collections::HashMap::new();
    for case in vectors["pending"].as_array().unwrap() {
        let due = case[0].as_str().unwrap();
        let email = registered.len().to_string();
        let email = registered
            .entry(due.to_string())
            .or_insert_with(|| {
                let address = format!("user{email}@example.com");
                scheduler
                    .register(&address, Some(moment(due) - Duration::seconds(1)))
                    .unwrap();
                address
            })
            .clone();
        let current = moment(case[1].as_str().unwrap());
        let status = scheduler.get_status(Some(current)).unwrap();
        let account = status
            .accounts
            .iter()
            .find(|account| account.email == email)
            .unwrap();
        assert_eq!(account.next_run_at, due);
        assert_eq!(
            account.pending_runs,
            case[2].as_i64().unwrap(),
            "pending_runs(due={due}, now={current})"
        );
    }
}
