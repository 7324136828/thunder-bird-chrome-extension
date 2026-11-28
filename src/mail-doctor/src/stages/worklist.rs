//! Stage 4 - generate a per-sender cleanup worklist
//! (port of `services/stages/worklist.py`).
//!
//! Applies heuristic recommendations (unsubscribe / review / delete / archive /
//! keep) to every sender group, honoring optional user overrides from
//! `annotations.json` files placed in the job inputs.
//!
//! `annotations.json` accepts either shape:
//! `{"newsletters.example.com": "unsubscribe_and_purge"}` or
//! `{"newsletters.example.com": {"action": "keep", "note": " receipts"}}`.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use super::csv_safety::{self, Cell};
use super::eml_extract::{file_name, rglob_sorted};
use super::inbox_summary::{aggregate, iter_records, rank, utc_now_iso, GroupStats};
use super::pyjson::Json;
use super::{value_error, LogFn};
use crate::cancellation::check_cancel;
use crate::pipeline::PipelineError;

pub const AUTOMATED_PATTERNS: [&str; 14] = [
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "mailer-daemon",
    "newsletter",
    "notifications",
    "notify",
    "bounce",
    "digest",
    "marketing",
    "promo",
    "updates",
];

pub const ACTIONS: [&str; 6] = [
    "unsubscribe_and_purge",
    "unsubscribe",
    "review_delete",
    "review",
    "archive",
    "keep",
];

pub const HIGH_VOLUME: i64 = 10;

/// `worklist._is_automated`.
fn is_automated(group: &str, addrs: &BTreeSet<String>) -> bool {
    let mut parts = vec![group];
    parts.extend(addrs.iter().map(String::as_str));
    let haystack = parts.join(" ").to_lowercase();
    AUTOMATED_PATTERNS
        .iter()
        .any(|pattern| haystack.contains(pattern))
}

/// `worklist._recommend` → (action, reason).
pub fn recommend(group: &str, g: &GroupStats) -> (&'static str, &'static str) {
    let has_unsub = !g.unsub.is_empty();
    let automated = is_automated(group, &g.addrs);
    if has_unsub && g.count >= HIGH_VOLUME {
        (
            "unsubscribe_and_purge",
            "High-volume sender advertising unsubscribe",
        )
    } else if has_unsub {
        ("unsubscribe", "Sender advertises an unsubscribe link")
    } else if automated && g.count >= 5 {
        (
            "review_delete",
            "Automated sender without unsubscribe option",
        )
    } else if automated {
        ("review", "Likely automated sender")
    } else if g.count >= HIGH_VOLUME {
        ("archive", "High-volume sender, no unsubscribe detected")
    } else {
        ("keep", "Low-volume human sender")
    }
}

/// `worklist._load_annotations`: `{group: override}` (later files win).
fn load_annotations(
    inputs_dir: &Path,
    log: &mut LogFn<'_>,
) -> Result<HashMap<String, Json>, PipelineError> {
    let mut notes: HashMap<String, Json> = HashMap::new();
    let mut entries = 0usize;
    for path in rglob_sorted(inputs_dir, |name| name == "annotations.json") {
        check_cancel()?;
        let parsed = fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| Json::loads_file_bytes(&bytes));
        let data = match parsed {
            Ok(data) => data,
            Err(error) => {
                log(format!(
                    "Ignoring invalid annotations file {}: {}",
                    file_name(&path),
                    error
                ))?;
                continue;
            }
        };
        let Json::Object(pairs) = data else {
            continue;
        };
        entries += pairs.len();
        if entries > 10000 {
            return Err(value_error(
                "Sender annotations exceed the maximum of 10000 entries",
            ));
        }
        for (group, value) in &pairs {
            check_cancel()?;
            if group.chars().count() > 320 {
                return Err(value_error(
                    "Sender annotation groups exceed the maximum of 320 characters",
                ));
            }
            if let Json::Object(_) = value {
                let note = value
                    .get("note")
                    .filter(|n| n.truthy())
                    .map(Json::py_str)
                    .unwrap_or_default();
                if note.chars().count() > 4000 {
                    return Err(value_error(
                        "Sender annotation notes exceed the maximum of 4000 characters",
                    ));
                }
            }
        }
        notes.extend(pairs);
    }
    Ok(notes)
}

/// Run the stage; returns the `worklist.json` payload.
pub fn run(
    inputs_dir: &Path,
    grouped_path: &Path,
    outputs_dir: &Path,
    log: &mut LogFn<'_>,
) -> Result<Json, PipelineError> {
    let records = iter_records(grouped_path)?;
    let ranked = rank(aggregate(&records)?);
    let annotations = load_annotations(inputs_dir, log)?;

    let mut items: Vec<Json> = Vec::new();
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    let mut action_counts: Vec<(&str, i64)> = ACTIONS.iter().map(|a| (*a, 0)).collect();
    for (group, g) in &ranked {
        check_cancel()?;
        let (mut action, mut reason) = recommend(group, g);
        let mut note = String::new();
        match annotations.get(group) {
            Some(Json::Str(value)) if ACTIONS.contains(&value.as_str()) => {
                action = ACTIONS.iter().find(|a| **a == value).expect("checked");
                reason = "User annotation override";
            }
            Some(value @ Json::Object(_)) => {
                if let Some(Json::Str(requested)) = value.get("action") {
                    if let Some(found) = ACTIONS.iter().find(|a| **a == requested) {
                        action = found;
                        reason = "User annotation override";
                    }
                }
                note = value
                    .get("note")
                    .filter(|n| n.truthy())
                    .map(Json::py_str)
                    .unwrap_or_default();
            }
            _ => {}
        }
        let unsubscribe_link = g.unsub.iter().next().cloned().unwrap_or_default();
        let addresses: Vec<String> = g.addrs.iter().cloned().collect();
        rows.push(vec![
            group.as_str().into(),
            action.into(),
            g.count.into(),
            g.size.into(),
            g.first.clone().unwrap_or_default().into(),
            g.last.clone().unwrap_or_default().into(),
            if g.unsub.is_empty() { "no" } else { "yes" }.into(),
            unsubscribe_link.as_str().into(),
            addresses.join(";").into(),
            reason.into(),
            note.as_str().into(),
        ]);
        items.push(Json::object([
            ("sender_group", Json::str(group)),
            ("recommended_action", Json::str(action)),
            ("message_count", Json::Int(g.count)),
            ("total_size_bytes", Json::Int(g.size)),
            ("first_seen", Json::str(g.first.clone().unwrap_or_default())),
            ("last_seen", Json::str(g.last.clone().unwrap_or_default())),
            ("has_unsubscribe", Json::Bool(!g.unsub.is_empty())),
            ("unsubscribe_link", Json::Str(unsubscribe_link)),
            (
                "addresses",
                Json::Array(addresses.into_iter().map(Json::Str).collect()),
            ),
            ("reason", Json::str(reason)),
            ("note", Json::Str(note)),
        ]));
    }

    fs::create_dir_all(outputs_dir)?;
    let mut writer = csv_safety::writer(Vec::new());
    writer.writerow(
        [
            "sender_group",
            "recommended_action",
            "message_count",
            "total_size_bytes",
            "first_seen",
            "last_seen",
            "has_unsubscribe",
            "unsubscribe_link",
            "addresses",
            "reason",
            "note",
        ]
        .into_iter()
        .map(Cell::from)
        .collect(),
    )?;
    for row in rows {
        check_cancel()?;
        writer.writerow(row)?;
    }
    fs::write(
        outputs_dir.join("inbox_cleanup_worklist.csv"),
        writer.into_inner(),
    )?;

    for item in &items {
        check_cancel()?;
        let action = item
            .get("recommended_action")
            .and_then(Json::as_str)
            .unwrap_or("");
        if let Some(slot) = action_counts.iter_mut().find(|(a, _)| *a == action) {
            slot.1 += 1;
        }
    }
    let payload = Json::object([
        ("generated_at", Json::Str(utc_now_iso())),
        ("total_senders", Json::Int(items.len() as i64)),
        (
            "action_counts",
            Json::object(action_counts.into_iter().map(|(a, c)| (a, Json::Int(c)))),
        ),
        ("items", Json::Array(items)),
    ]);
    fs::write(outputs_dir.join("worklist.json"), payload.dumps_indent())?;
    let total = payload.get("total_senders").cloned();
    if let Some(Json::Int(count)) = total {
        log(format!("Worklist generated for {count} sender groups"))?;
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(count: i64, unsub: bool, addr: &str) -> GroupStats {
        GroupStats {
            count,
            addrs: [addr.to_owned()].into_iter().collect(),
            unsub: if unsub {
                ["https://u".to_owned()].into_iter().collect()
            } else {
                BTreeSet::new()
            },
            ..Default::default()
        }
    }

    #[test]
    fn recommendations_follow_python_heuristics() {
        assert_eq!(
            recommend("x.com", &stats(10, true, "a@x.com")).0,
            "unsubscribe_and_purge"
        );
        assert_eq!(
            recommend("x.com", &stats(9, true, "a@x.com")).0,
            "unsubscribe"
        );
        assert_eq!(
            recommend("x.com", &stats(5, false, "noreply@x.com")).0,
            "review_delete"
        );
        assert_eq!(
            recommend("x.com", &stats(4, false, "Notify@x.com")).0,
            "review"
        );
        assert_eq!(
            recommend("x.com", &stats(10, false, "bob@x.com")).0,
            "archive"
        );
        assert_eq!(recommend("x.com", &stats(1, false, "bob@x.com")).0, "keep");
    }
}
