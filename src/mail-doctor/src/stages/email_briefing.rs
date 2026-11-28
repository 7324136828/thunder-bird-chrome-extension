//! Create a human-readable inventory of the recent emails being audited
//! (port of `services/stages/email_briefing.py`).
//!
//! Writes `report/recent_emails.csv` and `report/email_briefing.md`.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Duration, FixedOffset, Utc};

use super::csv_safety::{self, Cell};
use super::eml_extract::{read_records, MessageRecord};
use super::LogFn;
use crate::cancellation::check_cancel;
use crate::pipeline::PipelineError;

/// Maximum number of messages listed in the Markdown briefing.
pub const BRIEFING_PREVIEW_LIMIT: usize = 200;

/// `email_briefing._date`: `datetime.fromisoformat(value)` (naive values are UTC).
fn parse_sent(value: Option<&str>) -> Option<DateTime<Utc>> {
    let value = value.filter(|v| !v.is_empty())?;
    if let Ok(parsed) = DateTime::<FixedOffset>::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f"))
        .ok()
        .map(|naive| naive.and_utc())
}

fn or_default<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

/// Run the stage; returns the number of messages included.
pub fn run(
    messages_path: &Path,
    report_dir: &Path,
    days: Option<i64>,
    log: &mut LogFn<'_>,
) -> Result<usize, PipelineError> {
    let cutoff = match days.filter(|d| *d != 0) {
        None => None,
        Some(days) => {
            let delta = Duration::try_days(days)
                .ok_or_else(|| PipelineError::Failed("date value out of range".into()))?;
            Some(
                Utc::now()
                    .checked_sub_signed(delta)
                    .ok_or_else(|| PipelineError::Failed("date value out of range".into()))?,
            )
        }
    };

    let mut records: Vec<(MessageRecord, Option<DateTime<Utc>>)> = Vec::new();
    for record in read_records(messages_path)? {
        check_cancel()?;
        let sent = parse_sent(record.date.as_deref());
        if let (Some(cutoff), Some(sent)) = (cutoff, sent) {
            if sent < cutoff {
                continue;
            }
        }
        records.push((record, sent));
    }
    // Stable sort, newest first; undated messages sort as datetime.min.
    records.sort_by(|a, b| {
        b.1.unwrap_or(DateTime::<Utc>::MIN_UTC)
            .cmp(&a.1.unwrap_or(DateTime::<Utc>::MIN_UTC))
    });
    fs::create_dir_all(report_dir)?;

    let mut writer = csv_safety::writer(Vec::new());
    writer.writerow(
        ["date", "from", "sender_group", "subject", "snippet"]
            .into_iter()
            .map(Cell::from)
            .collect(),
    )?;
    for (item, _) in &records {
        check_cancel()?;
        let sender_group = item.sender_group.as_deref().unwrap_or("");
        writer.writerow(vec![
            item.date.clone().unwrap_or_default().into(),
            or_default(or_default(&item.from_name, &item.from_addr), "(unknown)").into(),
            or_default(sender_group, "(unknown)").into(),
            or_default(&item.subject, "(no subject)").into(),
            item.snippet.as_str().into(),
        ])?;
    }
    fs::write(report_dir.join("recent_emails.csv"), writer.into_inner())?;

    // Counter(...) in first-seen order, then most_common(10) (stable by count).
    let mut senders: Vec<(String, usize)> = Vec::new();
    let mut sender_positions: HashMap<String, usize> = HashMap::new();
    for (item, _) in &records {
        let key = or_default(item.sender_group.as_deref().unwrap_or(""), "(unknown)").to_owned();
        match sender_positions.get(&key) {
            Some(&index) => senders[index].1 += 1,
            None => {
                sender_positions.insert(key.clone(), senders.len());
                senders.push((key, 1));
            }
        }
    }
    let mut by_day: Vec<(String, Vec<&MessageRecord>)> = Vec::new();
    let mut day_positions: HashMap<String, usize> = HashMap::new();
    for (item, sent) in &records {
        check_cancel()?;
        let key = sent.map_or_else(
            || "Unknown date".to_owned(),
            |s| s.date_naive().format("%Y-%m-%d").to_string(),
        );
        match day_positions.get(&key) {
            Some(&index) => by_day[index].1.push(item),
            None => {
                day_positions.insert(key.clone(), by_day.len());
                by_day.push((key, vec![item]));
            }
        }
    }

    let title = match days.filter(|d| *d != 0) {
        Some(days) => format!(
            "Email briefing — last {days} day{}",
            if days != 1 { "s" } else { "" }
        ),
        None => "Email briefing".to_owned(),
    };
    let mut lines = vec![
        format!("# {title}"),
        String::new(),
        format!("{} messages are included.", records.len()),
        String::new(),
    ];
    if !senders.is_empty() {
        lines.push("## Most active senders".into());
        lines.push(String::new());
        let mut ranked = senders.clone();
        ranked.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        lines.extend(
            ranked
                .iter()
                .take(10)
                .map(|(sender, count)| format!("- {sender}: {count}")),
        );
        lines.push(String::new());
    }
    lines.push("## What arrived".into());
    lines.push(String::new());
    let mut shown = 0usize;
    by_day.sort_by(|a, b| b.0.cmp(&a.0));
    for (day, items) in &by_day {
        check_cancel()?;
        lines.push(format!("### {day}"));
        lines.push(String::new());
        for item in items {
            check_cancel()?;
            let sender = or_default(
                or_default(&item.from_name, &item.from_addr),
                "Unknown sender",
            );
            let subject = or_default(&item.subject, "(no subject)");
            let snippet = or_default(&item.snippet, "No plain-text preview available.");
            lines.push(format!("- **{subject}** — {sender}"));
            lines.push(format!("  {snippet}"));
            shown += 1;
            if shown >= BRIEFING_PREVIEW_LIMIT {
                lines.push(String::new());
                lines.push(
                    "_The briefing preview is limited to 200 messages; see `recent_emails.csv` for all rows._".into(),
                );
                break;
            }
        }
        lines.push(String::new());
        if shown >= BRIEFING_PREVIEW_LIMIT {
            break;
        }
    }
    fs::write(report_dir.join("email_briefing.md"), lines.join("\n"))?;
    log(format!(
        "Created recent-email briefing for {} messages",
        records.len()
    ))?;
    Ok(records.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_records(dir: &Path, records: &[MessageRecord]) -> std::path::PathBuf {
        let path = dir.join("grouped.jsonl");
        let text: String = records.iter().map(|r| r.to_json().dumps() + "\n").collect();
        fs::write(&path, text).unwrap();
        path
    }

    fn rec(subject: &str, date: Option<String>) -> MessageRecord {
        MessageRecord {
            subject: subject.into(),
            date,
            from_addr: "a@b.com".into(),
            sender_group: Some("b.com".into()),
            ..Default::default()
        }
    }

    #[test]
    fn days_window_excludes_old_messages_but_keeps_undated_ones() {
        let dir = tempfile::tempdir().unwrap();
        let recent = (Utc::now() - Duration::days(1))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string();
        let path = write_records(
            dir.path(),
            &[
                rec("old", Some("2001-01-01T00:00:00+00:00".into())),
                rec("recent", Some(recent)),
                rec("undated", None),
            ],
        );
        let mut log = |_: String| Ok(());
        let count = run(&path, dir.path(), Some(7), &mut log).unwrap();
        assert_eq!(count, 2);
        let md = fs::read_to_string(dir.path().join("email_briefing.md")).unwrap();
        assert!(md.starts_with("# Email briefing — last 7 days\n\n2 messages are included."));
        assert!(md.contains("**recent**") && md.contains("**undated**") && !md.contains("**old**"));
        let one = run(&path, dir.path(), Some(1), &mut log).unwrap();
        assert!(one <= 2);
        assert!(fs::read_to_string(dir.path().join("email_briefing.md"))
            .unwrap()
            .starts_with("# Email briefing — last 1 day\n"));
    }

    #[test]
    fn preview_is_capped_at_200_messages() {
        let dir = tempfile::tempdir().unwrap();
        let records: Vec<MessageRecord> = (0..205).map(|i| rec(&format!("m{i}"), None)).collect();
        let path = write_records(dir.path(), &records);
        let mut log = |_: String| Ok(());
        run(&path, dir.path(), None, &mut log).unwrap();
        let md = fs::read_to_string(dir.path().join("email_briefing.md")).unwrap();
        assert_eq!(md.matches("- **m").count(), 200);
        assert!(md.contains("_The briefing preview is limited to 200 messages"));
        let csv = fs::read_to_string(dir.path().join("recent_emails.csv")).unwrap();
        assert_eq!(csv.lines().count(), 206);
    }
}
