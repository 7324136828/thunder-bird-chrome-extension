//! Stage 3 - aggregate grouped messages into inbox summary reports
//! (port of `services/stages/inbox_summary.py`).
//!
//! Produces under `outputs/report/`:
//! * `senders.csv`     - per sender-group totals ranked by message count
//! * `unsubscribe.csv` - sender groups that advertise List-Unsubscribe links
//! * `summary.json`    - machine-readable totals
//! * `summary.md`      - human-readable summary

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use super::csv_safety::{self, Cell};
use super::eml_extract::{read_records, MessageRecord};
use super::pyjson::{thousands, Json};
use super::LogFn;
use crate::cancellation::check_cancel;
use crate::pipeline::PipelineError;

pub const TOP_N_JSON: usize = 10;
pub const TOP_N_MD: usize = 20;

/// Per sender-group aggregate (`inbox_summary._aggregate` dict values).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GroupStats {
    pub count: i64,
    pub size: i64,
    pub addrs: BTreeSet<String>,
    pub first: Option<String>,
    pub last: Option<String>,
    pub unsub: BTreeSet<String>,
    pub subjects: Vec<String>,
}

/// `inbox_summary._iter_records`.
pub fn iter_records(path: &Path) -> Result<Vec<MessageRecord>, PipelineError> {
    read_records(path)
}

/// `inbox_summary._aggregate`, returned in first-seen order.
pub fn aggregate(records: &[MessageRecord]) -> Result<Vec<(String, GroupStats)>, PipelineError> {
    let mut groups: Vec<(String, GroupStats)> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    for rec in records {
        check_cancel()?;
        let key = rec
            .sender_group
            .clone()
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| "(unknown)".to_owned());
        let index = match positions.get(&key) {
            Some(&index) => index,
            None => {
                positions.insert(key.clone(), groups.len());
                groups.push((key, GroupStats::default()));
                groups.len() - 1
            }
        };
        let g = &mut groups[index].1;
        g.count += 1;
        g.size += rec.size_bytes;
        if !rec.from_addr.is_empty() {
            g.addrs.insert(rec.from_addr.clone());
        }
        if let Some(date) = rec.date.as_deref().filter(|d| !d.is_empty()) {
            if g.first.as_deref().is_none_or(|first| date < first) {
                g.first = Some(date.to_owned());
            }
            if g.last.as_deref().is_none_or(|last| date > last) {
                g.last = Some(date.to_owned());
            }
        }
        if !rec.list_unsubscribe.is_empty() {
            g.unsub.insert(rec.list_unsubscribe.clone());
        }
        if !rec.subject.is_empty() && g.subjects.len() < 3 {
            g.subjects.push(rec.subject.clone());
        }
    }
    Ok(groups)
}

/// `sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0]))`.
pub fn rank(mut groups: Vec<(String, GroupStats)>) -> Vec<(String, GroupStats)> {
    groups.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
    groups
}

/// `datetime.now(timezone.utc).isoformat()`.
pub fn utc_now_iso() -> String {
    let now = chrono::Utc::now();
    let micros = now.timestamp_subsec_micros();
    if micros == 0 {
        format!("{}+00:00", now.format("%Y-%m-%dT%H:%M:%S"))
    } else {
        format!("{}.{:06}+00:00", now.format("%Y-%m-%dT%H:%M:%S"), micros)
    }
}

fn yes_no(flag: bool) -> &'static str {
    if flag {
        "yes"
    } else {
        "no"
    }
}

/// Python `value[:n]` on code points.
fn prefix(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

/// Run the stage; returns the `summary.json` payload.
pub fn run(
    grouped_path: &Path,
    report_dir: &Path,
    log: &mut LogFn<'_>,
) -> Result<Json, PipelineError> {
    let records = iter_records(grouped_path)?;
    let groups = aggregate(&records)?;
    let group_count = groups.len();
    let senders_with_unsubscribe = groups.iter().filter(|(_, g)| !g.unsub.is_empty()).count();
    let ranked = rank(groups);

    fs::create_dir_all(report_dir)?;

    let mut senders = csv_safety::writer(Vec::new());
    senders.writerow(
        [
            "rank",
            "sender_group",
            "message_count",
            "total_size_bytes",
            "distinct_addresses",
            "first_seen",
            "last_seen",
            "unsubscribe_available",
            "example_subjects",
        ]
        .into_iter()
        .map(Cell::from)
        .collect(),
    )?;
    for (rank, (group, g)) in ranked.iter().enumerate() {
        check_cancel()?;
        senders.writerow(vec![
            Cell::from(rank + 1),
            group.as_str().into(),
            g.count.into(),
            g.size.into(),
            g.addrs.len().into(),
            g.first.clone().unwrap_or_default().into(),
            g.last.clone().unwrap_or_default().into(),
            yes_no(!g.unsub.is_empty()).into(),
            g.subjects.join(" | ").into(),
        ])?;
    }
    fs::write(report_dir.join("senders.csv"), senders.into_inner())?;

    let mut unsubscribe = csv_safety::writer(Vec::new());
    unsubscribe.writerow(
        [
            "sender_group",
            "addresses",
            "message_count",
            "unsubscribe_link",
        ]
        .into_iter()
        .map(Cell::from)
        .collect(),
    )?;
    for (group, g) in &ranked {
        check_cancel()?;
        if let Some(link) = g.unsub.iter().next() {
            let addresses: Vec<&str> = g.addrs.iter().map(String::as_str).collect();
            unsubscribe.writerow(vec![
                group.as_str().into(),
                addresses.join(";").into(),
                g.count.into(),
                link.as_str().into(),
            ])?;
        }
    }
    fs::write(report_dir.join("unsubscribe.csv"), unsubscribe.into_inner())?;

    let dates: Vec<&str> = records
        .iter()
        .filter_map(|r| r.date.as_deref())
        .filter(|d| !d.is_empty())
        .collect();
    let first = dates.iter().min().map(|d| d.to_string());
    let last = dates.iter().max().map(|d| d.to_string());
    let unique_domains: HashSet<&str> = records
        .iter()
        .filter_map(|r| r.sender_domain.as_deref())
        .filter(|d| !d.is_empty())
        .collect();
    let total_size: i64 = records.iter().map(|r| r.size_bytes).sum();
    let messages_with_unsubscribe = records
        .iter()
        .filter(|r| !r.list_unsubscribe.is_empty())
        .count();

    let summary = Json::object([
        ("generated_at", Json::Str(utc_now_iso())),
        ("total_messages", Json::Int(records.len() as i64)),
        ("unique_senders", Json::Int(group_count as i64)),
        ("unique_domains", Json::Int(unique_domains.len() as i64)),
        (
            "date_range",
            Json::object([
                ("first", Json::opt_str(first.as_deref())),
                ("last", Json::opt_str(last.as_deref())),
            ]),
        ),
        ("total_size_bytes", Json::Int(total_size)),
        (
            "messages_with_unsubscribe",
            Json::Int(messages_with_unsubscribe as i64),
        ),
        (
            "senders_with_unsubscribe",
            Json::Int(senders_with_unsubscribe as i64),
        ),
        (
            "top_senders",
            Json::Array(
                ranked
                    .iter()
                    .take(TOP_N_JSON)
                    .map(|(group, g)| {
                        Json::object([
                            ("sender", Json::str(group)),
                            ("messages", Json::Int(g.count)),
                            ("size_bytes", Json::Int(g.size)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    fs::write(report_dir.join("summary.json"), summary.dumps_indent())?;

    let mut lines = vec![
        "# Inbox Summary".to_owned(),
        String::new(),
        format!("- **Messages analyzed:** {}", records.len()),
        format!("- **Unique sender groups:** {group_count}"),
        format!("- **Unique domains:** {}", unique_domains.len()),
        format!("- **Total size:** {} bytes", thousands(total_size)),
        format!("- **Messages with unsubscribe links:** {messages_with_unsubscribe}"),
        format!("- **Sender groups offering unsubscribe:** {senders_with_unsubscribe}"),
    ];
    if let Some(first) = &first {
        let last = last.as_deref().unwrap_or(first);
        lines.push(format!(
            "- **Date range:** {} to {}",
            prefix(first, 10),
            prefix(last, 10)
        ));
    }
    lines.extend(
        [
            "",
            "## Top senders",
            "",
            "| Rank | Sender | Messages | Size (bytes) | Unsubscribe |",
            "|---:|---|---:|---:|---|",
        ]
        .map(str::to_owned),
    );
    for (rank, (group, g)) in ranked.iter().take(TOP_N_MD).enumerate() {
        check_cancel()?;
        lines.push(format!(
            "| {} | {} | {} | {} | {} |",
            rank + 1,
            group,
            g.count,
            thousands(g.size),
            yes_no(!g.unsub.is_empty())
        ));
    }
    lines.extend(
        [
            "",
            "## Next steps",
            "",
            "See `inbox_cleanup_worklist.csv` for per-sender recommended actions and `inbox_audit.html` for the full interactive report.",
            "",
        ]
        .map(str::to_owned),
    );
    fs::write(report_dir.join("summary.md"), lines.join("\n"))?;

    log(format!(
        "Aggregated {} messages across {} sender groups",
        records.len(),
        group_count
    ))?;
    Ok(summary)
}
