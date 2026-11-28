//! Stage 5 - render a standalone HTML audit report (`inbox_audit.html`)
//! (port of `services/stages/gen_report.py`).

use std::fs;
use std::path::{Path, PathBuf};

use super::eml_extract::file_name;
use super::pyjson::{thousands, Json};
use super::{json_error, LogFn};
use crate::pipeline::PipelineError;

const CSS: &str = "
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
 margin:0;background:#f4f6f8;color:#1d2733}
header{background:#1f3a5f;color:#fff;padding:20px 32px}
header h1{margin:0;font-size:22px}
header p{margin:4px 0 0;opacity:.8;font-size:13px}
main{max-width:1100px;margin:24px auto;padding:0 20px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.card{background:#fff;border:1px solid #dde3ea;border-radius:8px;
 padding:14px 18px;min-width:150px;flex:1}
.card .num{font-size:24px;font-weight:700;color:#1f3a5f}
.card .lbl{font-size:12px;color:#5b6b7c;text-transform:uppercase;
 letter-spacing:.05em}
section{background:#fff;border:1px solid #dde3ea;border-radius:8px;
 padding:18px 22px;margin-bottom:20px}
h2{margin-top:0;font-size:17px;color:#1f3a5f}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #e6ebf0;
 vertical-align:top}
th{background:#eef2f6;font-size:12px;text-transform:uppercase;
 letter-spacing:.04em;color:#41556b}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
 font-weight:600;background:#e6ebf0}
.badge.unsubscribe_and_purge{background:#fde2e2;color:#a02222}
.badge.unsubscribe{background:#fff3d6;color:#8a6200}
.badge.review_delete{background:#ffe9d6;color:#964d00}
.badge.review{background:#e4ecfb;color:#2b4d8f}
.badge.archive{background:#e8e8f6;color:#4a4a8f}
.badge.keep{background:#ddf3e4;color:#1e6b3a}
footer{text-align:center;color:#8a97a5;font-size:12px;padding:20px}
";

/// Python `html.escape(text, quote=True)`.
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

/// `gen_report._e`: escape `str(value)`, with `None` rendered as "".
fn e(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(value) => html_escape(&value.py_str()),
    }
}

fn card(num: &str, label: &str) -> String {
    format!(
        "<div class=\"card\"><div class=\"num\">{}</div><div class=\"lbl\">{}</div></div>",
        html_escape(num),
        html_escape(label)
    )
}

/// `f"{value:,}"` for an integer JSON value.
fn grouped(value: Option<&Json>) -> String {
    match value {
        Some(Json::Int(i)) => thousands(*i),
        Some(Json::UInt(u)) => thousands(*u as i64),
        Some(other) => other.py_str(),
        None => "0".to_owned(),
    }
}

/// `dict.get(key, default)` as rendered by `_e` (`None` → "").
fn get_or(map: &Json, key: &str, default: &str) -> String {
    match map.get(key) {
        Some(Json::Null) => String::new(),
        Some(value) => value.py_str(),
        None => default.to_owned(),
    }
}

fn first10(value: Option<&Json>) -> String {
    match value {
        Some(Json::Str(s)) => s.chars().take(10).collect(),
        _ => String::new(),
    }
}

fn read_json(path: &Path) -> Result<Json, PipelineError> {
    Json::loads(&fs::read_to_string(path)?).map_err(json_error)
}

/// Run the stage; returns the written report path.
pub fn run(
    summary_path: &Path,
    worklist_path: &Path,
    out_path: &Path,
    log: &mut LogFn<'_>,
) -> Result<PathBuf, PipelineError> {
    let summary = read_json(summary_path)?;
    let worklist = read_json(worklist_path)?;

    let empty = Json::Object(Vec::new());
    let date_range = summary
        .get("date_range")
        .filter(|d| d.truthy())
        .unwrap_or(&empty);
    let cards = [
        card(&get_or(&summary, "total_messages", "0"), "Messages"),
        card(&get_or(&summary, "unique_senders", "0"), "Sender groups"),
        card(&get_or(&summary, "unique_domains", "0"), "Domains"),
        card(&grouped(summary.get("total_size_bytes")), "Total bytes"),
        card(
            &get_or(&summary, "senders_with_unsubscribe", "0"),
            "Unsubscribe-ready",
        ),
    ]
    .concat();

    let top_rows: String = match summary.get("top_senders") {
        Some(Json::Array(senders)) => senders
            .iter()
            .enumerate()
            .map(|(i, s)| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    i + 1,
                    e(s.get("sender")),
                    s.get("messages").map(Json::py_str).unwrap_or_default(),
                    grouped(s.get("size_bytes"))
                )
            })
            .collect(),
        _ => String::new(),
    };

    let wl_rows: String = match worklist.get("items") {
        Some(Json::Array(items)) => items
            .iter()
            .map(|it| {
                format!(
                    "<tr><td>{}</td><td><span class=\"badge {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    e(it.get("sender_group")),
                    e(it.get("recommended_action")),
                    e(it.get("recommended_action")),
                    it.get("message_count").map(Json::py_str).unwrap_or_default(),
                    grouped(it.get("total_size_bytes")),
                    if it.get("has_unsubscribe").is_some_and(Json::truthy) { "yes" } else { "no" },
                    e(it.get("reason")),
                )
            })
            .collect(),
        _ => String::new(),
    };

    let generated = html_escape(&get_or(&summary, "generated_at", ""));
    let first = html_escape(&first10(date_range.get("first")));
    let last = html_escape(&first10(date_range.get("last")));
    let page = format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Inbox Audit - email-doctor</title>
<style>{CSS}</style>
</head>
<body>
<header>
<h1>Inbox Audit Report</h1>
<p>Generated {generated} &middot;
{first} &rarr; {last}</p>
</header>
<main>
<div class=\"cards\">{cards}</div>
<section>
<h2>Top senders</h2>
<table><thead><tr><th>#</th><th>Sender</th><th>Messages</th><th>Bytes</th></tr></thead>
<tbody>{top_rows}</tbody></table>
</section>
<section>
<h2>Cleanup worklist</h2>
<table><thead><tr><th>Sender</th><th>Action</th><th>Messages</th><th>Bytes</th>
<th>Unsub</th><th>Reason</th></tr></thead>
<tbody>{wl_rows}</tbody></table>
</section>
</main>
<footer>Generated by email-doctor</footer>
</body>
</html>
"
    );
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, page)?;
    log(format!("HTML report written: {}", file_name(out_path)))?;
    Ok(out_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_python_html_escape() {
        assert_eq!(
            html_escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
    }
}
