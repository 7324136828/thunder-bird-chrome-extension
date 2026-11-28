//! Stage 2 - sender normalization ("rebrand")
//! (port of `services/stages/rebrand.py`).
//!
//! Rolls addresses like `no-reply@mail.example.com` and `news@example.com` up
//! into a single `example.com` sender group, applying optional user-supplied
//! `aliases.json` files from the inputs directory.
//!
//! `aliases.json` accepts either shape:
//! `{"example.com": ["mail.example.com", "news.example.com"]}` or
//! `{"mail.example.com": "example.com"}`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use super::eml_extract::{file_name, read_records, rglob_sorted};
use super::pyjson::Json;
use super::{value_error, LogFn};
use crate::cancellation::check_cancel;
use crate::pipeline::PipelineError;

/// Common second-level public suffixes where three labels are needed.
pub const SECOND_LEVEL_TLDS: [&str; 23] = [
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "or.jp", "co.kr", "co.in", "co.za", "com.br", "com.mx", "com.ar", "com.co", "com.cn", "com.hk",
    "com.sg", "com.tw", "com.tr",
];

/// `rebrand.canonical_domain`.
pub fn canonical_domain(domain: &str) -> String {
    let lower = domain.to_lowercase();
    let labels: Vec<&str> = lower
        .trim_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    let suffix2 = labels[labels.len() - 2..].join(".");
    if SECOND_LEVEL_TLDS.contains(&suffix2.as_str()) {
        return labels[labels.len() - 3..].join(".");
    }
    suffix2
}

fn char_len(value: &str) -> usize {
    value.chars().count()
}

/// Insertion-ordered alias map (`dict[str, str]` in Python).
#[derive(Debug, Default)]
struct AliasMap {
    entries: std::collections::HashMap<String, String>,
}

impl AliasMap {
    fn insert(&mut self, domain: String, group: String) {
        self.entries.insert(domain, group);
    }

    fn get(&self, domain: &str) -> Option<&str> {
        self.entries.get(domain).map(String::as_str)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// `rebrand._load_aliases`.
fn load_aliases(inputs_dir: &Path, log: &mut LogFn<'_>) -> Result<AliasMap, PipelineError> {
    let mut alias_map = AliasMap::default();
    let mut entries = 0usize;
    let mut add =
        |alias_map: &mut AliasMap, domain: String, group: String| -> Result<(), PipelineError> {
            if char_len(&domain) > 253 || char_len(&group) > 320 {
                return Err(value_error(
                "Sender aliases exceed the maximum domain or group length (253 / 320 characters)",
            ));
            }
            entries += 1;
            if entries > 10000 {
                return Err(value_error(
                    "Sender aliases exceed the maximum of 10000 entries",
                ));
            }
            alias_map.insert(domain.to_lowercase(), group.to_lowercase());
            Ok(())
        };

    for path in rglob_sorted(inputs_dir, |name| name == "aliases.json") {
        check_cancel()?;
        let parsed = fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| Json::loads_file_bytes(&bytes));
        let data = match parsed {
            Ok(data) => data,
            Err(error) => {
                log(format!(
                    "Ignoring invalid aliases file {}: {}",
                    file_name(&path),
                    error
                ))?;
                continue;
            }
        };
        let Json::Object(pairs) = data else {
            continue;
        };
        if pairs.len() > 10000 {
            return Err(value_error(
                "Sender aliases exceed the maximum of 10000 entries",
            ));
        }
        for (key, value) in pairs {
            check_cancel()?;
            match value {
                Json::Array(aliases) => {
                    if char_len(&key) > 320 || aliases.len() > 10000 {
                        return Err(value_error(
                            "Sender aliases exceed the maximum group length or entry count",
                        ));
                    }
                    for alias in aliases {
                        check_cancel()?;
                        add(&mut alias_map, alias.py_str(), key.clone())?;
                    }
                }
                other => add(&mut alias_map, key, other.py_str())?,
            }
        }
    }
    Ok(alias_map)
}

/// Run the stage; returns the number of records written.
pub fn run(
    inputs_dir: &Path,
    messages_path: &Path,
    out_path: &Path,
    aliases_out: &Path,
    log: &mut LogFn<'_>,
) -> Result<usize, PipelineError> {
    let alias_map = load_aliases(inputs_dir, log)?;
    let mut observed: BTreeMap<String, String> = BTreeMap::new();
    let mut count = 0usize;

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let records = read_records(messages_path)?;
    let mut output = std::io::BufWriter::new(fs::File::create(out_path)?);
    for mut rec in records {
        check_cancel()?;
        let domain = rec.from_domain.clone();
        let canonical = canonical_domain(&domain);
        let group = alias_map
            .get(&domain)
            .filter(|g| !g.is_empty())
            .or_else(|| alias_map.get(&canonical).filter(|g| !g.is_empty()))
            .map(str::to_owned)
            .unwrap_or_else(|| canonical.clone());
        rec.sender_domain = Some(domain.clone());
        rec.sender_group = Some(if !group.is_empty() {
            group.clone()
        } else if !domain.is_empty() {
            domain.clone()
        } else {
            "(unknown)".to_owned()
        });
        if !domain.is_empty() {
            observed.insert(domain, group);
        }
        output.write_all(rec.to_json().dumps().as_bytes())?;
        output.write_all(b"\n")?;
        count += 1;
    }
    output.flush()?;

    if let Some(parent) = aliases_out.parent() {
        fs::create_dir_all(parent)?;
    }
    let observed_json = Json::object(
        observed
            .into_iter()
            .map(|(domain, group)| (domain, Json::Str(group))),
    );
    fs::write(aliases_out, observed_json.dumps_indent())?;
    if alias_map.len() > 0 {
        log(format!("Applied {} custom sender aliases", alias_map.len()))?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_domain_rolls_up_subdomains() {
        assert_eq!(canonical_domain("mail.example.com"), "example.com");
        assert_eq!(
            canonical_domain("Mailer.Shop.Example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(canonical_domain("example.com"), "example.com");
        assert_eq!(canonical_domain(".a..b.c."), "b.c");
        assert_eq!(canonical_domain(""), "");
        assert_eq!(canonical_domain("co.uk"), "co.uk");
        assert_eq!(canonical_domain("x.co.uk"), "x.co.uk");
    }
}
