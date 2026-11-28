//! Folder listing helpers (`_parse_folders`, `_sent_folder`,
//! `_new_sent_folder` of `imap_client.py`).

use mail_proto::imap::{CommandResponse, ListEntry};
use serde_json::{json, Value};

/// `_SPECIAL_FLAG_MAP`, in Python dict order.
const SPECIAL_FLAG_MAP: [(&str, &str); 8] = [
    ("\\inbox", "inbox"),
    ("\\sent", "sent"),
    ("\\drafts", "drafts"),
    ("\\trash", "trash"),
    ("\\junk", "junk"),
    ("\\archive", "archive"),
    ("\\all", "all"),
    ("\\flagged", "flagged"),
];

/// Names a conventional Sent folder may have (`_sent_folder` aliases).
const SENT_ALIASES: [&str; 5] = [
    "sent",
    "sent items",
    "sent mail",
    "sent messages",
    "sentmail",
];

/// One folder dict: `{"name", "delimiter", "flags", "special", "selectable"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Folder {
    pub name: String,
    pub delimiter: String,
    pub flags: Vec<String>,
    pub special: String,
    pub selectable: bool,
}

impl Folder {
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "delimiter": self.delimiter,
            "flags": self.flags,
            "special": self.special,
            "selectable": self.selectable,
        })
    }

    fn from_entry(entry: ListEntry) -> Self {
        let lowered: Vec<String> = entry.attributes.iter().map(|f| f.to_lowercase()).collect();
        let special = SPECIAL_FLAG_MAP
            .iter()
            .find(|(flag, _)| lowered.iter().any(|l| l == flag))
            .map(|(_, kind)| (*kind).to_string())
            .unwrap_or_default();
        let name = entry.name;
        let special = if special.is_empty() && name.to_uppercase() == "INBOX" {
            "inbox".to_string()
        } else {
            special
        };
        let selectable = !lowered
            .iter()
            .any(|l| l == "\\noselect" || l == "\\nonexistent");
        Folder {
            delimiter: entry.delimiter.unwrap_or_default(),
            flags: entry.attributes,
            special,
            selectable,
            name,
        }
    }
}

/// `_parse_folders(data)`: every parsable untagged LIST response, INBOX
/// first, then by lowercased name. Malformed lines are skipped.
pub(crate) fn parse_folders(response: &CommandResponse) -> Vec<Folder> {
    let mut folders: Vec<Folder> = response
        .untagged_of("LIST")
        .filter_map(|item| item.list_entry().ok())
        .map(Folder::from_entry)
        .collect();
    folders.sort_by_cached_key(|folder| (folder.special != "inbox", folder.name.to_lowercase()));
    folders
}

/// `str.casefold()` closely enough for comparing against ASCII aliases.
fn casefold(value: &str) -> String {
    value
        .to_lowercase()
        .replace('\u{17f}', "s")
        .replace('ß', "ss")
}

/// `_sent_folder(folders)`: a selectable `\Sent` folder, else the best
/// conventional name (root level first, then below INBOX, then elsewhere).
pub(crate) fn sent_folder(folders: &[Folder]) -> Option<String> {
    let selectable: Vec<&Folder> = folders.iter().filter(|f| f.selectable).collect();
    if let Some(folder) = selectable
        .iter()
        .find(|f| f.flags.iter().any(|flag| flag.to_lowercase() == "\\sent"))
    {
        return Some(folder.name.clone());
    }
    let mut matches: Vec<(u8, usize, String)> = Vec::new();
    for folder in selectable {
        let (name, delimiter) = (&folder.name, &folder.delimiter);
        let leaf = if delimiter.is_empty() {
            name.as_str()
        } else {
            name.rsplit(delimiter.as_str()).next().unwrap_or(name)
        };
        let folded = casefold(leaf);
        if let Some(index) = SENT_ALIASES.iter().position(|alias| *alias == folded) {
            let hierarchy = if name == leaf {
                0
            } else if name
                .to_uppercase()
                .starts_with(&format!("INBOX{delimiter}"))
            {
                1
            } else {
                2
            };
            matches.push((hierarchy, index, name.clone()));
        }
    }
    matches.into_iter().min().map(|(_, _, name)| name)
}

/// `_new_sent_folder(folders)`: `INBOX<delim>Sent` when every other folder
/// lives below INBOX, else `Sent`.
pub(crate) fn new_sent_folder(folders: &[Folder]) -> String {
    for inbox in folders {
        if inbox.name.to_uppercase() == "INBOX" && !inbox.delimiter.is_empty() {
            let prefix = format!("{}{}", inbox.name, inbox.delimiter);
            let upper_prefix = prefix.to_uppercase();
            let children: Vec<&Folder> = folders
                .iter()
                .filter(|f| f.name.to_uppercase() != "INBOX")
                .collect();
            if !children.is_empty()
                && children
                    .iter()
                    .all(|f| f.name.to_uppercase().starts_with(&upper_prefix))
            {
                return prefix + "Sent";
            }
        }
    }
    "Sent".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, delimiter: &str, flags: &[&str]) -> Folder {
        let lowered: Vec<String> = flags.iter().map(|f| f.to_lowercase()).collect();
        Folder {
            name: name.into(),
            delimiter: delimiter.into(),
            flags: flags.iter().map(|f| f.to_string()).collect(),
            special: String::new(),
            selectable: !lowered.iter().any(|l| l == "\\noselect"),
        }
    }

    #[test]
    fn sent_folder_prefers_attribute_then_hierarchy_then_alias_order() {
        assert_eq!(
            sent_folder(&[
                folder("Sent", "/", &[]),
                folder("[Gmail]/Sent Mail", "/", &["\\Sent"])
            ]),
            Some("[Gmail]/Sent Mail".into())
        );
        assert_eq!(
            sent_folder(&[
                folder("INBOX/Sent", "/", &[]),
                folder("Sent Items", "/", &[])
            ]),
            Some("Sent Items".into())
        );
        assert_eq!(
            sent_folder(&[
                folder("Other/Sent", "/", &[]),
                folder("INBOX.Sent", ".", &[])
            ]),
            Some("INBOX.Sent".into())
        );
        assert_eq!(
            sent_folder(&[folder("Sent Items", "/", &["\\Sent", "\\Noselect"])]),
            None
        );
        assert_eq!(
            sent_folder(&[folder("SENTMAIL", "", &[])]),
            Some("SENTMAIL".into())
        );
    }

    #[test]
    fn new_sent_folder_follows_inbox_namespace() {
        assert_eq!(new_sent_folder(&[folder("INBOX", "/", &[])]), "Sent");
        assert_eq!(
            new_sent_folder(&[folder("INBOX", ".", &[]), folder("INBOX.Drafts", ".", &[])]),
            "INBOX.Sent"
        );
        assert_eq!(
            new_sent_folder(&[folder("INBOX", ".", &[]), folder("Drafts", ".", &[])]),
            "Sent"
        );
        assert_eq!(
            new_sent_folder(&[folder("INBOX", "", &[]), folder("INBOXDrafts", "", &[])]),
            "Sent"
        );
    }
}
