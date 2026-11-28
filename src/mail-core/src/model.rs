//! Constants shared across modules (from `backend/settings.py` and `app/mail/schemas.py`).

pub const APP_NAME: &str = "webmail-thunderbird";
pub const MAIL_SERVERS_FILENAME: &str = "mail-servers.json";
pub const DEFAULT_MESSAGES_PER_PAGE: u32 = 5;
pub const MAX_MESSAGES_PER_PAGE: u32 = 200;
pub const DEFAULT_LOCAL_AI_MODEL: &str = "llama3.2:latest";
pub const MAX_SIGNATURE_LENGTH: usize = 10_000;
pub const MAX_EXPIRATION_DAYS: i64 = 365_000;

/// Every email has exactly one of these categories.
pub const EMAIL_CATEGORIES: [&str; 5] = [
    "marketing",
    "transactional",
    "updates",
    "verification",
    "uncategorized",
];

pub fn is_category(value: &str) -> bool {
    EMAIL_CATEGORIES.contains(&value)
}

/// `DEFAULT_CATEGORY_EXPIRATION_DAYS`: 30 days, except uncategorized = never (-1).
pub fn default_category_expiration_days() -> std::collections::BTreeMap<String, i64> {
    EMAIL_CATEGORIES
        .iter()
        .map(|c| (c.to_string(), if *c == "uncategorized" { -1 } else { 30 }))
        .collect()
}

/// Negative lifetimes mean never; reject coercion and impractical durations.
/// Mirrors Python's `type(value) is not int` check: bools, floats and strings are rejected.
pub fn normalize_expiration_days(value: &serde_json::Value) -> Result<i64, String> {
    let error =
        || format!("Expiration must be an integer no greater than {MAX_EXPIRATION_DAYS} days");
    let n = match value {
        serde_json::Value::Number(n) => n.as_i64().ok_or_else(error)?,
        _ => return Err(error()),
    };
    if n > MAX_EXPIRATION_DAYS {
        return Err(error());
    }
    Ok(if n < 0 { -1 } else { n })
}

/// Exactly the five categories, each a valid expiration.
pub fn validate_category_expiration_days(
    value: &serde_json::Value,
) -> Result<std::collections::BTreeMap<String, i64>, String> {
    let object = value
        .as_object()
        .filter(|o| {
            o.len() == EMAIL_CATEGORIES.len() && EMAIL_CATEGORIES.iter().all(|c| o.contains_key(*c))
        })
        .ok_or_else(|| {
            "Category expiration must include exactly the five email categories".to_string()
        })?;
    EMAIL_CATEGORIES
        .iter()
        .map(|c| Ok((c.to_string(), normalize_expiration_days(&object[*c])?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn expiration_validation() {
        assert_eq!(normalize_expiration_days(&json!(-5)), Ok(-1));
        assert_eq!(normalize_expiration_days(&json!(0)), Ok(0));
        assert!(normalize_expiration_days(&json!(365_001)).is_err());
        assert!(normalize_expiration_days(&json!(true)).is_err());
        assert!(normalize_expiration_days(&json!(1.5)).is_err());
        assert!(normalize_expiration_days(&json!("3")).is_err());
        let ok = json!({"marketing":1,"transactional":2,"updates":3,"verification":4,"uncategorized":-9});
        assert_eq!(
            validate_category_expiration_days(&ok).unwrap()["uncategorized"],
            -1
        );
        assert!(validate_category_expiration_days(&json!({"marketing":1})).is_err());
        assert_eq!(default_category_expiration_days()["marketing"], 30);
    }
}
