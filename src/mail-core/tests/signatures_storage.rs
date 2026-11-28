//! `mail_core::signatures` storage functions (the `save_signature` /
//! `load_signature` / `signature_image` halves of tests/test_signatures.py
//! that do not need HTTP), using a scoped `settings.json`.

use mail_core::send_uploads::MessageFile;
use mail_core::settings::scoped_settings_path;
use mail_core::signatures::{self, load_signature, save_signature, signature_image};
use mail_core::MailError;
use serde_json::json;

fn png_chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
    chunk
}

fn png() -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    data.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
    data.extend(png_chunk(
        b"IDAT",
        b"x\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff",
    ));
    data.extend(png_chunk(b"IEND", b""));
    data
}

fn detail(error: MailError) -> (u16, String) {
    (error.status(), error.to_string())
}

#[test]
fn save_load_and_serve_round_trip() {
    let temporary = tempfile::tempdir().unwrap();
    let settings = temporary.path().join("settings.json");
    let _scope = scoped_settings_path(&settings);
    assert_eq!(
        serde_json::to_value(load_signature(" User@Example.com ").unwrap()).unwrap(),
        json!({"account": "user@example.com", "text": "", "multipart-path": {}, "images": []})
    );
    assert!(!settings.exists(), "loading never creates settings");
    let image = MessageFile::inline("logo", "image/x-png", png(), "Logo.1");
    let saved = save_signature(
        "user@example.com",
        "<div title=\"T\">Hi<img src=\"cid:Logo.1\" alt=\"L\"></div>",
        &[image],
    )
    .unwrap();
    assert_eq!(
        saved.text,
        "<div title=\"T\">Hi<img src=\"cid:Logo.1\" alt=\"L\"></div>"
    );
    assert_eq!(saved.images[0].filename, "Logo.1.png");
    let relative = &saved.multipart_path[0].1;
    let revision = relative.split('/').nth(2).unwrap();
    assert_eq!(
        signature_image("USER@example.com", "Logo.1", revision).unwrap(),
        (png(), "image/png")
    );
    assert_eq!(
        signature_image("user@example.com", "Logo.1", "").unwrap().1,
        "image/png"
    );
    assert_eq!(load_signature("user@example.com").unwrap(), saved);
}

#[test]
fn value_errors_are_422_and_identifiers_400_or_404() {
    let temporary = tempfile::tempdir().unwrap();
    let _scope = scoped_settings_path(temporary.path().join("settings.json"));
    let inline = |cid: &str| MessageFile::inline("a.png", "image/png", png(), cid);
    assert_eq!(
        detail(
            save_signature(
                "a@example.com",
                "<img src=\"cid:a\">",
                &[MessageFile::attachment("a.png", "image/png", png())]
            )
            .unwrap_err()
        ),
        (
            422,
            "Every inline image must have a matching cid reference in the HTML message".into()
        )
    );
    assert_eq!(
        detail(
            save_signature("a@example.com", "<img src=\"cid:a@b\">", &[inline("a@b")]).unwrap_err()
        ),
        (
            422,
            "Every inline image must have a matching cid reference in the HTML message".into()
        )
    );
    assert_eq!(
        detail(save_signature("a@example.com", "\u{7f}", &[]).unwrap_err()),
        (
            422,
            "Signature must be valid Unicode without control characters".into()
        )
    );
    assert_eq!(
        detail(signature_image("a@example.com", "nul", "").unwrap_err()),
        (400, "Invalid signature image identifier".into())
    );
    assert_eq!(
        detail(signature_image("a@example.com", "a", "ABC").unwrap_err()),
        (400, "Invalid signature image identifier".into())
    );
    assert_eq!(
        detail(signature_image("a@example.com", "a", "").unwrap_err()),
        (404, "Signature image not found".into())
    );
}

#[test]
fn corrupt_settings_are_settings_errors() {
    let temporary = tempfile::tempdir().unwrap();
    let settings = temporary.path().join("settings.json");
    let _scope = scoped_settings_path(&settings);
    let cases = [
        (
            json!({"emails_signatures": []}),
            "Invalid emails_signatures in settings",
        ),
        (
            json!({"emails_signatures": {"a@example.com": "x"}}),
            "Invalid saved email signature",
        ),
        (
            json!({"emails_signatures": {"a@example.com": {"text": "", "multipart-path": {}, "x": 1}}}),
            "Invalid saved email signature",
        ),
        (
            json!({"emails_signatures": {"a@example.com": {"text": 5, "multipart-path": {}}}}),
            "Invalid saved email signature: Signature text must be rich HTML",
        ),
        (
            json!({"emails_signatures": {"a@example.com": {"text": "<img src=\"cid:a\">", "multipart-path": {}}}}),
            "Saved signature images do not match its HTML",
        ),
        (
            json!({"emails_signatures": {"a@example.com": {"text": "<img src=\"cid:a\">", "multipart-path": {"a": 1}}}}),
            "Invalid signature image path",
        ),
    ];
    for (values, message) in cases {
        std::fs::write(&settings, values.to_string()).unwrap();
        assert_eq!(
            detail(load_signature("a@example.com").unwrap_err()),
            (500, message.to_string()),
            "{values}"
        );
    }
    // Legacy text that cannot be validated is not migrated.
    std::fs::write(
        &settings,
        json!({"signature": "x".repeat(20_000)}).to_string(),
    )
    .unwrap();
    assert_eq!(
        detail(load_signature("a@example.com").unwrap_err()),
        (500, "Cannot migrate the existing email signature".into())
    );
}

#[test]
fn account_roots_are_hashed_per_normalized_account() {
    let path = std::path::Path::new("settings.json");
    let a = signatures::account_root_for(path, " A@Example.com");
    let b = signatures::account_root_for(path, "a@example.com");
    assert_eq!(a, b);
    assert_eq!(a.file_name().unwrap().len(), 64);
    assert_eq!(a.parent().unwrap().file_name().unwrap(), "signature-images");
}
