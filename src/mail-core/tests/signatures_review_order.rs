//! Saved signature images keep their upload (insertion) order after a reload,
//! like Python's dict-backed `multipart-path` (serde_json `preserve_order`).

use mail_core::send_uploads::MessageFile;
use mail_core::settings::scoped_settings_path;
use mail_core::signatures::{load_signature, save_signature};

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

#[test]
fn image_order_survives_a_reload() {
    let temporary = tempfile::tempdir().unwrap();
    let _scope = scoped_settings_path(temporary.path().join("settings.json"));
    let ids = ["zeta", "alpha", "mid"];
    let images: Vec<MessageFile> = ids
        .iter()
        .map(|id| MessageFile::inline(format!("{id}.png"), "image/png", png(), *id))
        .collect();
    let html = r#"<p><img src="cid:zeta"><img src="cid:alpha"><img src="cid:mid"></p>"#;
    let saved = save_signature("user@example.com", html, &images).unwrap();
    let loaded = load_signature("user@example.com").unwrap();
    assert_eq!(loaded, saved);
    let order =
        |paths: &[(String, String)]| paths.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
    assert_eq!(order(&loaded.multipart_path), ids);
    let json = serde_json::to_value(&loaded).unwrap();
    let keys: Vec<&String> = json["multipart-path"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ids);
    let image_ids: Vec<&str> = json["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|image| image["content_id"].as_str().unwrap())
        .collect();
    assert_eq!(image_ids, ids);
}
