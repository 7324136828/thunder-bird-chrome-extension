//! Port of `tests/test_image_proxy.py::ImageSourceTests` plus normalization
//! and extraction vectors generated from the Python implementation.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use mail_core::image_sources::{self, ImageSources, MAX_MESSAGES, SOURCE_TTL};

const IMAGE_URL: &str = "https://lh3.example.com/d/1NoNBoOQt2BCK3ki_4cUeRThRQz9Nrr5S=w1200";

fn set(items: &[&str]) -> HashSet<String> {
    items.iter().map(|item| item.to_string()).collect()
}

#[test]
fn image_sources_include_srcset_background_and_entities_but_not_links() {
    let urls = image_sources::image_urls(
        r#"
            <a href="https://other.example/link">A link</a>
            <img src="//images.example/picture.png?a=1&amp;b=2#preview"
                 srcset="https://images.example/small.png 1x, https://images.example/large.png 2x">
            <picture><source srcset="https://images.example/fallback.png 2x"></picture>
            <td background="https://images.example/legacy.png"
                style="background-image: url('https://images.example/background.png')">Text</td>
        "#,
    );
    assert_eq!(
        urls,
        set(&[
            "https://images.example/picture.png?a=1&b=2",
            "https://images.example/small.png",
            "https://images.example/large.png",
            "https://images.example/fallback.png",
            "https://images.example/legacy.png",
            "https://images.example/background.png",
        ])
    );
}

#[test]
fn sources_are_scoped_to_account_folder_and_message_and_expire() {
    let registry = ImageSources::new();
    let start = Instant::now();
    registry.register_at(
        "User@Example.com",
        "INBOX",
        7,
        &format!(r#"<img src="{IMAGE_URL}">"#),
        start,
    );
    assert_eq!(
        registry.sources_at("user@example.com", "INBOX", 7, start),
        Some(set(&[IMAGE_URL]))
    );
    for (account, folder, uid) in [
        ("other@example.com", "INBOX", 7),
        ("user@example.com", "Trash", 7),
        ("user@example.com", "INBOX", 8),
    ] {
        assert_eq!(registry.sources_at(account, folder, uid, start), None);
    }
    // Python: registered at monotonic 100, read at 2000 (TTL 1800).
    let later = start + Duration::from_secs(1900);
    assert!(later >= start + SOURCE_TTL);
    assert_eq!(
        registry.sources_at("user@example.com", "INBOX", 7, later),
        None
    );
    // The expired record was removed, not just hidden.
    assert_eq!(
        registry.sources_at("user@example.com", "INBOX", 7, start),
        None
    );
}

#[test]
fn registry_is_bounded_and_locking_forgets_only_that_account() {
    let registry = ImageSources::new();
    let html = format!(r#"<img src="{IMAGE_URL}">"#);
    for uid in 1..=(MAX_MESSAGES as u32 + 1) {
        registry.register("user@example.com", "INBOX", uid, &html);
    }
    assert_eq!(registry.sources("user@example.com", "INBOX", 1), None);
    assert!(registry.sources("user@example.com", "INBOX", 2).is_some());
    registry.register("other@example.com", "INBOX", 7, "");
    registry.forget("USER@example.com");
    assert_eq!(registry.sources("user@example.com", "INBOX", 3), None);
    assert_eq!(
        registry.sources("other@example.com", "INBOX", 7),
        Some(HashSet::new())
    );
    registry.clear();
    assert_eq!(registry.sources("other@example.com", "INBOX", 7), None);
}

#[test]
fn reading_sources_refreshes_lru_order() {
    let registry = ImageSources::new();
    registry.register("user@example.com", "INBOX", 1, "");
    for uid in 2..=(MAX_MESSAGES as u32) {
        registry.register("user@example.com", "INBOX", uid, "");
    }
    // Touch uid 1 so uid 2 becomes the oldest.
    assert!(registry.sources("user@example.com", "INBOX", 1).is_some());
    registry.register("user@example.com", "INBOX", 999, "");
    assert!(registry.sources("user@example.com", "INBOX", 1).is_some());
    assert_eq!(registry.sources("user@example.com", "INBOX", 2), None);
}

#[test]
fn normalization_uses_only_web_urls_without_credentials() {
    assert_eq!(
        image_sources::normalize_url(" HTTPS://EXAMPLE.COM:443/a b.png#part ").as_deref(),
        Some("https://example.com/a%20b.png")
    );
    for url in [
        "data:image/png;base64,abc",
        "file:///image.png",
        "javascript:alert(1)",
        "https://user:password@example.com/a.png",
        "https://example.com:bad/a.png",
        "https://example.com/a\n.png",
        "https://example.com:0/image.png",
    ] {
        assert_eq!(image_sources::normalize_url(url), None, "{url}");
    }
}

#[test]
fn browser_url_normalization_and_duplicate_attributes_match() {
    let urls = image_sources::image_urls(
        r#"
            <img src="https://images.example/a/../photo.png" src="https://other.example/unused.png">
            <style>.photo { background-image: url("https://images.example/a/%2e%2e/background.png"); }</style>
        "#,
    );
    assert_eq!(
        urls,
        set(&[
            "https://images.example/photo.png",
            "https://images.example/background.png",
        ])
    );
}

/// Vectors produced by running the Python `normalize_url`.
#[test]
fn normalize_url_matches_python_vectors() {
    let long = format!("https://example.com/{}", "a".repeat(4100));
    let cases: Vec<(&str, Option<&str>)> = vec![
        (
            "//images.example/p.png?a=1&b=2#x",
            Some("https://images.example/p.png?a=1&b=2"),
        ),
        ("http://Example.com:80/", Some("http://example.com/")),
        (
            "http://example.com:8080/x",
            Some("http://example.com:8080/x"),
        ),
        (
            "https://example.com/a/./b/../c",
            Some("https://example.com/a/c"),
        ),
        (
            "https://example.com/a/%2e%2E/c/.",
            Some("https://example.com/c/"),
        ),
        ("https://example.com", Some("https://example.com/")),
        ("https://example.com?", Some("https://example.com/")),
        (
            "https://example.com/?q=a b[]|",
            Some("https://example.com/?q=a%20b[]%7C"),
        ),
        (
            "https://b\u{fc}cher.example/\u{fc}?\u{e4}=\u{f6}",
            Some("https://xn--bcher-kva.example/%C3%BC?%C3%A4=%C3%B6"),
        ),
        (
            "https://[2001:DB8::0:1]:443/x",
            Some("https://[2001:db8::1]/x"),
        ),
        ("https://[::1]/", Some("https://[::1]/")),
        ("http://[fe80::1%25eth0]/", Some("http://[fe80::1%25eth0]/")),
        ("https://example.com:0/", None),
        ("https://example.com:65536/", None),
        ("https://exa mple.com/", Some("https://exa mple.com/")),
        ("https://a..b/", None),
        ("https://example.com./x", Some("https://example.com./x")),
        ("https://user@example.com/", None),
        ("https://:@example.com/", None),
        ("ftp://example.com/", None),
        ("https:///x", None),
        (
            "https://example.com/%zz/\u{e9}",
            Some("https://example.com/%zz/%C3%A9"),
        ),
        (
            "\u{a0}https://example.com/\u{3000}",
            Some("https://example.com/"),
        ),
        (
            "https://example.com/a;b?c;d",
            Some("https://example.com/a;b?c;d"),
        ),
        (
            "https://EXAMPLE.com/A%2fB",
            Some("https://example.com/A%2fB"),
        ),
        ("http://1.2.3.4:443/", Some("http://1.2.3.4:443/")),
        ("https://[v1.x]/", Some("https://v1.x/")),
        (long.as_str(), None),
        ("https://example.com\\@evil/", None),
        (
            "https://example.com/\u{7f}",
            Some("https://example.com/%7F"),
        ),
        ("HtTp://x/../../y", Some("http://x/y")),
    ];
    for (input, expected) in cases {
        assert_eq!(
            image_sources::normalize_url(input).as_deref(),
            expected,
            "{input:?}"
        );
    }
}

/// Extraction vectors (Python 3.14 `HTMLParser`: comments, `<script>` and
/// `<title>` contents are not markup; `<style/>` still switches CSS
/// scanning on; attribute entities only decode on exact matches).
#[test]
fn image_urls_match_python_parser_vectors() {
    let html = r#"<a href="https://other.example/link">A link</a>
<img src="//images.example/picture.png?a=1&amp;b=2#preview" srcset="https://images.example/small.png 1x, https://images.example/large.png 2x">
<picture><source srcset="https://images.example/fallback.png 2x"></picture>
<td background="https://images.example/legacy.png" style="background-image: url('https://images.example/background.png')">Text</td>
<video poster="https://images.example/poster.png"></video><img src="https://images.example/a/../photo.png" src="https://other.example/unused.png">
<style>.photo { background-image: url("https://images.example/a/%2e%2e/background2.png"); } .x{background:URL( https://images.example/bare.png )}</style>
<!-- <img src="https://images.example/commented.png"> --><script><img src="https://images.example/script.png"></script>
<style/>.y{background:url(https://images.example/after-selfclosing-style.png)}</style>
<div STYLE="background:url(&quot;https://images.example/entity.png&quot;)"></div>
<img src="https://images.example/q.png?x=1&copy=2"><img src='https://images.example/c.png?&lt;'>
<title><img src="https://images.example/title.png"></title><img src=""><img srcset=" , https://images.example/set.png">"#;
    assert_eq!(
        image_sources::image_urls(html),
        set(&[
            "https://images.example/after-selfclosing-style.png",
            "https://images.example/background.png",
            "https://images.example/background2.png",
            "https://images.example/bare.png",
            "https://images.example/c.png?%3C",
            "https://images.example/entity.png",
            "https://images.example/fallback.png",
            "https://images.example/large.png",
            "https://images.example/legacy.png",
            "https://images.example/photo.png",
            "https://images.example/picture.png?a=1&b=2",
            "https://images.example/poster.png",
            // Python 3.14 keeps "&copy=" in attribute values (3.12 decoded it).
            "https://images.example/q.png?x=1&copy=2",
            "https://images.example/small.png",
            "https://images.example/set.png",
        ])
    );
}

#[test]
fn incomplete_markup_at_the_end_is_not_reported() {
    // feed() without close(): an unterminated tag or style block is held back.
    assert!(image_sources::image_urls(r#"<img src="https://images.example/x.png""#).is_empty());
    assert!(
        image_sources::image_urls("<style>a{background:url(https://images.example/x.png)}")
            .is_empty()
    );
}

#[test]
fn sources_per_message_are_bounded() {
    let html: String = (0..400)
        .map(|index| format!(r#"<img src="https://images.example/{index}.png">"#))
        .collect();
    assert_eq!(
        image_sources::image_urls(&html).len(),
        image_sources::MAX_SOURCES
    );
}
