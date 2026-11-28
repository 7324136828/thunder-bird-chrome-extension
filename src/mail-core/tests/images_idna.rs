//! IDNA 2003 (`"idna"` codec, RFC 3491 nameprep) host canonicalization in
//! `image_sources::normalize_url` and `remote_images::target`. Expected
//! values were produced by the Python implementation (`image_sources.py`,
//! `remote_images._target`).

use mail_core::{image_sources, remote_images};

const NOT_PERMITTED: &str = "The image URL is not permitted.";

/// `(input, normalize_url, _target(...).url or error)`.
const VECTORS: &[(&str, Option<&str>, Result<&str, &str>)] = &[
    // B.2 case folding: sharp s and capital sharp s fold to "ss".
    (
        "https://Stra\u{df}e.example/a.png",
        Some("https://strasse.example/a.png"),
        Ok("https://strasse.example/a.png"),
    ),
    (
        "https://\u{1e9e}.example/",
        Some("https://ss.example/"),
        Ok("https://ss.example/"),
    ),
    // Final sigma folds to sigma.
    (
        "https://\u{3c2}\u{3b1}.example/",
        Some("https://xn--mxa9a.example/"),
        Ok("https://xn--mxa9a.example/"),
    ),
    (
        "https://\u{2102}af\u{e9}.example/",
        Some("https://xn--caf-dma.example/"),
        Ok("https://xn--caf-dma.example/"),
    ),
    (
        "https://\u{1f80}.example/",
        Some("https://xn--uxa970l.example/"),
        Ok("https://xn--uxa970l.example/"),
    ),
    (
        "https://\u{130}stanbul.example/",
        Some("https://xn--istanbul-o0e.example/"),
        Ok("https://xn--istanbul-o0e.example/"),
    ),
    // B.1: mapped to nothing.
    (
        "https://exa\u{ad}mple.com/",
        Some("https://example.com/"),
        Ok("https://example.com/"),
    ),
    // Unassigned in Unicode 3.2: no compatibility decomposition.
    (
        "https://\u{213b}.example/",
        Some("https://xn--o3g.example/"),
        Ok("https://xn--o3g.example/"),
    ),
    // Prohibited output (C.3 private use, C.8 bidi controls).
    ("https://a\u{e000}.example/", None, Err(NOT_PERMITTED)),
    ("https://a\u{200e}b.example/", None, Err(NOT_PERMITTED)),
    // Bidi: RandAL with L characters, or not at both ends.
    ("https://\u{5d0}a\u{5d1}.example/", None, Err(NOT_PERMITTED)),
    ("https://\u{5d0}1.example/", None, Err(NOT_PERMITTED)),
    (
        "https://\u{5d0}\u{5d1}.example/",
        Some("https://xn--4dbc.example/"),
        Ok("https://xn--4dbc.example/"),
    ),
];

#[test]
fn hostnames_use_python_nameprep() {
    for (input, normalized, target) in VECTORS {
        assert_eq!(
            image_sources::normalize_url(input).as_deref(),
            *normalized,
            "normalize_url({input:?})"
        );
        let actual = remote_images::target(input)
            .map(|target| target.url)
            .map_err(|error| error.0);
        assert_eq!(
            actual.as_deref().map_err(String::as_str),
            *target,
            "target({input:?})"
        );
    }
}

/// Registered URLs and proxy requests agree on the canonical host, so an
/// image whose host needs case folding is still authorized.
#[test]
fn folded_hosts_are_registered_under_their_canonical_url() {
    let urls = image_sources::image_urls(r#"<img src="https://STRA&szlig;E.example/i.png">"#);
    assert!(urls.contains("https://strasse.example/i.png"), "{urls:?}");
    let urls = image_sources::image_urls("<img src=\"https://\u{5d0}a\u{5d1}.example/i.png\">");
    assert!(urls.is_empty(), "{urls:?}");
}
