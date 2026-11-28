//! Modified UTF-7 vectors (RFC 3501 section 5.1.3 examples and others).

use crate::imap::utf7::{decode, encode};

#[test]
fn known_vectors() {
    let vectors = [
        ("INBOX", "INBOX"),
        ("", ""),
        ("&", "&-"),
        ("Tom & Jerry", "Tom &- Jerry"),
        ("Entwürfe", "Entw&APw-rfe"),
        ("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
        ("😀", "&2D3eAA-"),
        ("Gesendete Objekte", "Gesendete Objekte"),
    ];
    for (plain, encoded) in vectors {
        assert_eq!(encode(plain), encoded, "encode {plain:?}");
        assert_eq!(decode(encoded).unwrap(), plain, "decode {encoded:?}");
    }
}

#[test]
fn round_trips() {
    for name in [
        "Отправленные",
        "Корзина/Старое",
        "已发送",
        "a&b&c",
        "x\u{7f}y",
        "tab\there",
    ] {
        assert_eq!(decode(&encode(name)).unwrap(), name, "{name:?}");
        assert!(encode(name).is_ascii());
    }
}

#[test]
fn invalid_inputs() {
    for bad in ["&Jjo", "&AGE-", "Caf\u{e9}", "&2D3e-", "&!!-"] {
        assert!(decode(bad).is_err(), "{bad:?} should be rejected");
    }
}
