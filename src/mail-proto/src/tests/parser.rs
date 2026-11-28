//! Parser unit tests with tricky server responses.

use super::{wire_parts, with_literal};
use crate::imap::parser::{parse_line, Value};
use crate::imap::response::{literal_size, parse_response, Response, Status};
use crate::imap::{
    compress_uid_set, expand_uid_set, normalize_crlf, quote, unquote, CopyUid, UntaggedResponse,
};
use crate::ProtoError;

fn untagged(wire: &[u8]) -> UntaggedResponse {
    match parse_response(wire_parts(wire)).expect("parse") {
        Response::Untagged(response) => response,
        other => panic!("expected untagged response, got {other:?}"),
    }
}

#[test]
fn fetch_summary_with_header_literal() {
    let headers = b"From: Alice <alice@example.com>\r\nSubject: Hi (there)\r\n\r\n";
    let wire = with_literal(
        "* 12 FETCH (UID 42 FLAGS (\\Seen \\Flagged $Label) INTERNALDATE \"17-Jul-1996 02:44:25 -0700\" RFC822.SIZE 4286 BODY[HEADER.FIELDS (FROM SUBJECT)] ",
        headers,
        ")",
    );
    let response = untagged(&wire);
    assert_eq!(response.kind, "FETCH");
    assert_eq!(response.number, Some(12));
    let fetch = response.fetch().unwrap();
    assert_eq!(fetch.seq, 12);
    assert_eq!(fetch.uid(), Some(42));
    assert_eq!(
        fetch.flags().unwrap(),
        vec!["\\Seen", "\\Flagged", "$Label"]
    );
    assert!(fetch.has_flag("\\seen"));
    assert!(!fetch.has_flag("\\Deleted"));
    assert_eq!(
        fetch.internal_date().as_deref(),
        Some("17-Jul-1996 02:44:25 -0700")
    );
    assert_eq!(fetch.rfc822_size(), Some(4286));
    assert_eq!(
        fetch.body("HEADER.FIELDS (FROM SUBJECT)"),
        Some(&headers[..])
    );
    assert_eq!(
        fetch.body("header.fields (\"from\"  \"subject\")"),
        Some(&headers[..])
    );
    assert_eq!(fetch.first_body(), Some(&headers[..]));
    // The raw imaplib-style data items keep the literal as bytes.
    assert_eq!(response.parts.len(), 2);
    assert_eq!(response.parts[0].literal.as_deref(), Some(&headers[..]));
    assert_eq!(response.parts[1].text, b")");
}

#[test]
fn fetch_literal_containing_protocol_lookalikes() {
    let body = b"line one )\r\n* 1 FETCH (UID 9)\r\nends with marker {5}\r\nA0001 OK fake\r\n";
    let wire = with_literal("* 3 FETCH (UID 7 BODY[] ", body, " FLAGS ())");
    let fetch = untagged(&wire).fetch().unwrap();
    assert_eq!(fetch.uid(), Some(7));
    assert_eq!(fetch.body(""), Some(&body[..]));
    assert_eq!(fetch.flags().unwrap(), Vec::<String>::new());
}

#[test]
fn fetch_multiple_literals_and_partial_and_binary() {
    let header = b"Subject: x\r\n\r\n";
    let text = b"body\r\n";
    let mut wire = format!("* 1 FETCH (UID 3 BODY[HEADER] {{{}}}\r\n", header.len()).into_bytes();
    wire.extend_from_slice(header);
    wire.extend_from_slice(format!(" BODY[TEXT]<0> {{{}}}\r\n", text.len()).as_bytes());
    wire.extend_from_slice(text);
    wire.extend_from_slice(format!(" BINARY[1] ~{{{}}}\r\n", 3).as_bytes());
    wire.extend_from_slice(b"\x00\x01\x02");
    wire.extend_from_slice(b")\r\n");
    let fetch = untagged(&wire).fetch().unwrap();
    assert_eq!(fetch.body("HEADER"), Some(&header[..]));
    assert_eq!(fetch.body("TEXT"), Some(&text[..]));
    assert_eq!(fetch.get("BINARY[1]"), Some(&Value::Literal(vec![0, 1, 2])));
    assert_eq!(fetch.first_body(), Some(&header[..]));
}

#[test]
fn fetch_nested_lists_nil_and_escaped_quotes() {
    let wire = b"* 5 FETCH (UID 11 X-GM-LABELS (\"\\\\Important\" \"a \\\"b\\\"\") ENVELOPE (\"Mon, 1 Jan 2026\" \"Subj\" ((\"Name\" NIL \"user\" \"example.com\")) NIL) BODY[] NIL)\r\n";
    let fetch = untagged(wire).fetch().unwrap();
    assert_eq!(fetch.uid(), Some(11));
    let labels = fetch.get("X-GM-LABELS").unwrap().as_list().unwrap();
    assert_eq!(labels[0], Value::Quoted(b"\\Important".to_vec()));
    assert_eq!(labels[1], Value::Quoted(b"a \"b\"".to_vec()));
    let envelope = fetch.get("ENVELOPE").unwrap().as_list().unwrap();
    assert_eq!(envelope.len(), 4);
    assert!(envelope[3].is_nil());
    let addresses = envelope[2].as_list().unwrap()[0].as_list().unwrap();
    assert_eq!(addresses[2], Value::Quoted(b"user".to_vec()));
    assert!(fetch.get("BODY[]").unwrap().is_nil());
    assert_eq!(fetch.body(""), None);
    assert_eq!(fetch.first_body(), None);
}

#[test]
fn fetch_quoted_body_and_empty_literal() {
    let fetch = untagged(b"* 2 FETCH (BODY[TEXT] \"short\" UID 4)\r\n")
        .fetch()
        .unwrap();
    assert_eq!(fetch.body("TEXT"), Some(&b"short"[..]));
    let wire = with_literal("* 2 FETCH (UID 4 BODY[] ", b"", ")");
    let fetch = untagged(&wire).fetch().unwrap();
    assert_eq!(fetch.body(""), Some(&b""[..]));
}

#[test]
fn fetch_malformed_inputs_are_errors() {
    for wire in [
        &b"* 1 FETCH (UID 5 FLAGS)\r\n"[..],
        b"* 1 FETCH (UID 5 FLAGS (\\Seen)\r\n",
        b"* 1 FETCH (UID \"unterminated)\r\n",
        b"* 1 FETCH UID 5\r\n",
        b"* 1 FETCH (BODY[HEADER 5)\r\n",
    ] {
        let result = untagged(wire).fetch();
        assert!(
            matches!(result, Err(ProtoError::Protocol(_))),
            "{:?} -> {result:?}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn list_entries_quoted_atom_literal_and_extended() {
    let entry = untagged(b"* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent Items\"\r\n")
        .list_entry()
        .unwrap();
    assert_eq!(entry.attributes, vec!["\\HasNoChildren", "\\Sent"]);
    assert_eq!(entry.delimiter.as_deref(), Some("/"));
    assert_eq!(entry.name, "Sent Items");
    assert!(entry.has_attribute("\\sent"));
    assert!(entry.is_selectable());

    let entry = untagged(b"* LIST () NIL INBOX\r\n").list_entry().unwrap();
    assert_eq!(entry.delimiter, None);
    assert_eq!(entry.name, "INBOX");

    let entry = untagged(b"* LIST (\\Noselect) \".\" \"a\\\\b\\\"c\"\r\n")
        .list_entry()
        .unwrap();
    assert_eq!(entry.name, "a\\b\"c");
    assert!(!entry.is_selectable());

    let wire = with_literal("* LIST (\\Drafts) \"/\" ", "Café".as_bytes(), "");
    let entry = untagged(&wire).list_entry().unwrap();
    assert_eq!(entry.name, "Café");
    assert!(entry.name_was_literal);

    let entry =
        untagged(b"* LIST (\\Noselect) \".\" \"#news\" (\"CHILDINFO\" (\"SUBSCRIBED\"))\r\n")
            .list_entry()
            .unwrap();
    assert_eq!(entry.name, "#news");

    let entry = untagged(b"* LIST () \"/\" \"Entw&APw-rfe\"\r\n")
        .list_entry()
        .unwrap();
    assert_eq!(entry.decoded_name(), "Entwürfe");
}

#[test]
fn search_responses() {
    assert_eq!(
        untagged(b"* SEARCH 2 84 882\r\n").search().unwrap(),
        vec![2, 84, 882]
    );
    assert_eq!(
        untagged(b"* SEARCH\r\n").search().unwrap(),
        Vec::<u32>::new()
    );
    assert_eq!(
        untagged(b"* SEARCH 2 5 (MODSEQ 917162500)\r\n")
            .search()
            .unwrap(),
        vec![2, 5]
    );
    assert!(untagged(b"* SEARCH 1 x\r\n").search().is_err());
    assert!(untagged(b"* SEARCH 99999999999\r\n").search().is_err());
}

#[test]
fn status_responses_and_codes() {
    let response = untagged(b"* OK [UIDVALIDITY 3857529045] UIDs valid\r\n");
    assert_eq!(response.kind, "OK");
    let code = response.code.clone().unwrap();
    assert_eq!(code.name, "UIDVALIDITY");
    assert_eq!(code.number(), Some(3_857_529_045));
    assert_eq!(response.text(), "UIDs valid");

    let response = untagged(b"* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n");
    assert_eq!(
        response.code.unwrap().words(),
        vec!["\\Deleted", "\\Seen", "\\*"]
    );

    let response = untagged(b"* 23 EXISTS\r\n");
    assert_eq!(
        (response.number, response.kind.as_str()),
        (Some(23), "EXISTS")
    );

    let response = untagged(b"* CAPABILITY IMAP4rev1 uidplus Move\r\n");
    assert_eq!(response.words_upper(), vec!["IMAP4REV1", "UIDPLUS", "MOVE"]);

    match parse_response(wire_parts(
        b"A0007 OK [APPENDUID 38505 3955] APPEND completed\r\n",
    ))
    .unwrap()
    {
        Response::Tagged(tagged) => {
            assert_eq!(tagged.tag, "A0007");
            assert_eq!(tagged.status, Status::Ok);
            let code = tagged.code.unwrap();
            assert_eq!(
                (code.name.as_str(), code.args.as_str()),
                ("APPENDUID", "38505 3955")
            );
            assert_eq!(tagged.text, "APPEND completed");
            assert_eq!(tagged.raw_text, "[APPENDUID 38505 3955] APPEND completed");
        }
        other => panic!("{other:?}"),
    }
    match parse_response(wire_parts(b"a1 no Mailbox is busy\r\n")).unwrap() {
        Response::Tagged(tagged) => assert_eq!(tagged.status, Status::No),
        other => panic!("{other:?}"),
    }
    match parse_response(wire_parts(b"+ Ready\r\n")).unwrap() {
        Response::Continuation(text) => assert_eq!(text, "Ready"),
        other => panic!("{other:?}"),
    }
    assert!(parse_response(wire_parts(b"garbage line\r\n")).is_err());
}

#[test]
fn copyuid_pairs() {
    let code = crate::imap::ResponseCode {
        name: "COPYUID".into(),
        args: "38505 304,319:320 3956:3958".into(),
    };
    let copy = CopyUid::from_code(&code).unwrap();
    assert_eq!(copy.uid_validity, 38505);
    assert_eq!(
        copy.pairs().unwrap(),
        vec![(304, 3956), (319, 3957), (320, 3958)]
    );
}

#[test]
fn literal_markers() {
    assert_eq!(literal_size(b"* 1 FETCH (BODY[] {5}"), Some(5));
    assert_eq!(literal_size(b"A1 APPEND x {12+}"), Some(12));
    assert_eq!(literal_size(b"A1 APPEND x UTF8 (~{3}"), Some(3));
    assert_eq!(literal_size(b"{0}"), Some(0));
    assert_eq!(literal_size(b"* OK {a}"), None);
    assert_eq!(literal_size(b"* OK done}"), None);
    assert_eq!(literal_size(b"* OK {}"), None);
    assert_eq!(literal_size(b"* OK"), None);
}

#[test]
fn quoting_helpers_match_python() {
    // imap_client._mailbox
    assert_eq!(quote("INBOX"), "\"INBOX\"");
    assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    // imap_client._unquote
    assert_eq!(unquote("\"a\\\"b\\\\c\""), "a\"b\\c");
    assert_eq!(unquote("plain"), "plain");
    assert_eq!(unquote("\"x\\yz\""), "x\\yz");
    assert_eq!(
        normalize_crlf(b"a\nb\r\nc\rd"),
        b"a\r\nb\r\nc\r\nd".to_vec()
    );
}

#[test]
fn uid_set_helpers() {
    assert_eq!(expand_uid_set("1:3,7"), Some(vec![1, 2, 3, 7]));
    assert_eq!(expand_uid_set("5:4"), Some(vec![4, 5]));
    assert_eq!(expand_uid_set("1:*"), None);
    assert_eq!(compress_uid_set(&[7, 1, 2, 3, 3, 9]), "1:3,7,9");
    assert_eq!(compress_uid_set(&[]), "");
}

#[test]
fn parse_line_values() {
    let values =
        parse_line(b"(\\Seen) \"q\" NIL 12 atom BODY.PEEK[HEADER.FIELDS (A B)]<0.10>").unwrap();
    assert_eq!(values.len(), 6);
    assert_eq!(values[3], Value::Number(12));
    assert_eq!(
        values[5],
        Value::Atom("BODY.PEEK[HEADER.FIELDS (A B)]<0.10>".into())
    );
    assert!(parse_line(b"(a b").is_err());
    assert!(parse_line(b"a b)").is_err());
}
