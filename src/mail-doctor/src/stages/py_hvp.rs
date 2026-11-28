//! Port of the address-list and msg-id grammar of CPython's
//! `email._header_value_parser` (3.12) and of the `email.headerregistry`
//! rendering that `policy.default` applies before `eml_extract.py` sees a
//! header: `str(msg["From"])` is `", ".join(str(Group(...)))` rebuilt from
//! the parse tree, and `str(msg["Message-ID"])` is `str(parse_message_id())`.
//!
//! The parser keeps CPython's error recovery (invalid mailboxes, missing
//! `>`, obsolete local parts, ...) because it decides which address the
//! report attributes a message to. Where CPython itself raises an exception
//! other than `HeaderParseError` (e.g. `'Group' object has no attribute
//! 'local_part'` for `Group: a@b; junk`, an unterminated domain literal, or
//! `_get_ptext_to_endchars` on an empty fragment) the Python audit failed
//! as a whole; this port deliberately treats the header as empty instead.
//!
//! It also ports the MIME header grammar (`parse_content_type_header`,
//! `parse_content_disposition_header`,
//! `parse_content_transfer_encoding_header`) and the rendering of
//! `str(header)`: the tree's string with comments and quoted strings closed
//! and re-quoted, and the parameter list rebuilt from `MimeParameters.params`
//! (RFC 2231 sections joined and decoded, duplicates and invalid parameters
//! dropped, every value re-quoted). Residual differences: a section number
//! made of non-ASCII digits is not a section here, and RFC 2231 values in
//! charsets other than ASCII/Latin-1/UTF-8 that fail to decode get U+FFFD
//! per `encoding_rs` instead of surrogate-escaped bytes.

use super::py_header::{
    decode_replace, decode_strict, decode_unstructured, get_encoded_word, has_surrogates,
    lookup_codec, py_lstrip, py_split, py_strip, sanitize, sesc_decode, Codec, EwError,
};

const WSP: &str = " \t";
const CFWS_LEADER: &str = " \t(";
const SPECIALS: &str = "()<>@,:;.\\\"[]";
const PHRASE_ENDS: &str = ")<>@,:;\\[]";

fn is_wsp(c: char) -> bool {
    WSP.contains(c)
}

fn is_cfws_leader(c: char) -> bool {
    CFWS_LEADER.contains(c)
}

fn is_special(c: char) -> bool {
    SPECIALS.contains(c)
}

fn is_atom_end(c: char) -> bool {
    is_special(c) || is_wsp(c)
}

fn is_dot_atom_end(c: char) -> bool {
    c != '.' && is_atom_end(c)
}

fn is_phrase_end(c: char) -> bool {
    PHRASE_ENDS.contains(c)
}

fn first(value: &str) -> Option<char> {
    value.chars().next()
}

fn starts(value: &str, pred: impl Fn(char) -> bool) -> bool {
    first(value).is_some_and(pred)
}

fn rest_after_first(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next();
    chars.as_str()
}

/// `quote_string`.
fn quote_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Why a parse step stopped.
#[derive(Debug)]
enum Fail {
    /// `errors.HeaderParseError` (caught by the grammar's alternatives).
    Parse,
    /// Any other exception: CPython's whole header parse raised.
    Crash,
}

type Res<T> = Result<T, Fail>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermKind {
    /// `WhiteSpaceTerminal` (value `" "`).
    WhiteSpace,
    /// `ValueTerminal` (value = text).
    Value,
    /// `EWWhiteSpaceTerminal` (value and str `""`).
    EwWhiteSpace,
}

/// The `TokenList` subclass (behavior), separate from the mutable `token_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    TokenList,
    Phrase,
    CfwsList,
    Atom,
    EncodedWord,
    QuotedString,
    BareQuotedString,
    Comment,
    AddressList,
    Address,
    MailboxList,
    GroupList,
    Group,
    NameAddr,
    AngleAddr,
    ObsRoute,
    Mailbox,
    InvalidMailbox,
    Domain,
    DotAtom,
    DotAtomText,
    NoFoldLiteral,
    AddrSpec,
    ObsLocalPart,
    DisplayName,
    LocalPart,
    DomainLiteral,
    MsgId,
    MessageId,
}

#[derive(Debug, Clone)]
struct List {
    class: Class,
    ttype: &'static str,
    items: Vec<Tok>,
    /// `bool(self.defects)` (only DisplayName / obs-local-part read it).
    defects: bool,
    /// An `InvalidHeaderDefect` object was appended as a token
    /// (`_check_for_early_dl_end`): computing `all_defects`/`value` raises.
    poisoned: bool,
}

#[derive(Debug, Clone)]
enum Tok {
    Term {
        kind: TermKind,
        ttype: &'static str,
        text: String,
    },
    List(List),
}

fn list(class: Class, ttype: &'static str) -> List {
    List {
        class,
        ttype,
        items: Vec::new(),
        defects: false,
        poisoned: false,
    }
}

fn generic(items: Vec<Tok>) -> Tok {
    let mut tl = list(Class::TokenList, "");
    tl.items = items;
    Tok::List(tl)
}

fn term(kind: TermKind, ttype: &'static str, text: impl Into<String>) -> Tok {
    Tok::Term {
        kind,
        ttype,
        text: text.into(),
    }
}

fn value_term(text: impl Into<String>, ttype: &'static str) -> Tok {
    term(TermKind::Value, ttype, text)
}

fn dot() -> Tok {
    value_term(".", "dot")
}

fn list_separator() -> Tok {
    value_term(",", "list-separator")
}

impl Tok {
    fn ttype(&self) -> &'static str {
        match self {
            Tok::Term { ttype, .. } => ttype,
            Tok::List(l) => l.ttype,
        }
    }

    fn as_list(&self) -> Option<&List> {
        match self {
            Tok::List(l) => Some(l),
            Tok::Term { .. } => None,
        }
    }

    fn poisoned(&self) -> bool {
        match self {
            Tok::Term { .. } => false,
            Tok::List(l) => l.poisoned || l.items.iter().any(Tok::poisoned),
        }
    }

    /// `str(token)`.
    fn to_str(&self) -> String {
        match self {
            Tok::Term { kind, text, .. } => {
                if *kind == TermKind::EwWhiteSpace {
                    String::new()
                } else {
                    text.clone()
                }
            }
            Tok::List(l) => l.to_str(),
        }
    }

    /// `token.value`.
    fn value(&self) -> String {
        match self {
            Tok::Term { kind, text, .. } => match kind {
                TermKind::WhiteSpace => " ".into(),
                TermKind::EwWhiteSpace => String::new(),
                TermKind::Value => text.clone(),
            },
            Tok::List(l) => l.value(),
        }
    }

    /// `isinstance(tok, TokenList) and tok[0].token_type == ttype`.
    fn first_child_is(&self, ttype: &str) -> Res<bool> {
        match self {
            Tok::Term { .. } => Ok(false),
            Tok::List(l) => Ok(l.items.first().ok_or(Fail::Crash)?.ttype() == ttype),
        }
    }

    fn last_child_is(&self, ttype: &str) -> Res<bool> {
        match self {
            Tok::Term { .. } => Ok(false),
            Tok::List(l) => Ok(l.items.last().ok_or(Fail::Crash)?.ttype() == ttype),
        }
    }
}

impl List {
    fn push(&mut self, tok: Tok) {
        self.items.push(tok);
    }

    fn insert_front(&mut self, tok: Tok) {
        self.items.insert(0, tok);
    }

    fn concat_str(&self) -> String {
        self.items.iter().map(Tok::to_str).collect()
    }

    fn to_str(&self) -> String {
        match self.class {
            Class::BareQuotedString => quote_string(&self.concat_str()),
            Class::Comment => {
                let mut out = String::from("(");
                for item in &self.items {
                    if item.ttype() == "comment" {
                        out.push_str(&item.to_str());
                    } else {
                        out.push_str(
                            &item
                                .to_str()
                                .replace('\\', "\\\\")
                                .replace('(', "\\(")
                                .replace(')', "\\)"),
                        );
                    }
                }
                out.push(')');
                out
            }
            _ => self.concat_str(),
        }
    }

    fn concat_value(&self) -> String {
        self.items.iter().map(Tok::value).collect()
    }

    fn value(&self) -> String {
        match self.class {
            Class::CfwsList | Class::Comment => " ".into(),
            Class::BareQuotedString => self.concat_str(),
            Class::DisplayName => self.display_name_value().unwrap_or_default(),
            Class::LocalPart => match self.items.first() {
                Some(Tok::List(inner)) if inner.ttype == "quoted-string" => inner.quoted_value(),
                Some(inner) => inner.value(),
                None => String::new(),
            },
            Class::AddrSpec => {
                if self.items.len() < 3 {
                    self.items.first().map(Tok::value).unwrap_or_default()
                } else {
                    let local = self.items[0].value();
                    let domain = self.items[2].value();
                    format!(
                        "{}{}{}",
                        local.trim_end_matches(super::py_header::py_isspace),
                        self.items[1].value(),
                        py_lstrip(&domain)
                    )
                }
            }
            _ => self.concat_value(),
        }
    }

    /// `QuotedString.quoted_value`.
    fn quoted_value(&self) -> String {
        self.items
            .iter()
            .map(|x| {
                if x.ttype() == "bare-quoted-string" {
                    x.to_str()
                } else {
                    x.value()
                }
            })
            .collect()
    }

    /// `DisplayName.display_name`.
    fn display_name(&self) -> Res<String> {
        let mut res: Vec<Tok> = self.items.clone();
        if res.is_empty() {
            return Ok(String::new());
        }
        if res[0].ttype() == "cfws" {
            res.remove(0);
        } else if res[0].first_child_is("cfws")? {
            let inner = res[0].as_list().expect("list").items[1..].to_vec();
            res[0] = generic(inner);
        }
        let last = res.last().ok_or(Fail::Crash)?;
        if last.ttype() == "cfws" {
            res.pop();
        } else if last.last_child_is("cfws")? {
            let items = &last.as_list().expect("list").items;
            let inner = items[..items.len() - 1].to_vec();
            let index = res.len() - 1;
            res[index] = generic(inner);
        }
        Ok(res.iter().map(Tok::value).collect())
    }

    /// `DisplayName.value`.
    fn display_name_value(&self) -> Res<String> {
        let quote = self.defects || self.items.iter().any(|x| x.ttype() == "quoted-string");
        if !self.items.is_empty() && quote {
            let head = &self.items[0];
            let tail = &self.items[self.items.len() - 1];
            let pre = if head.ttype() == "cfws" || head.first_child_is("cfws")? {
                " "
            } else {
                ""
            };
            let post = if tail.ttype() == "cfws" || tail.last_child_is("cfws")? {
                " "
            } else {
                ""
            };
            Ok(format!(
                "{pre}{}{post}",
                quote_string(&self.display_name()?)
            ))
        } else {
            Ok(self.concat_value())
        }
    }

    /// `LocalPart.local_part`.
    fn local_part(&self) -> Res<String> {
        let inner = match self.items.first() {
            Some(Tok::List(inner)) => inner.items.clone(),
            Some(Tok::Term { .. }) | None => return Err(Fail::Crash),
        };
        let mut res: Vec<Tok> = vec![dot()];
        let mut last_is_tl = false;
        for tok in inner.into_iter().chain(std::iter::once(dot())) {
            if tok.ttype() == "cfws" {
                continue;
            }
            let last = res.last().expect("non-empty").clone();
            if last_is_tl && tok.ttype() == "dot" && last.last_child_is("cfws")? {
                let items = &last.as_list().expect("list").items;
                let index = res.len() - 1;
                res[index] = generic(items[..items.len() - 1].to_vec());
            }
            let is_tl = matches!(tok, Tok::List(_));
            let last_type = res.last().expect("non-empty").ttype();
            if is_tl && last_type == "dot" && tok.first_child_is("cfws")? {
                let items = tok.as_list().expect("list").items[1..].to_vec();
                res.push(generic(items));
            } else {
                res.push(tok);
            }
            last_is_tl = is_tl;
        }
        let middle = res[1..res.len() - 1].to_vec();
        Ok(generic(middle).value())
    }

    /// `Domain.domain` / `DomainLiteral.domain`.
    fn domain(&self) -> String {
        py_split(&self.concat_value()).concat()
    }
}

// ---------------------------------------------------------------------------
// Terminal scanners
// ---------------------------------------------------------------------------

/// `get_fws`: leading whitespace (`str.lstrip()`).
fn get_fws(value: &str) -> (Tok, &str) {
    let rest = py_lstrip(value);
    let fws = &value[..value.len() - rest.len()];
    (term(TermKind::WhiteSpace, "fws", fws), rest)
}

/// `_get_ptext_to_endchars` → (ptext, rest, had_qp).
fn get_ptext_to_endchars(value: &str, endchars: &str) -> Res<(String, String, bool)> {
    let split = value.find(is_wsp).unwrap_or(value.len());
    let (fragment, remainder) = value.split_at(split);
    if fragment.is_empty() {
        // `pos` is unbound in CPython (UnboundLocalError).
        return Err(Fail::Crash);
    }
    let mut vchars = String::new();
    let mut escape = false;
    let mut had_qp = false;
    let mut stop = fragment.len();
    for (index, c) in fragment.char_indices() {
        if c == '\\' {
            if escape {
                escape = false;
                had_qp = true;
            } else {
                escape = true;
                continue;
            }
        }
        if escape {
            escape = false;
        } else if endchars.contains(c) {
            stop = index;
            break;
        }
        vchars.push(c);
    }
    Ok((vchars, format!("{}{remainder}", &fragment[stop..]), had_qp))
}

fn get_qp_ctext(value: &str) -> Res<(Tok, String)> {
    let (ptext, rest, _) = get_ptext_to_endchars(value, "()")?;
    Ok((term(TermKind::WhiteSpace, "ptext", ptext), rest))
}

fn get_qcontent(value: &str) -> Res<(Tok, String)> {
    let (ptext, rest, _) = get_ptext_to_endchars(value, "\"")?;
    Ok((value_term(ptext, "ptext"), rest))
}

fn get_atext(value: &str) -> Res<(Tok, &str)> {
    let end = value.find(is_atom_end).unwrap_or(value.len());
    if end == 0 {
        return Err(Fail::Parse);
    }
    Ok((value_term(&value[..end], "atext"), &value[end..]))
}

/// `get_encoded_word` as a token whose children are fws / vtext terminals.
fn get_encoded_word_token(value: &str) -> Res<(Tok, &str)> {
    if !value.starts_with("=?") {
        return Err(Fail::Parse);
    }
    let (text, rest) = match get_encoded_word(value) {
        Ok(decoded) => decoded,
        Err(EwError::NotEncodedWord) | Err(EwError::Invalid) => return Err(Fail::Parse),
    };
    let mut ew = list(Class::EncodedWord, "encoded-word");
    let mut text = text.as_str();
    while !text.is_empty() {
        if starts(text, is_wsp) {
            let (fws, after) = get_fws(text);
            ew.push(fws);
            text = after;
            continue;
        }
        let end = text.find(is_wsp).unwrap_or(text.len());
        ew.push(value_term(&text[..end], "vtext"));
        text = &text[end..];
    }
    Ok((Tok::List(ew), rest))
}

// ---------------------------------------------------------------------------
// Grammar (owned remainders keep the code close to CPython's slicing)
// ---------------------------------------------------------------------------

type Step = (Tok, String);
type ListStep = (List, String);

fn get_bare_quoted_string(value: &str) -> Res<ListStep> {
    if !value.starts_with('"') {
        return Err(Fail::Parse);
    }
    let mut bqs = list(Class::BareQuotedString, "bare-quoted-string");
    let mut value = value[1..].to_string();
    if value.starts_with('"') {
        let (token, rest) = get_qcontent(&value)?;
        bqs.push(token);
        value = rest;
    }
    while !value.is_empty() && !value.starts_with('"') {
        let (token, rest) = if starts(&value, is_wsp) {
            let (token, rest) = get_fws(&value);
            (token, rest.to_string())
        } else if value.starts_with("=?") {
            match get_encoded_word_token(&value) {
                Ok((token, rest)) => {
                    let rest = rest.to_string();
                    let n = bqs.items.len();
                    if n > 1
                        && bqs.items[n - 1].ttype() == "fws"
                        && bqs.items[n - 2].ttype() == "encoded-word"
                    {
                        let text = bqs.items[n - 1].to_str();
                        bqs.items[n - 1] = term(TermKind::EwWhiteSpace, "fws", text);
                    }
                    (token, rest)
                }
                Err(Fail::Parse) => get_qcontent(&value)?,
                Err(Fail::Crash) => return Err(Fail::Crash),
            }
        } else {
            get_qcontent(&value)?
        };
        bqs.push(token);
        value = rest;
    }
    if value.is_empty() {
        return Ok((bqs, value));
    }
    Ok((bqs, value[1..].to_string()))
}

fn get_comment(value: &str) -> Res<ListStep> {
    if !value.is_empty() && !value.starts_with('(') {
        return Err(Fail::Parse);
    }
    let mut comment = list(Class::Comment, "comment");
    let mut value = rest_after_first(value).to_string();
    while !value.is_empty() && !value.starts_with(')') {
        let (token, rest) = if starts(&value, is_wsp) {
            let (token, rest) = get_fws(&value);
            (token, rest.to_string())
        } else if value.starts_with('(') {
            let (token, rest) = get_comment(&value)?;
            (Tok::List(token), rest)
        } else {
            get_qp_ctext(&value)?
        };
        comment.push(token);
        value = rest;
    }
    if value.is_empty() {
        return Ok((comment, value));
    }
    Ok((comment, value[1..].to_string()))
}

fn get_cfws(value: &str) -> Res<ListStep> {
    let mut cfws = list(Class::CfwsList, "cfws");
    let mut value = value.to_string();
    while starts(&value, is_cfws_leader) {
        let (token, rest) = if starts(&value, is_wsp) {
            let (token, rest) = get_fws(&value);
            (token, rest.to_string())
        } else {
            let (token, rest) = get_comment(&value)?;
            (Tok::List(token), rest)
        };
        cfws.push(token);
        value = rest;
    }
    Ok((cfws, value))
}

fn get_quoted_string(value: &str) -> Res<ListStep> {
    let mut qs = list(Class::QuotedString, "quoted-string");
    let mut value = value.to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        qs.push(Tok::List(token));
        value = rest;
    }
    let (token, rest) = get_bare_quoted_string(&value)?;
    qs.push(Tok::List(token));
    value = rest;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        qs.push(Tok::List(token));
        value = rest;
    }
    Ok((qs, value))
}

fn get_atom(value: &str) -> Res<ListStep> {
    let mut atom = list(Class::Atom, "atom");
    let mut value = value.to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        atom.push(Tok::List(token));
        value = rest;
    }
    if starts(&value, is_atom_end) {
        return Err(Fail::Parse);
    }
    let (token, rest) = if value.starts_with("=?") {
        match get_encoded_word_token(&value) {
            Ok((token, rest)) => (token, rest.to_string()),
            Err(Fail::Parse) => {
                let (token, rest) = get_atext(&value)?;
                (token, rest.to_string())
            }
            Err(Fail::Crash) => return Err(Fail::Crash),
        }
    } else {
        let (token, rest) = get_atext(&value)?;
        (token, rest.to_string())
    };
    atom.push(token);
    value = rest;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        atom.push(Tok::List(token));
        value = rest;
    }
    Ok((atom, value))
}

fn get_dot_atom_text(value: &str) -> Res<ListStep> {
    let mut dat = list(Class::DotAtomText, "dot-atom-text");
    if value.is_empty() || starts(value, is_atom_end) {
        return Err(Fail::Parse);
    }
    let mut value = value;
    let mut last_is_dot = false;
    while !value.is_empty() && !starts(value, is_atom_end) {
        let (token, rest) = get_atext(value)?;
        dat.push(token);
        value = rest;
        last_is_dot = false;
        if value.starts_with('.') {
            dat.push(dot());
            value = &value[1..];
            last_is_dot = true;
        }
    }
    if last_is_dot {
        return Err(Fail::Parse);
    }
    Ok((dat, value.to_string()))
}

fn get_dot_atom(value: &str) -> Res<ListStep> {
    let mut da = list(Class::DotAtom, "dot-atom");
    let mut value = value.to_string();
    let Some(c) = first(&value) else {
        return Err(Fail::Crash);
    };
    if is_cfws_leader(c) {
        let (token, rest) = get_cfws(&value)?;
        da.push(Tok::List(token));
        value = rest;
    }
    let (token, rest) = if value.starts_with("=?") {
        match get_encoded_word_token(&value) {
            Ok((token, rest)) => (token, rest.to_string()),
            Err(Fail::Parse) => {
                let (token, rest) = get_dot_atom_text(&value)?;
                (Tok::List(token), rest)
            }
            Err(Fail::Crash) => return Err(Fail::Crash),
        }
    } else {
        let (token, rest) = get_dot_atom_text(&value)?;
        (Tok::List(token), rest)
    };
    da.push(token);
    value = rest;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        da.push(Tok::List(token));
        value = rest;
    }
    Ok((da, value))
}

fn get_word(value: &str) -> Res<ListStep> {
    let Some(c) = first(value) else {
        return Err(Fail::Crash);
    };
    let (leader, value) = if is_cfws_leader(c) {
        let (leader, rest) = get_cfws(value)?;
        (Some(leader), rest)
    } else {
        (None, value.to_string())
    };
    let Some(c) = first(&value) else {
        return Err(Fail::Parse);
    };
    let (mut token, rest) = if c == '"' {
        get_quoted_string(&value)?
    } else if is_special(c) {
        return Err(Fail::Parse);
    } else {
        get_atom(&value)?
    };
    if let Some(leader) = leader {
        token.insert_front(Tok::List(leader));
    }
    Ok((token, rest))
}

fn get_phrase(value: &str) -> Res<ListStep> {
    let mut phrase = list(Class::Phrase, "phrase");
    let mut value = value.to_string();
    match get_word(&value) {
        Ok((token, rest)) => {
            phrase.push(Tok::List(token));
            value = rest;
        }
        Err(Fail::Parse) => phrase.defects = true,
        Err(Fail::Crash) => return Err(Fail::Crash),
    }
    while !value.is_empty() && !starts(&value, is_phrase_end) {
        if value.starts_with('.') {
            phrase.push(dot());
            phrase.defects = true;
            value = value[1..].to_string();
            continue;
        }
        match get_word(&value) {
            Ok((token, rest)) => {
                phrase.push(Tok::List(token));
                value = rest;
            }
            Err(Fail::Parse) if starts(&value, is_cfws_leader) => {
                let (token, rest) = get_cfws(&value)?;
                phrase.defects = true;
                phrase.push(Tok::List(token));
                value = rest;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((phrase, value))
}

fn get_local_part(value: &str) -> Res<ListStep> {
    let mut lp = list(Class::LocalPart, "local-part");
    let mut value = value.to_string();
    let mut leader = None;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
    }
    if value.is_empty() {
        return Err(Fail::Parse);
    }
    let mut token = match get_dot_atom(&value) {
        Ok((token, rest)) => {
            value = rest;
            token
        }
        Err(Fail::Parse) => match get_word(&value) {
            Ok((token, rest)) => {
                value = rest;
                token
            }
            Err(Fail::Parse) => {
                let c = first(&value).expect("non-empty");
                if c != '\\' && is_phrase_end(c) {
                    return Err(Fail::Parse);
                }
                list(Class::TokenList, "")
            }
            Err(Fail::Crash) => return Err(Fail::Crash),
        },
        Err(Fail::Crash) => return Err(Fail::Crash),
    };
    if let Some(leader) = leader {
        token.insert_front(Tok::List(leader));
    }
    lp.push(Tok::List(token));
    if first(&value).is_some_and(|c| c == '\\' || !is_phrase_end(c)) {
        let source = format!("{}{value}", lp.to_str());
        let (obs, rest) = get_obs_local_part(&source)?;
        lp.items[0] = Tok::List(obs);
        value = rest;
    }
    Ok((lp, value))
}

fn get_obs_local_part(value: &str) -> Res<ListStep> {
    let mut obs = list(Class::ObsLocalPart, "obs-local-part");
    let mut value = value.to_string();
    let mut last_non_ws_was_dot = false;
    while first(&value).is_some_and(|c| c == '\\' || !is_phrase_end(c)) {
        if value.starts_with('.') {
            if last_non_ws_was_dot {
                obs.defects = true;
            }
            obs.push(dot());
            last_non_ws_was_dot = true;
            value = value[1..].to_string();
            continue;
        }
        if value.starts_with('\\') {
            obs.push(value_term("\\", "misplaced-special"));
            value = value[1..].to_string();
            obs.defects = true;
            last_non_ws_was_dot = false;
            continue;
        }
        if obs.items.last().is_some_and(|x| x.ttype() != "dot") {
            obs.defects = true;
        }
        let (token, rest) = match get_word(&value) {
            Ok((token, rest)) => {
                last_non_ws_was_dot = false;
                (token, rest)
            }
            Err(Fail::Parse) if starts(&value, is_cfws_leader) => get_cfws(&value)?,
            Err(error) => return Err(error),
        };
        obs.push(Tok::List(token));
        value = rest;
    }
    if obs.items.is_empty() {
        return Err(Fail::Parse);
    }
    let n = obs.items.len();
    let ty = |i: usize| obs.items[i].ttype();
    if ty(0) == "dot" || (ty(0) == "cfws" && n > 1 && ty(1) == "dot") {
        obs.defects = true;
    }
    if ty(n - 1) == "dot" || (ty(n - 1) == "cfws" && n > 1 && ty(n - 2) == "dot") {
        obs.defects = true;
    }
    if obs.defects {
        obs.ttype = "invalid-obs-local-part";
    }
    Ok((obs, value))
}

fn get_dtext(value: &str) -> Res<Step> {
    let (ptext, rest, _) = get_ptext_to_endchars(value, "[]")?;
    Ok((value_term(ptext, "ptext"), rest))
}

fn get_domain_literal(value: &str) -> Res<ListStep> {
    let mut dl = list(Class::DomainLiteral, "domain-literal");
    let mut value = value.to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        dl.push(Tok::List(token));
        value = rest;
    }
    if value.is_empty() || !value.starts_with('[') {
        return Err(Fail::Parse);
    }
    value = value[1..].to_string();
    let early_end = |dl: &mut List, value: &str| {
        if value.is_empty() {
            dl.poisoned = true;
            dl.push(value_term("]", "domain-literal-end"));
            true
        } else {
            false
        }
    };
    if early_end(&mut dl, &value) {
        return Ok((dl, value));
    }
    dl.push(value_term("[", "domain-literal-start"));
    if starts(&value, is_wsp) {
        let (token, rest) = get_fws(&value);
        dl.push(token);
        value = rest.to_string();
    }
    let (token, rest) = get_dtext(&value)?;
    dl.push(token);
    value = rest;
    if early_end(&mut dl, &value) {
        return Ok((dl, value));
    }
    if starts(&value, is_wsp) {
        let (token, rest) = get_fws(&value);
        dl.push(token);
        value = rest.to_string();
    }
    if early_end(&mut dl, &value) {
        return Ok((dl, value));
    }
    if !value.starts_with(']') {
        return Err(Fail::Parse);
    }
    dl.push(value_term("]", "domain-literal-end"));
    value = value[1..].to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        dl.push(Tok::List(token));
        value = rest;
    }
    Ok((dl, value))
}

fn get_domain(value: &str) -> Res<ListStep> {
    let mut domain = list(Class::Domain, "domain");
    let mut value = value.to_string();
    let mut leader = None;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
    }
    if value.is_empty() {
        return Err(Fail::Parse);
    }
    if value.starts_with('[') {
        let (mut token, rest) = get_domain_literal(&value)?;
        if let Some(leader) = leader {
            token.insert_front(Tok::List(leader));
        }
        domain.push(Tok::List(token));
        return Ok((domain, rest));
    }
    let (mut token, rest) = match get_dot_atom(&value) {
        Ok(step) => step,
        Err(Fail::Parse) => get_atom(&value)?,
        Err(Fail::Crash) => return Err(Fail::Crash),
    };
    value = rest;
    if value.starts_with('@') {
        return Err(Fail::Parse);
    }
    if let Some(leader) = leader {
        token.insert_front(Tok::List(leader));
    }
    domain.push(Tok::List(token));
    if value.starts_with('.') {
        if domain.items[0].ttype() == "dot-atom" {
            let inner = domain.items[0].as_list().expect("list").items.clone();
            domain.items = inner;
        }
        while value.starts_with('.') {
            domain.push(dot());
            let (token, rest) = get_atom(&value[1..])?;
            domain.push(Tok::List(token));
            value = rest;
        }
    }
    Ok((domain, value))
}

fn get_addr_spec(value: &str) -> Res<ListStep> {
    let mut spec = list(Class::AddrSpec, "addr-spec");
    let (token, value) = get_local_part(value)?;
    spec.push(Tok::List(token));
    if !value.starts_with('@') {
        return Ok((spec, value));
    }
    spec.push(value_term("@", "address-at-symbol"));
    let (token, value) = get_domain(&value[1..])?;
    spec.push(Tok::List(token));
    Ok((spec, value))
}

fn get_obs_route(value: &str) -> Res<ListStep> {
    let mut route = list(Class::ObsRoute, "obs-route");
    let mut value = value.to_string();
    while first(&value).is_some_and(|c| c == ',' || is_cfws_leader(c)) {
        if starts(&value, is_cfws_leader) {
            let (token, rest) = get_cfws(&value)?;
            route.push(Tok::List(token));
            value = rest;
        } else {
            route.push(list_separator());
            value = value[1..].to_string();
        }
    }
    if !value.starts_with('@') {
        return Err(Fail::Parse);
    }
    route.push(value_term("@", "route-component-marker"));
    let (token, rest) = get_domain(&value[1..])?;
    route.push(Tok::List(token));
    value = rest;
    while value.starts_with(',') {
        route.push(list_separator());
        value = value[1..].to_string();
        if value.is_empty() {
            break;
        }
        if starts(&value, is_cfws_leader) {
            let (token, rest) = get_cfws(&value)?;
            route.push(Tok::List(token));
            value = rest;
        }
        if value.is_empty() {
            break;
        }
        if value.starts_with('@') {
            route.push(value_term("@", "route-component-marker"));
            let (token, rest) = get_domain(&value[1..])?;
            route.push(Tok::List(token));
            value = rest;
        }
    }
    if value.is_empty() || !value.starts_with(':') {
        return Err(Fail::Parse);
    }
    route.push(value_term(":", "end-of-obs-route-marker"));
    Ok((route, value[1..].to_string()))
}

fn get_angle_addr(value: &str) -> Res<ListStep> {
    let mut angle = list(Class::AngleAddr, "angle-addr");
    let mut value = value.to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        angle.push(Tok::List(token));
        value = rest;
    }
    if !value.starts_with('<') {
        return Err(Fail::Parse);
    }
    angle.push(value_term("<", "angle-addr-start"));
    value = value[1..].to_string();
    if let Some(rest) = value.strip_prefix('>') {
        angle.push(value_term(">", "angle-addr-end"));
        return Ok((angle, rest.to_string()));
    }
    let (token, rest) = match get_addr_spec(&value) {
        Ok(step) => step,
        Err(Fail::Parse) => {
            let (route, rest) = get_obs_route(&value)?;
            angle.push(Tok::List(route));
            get_addr_spec(&rest)?
        }
        Err(Fail::Crash) => return Err(Fail::Crash),
    };
    angle.push(Tok::List(token));
    value = rest;
    if value.starts_with('>') {
        value = value[1..].to_string();
    }
    angle.push(value_term(">", "angle-addr-end"));
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        angle.push(Tok::List(token));
        value = rest;
    }
    Ok((angle, value))
}

fn get_display_name(value: &str) -> Res<ListStep> {
    let (phrase, rest) = get_phrase(value)?;
    let mut name = list(Class::DisplayName, "display-name");
    name.items = phrase.items;
    name.defects = phrase.defects;
    Ok((name, rest))
}

fn get_name_addr(value: &str) -> Res<ListStep> {
    let mut name_addr = list(Class::NameAddr, "name-addr");
    let mut value = value.to_string();
    if value.is_empty() {
        return Err(Fail::Parse);
    }
    let mut leader = None;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
        if value.is_empty() {
            return Err(Fail::Parse);
        }
    }
    if !value.starts_with('<') {
        if starts(&value, is_phrase_end) {
            return Err(Fail::Parse);
        }
        let (mut token, rest) = get_display_name(&value)?;
        value = rest;
        if value.is_empty() {
            return Err(Fail::Parse);
        }
        if let Some(leader) = leader.take() {
            match token.items.first_mut() {
                Some(Tok::List(inner)) => inner.insert_front(Tok::List(leader)),
                Some(Tok::Term { .. }) => token.insert_front(Tok::List(leader)),
                None => return Err(Fail::Crash),
            }
        }
        name_addr.push(Tok::List(token));
    }
    let (mut token, rest) = get_angle_addr(&value)?;
    if let Some(leader) = leader {
        token.insert_front(Tok::List(leader));
    }
    name_addr.push(Tok::List(token));
    Ok((name_addr, rest))
}

/// `any(isinstance(x, InvalidHeaderDefect) for x in token.all_defects)` is
/// not needed for the rendering; only the crash of `all_defects` on a
/// poisoned domain literal is reproduced.
fn get_mailbox(value: &str) -> Res<ListStep> {
    let mut mailbox = list(Class::Mailbox, "mailbox");
    let (token, rest) = match get_name_addr(value) {
        Ok(step) => step,
        Err(Fail::Parse) => get_addr_spec(value)?,
        Err(Fail::Crash) => return Err(Fail::Crash),
    };
    let token = Tok::List(token);
    if token.poisoned() {
        return Err(Fail::Crash);
    }
    mailbox.push(token);
    Ok((mailbox, rest))
}

fn get_invalid_mailbox(value: &str, endchars: &str) -> Res<ListStep> {
    let mut invalid = list(Class::InvalidMailbox, "invalid-mailbox");
    let mut value = value.to_string();
    while first(&value).is_some_and(|c| !endchars.contains(c)) {
        let c = first(&value).expect("non-empty");
        if is_phrase_end(c) {
            invalid.push(value_term(c.to_string(), "misplaced-special"));
            value = rest_after_first(&value).to_string();
        } else {
            let (token, rest) = get_phrase(&value)?;
            invalid.push(Tok::List(token));
            value = rest;
        }
    }
    Ok((invalid, value))
}

/// The error recovery of `get_mailbox_list` / `get_address_list`:
/// `target.token_type = 'invalid-mailbox'; target.extend(invalid)`.
fn absorb_invalid(target: &mut Tok, value: &str, endchars: &str) -> Res<String> {
    let Tok::List(target) = target else {
        // `Terminal` has no `extend` (AttributeError).
        return Err(Fail::Crash);
    };
    target.ttype = "invalid-mailbox";
    let (token, rest) = get_invalid_mailbox(value, endchars)?;
    target.items.extend(token.items);
    Ok(rest)
}

fn get_mailbox_list(value: &str) -> Res<ListStep> {
    let mut mailbox_list = list(Class::MailboxList, "mailbox-list");
    let mut value = value.to_string();
    while !value.is_empty() && !value.starts_with(';') {
        match get_mailbox(&value) {
            Ok((token, rest)) => {
                mailbox_list.push(Tok::List(token));
                value = rest;
            }
            Err(Fail::Crash) => return Err(Fail::Crash),
            Err(Fail::Parse) => {
                if starts(&value, is_cfws_leader) {
                    let (leader, rest) = get_cfws(&value)?;
                    value = rest;
                    if value.is_empty() || value.starts_with([',', ';']) {
                        mailbox_list.push(Tok::List(leader));
                    } else {
                        let (mut token, rest) = get_invalid_mailbox(&value, ",;")?;
                        token.insert_front(Tok::List(leader));
                        mailbox_list.push(Tok::List(token));
                        value = rest;
                    }
                } else if !value.starts_with(',') {
                    let (token, rest) = get_invalid_mailbox(&value, ",;")?;
                    mailbox_list.push(Tok::List(token));
                    value = rest;
                }
            }
        }
        if !value.is_empty() && !value.starts_with([',', ';']) {
            let target = mailbox_list.items.last_mut().ok_or(Fail::Crash)?;
            value = absorb_invalid(target, &value, ",;")?;
        }
        if value.starts_with(',') {
            mailbox_list.push(list_separator());
            value = value[1..].to_string();
        }
    }
    Ok((mailbox_list, value))
}

/// `MailboxList.all_mailboxes` (`mailbox` and `invalid-mailbox` tokens).
fn mailbox_list_all(l: &List) -> Vec<Tok> {
    l.items
        .iter()
        .filter(|x| matches!(x.ttype(), "mailbox" | "invalid-mailbox"))
        .cloned()
        .collect()
}

fn get_group_list(value: &str) -> Res<ListStep> {
    let mut group_list = list(Class::GroupList, "group-list");
    let mut value = value.to_string();
    if value.is_empty() {
        return Ok((group_list, value));
    }
    let mut leader = None;
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        value = rest;
        if value.is_empty() || value.starts_with(';') {
            group_list.push(Tok::List(token));
            return Ok((group_list, value));
        }
        leader = Some(token);
    }
    let (mut token, rest) = get_mailbox_list(&value)?;
    value = rest;
    if mailbox_list_all(&token).is_empty() {
        if let Some(leader) = leader {
            group_list.push(Tok::List(leader));
        }
        group_list.items.extend(token.items);
        return Ok((group_list, value));
    }
    if let Some(leader) = leader {
        token.insert_front(Tok::List(leader));
    }
    group_list.push(Tok::List(token));
    Ok((group_list, value))
}

fn get_group(value: &str) -> Res<ListStep> {
    let mut group = list(Class::Group, "group");
    let (token, value) = get_display_name(value)?;
    if !value.starts_with(':') {
        return Err(Fail::Parse);
    }
    group.push(Tok::List(token));
    group.push(value_term(":", "group-display-name-terminator"));
    let mut value = value[1..].to_string();
    if let Some(rest) = value.strip_prefix(';') {
        group.push(value_term(";", "group-terminator"));
        return Ok((group, rest.to_string()));
    }
    let (token, rest) = get_group_list(&value)?;
    group.push(Tok::List(token));
    value = rest;
    if !value.is_empty() && !value.starts_with(';') {
        return Err(Fail::Parse);
    }
    group.push(value_term(";", "group-terminator"));
    value = rest_after_first(&value).to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        group.push(Tok::List(token));
        value = rest;
    }
    Ok((group, value))
}

fn get_address(value: &str) -> Res<ListStep> {
    let mut address = list(Class::Address, "address");
    let (token, rest) = match get_group(value) {
        Ok(step) => step,
        Err(Fail::Parse) => get_mailbox(value)?,
        Err(Fail::Crash) => return Err(Fail::Crash),
    };
    address.push(Tok::List(token));
    Ok((address, rest))
}

fn get_address_list(value: &str) -> Res<List> {
    let mut address_list = list(Class::AddressList, "address-list");
    let mut value = value.to_string();
    let wrap = |token: List| {
        let mut address = list(Class::Address, "address");
        address.push(Tok::List(token));
        Tok::List(address)
    };
    while !value.is_empty() {
        match get_address(&value) {
            Ok((token, rest)) => {
                address_list.push(Tok::List(token));
                value = rest;
            }
            Err(Fail::Crash) => return Err(Fail::Crash),
            Err(Fail::Parse) => {
                if starts(&value, is_cfws_leader) {
                    let (leader, rest) = get_cfws(&value)?;
                    value = rest;
                    if value.is_empty() || value.starts_with(',') {
                        address_list.push(Tok::List(leader));
                    } else {
                        let (mut token, rest) = get_invalid_mailbox(&value, ",")?;
                        token.insert_front(Tok::List(leader));
                        address_list.push(wrap(token));
                        value = rest;
                    }
                } else if !value.starts_with(',') {
                    let (token, rest) = get_invalid_mailbox(&value, ",")?;
                    address_list.push(wrap(token));
                    value = rest;
                }
            }
        }
        if !value.is_empty() && !value.starts_with(',') {
            // `address_list[-1][0]`
            let last = address_list.items.last_mut().ok_or(Fail::Crash)?;
            let Tok::List(last) = last else {
                return Err(Fail::Crash);
            };
            let target = last.items.first_mut().ok_or(Fail::Crash)?;
            value = absorb_invalid(target, &value, ",")?;
        }
        if !value.is_empty() {
            address_list.push(list_separator());
            value = rest_after_first(&value).to_string();
        }
    }
    Ok(address_list)
}

fn get_no_fold_literal(value: &str) -> Res<ListStep> {
    let mut literal = list(Class::NoFoldLiteral, "no-fold-literal");
    if !value.starts_with('[') {
        return Err(Fail::Parse);
    }
    literal.push(value_term("[", "no-fold-literal-start"));
    let (token, value) = get_dtext(&value[1..])?;
    literal.push(token);
    if !value.starts_with(']') {
        return Err(Fail::Parse);
    }
    literal.push(value_term("]", "no-fold-literal-end"));
    Ok((literal, value[1..].to_string()))
}

fn get_msg_id(value: &str) -> Res<ListStep> {
    let mut msg_id = list(Class::MsgId, "msg-id");
    let mut value = value.to_string();
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        msg_id.push(Tok::List(token));
        value = rest;
    }
    if !value.starts_with('<') {
        return Err(Fail::Parse);
    }
    msg_id.push(value_term("<", "msg-id-start"));
    value = value[1..].to_string();
    let (token, rest) = match get_dot_atom_text(&value) {
        Ok(step) => step,
        Err(Fail::Parse) => get_obs_local_part(&value)?,
        Err(Fail::Crash) => return Err(Fail::Crash),
    };
    msg_id.push(Tok::List(token));
    value = rest;
    if !value.starts_with('@') {
        if value.starts_with('>') {
            msg_id.push(value_term(">", "msg-id-end"));
            value = value[1..].to_string();
        }
        return Ok((msg_id, value));
    }
    msg_id.push(value_term("@", "address-at-symbol"));
    value = value[1..].to_string();
    let (token, rest) = match get_dot_atom_text(&value) {
        Ok(step) => step,
        Err(Fail::Crash) => return Err(Fail::Crash),
        Err(Fail::Parse) => match get_no_fold_literal(&value) {
            Ok(step) => step,
            Err(Fail::Crash) => return Err(Fail::Crash),
            Err(Fail::Parse) => get_domain(&value)?,
        },
    };
    msg_id.push(Tok::List(token));
    value = rest;
    if value.starts_with('>') {
        value = value[1..].to_string();
    }
    msg_id.push(value_term(">", "msg-id-end"));
    if starts(&value, is_cfws_leader) {
        let (token, rest) = get_cfws(&value)?;
        msg_id.push(Tok::List(token));
        value = rest;
    }
    Ok((msg_id, value))
}

// ---------------------------------------------------------------------------
// MIME headers: Content-Type, Content-Disposition, Content-Transfer-Encoding
// ---------------------------------------------------------------------------

/// `TOKEN_ENDS`, `ATTRIBUTE_ENDS`, `EXTENDED_ATTRIBUTE_ENDS`.
const TOKEN_ENDS: &str = "\t \"(),/:;<=>?@[\\]";
const ATTRIBUTE_ENDS: &str = "\t \"%'()*,/:;<=>?@[\\]";
const EXTENDED_ATTRIBUTE_ENDS: &str = "\t \"'()*,/:;<=>?@[\\]";

/// `get_ttext` / `get_attrtext` / `get_extended_attrtext`: the
/// `[^ends]+` run at the start of `value`.
fn get_text_run<'a>(value: &'a str, ends: &str, ttype: &'static str) -> Res<(Tok, &'a str)> {
    let end = value.find(|c| ends.contains(c)).unwrap_or(value.len());
    if end == 0 {
        return Err(Fail::Parse);
    }
    Ok((value_term(&value[..end], ttype), &value[end..]))
}

/// `get_token` / `get_attribute` / `get_extended_attribute`:
/// `[CFWS] 1*text [CFWS]`.
fn get_cfws_wrapped(
    value: &str,
    ends: &str,
    text_type: &'static str,
    ttype: &'static str,
) -> Res<ListStep> {
    let mut token = list(Class::TokenList, ttype);
    let mut value = value.to_string();
    if starts(&value, is_cfws_leader) {
        let (cfws, rest) = get_cfws(&value)?;
        token.push(Tok::List(cfws));
        value = rest;
    }
    if starts(&value, |c| ends.contains(c)) {
        return Err(Fail::Parse);
    }
    let (text, rest) = get_text_run(&value, ends, text_type)?;
    token.push(text);
    let mut value = rest.to_string();
    if starts(&value, is_cfws_leader) {
        let (cfws, rest) = get_cfws(&value)?;
        token.push(Tok::List(cfws));
        value = rest;
    }
    Ok((token, value))
}

fn get_token(value: &str) -> Res<ListStep> {
    get_cfws_wrapped(value, TOKEN_ENDS, "ttext", "token")
}

fn get_attribute(value: &str) -> Res<ListStep> {
    get_cfws_wrapped(value, ATTRIBUTE_ENDS, "attrtext", "attribute")
}

fn get_extended_attribute(value: &str) -> Res<ListStep> {
    get_cfws_wrapped(
        value,
        EXTENDED_ATTRIBUTE_ENDS,
        "extended-attrtext",
        "attribute",
    )
}

/// `get_section` → (section, rest, `section.number`). Only ASCII digits
/// are accepted (`str.isdigit()` also takes other Unicode digits, for which
/// CPython's `int()` then fails anyway); huge numbers saturate.
fn get_section(value: &str) -> Res<(Tok, String, u64)> {
    let Some(rest) = value.strip_prefix('*') else {
        return Err(Fail::Parse);
    };
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return Err(Fail::Parse);
    }
    let digits = &rest[..end];
    let section = generic(vec![
        value_term("*", "section-marker"),
        value_term(digits, "digits"),
    ]);
    let number = digits.parse::<u64>().unwrap_or(u64::MAX);
    Ok((section, rest[end..].to_string(), number))
}

/// `get_value`: `quoted-string / attribute`.
fn get_value(value: &str) -> Res<ListStep> {
    if value.is_empty() {
        return Err(Fail::Parse);
    }
    let mut value = value.to_string();
    let mut leader = None;
    if starts(&value, is_cfws_leader) {
        let (cfws, rest) = get_cfws(&value)?;
        leader = Some(cfws);
        value = rest;
    }
    if value.is_empty() {
        return Err(Fail::Parse);
    }
    let (mut token, rest) = if value.starts_with('"') {
        get_quoted_string(&value)?
    } else {
        get_extended_attribute(&value)?
    };
    if let Some(leader) = leader {
        token.insert_front(Tok::List(leader));
    }
    let mut v = list(Class::TokenList, "value");
    v.push(Tok::List(token));
    Ok((v, rest))
}

/// `Value.stripped_value` (`Err` for CPython's `IndexError` on an empty or
/// CFWS-only value).
fn value_stripped_value(value: &List) -> Res<String> {
    let mut token = value.items.first().ok_or(Fail::Crash)?;
    if token.ttype() == "cfws" {
        token = value.items.get(1).ok_or(Fail::Crash)?;
    }
    let ttype = token.ttype();
    if ttype.ends_with("quoted-string") {
        // `QuotedString.stripped_value`: the bare-quoted-string's value.
        return Ok(token
            .as_list()
            .and_then(|qs| {
                qs.items
                    .iter()
                    .find(|item| item.ttype() == "bare-quoted-string")
            })
            .map(Tok::value)
            .unwrap_or_default());
    }
    if ttype.ends_with("attribute") {
        // `Attribute.stripped_value`: the attrtext's value.
        return Ok(token
            .as_list()
            .and_then(|attr| {
                attr.items
                    .iter()
                    .find(|item| item.ttype().ends_with("attrtext"))
            })
            .map(Tok::value)
            .unwrap_or_default());
    }
    Ok(value.value())
}

/// What `MimeParameters.params` reads from one parsed `Parameter`.
struct ParamInfo {
    /// `token[0].value.strip()`.
    name: String,
    section_number: u64,
    extended: bool,
    charset: String,
    /// `param.param_value` (`Err` where computing it raises).
    value: Res<String>,
}

/// `Parameter.param_value`: the first `value` token appended after `=`
/// (directly, or inside the emptied bare-quoted-string of the hack).
fn param_value(tokens: &[Tok]) -> Res<String> {
    match tokens.iter().find(|token| token.ttype() == "value") {
        Some(Tok::List(value)) => value_stripped_value(value),
        _ => Ok(String::new()),
    }
}

/// Append `tokens` where CPython's `appendto` pointed: the parameter itself,
/// or the emptied bare-quoted-string of `quoted` (the "quoted extended
/// value" hack), which is then appended to the parameter.
fn finish_parameter(mut param: List, quoted: Option<List>, tokens: Vec<Tok>) -> List {
    match quoted {
        None => param.items.extend(tokens),
        Some(mut quoted) => {
            if let Some(Tok::List(bqs)) = quoted
                .items
                .iter_mut()
                .find(|item| item.ttype() == "bare-quoted-string")
            {
                bqs.items = tokens;
            }
            param.push(Tok::List(quoted));
        }
    }
    param
}

/// `get_parameter`: `attribute [section] ["*"] [CFWS] "=" value`.
fn get_parameter(value: &str) -> Res<(List, String, ParamInfo)> {
    let mut param = list(Class::TokenList, "parameter");
    let (attribute, rest) = get_attribute(value)?;
    let mut info = ParamInfo {
        name: py_strip(&attribute.value()).to_string(),
        section_number: 0,
        extended: false,
        charset: "us-ascii".to_string(),
        value: Ok(String::new()),
    };
    param.push(Tok::List(attribute));
    let mut value = rest;
    if value.is_empty() || value.starts_with(';') {
        return Ok((param, value, info));
    }
    if value.starts_with('*') {
        if let Ok((section, rest, number)) = get_section(&value) {
            info.section_number = number;
            param.push(section);
            value = rest;
        }
        if value.is_empty() {
            return Err(Fail::Parse);
        }
        if let Some(rest) = value.strip_prefix('*') {
            param.push(value_term("*", "extended-parameter-marker"));
            value = rest.to_string();
            info.extended = true;
        }
    }
    let extended = info.extended;
    let section_positive = info.section_number > 0;
    let Some(rest) = value.strip_prefix('=') else {
        return Err(Fail::Parse);
    };
    param.push(value_term("=", "parameter-separator"));
    value = rest.to_string();
    if starts(&value, is_cfws_leader) {
        let (cfws, rest) = get_cfws(&value)?;
        param.push(Tok::List(cfws));
        value = rest;
    }
    let mut remainder: Option<String> = None;
    let mut quoted: Option<List> = None;
    let mut tokens: Vec<Tok> = Vec::new();
    let done = |param: List,
                quoted: Option<List>,
                tokens: Vec<Tok>,
                value: String,
                mut info: ParamInfo| {
        info.value = param_value(&tokens);
        (finish_parameter(param, quoted, tokens), value, info)
    };
    if extended && value.starts_with('"') {
        // Double quotes around an extended value (a common invalid case).
        let (qstring, rest) = get_quoted_string(&value)?;
        let inner_value = qstring
            .items
            .iter()
            .find(|item| item.ttype() == "bare-quoted-string")
            .map(Tok::value)
            .unwrap_or_default();
        let semi_valid = if !section_positive {
            if inner_value.starts_with('\'') {
                true
            } else {
                let (_, rest) = get_text_run(&inner_value, ATTRIBUTE_ENDS, "attrtext")?;
                rest.starts_with('\'')
            }
        } else {
            get_text_run(&inner_value, EXTENDED_ATTRIBUTE_ENDS, "extended-attrtext")
                .is_ok_and(|(_, rest)| rest.is_empty())
        };
        if semi_valid {
            remainder = Some(rest);
            quoted = Some(qstring);
            value = inner_value;
        }
    }
    let token = if value.starts_with('\'') {
        None
    } else {
        let (token, rest) = get_value(&value)?;
        value = rest;
        Some(token)
    };
    if (!extended || section_positive) && !value.starts_with('\'') {
        tokens.push(Tok::List(token.ok_or(Fail::Crash)?));
        if let Some(remainder) = remainder {
            if !value.is_empty() {
                return Err(Fail::Crash); // `assert not value`
            }
            value = remainder;
        }
        return Ok(done(param, quoted, tokens, value, info));
    }
    if value.is_empty() {
        // The charset/lang delimiters are missing: the token is the value.
        tokens.push(Tok::List(token.ok_or(Fail::Crash)?));
        if remainder.is_none() {
            return Ok(done(param, quoted, tokens, value, info));
        }
    } else {
        if let Some(token) = token {
            // `for t in token: ...` leaves `t` at the value's last child.
            let t = token.items.last().cloned().ok_or(Fail::Crash)?;
            info.charset = t.value();
            tokens.push(t);
        }
        let Some(rest) = value.strip_prefix('\'') else {
            return Err(Fail::Parse);
        };
        tokens.push(value_term("'", "RFC2231-delimiter"));
        value = rest.to_string();
        if !value.is_empty() && !value.starts_with('\'') {
            let (lang, rest) = get_text_run(&value, ATTRIBUTE_ENDS, "attrtext")?;
            tokens.push(lang);
            value = rest.to_string();
            if !value.starts_with('\'') {
                return Err(Fail::Parse);
            }
        }
        tokens.push(value_term("'", "RFC2231-delimiter"));
        value = value[1..].to_string();
    }
    let token = if remainder.is_some() {
        // The rest of the value is bare quoted-string content.
        let mut v = list(Class::TokenList, "value");
        while !value.is_empty() {
            let (token, rest) = if starts(&value, is_wsp) {
                let (token, rest) = get_fws(&value);
                (token, rest.to_string())
            } else if let Some(rest) = value.strip_prefix('"') {
                (value_term("\"", "DQUOTE"), rest.to_string())
            } else {
                get_qcontent(&value)?
            };
            v.push(token);
            value = rest;
        }
        v
    } else {
        let (token, rest) = get_value(&value)?;
        value = rest;
        token
    };
    tokens.push(Tok::List(token));
    if let Some(remainder) = remainder {
        if !value.is_empty() {
            return Err(Fail::Crash); // `assert not value`
        }
        value = remainder;
    }
    Ok(done(param, quoted, tokens, value, info))
}

/// `get_invalid_parameter`: everything up to the next `;`.
fn get_invalid_parameter(value: &str) -> Res<ListStep> {
    let mut invalid = list(Class::TokenList, "invalid-parameter");
    let mut value = value.to_string();
    while !value.is_empty() && !value.starts_with(';') {
        if starts(&value, is_phrase_end) {
            let rest = rest_after_first(&value).to_string();
            invalid.push(value_term(
                &value[..value.len() - rest.len()],
                "misplaced-special",
            ));
            value = rest;
        } else {
            let (phrase, rest) = get_phrase(&value)?;
            invalid.push(Tok::List(phrase));
            value = rest;
        }
    }
    Ok((invalid, value))
}

/// `bytes.decode(codec, "surrogateescape")` as a sesc string. Codecs other
/// than ASCII, Latin-1 and UTF-8 replace undecodable input with U+FFFD
/// (the later `_sanitize` turns lone raw bytes into U+FFFD as well).
fn decode_surrogateescape(bytes: &[u8], codec: Codec) -> String {
    match codec {
        Codec::Utf8 => {
            let mut out = String::new();
            let mut rest = bytes;
            loop {
                match std::str::from_utf8(rest) {
                    Ok(text) => {
                        out.push_str(text);
                        return out;
                    }
                    Err(error) => {
                        let (valid, after) = rest.split_at(error.valid_up_to());
                        out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                        let bad = error.error_len().unwrap_or(after.len());
                        out.push_str(&sesc_decode(&after[..bad]));
                        rest = &after[bad..];
                    }
                }
            }
        }
        Codec::Ascii => sesc_decode(bytes),
        _ => decode_strict(bytes, codec).unwrap_or_else(|| decode_replace(bytes, codec)),
    }
}

/// `urllib.parse.unquote_to_bytes` / `unquote(value, encoding="latin-1")`
/// followed by the charset decoding of `MimeParameters.params`.
fn decode_extended_value(value: &str, charset: &str) -> String {
    let percent_decode = |bytes: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                let hex = [bytes[i + 1], bytes[i + 2]];
                let text = std::str::from_utf8(&hex).unwrap_or("00");
                out.push(u8::from_str_radix(text, 16).unwrap_or(0));
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out
    };
    if has_surrogates(value) {
        // `str.encode("utf-8")` fails on surrogates: `unquote(value,
        // encoding="latin-1")` decodes each %XX run as Latin-1 instead.
        let mut out = String::new();
        let mut buffer = String::new();
        let flush = |buffer: &mut String, out: &mut String| {
            let bytes = percent_decode(buffer.as_bytes());
            out.extend(bytes.iter().map(|&b| b as char));
            buffer.clear();
        };
        for ch in value.chars() {
            if ch.is_ascii() {
                buffer.push(ch);
            } else {
                flush(&mut buffer, &mut out);
                out.push(ch);
            }
        }
        flush(&mut buffer, &mut out);
        return out;
    }
    let bytes = percent_decode(value.as_bytes());
    let codec = lookup_codec(charset).unwrap_or(Codec::Ascii);
    decode_surrogateescape(&bytes, codec)
}

/// `str(MimeParameters)`: the parameters rebuilt from `.params` (RFC 2231
/// sections joined and decoded, duplicates dropped) as
/// `' ' + '; '.join(name="value" / name)`.
fn render_mime_parameters(infos: &[ParamInfo]) -> Res<String> {
    let mut names: Vec<&str> = Vec::new();
    for info in infos {
        if !names.contains(&info.name.as_str()) {
            names.push(&info.name);
        }
    }
    let mut rendered = Vec::new();
    for name in names {
        let mut parts: Vec<&ParamInfo> = infos.iter().filter(|info| info.name == name).collect();
        parts.sort_by_key(|info| info.section_number);
        let first = parts[0];
        if !first.extended && parts.len() > 1 && parts[1].section_number == 0 {
            parts.truncate(1);
        }
        let mut value = String::new();
        let mut expected = 0u64;
        for param in parts {
            if param.section_number != expected && !param.extended {
                continue;
            }
            expected += 1;
            let raw = match &param.value {
                Ok(raw) => raw.clone(),
                Err(_) => return Err(Fail::Crash),
            };
            if param.extended {
                value.push_str(&decode_extended_value(&raw, &first.charset));
            } else {
                value.push_str(&raw);
            }
        }
        rendered.push(if value.is_empty() {
            name.to_string()
        } else {
            format!("{name}={}", quote_string(&value))
        });
    }
    let joined = rendered.join("; ");
    Ok(if joined.is_empty() {
        joined
    } else {
        format!(" {joined}")
    })
}

/// `parse_mime_parameters`: `parameter *( ";" parameter )`, as the token
/// `str(MimeParameters)` renders.
fn parse_mime_parameters(value: &str) -> Res<Tok> {
    let mut infos: Vec<ParamInfo> = Vec::new();
    let mut value = value.to_string();
    let mut last_is_param;
    while !value.is_empty() {
        match get_parameter(&value) {
            Ok((_, rest, info)) => {
                infos.push(info);
                last_is_param = true;
                value = rest;
            }
            Err(Fail::Crash) => return Err(Fail::Crash),
            Err(Fail::Parse) => {
                last_is_param = false;
                if starts(&value, is_cfws_leader) {
                    let (_, rest) = get_cfws(&value)?;
                    value = rest;
                }
                if value.is_empty() {
                    break;
                }
                if !value.starts_with(';') {
                    let (_, rest) = get_invalid_parameter(&value)?;
                    value = rest;
                }
            }
        }
        if !value.is_empty() && !value.starts_with(';') {
            // Junk after an otherwise valid parameter joins that parameter
            // (which keeps its name and value).
            if !last_is_param {
                return Err(Fail::Crash);
            }
            let (_, rest) = get_invalid_parameter(&value)?;
            value = rest;
        }
        if !value.is_empty() {
            value = value[1..].to_string();
        }
    }
    Ok(value_term(
        render_mime_parameters(&infos)?,
        "mime-parameters",
    ))
}

/// `_find_mime_parameters`: recover the parameters of an invalid header.
fn find_mime_parameters(tokens: &mut List, value: &str) -> Res<()> {
    let mut value = value.to_string();
    while !value.is_empty() && !value.starts_with(';') {
        if starts(&value, is_phrase_end) {
            let rest = rest_after_first(&value).to_string();
            tokens.push(value_term(
                &value[..value.len() - rest.len()],
                "misplaced-special",
            ));
            value = rest;
        } else {
            let (phrase, rest) = get_phrase(&value)?;
            tokens.push(Tok::List(phrase));
            value = rest;
        }
    }
    if value.is_empty() {
        return Ok(());
    }
    tokens.push(value_term(";", "parameter-separator"));
    tokens.push(parse_mime_parameters(&value[1..])?);
    Ok(())
}

/// `parse_content_type_header`.
fn parse_content_type(value: &str) -> Res<List> {
    let mut ctype = list(Class::TokenList, "content-type");
    if value.is_empty() {
        return Ok(ctype);
    }
    let Ok((token, rest)) = get_token(value) else {
        find_mime_parameters(&mut ctype, value)?;
        return Ok(ctype);
    };
    ctype.push(Tok::List(token));
    let Some(rest) = rest.strip_prefix('/') else {
        if !rest.is_empty() {
            find_mime_parameters(&mut ctype, &rest)?;
        }
        return Ok(ctype);
    };
    ctype.push(value_term("/", "content-type-separator"));
    let Ok((token, rest)) = get_token(rest) else {
        find_mime_parameters(&mut ctype, rest)?;
        return Ok(ctype);
    };
    ctype.push(Tok::List(token));
    if rest.is_empty() {
        return Ok(ctype);
    }
    let Some(params) = rest.strip_prefix(';') else {
        find_mime_parameters(&mut ctype, &rest)?;
        return Ok(ctype);
    };
    ctype.push(value_term(";", "parameter-separator"));
    ctype.push(parse_mime_parameters(params)?);
    Ok(ctype)
}

/// `parse_content_disposition_header`.
fn parse_content_disposition(value: &str) -> Res<List> {
    let mut disposition = list(Class::TokenList, "content-disposition");
    if value.is_empty() {
        return Ok(disposition);
    }
    let Ok((token, rest)) = get_token(value) else {
        find_mime_parameters(&mut disposition, value)?;
        return Ok(disposition);
    };
    disposition.push(Tok::List(token));
    if rest.is_empty() {
        return Ok(disposition);
    }
    let Some(params) = rest.strip_prefix(';') else {
        find_mime_parameters(&mut disposition, &rest)?;
        return Ok(disposition);
    };
    disposition.push(value_term(";", "parameter-separator"));
    disposition.push(parse_mime_parameters(params)?);
    Ok(disposition)
}

/// `parse_content_transfer_encoding_header` → (tree, `cte`).
fn parse_content_transfer_encoding(value: &str) -> Res<(List, String)> {
    let mut header = list(Class::TokenList, "content-transfer-encoding");
    let mut cte = "7bit".to_string();
    if value.is_empty() {
        return Ok((header, cte));
    }
    let mut value = value.to_string();
    if let Ok((token, rest)) = get_token(&value) {
        cte = py_strip(&token.value()).to_lowercase();
        header.push(Tok::List(token));
        value = rest;
    }
    while !value.is_empty() {
        if starts(&value, is_phrase_end) {
            let rest = rest_after_first(&value).to_string();
            header.push(value_term(
                &value[..value.len() - rest.len()],
                "misplaced-special",
            ));
            value = rest;
        } else {
            let (phrase, rest) = get_phrase(&value)?;
            header.push(Tok::List(phrase));
            value = rest;
        }
    }
    Ok((header, cte))
}

/// The structured MIME headers `policy.default` parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeHeader {
    Type,
    Disposition,
    TransferEncoding,
}

impl MimeHeader {
    /// The header for a (case-insensitive) field name.
    pub fn for_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "content-type" => Some(Self::Type),
            "content-disposition" => Some(Self::Disposition),
            "content-transfer-encoding" => Some(Self::TransferEncoding),
            _ => None,
        }
    }
}

/// `str(msg[name])` for a MIME header under `policy.default`, given the
/// unfolded raw value: the string of the `_header_value_parser` tree, which
/// closes unterminated comments and quoted strings and re-quotes their
/// content. `None` where CPython's parser raised (an `assert` in the
/// quoted-extended-parameter recovery of `get_parameter`); callers then keep
/// the raw value, while CPython failed the whole access.
pub fn mime_header_str(header: MimeHeader, value: &str) -> Option<String> {
    let tree = match header {
        MimeHeader::Type => parse_content_type(value),
        MimeHeader::Disposition => parse_content_disposition(value),
        MimeHeader::TransferEncoding => {
            parse_content_transfer_encoding(value).map(|(tree, _)| tree)
        }
    };
    tree.ok().map(|tree| sanitize(&tree.to_str()))
}

/// `msg["Content-Transfer-Encoding"].cte` under `policy.default`: the
/// first token, stripped and lowercased (`"7bit"` when there is none),
/// whatever follows it. `None` where CPython's parser raised.
pub fn content_transfer_encoding_cte(value: &str) -> Option<String> {
    parse_content_transfer_encoding(value)
        .ok()
        .map(|(_, cte)| sanitize(&cte))
}

// ---------------------------------------------------------------------------
// headerregistry rendering
// ---------------------------------------------------------------------------

/// `headerregistry.Address`.
struct HAddress {
    display_name: String,
    username: String,
    domain: String,
}

impl HAddress {
    fn addr_spec(&self) -> String {
        let mut lp = self.username.clone();
        if lp.chars().any(is_dot_atom_end) {
            lp = quote_string(&lp);
        }
        if !self.domain.is_empty() {
            return format!("{lp}@{}", self.domain);
        }
        if lp.is_empty() {
            return "<>".into();
        }
        lp
    }

    fn render(&self) -> String {
        let mut disp = self.display_name.clone();
        if disp.chars().any(is_special) {
            disp = quote_string(&disp);
        }
        if !disp.is_empty() {
            let spec = self.addr_spec();
            let spec = if spec == "<>" { String::new() } else { spec };
            return format!("{disp} <{spec}>");
        }
        self.addr_spec()
    }
}

/// `headerregistry.Group`.
fn render_group(display_name: Option<String>, addresses: &[HAddress]) -> String {
    if display_name.is_none() && addresses.len() == 1 {
        return addresses[0].render();
    }
    let disp = match display_name {
        None => "None".to_string(),
        Some(name) if name.chars().any(is_special) => quote_string(&name),
        Some(name) => name,
    };
    let joined = addresses
        .iter()
        .map(HAddress::render)
        .collect::<Vec<_>>()
        .join(", ");
    let joined = if joined.is_empty() {
        joined
    } else {
        format!(" {joined}")
    };
    format!("{disp}:{joined};")
}

fn child(l: &List, index: usize) -> Res<&Tok> {
    l.items.get(index).ok_or(Fail::Crash)
}

/// `DisplayName.display_name` of `tok` (must be a display-name list).
fn display_name_of(tok: &Tok) -> Res<String> {
    match tok {
        Tok::List(l) if l.class == Class::DisplayName => l.display_name(),
        _ => Err(Fail::Crash),
    }
}

/// `mb.display_name` for an element of `all_mailboxes`.
fn mailbox_display_name(mb: &List) -> Res<Option<String>> {
    match mb.class {
        Class::Mailbox => {
            let inner = child(mb, 0)?;
            if inner.ttype() != "name-addr" {
                return Ok(None);
            }
            let name_addr = inner.as_list().ok_or(Fail::Crash)?;
            if name_addr.items.len() == 1 {
                return Ok(None);
            }
            display_name_of(child(name_addr, 0)?).map(Some)
        }
        Class::Group => display_name_of(child(mb, 0)?).map(Some),
        _ => Ok(None),
    }
}

/// The `addr-spec` reached through `Mailbox` → `NameAddr` → `AngleAddr`.
fn mailbox_addr_spec(mb: &List) -> Res<Option<&List>> {
    let inner = child(mb, 0)?.as_list().ok_or(Fail::Crash)?;
    let spec_holder = match inner.class {
        Class::NameAddr => inner
            .items
            .last()
            .ok_or(Fail::Crash)?
            .as_list()
            .ok_or(Fail::Crash)?,
        Class::AddrSpec => return Ok(Some(inner)),
        _ => return Err(Fail::Crash),
    };
    // AngleAddr: the first `addr-spec` child (none for `<>`).
    Ok(spec_holder
        .items
        .iter()
        .filter_map(Tok::as_list)
        .find(|x| x.ttype == "addr-spec"))
}

/// `(mb.local_part, mb.domain)`.
fn mailbox_parts(mb: &List) -> Res<(Option<String>, Option<String>)> {
    match mb.class {
        Class::InvalidMailbox => Ok((None, None)),
        Class::Mailbox => {
            let Some(spec) = mailbox_addr_spec(mb)? else {
                return Ok((None, None));
            };
            let local = match child(spec, 0)? {
                Tok::List(lp) if lp.class == Class::LocalPart => lp.local_part()?,
                _ => return Err(Fail::Crash),
            };
            let domain = if spec.items.len() < 3 {
                None
            } else {
                match spec.items.last() {
                    Some(Tok::List(d)) => Some(d.domain()),
                    _ => return Err(Fail::Crash),
                }
            };
            Ok((Some(local), domain))
        }
        // `'Group' object has no attribute 'local_part'`.
        _ => Err(Fail::Crash),
    }
}

/// `Address.all_mailboxes` / `Group.all_mailboxes`.
fn address_all_mailboxes(address: &List) -> Res<Vec<Tok>> {
    let first = child(address, 0)?;
    match first.ttype() {
        "mailbox" | "invalid-mailbox" => Ok(vec![first.clone()]),
        _ => {
            let group = first.as_list().ok_or(Fail::Crash)?;
            if group.class != Class::Group {
                return Err(Fail::Crash);
            }
            let group_list = child(group, 2)?;
            if group_list.ttype() != "group-list" {
                return Ok(Vec::new());
            }
            let group_list = group_list.as_list().ok_or(Fail::Crash)?;
            match group_list.items.first() {
                Some(Tok::List(mailboxes)) if mailboxes.ttype == "mailbox-list" => {
                    Ok(mailbox_list_all(mailboxes))
                }
                _ => Ok(Vec::new()),
            }
        }
    }
}

fn render_address_list(tree: &List) -> Res<String> {
    let mut rendered = Vec::new();
    for address in tree.items.iter().filter(|x| x.ttype() == "address") {
        let address = address.as_list().ok_or(Fail::Crash)?;
        let first = child(address, 0)?;
        let display_name = if first.ttype() == "group" {
            Some(display_name_of(child(
                first.as_list().ok_or(Fail::Crash)?,
                0,
            )?)?)
        } else {
            None
        };
        let mut members = Vec::new();
        for mb in address_all_mailboxes(address)? {
            let mb = mb.as_list().ok_or(Fail::Crash)?;
            let name = mailbox_display_name(mb)?.unwrap_or_default();
            let (local, domain) = mailbox_parts(mb)?;
            members.push(HAddress {
                display_name: name,
                username: local.unwrap_or_default(),
                domain: domain.unwrap_or_default(),
            });
        }
        rendered.push(render_group(display_name, &members));
    }
    Ok(rendered.join(", "))
}

/// `str(msg[name])` for an address header (`From`, `To`, ...) under
/// `policy.default`, given the unfolded raw value (surrogate-escaped bytes
/// allowed). `""` where CPython raised.
pub fn address_header_str(value: &str) -> String {
    let rendered = get_address_list(value).and_then(|tree| {
        if Tok::List(tree.clone()).poisoned() {
            return Err(Fail::Crash);
        }
        render_address_list(&tree)
    });
    sanitize(&rendered.unwrap_or_default())
}

/// `str(msg["Message-ID"])` under `policy.default` (`parse_message_id`),
/// given the unfolded raw value. The raw value, stripped, where CPython
/// raised.
pub fn message_id_header_str(value: &str) -> String {
    let rendered = match get_msg_id(value) {
        Ok((msg_id, _)) => {
            let mut message_id = list(Class::MessageId, "message-id");
            message_id.push(Tok::List(msg_id));
            let tok = Tok::List(message_id);
            if tok.poisoned() {
                py_strip(value).to_string()
            } else {
                tok.to_str()
            }
        }
        Err(Fail::Parse) => decode_unstructured(value),
        Err(Fail::Crash) => py_strip(value).to_string(),
    };
    sanitize(&rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_lists_render_like_headerregistry() {
        // Expected values: `str(email.message_from_string(f"From: {v}\n\n",
        // policy=policy.default)["From"])` on CPython 3.12.
        for (input, expected) in [
            ("Name <a@b.example>", "Name <a@b.example>"),
            ("a@b.example <c@d.example>", "a@b.example"),
            ("Name <a@b.example> trailing", "Name <a@b.example>"),
            ("a@b.example;", "a@b.example"),
            ("Name <a@b.example>, ", "Name <a@b.example>"),
            (", Name <a@b.example>", "Name <a@b.example>"),
            ("\"us er\"@b.example", "\"us er\"@b.example"),
            (
                "Group: a@b.example, c@d.example;",
                "Group: a@b.example, c@d.example;",
            ),
            ("undisclosed-recipients:;", "undisclosed-recipients:;"),
            ("Name <a@b.example", "Name <a@b.example>"),
            ("<>", "<>"),
            ("Doe, John <jd@b.example>", "Doe, John <jd@b.example>"),
            (
                "\"Doe, John\" <jd@b.example>",
                "\"Doe, John\" <jd@b.example>",
            ),
            ("a@b.example (Comment Name)", "a@b.example"),
            (
                "=?utf-8?q?Caf=C3=A9?= <cafe@b.example>",
                "Café <cafe@b.example>",
            ),
        ] {
            assert_eq!(address_header_str(input), expected, "{input:?}");
        }
        // CPython raises for these; the port renders nothing.
        assert_eq!(address_header_str("a@[1.2.3.4"), "");
        assert_eq!(address_header_str("Group: a@b.example; junk"), "");
    }

    #[test]
    fn message_ids_render_like_parse_message_id() {
        for (input, expected) in [
            ("<ok@b.example>", "<ok@b.example>"),
            ("<noclose@b.example", "<noclose@b.example>"),
            ("<a@b.example> trailing", "<a@b.example> "),
            ("<a@b.example>, <c@d.example>", "<a@b.example>"),
            ("<a b@c.example>", "<a"),
            ("<a@b.ex ample>", "<a@b.ex> "),
            ("garbage", "garbage"),
            ("", ""),
        ] {
            assert_eq!(message_id_header_str(input), expected, "{input:?}");
        }
    }
}
