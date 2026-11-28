//! Port of `email._parseaddr` (`AddrlistClass`, `_parsedate_tz`) and the
//! Python 3.12 strict wrappers in `email.utils` (`parseaddr`, `getaddresses`,
//! `parsedate_to_datetime`), as used by `services/stages/eml_extract.py`.

use chrono::{Duration, NaiveDate};

use super::py_header::{py_isspace, py_split};

const SPECIALS: &str = "()<>@,:;.\"[]";
const LWS: &str = " \t";
const CR: &str = "\r\n";

/// One parsed address: (display name, addr-spec), plus the raw phrase words
/// of a `phrase <route-addr>` address (used to emulate `policy.default`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddress {
    pub name: String,
    pub addr: String,
    pub phrase: Vec<String>,
}

impl ParsedAddress {
    fn new(name: String, addr: String) -> Self {
        Self {
            name,
            addr,
            phrase: Vec::new(),
        }
    }

    fn empty() -> Self {
        Self::new(String::new(), String::new())
    }
}

/// `email._parseaddr.AddrlistClass`.
struct AddrList {
    field: Vec<char>,
    pos: usize,
    commentlist: Vec<String>,
}

fn is_in(ch: char, set: &str) -> bool {
    set.contains(ch)
}

fn is_atomend(ch: char) -> bool {
    is_in(ch, SPECIALS) || is_in(ch, LWS) || is_in(ch, CR)
}

fn is_phraseend(ch: char) -> bool {
    ch != '.' && is_atomend(ch)
}

/// `email._parseaddr.quote`.
fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

impl AddrList {
    fn new(field: &str) -> Self {
        Self {
            field: field.chars().collect(),
            pos: 0,
            commentlist: Vec::new(),
        }
    }

    fn at(&self) -> char {
        self.field[self.pos]
    }

    fn more(&self) -> bool {
        self.pos < self.field.len()
    }

    fn gotonext(&mut self) -> String {
        let mut whitespace = String::new();
        while self.more() {
            let ch = self.at();
            if is_in(ch, " \t\n\r") {
                if !is_in(ch, "\n\r") {
                    whitespace.push(ch);
                }
                self.pos += 1;
            } else if ch == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else {
                break;
            }
        }
        whitespace
    }

    fn getaddrlist(&mut self) -> Vec<ParsedAddress> {
        let mut result = Vec::new();
        while self.more() {
            let addresses = self.getaddress();
            if addresses.is_empty() {
                result.push(ParsedAddress::empty());
            } else {
                result.extend(addresses);
            }
        }
        result
    }

    fn getaddress(&mut self) -> Vec<ParsedAddress> {
        self.commentlist.clear();
        self.gotonext();
        let oldpos = self.pos;
        let oldcl = self.commentlist.clone();
        let plist = self.getphraselist();
        self.gotonext();
        let mut returnlist = Vec::new();

        if !self.more() {
            if let Some(first) = plist.first() {
                returnlist.push(ParsedAddress::new(
                    self.commentlist.join(" "),
                    first.clone(),
                ));
            }
        } else if is_in(self.at(), ".@") {
            self.pos = oldpos;
            self.commentlist = oldcl;
            let addrspec = self.getaddrspec();
            returnlist.push(ParsedAddress::new(self.commentlist.join(" "), addrspec));
        } else if self.at() == ':' {
            let fieldlen = self.field.len();
            self.pos += 1;
            while self.more() {
                self.gotonext();
                if self.pos < fieldlen && self.at() == ';' {
                    self.pos += 1;
                    break;
                }
                let more = self.getaddress();
                returnlist.extend(more);
            }
        } else if self.at() == '<' {
            let routeaddr = self.getrouteaddr();
            let name = if self.commentlist.is_empty() {
                plist.join(" ")
            } else {
                format!("{} ({})", plist.join(" "), self.commentlist.join(" "))
            };
            returnlist.push(ParsedAddress {
                name,
                addr: routeaddr,
                phrase: plist.clone(),
            });
        } else if let Some(first) = plist.first() {
            returnlist.push(ParsedAddress::new(
                self.commentlist.join(" "),
                first.clone(),
            ));
        } else if is_in(self.at(), SPECIALS) {
            self.pos += 1;
        }

        self.gotonext();
        if self.more() && self.at() == ',' {
            self.pos += 1;
        }
        returnlist
    }

    fn getrouteaddr(&mut self) -> String {
        if self.at() != '<' {
            return String::new();
        }
        let mut expectroute = false;
        self.pos += 1;
        self.gotonext();
        let mut adlist = String::new();
        while self.more() {
            if expectroute {
                self.getdomain();
                expectroute = false;
            } else if self.at() == '>' {
                self.pos += 1;
                break;
            } else if self.at() == '@' {
                self.pos += 1;
                expectroute = true;
            } else if self.at() == ':' {
                self.pos += 1;
            } else {
                adlist = self.getaddrspec();
                self.pos += 1;
                break;
            }
            self.gotonext();
        }
        adlist
    }

    fn getaddrspec(&mut self) -> String {
        let mut aslist: Vec<String> = Vec::new();
        self.gotonext();
        while self.more() {
            let mut preserve_ws = true;
            let ch = self.at();
            if ch == '.' {
                if aslist
                    .last()
                    .is_some_and(|last| last.trim_matches(py_isspace).is_empty())
                {
                    aslist.pop();
                }
                aslist.push(".".into());
                self.pos += 1;
                preserve_ws = false;
            } else if ch == '"' {
                let quoted = self.getquote();
                aslist.push(format!("\"{}\"", quote(&quoted)));
            } else if is_atomend(ch) {
                if aslist
                    .last()
                    .is_some_and(|last| last.trim_matches(py_isspace).is_empty())
                {
                    aslist.pop();
                }
                break;
            } else {
                let atom = self.getatom(is_atomend);
                aslist.push(atom);
            }
            let ws = self.gotonext();
            if preserve_ws && !ws.is_empty() {
                aslist.push(ws);
            }
        }
        if !self.more() || self.at() != '@' {
            return aslist.concat();
        }
        aslist.push("@".into());
        self.pos += 1;
        self.gotonext();
        let domain = self.getdomain();
        if domain.is_empty() {
            return String::new();
        }
        aslist.concat() + &domain
    }

    fn getdomain(&mut self) -> String {
        let mut sdlist: Vec<String> = Vec::new();
        while self.more() {
            let ch = self.at();
            if is_in(ch, LWS) {
                self.pos += 1;
            } else if ch == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if ch == '[' {
                let literal = self.getdomainliteral();
                sdlist.push(literal);
            } else if ch == '.' {
                self.pos += 1;
                sdlist.push(".".into());
            } else if ch == '@' {
                return String::new();
            } else if is_atomend(ch) {
                break;
            } else {
                let atom = self.getatom(is_atomend);
                sdlist.push(atom);
            }
        }
        sdlist.concat()
    }

    fn getdelimited(&mut self, beginchar: char, endchars: &str, allowcomments: bool) -> String {
        if self.at() != beginchar {
            return String::new();
        }
        let mut out = String::new();
        let mut quoted = false;
        self.pos += 1;
        while self.more() {
            let ch = self.at();
            if quoted {
                out.push(ch);
                quoted = false;
            } else if is_in(ch, endchars) {
                self.pos += 1;
                break;
            } else if allowcomments && ch == '(' {
                let comment = self.getcomment();
                out.push_str(&comment);
                continue;
            } else if ch == '\\' {
                quoted = true;
            } else {
                out.push(ch);
            }
            self.pos += 1;
        }
        out
    }

    fn getquote(&mut self) -> String {
        self.getdelimited('"', "\"\r", false)
    }

    fn getcomment(&mut self) -> String {
        self.getdelimited('(', ")\r", true)
    }

    fn getdomainliteral(&mut self) -> String {
        format!("[{}]", self.getdelimited('[', "]\r", false))
    }

    fn getatom(&mut self, ends: fn(char) -> bool) -> String {
        let mut atom = String::new();
        while self.more() {
            let ch = self.at();
            if ends(ch) {
                break;
            }
            atom.push(ch);
            self.pos += 1;
        }
        atom
    }

    fn getphraselist(&mut self) -> Vec<String> {
        let mut plist = Vec::new();
        while self.more() {
            let ch = self.at();
            if is_in(ch, " \t\r\n") {
                self.pos += 1;
            } else if ch == '"' {
                let quoted = self.getquote();
                plist.push(quoted);
            } else if ch == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if is_phraseend(ch) {
                break;
            } else {
                let atom = self.getatom(is_phraseend);
                plist.push(atom);
            }
        }
        plist
    }
}

/// `email._parseaddr.AddressList(field).addresslist`.
fn address_list(field: &str) -> Vec<ParsedAddress> {
    if field.is_empty() {
        return Vec::new();
    }
    AddrList::new(field).getaddrlist()
}

/// `email.utils._iter_escaped_chars`: (position, char, escaped).
fn iter_escaped_chars(addr: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut escape = false;
    let mut last = 0;
    for (pos, ch) in addr.chars().enumerate() {
        last = pos;
        if escape {
            out.push((pos, format!("\\{ch}")));
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else {
            out.push((pos, ch.to_string()));
        }
    }
    if escape {
        out.push((last, "\\".into()));
    }
    out
}

/// `email.utils._strip_quoted_realnames`.
fn strip_quoted_realnames(addr: &str) -> String {
    if !addr.contains('"') {
        return addr.to_owned();
    }
    let chars: Vec<char> = addr.chars().collect();
    let mut start = 0;
    let mut open_pos: Option<usize> = None;
    let mut result = String::new();
    for (pos, ch) in iter_escaped_chars(addr) {
        if ch == "\"" {
            match open_pos {
                None => open_pos = Some(pos),
                Some(open) => {
                    if start != open {
                        result.extend(&chars[start..open]);
                    }
                    start = pos + 1;
                    open_pos = None;
                }
            }
        }
    }
    if start < chars.len() {
        result.extend(&chars[start..]);
    }
    result
}

/// `email.utils._check_parenthesis`.
fn check_parenthesis(addr: &str) -> bool {
    let stripped = strip_quoted_realnames(addr);
    let mut opens = 0i64;
    for (_, ch) in iter_escaped_chars(&stripped) {
        if ch == "(" {
            opens += 1;
        } else if ch == ")" {
            opens -= 1;
            if opens < 0 {
                return false;
            }
        }
    }
    opens == 0
}

fn pre_parse_validation(value: &str) -> String {
    if check_parenthesis(value) {
        value.to_owned()
    } else {
        "('', '')".to_owned()
    }
}

fn post_parse_validation(addresses: Vec<ParsedAddress>) -> Vec<ParsedAddress> {
    addresses
        .into_iter()
        .map(|address| {
            if address.addr.contains('[') {
                ParsedAddress::empty()
            } else {
                address
            }
        })
        .collect()
}

/// Python 3.12 `email.utils.parseaddr(addr)` (strict mode), keeping phrase words.
pub fn parseaddr_full(addr: &str) -> ParsedAddress {
    let addr = pre_parse_validation(addr);
    let addresses = post_parse_validation(address_list(&addr));
    if addresses.len() != 1 {
        return ParsedAddress::empty();
    }
    addresses.into_iter().next().expect("exactly one")
}

/// Python 3.12 `email.utils.parseaddr(addr)` → (realname, email).
pub fn parseaddr(addr: &str) -> (String, String) {
    let parsed = parseaddr_full(addr);
    (parsed.name, parsed.addr)
}

/// Python 3.12 `email.utils.getaddresses([value])` (strict mode).
pub fn getaddresses(value: &str) -> Vec<(String, String)> {
    let value = pre_parse_validation(value);
    let result = post_parse_validation(address_list(&value));
    let expected = 1 + strip_quoted_realnames(&value).matches(',').count();
    if result.len() != expected {
        return vec![(String::new(), String::new())];
    }
    result
        .into_iter()
        .map(|address| (address.name, address.addr))
        .collect()
}

const MONTHNAMES: [&str; 24] = [
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];
const DAYNAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn timezone_offset(name: &str) -> Option<i64> {
    Some(match name {
        "UT" | "UTC" | "GMT" | "Z" => 0,
        "AST" => -400,
        "ADT" => -300,
        "EST" => -500,
        "EDT" => -400,
        "CST" => -600,
        "CDT" => -500,
        "MST" => -700,
        "MDT" => -600,
        "PST" => -800,
        "PDT" => -700,
        _ => return None,
    })
}

/// Python `int(text)` for decimal strings (sign, digits, single underscores).
fn py_int(text: &str) -> Option<i64> {
    let text = text.trim_matches(py_isspace);
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut value: i64 = 0;
    for ch in digits.chars() {
        if ch == '_' {
            continue;
        }
        let digit = ch.to_digit(10)? as i64;
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(if negative { -value } else { value })
}

/// Result of `_parsedate_tz`: date-time fields and the tz offset in seconds
/// (`None` for "-0000" / unknown zones, i.e. a naive datetime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedDate {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    pub offset: Option<i64>,
}

/// Port of `email._parseaddr._parsedate_tz`.
pub fn parsedate_tz(data: &str) -> Option<ParsedDate> {
    if data.is_empty() {
        return None;
    }
    let mut data: Vec<String> = py_split(data).into_iter().map(str::to_owned).collect();
    if data.is_empty() {
        return None;
    }
    if data[0].ends_with(',') || DAYNAMES.contains(&data[0].to_lowercase().as_str()) {
        data.remove(0);
    } else if let Some(i) = data[0].rfind(',') {
        data[0] = data[0][i + 1..].to_owned();
    }
    if data.len() == 3 {
        let stuff: Vec<String> = data[0].split('-').map(str::to_owned).collect();
        if stuff.len() == 3 {
            let mut joined = stuff;
            joined.extend(data[1..].iter().cloned());
            data = joined;
        }
    }
    if data.len() == 4 {
        let s = data[3].clone();
        let i = s.find('+').or_else(|| s.find('-'));
        match i {
            Some(i) if i > 0 => {
                data.truncate(3);
                data.push(s[..i].to_owned());
                data.push(s[i..].to_owned());
            }
            _ => data.push(String::new()),
        }
    }
    if data.len() < 5 {
        return None;
    }
    data.truncate(5);
    let [mut dd, mut mm, mut yy, mut tm, mut tz]: [String; 5] = data.try_into().ok()?;
    if dd.is_empty() || mm.is_empty() || yy.is_empty() {
        return None;
    }
    mm = mm.to_lowercase();
    if !MONTHNAMES.contains(&mm.as_str()) {
        let swapped = dd.to_lowercase();
        dd = mm;
        mm = swapped;
        if !MONTHNAMES.contains(&mm.as_str()) {
            return None;
        }
    }
    let mut month = MONTHNAMES
        .iter()
        .position(|name| *name == mm)
        .expect("checked") as i64
        + 1;
    if month > 12 {
        month -= 12;
    }
    if dd.ends_with(',') {
        dd.pop();
    }
    if yy.find(':').is_some_and(|i| i > 0) {
        std::mem::swap(&mut yy, &mut tm);
    }
    if yy.ends_with(',') {
        yy.pop();
        if yy.is_empty() {
            return None;
        }
    }
    if !yy.chars().next().is_some_and(|c| c.is_numeric()) {
        std::mem::swap(&mut yy, &mut tz);
    }
    if tm.ends_with(',') {
        tm.pop();
    }
    let parts: Vec<&str> = tm.split(':').collect();
    let (thh, tmm, tss): (String, String, String) = match parts.as_slice() {
        [h, m] => ((*h).into(), (*m).into(), "0".into()),
        [h, m, s] => ((*h).into(), (*m).into(), (*s).into()),
        [single] if single.contains('.') => {
            let dotted: Vec<&str> = single.split('.').collect();
            match dotted.as_slice() {
                [h, m] => ((*h).into(), (*m).into(), "0".into()),
                [h, m, s] => ((*h).into(), (*m).into(), (*s).into()),
                _ => return None,
            }
        }
        _ => return None,
    };
    let mut year = py_int(&yy)?;
    let day = py_int(&dd)?;
    let hour = py_int(&thh)?;
    let minute = py_int(&tmm)?;
    let second = py_int(&tss)?;
    if year < 100 {
        year += if year > 68 { 1900 } else { 2000 };
    }
    let tz = tz.to_uppercase();
    let mut offset = timezone_offset(&tz);
    if offset.is_none() {
        offset = py_int(&tz);
        if offset == Some(0) && tz.starts_with('-') {
            offset = None;
        }
    }
    if let Some(value) = offset {
        if value != 0 {
            let (sign, magnitude) = if value < 0 { (-1, -value) } else { (1, value) };
            offset = Some(sign * ((magnitude / 100) * 3600 + (magnitude % 100) * 60));
        }
    }
    Some(ParsedDate {
        year,
        month,
        day,
        hour,
        minute,
        second,
        offset,
    })
}

/// `eml_extract._parse_date`: RFC 2822 date → UTC ISO 8601 string, or `None`.
pub fn parse_date_iso(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let parsed = parsedate_tz(value)?;
    // datetime(*fields) validation.
    let year = i32::try_from(parsed.year)
        .ok()
        .filter(|y| (1..=9999).contains(y))?;
    let date = NaiveDate::from_ymd_opt(
        year,
        u32::try_from(parsed.month).ok()?,
        u32::try_from(parsed.day).ok()?,
    )?;
    if !(0..24).contains(&parsed.hour)
        || !(0..60).contains(&parsed.minute)
        || !(0..60).contains(&parsed.second)
    {
        return None;
    }
    let local = date.and_hms_opt(
        parsed.hour as u32,
        parsed.minute as u32,
        parsed.second as u32,
    )?;
    let offset = parsed.offset.unwrap_or(0);
    // datetime.timezone requires -24h < offset < 24h.
    if offset.abs() >= 86_400 {
        return None;
    }
    let utc = local.checked_sub_signed(Duration::seconds(offset))?;
    if !(1..=9999).contains(&chrono::Datelike::year(&utc)) {
        return None; // OverflowError in astimezone()
    }
    Some(format!("{}+00:00", utc.format("%Y-%m-%dT%H:%M:%S")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_cases() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/pipeline/unit_cases.json"
        ))
        .unwrap()
    }

    #[test]
    fn dates_match_python_golden_cases() {
        for case in unit_cases()["dates"].as_array().unwrap() {
            let input = case[0].as_str().unwrap();
            assert_eq!(
                parse_date_iso(input).as_deref(),
                case[1].as_str(),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn parseaddr_matches_python_golden_cases() {
        for case in unit_cases()["parseaddr"].as_array().unwrap() {
            let input = case[0].as_str().unwrap();
            let (name, addr) = parseaddr(input);
            assert_eq!(name, case[1][0].as_str().unwrap(), "name of {input:?}");
            assert_eq!(addr, case[1][1].as_str().unwrap(), "addr of {input:?}");
        }
    }

    #[test]
    fn first_address_matches_python_golden_cases() {
        for case in unit_cases()["first_address"].as_array().unwrap() {
            let input = case[0].as_str().unwrap();
            let first = getaddresses(input)
                .into_iter()
                .next()
                .map(|(_, a)| a)
                .unwrap_or_default();
            assert_eq!(first, case[1].as_str().unwrap(), "input {input:?}");
        }
    }
}
