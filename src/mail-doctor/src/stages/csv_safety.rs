//! Keep untrusted email text literal when reports are opened in a spreadsheet
//! (port of `services/stages/csv_safety.py`).
//!
//! The writer reproduces Python's `csv.writer` with the default `excel`
//! dialect: `,` delimiter, `"` quote character with doubling, `QUOTE_MINIMAL`
//! and `\r\n` record terminators.

use std::io::{self, Write};

use super::py_header::py_isspace;

/// One CSV field. Python only applies `safe_cell` to `str` values, so numbers
/// are kept separate.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Text(String),
    Int(i64),
}

impl From<&str> for Cell {
    fn from(value: &str) -> Self {
        Cell::Text(value.to_owned())
    }
}

impl From<String> for Cell {
    fn from(value: String) -> Self {
        Cell::Text(value)
    }
}

impl From<i64> for Cell {
    fn from(value: i64) -> Self {
        Cell::Int(value)
    }
}

impl From<usize> for Cell {
    fn from(value: usize) -> Self {
        Cell::Int(value as i64)
    }
}

/// `csv_safety.safe_cell`: prefix formula-like text with `'`.
pub fn safe_cell(value: Cell) -> Cell {
    match value {
        Cell::Text(text) => {
            let risky = text.chars().next().is_some_and(|first| {
                "=+-@".contains(first)
                    || py_isspace(first)
                    || (first as u32) < 32
                    || first as u32 == 127
            });
            if risky {
                Cell::Text(format!("'{text}"))
            } else {
                Cell::Text(text)
            }
        }
        other => other,
    }
}

fn render_field(cell: &Cell, sole_field: bool) -> String {
    let text = match cell {
        Cell::Text(text) => text.clone(),
        Cell::Int(value) => value.to_string(),
    };
    if sole_field && text.is_empty() {
        return "\"\"".to_owned();
    }
    if text.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

/// `csv_safety.SafeCsvWriter`.
pub struct SafeCsvWriter<W: Write> {
    stream: W,
}

impl<W: Write> SafeCsvWriter<W> {
    /// `csv_safety.writer(stream)`.
    pub fn new(stream: W) -> Self {
        Self { stream }
    }

    pub fn writerow(&mut self, row: Vec<Cell>) -> io::Result<()> {
        let sole = row.len() == 1;
        let line: Vec<String> = row
            .into_iter()
            .map(|cell| render_field(&safe_cell(cell), sole))
            .collect();
        self.stream.write_all(line.join(",").as_bytes())?;
        self.stream.write_all(b"\r\n")
    }

    pub fn writerows(&mut self, rows: impl IntoIterator<Item = Vec<Cell>>) -> io::Result<()> {
        for row in rows {
            self.writerow(row)?;
        }
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.stream
    }
}

/// `csv_safety.writer(stream)`.
pub fn writer<W: Write>(stream: W) -> SafeCsvWriter<W> {
    SafeCsvWriter::new(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_prefixes_are_neutralized() {
        for risky in [
            "=SUM(A1)", "+1", "-1", "@cmd", " lead", "\tx", "\u{1}x", "\u{7f}x",
        ] {
            assert_eq!(safe_cell(risky.into()), Cell::Text(format!("'{risky}")));
        }
        assert_eq!(safe_cell("plain".into()), Cell::Text("plain".into()));
        assert_eq!(safe_cell("".into()), Cell::Text(String::new()));
        assert_eq!(safe_cell(Cell::Int(-5)), Cell::Int(-5));
    }

    #[test]
    fn rows_are_quoted_like_python_csv() {
        let mut w = writer(Vec::new());
        w.writerow(vec![
            "a,b".into(),
            "say \"hi\"".into(),
            "line\nbreak".into(),
            Cell::Int(3),
            "=x".into(),
        ])
        .unwrap();
        w.writerow(vec!["".into()]).unwrap();
        w.writerow(vec!["".into(), "".into()]).unwrap();
        let out = String::from_utf8(w.into_inner()).unwrap();
        assert_eq!(
            out,
            "\"a,b\",\"say \"\"hi\"\"\",\"line\nbreak\",3,'=x\r\n\"\"\r\n,\r\n"
        );
    }
}
