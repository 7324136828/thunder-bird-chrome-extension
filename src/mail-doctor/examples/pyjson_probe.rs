//! Decode each file argument like Python's
//! `json.loads(path.read_text(encoding="utf-8"))` and print one JSON line
//! per file: `["ok", repr(value)]` or `["err", str(error)]`. Used for
//! differential testing of the Python-compatible decoder.

use mail_doctor::stages::pyjson::Json;

fn main() {
    for path in std::env::args().skip(1) {
        let line = match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| Json::loads_file_bytes(&bytes))
        {
            Ok(value) => serde_json::json!(["ok", value.py_repr()]),
            Err(error) => serde_json::json!(["err", error]),
        };
        println!("{line}");
    }
}
