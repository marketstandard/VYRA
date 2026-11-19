//! Canonical JSON output and small accessors for reading JSON back.
//!
//! Output is byte-stable: object keys sorted by byte order, two-space
//! indentation, `\n` line endings, a trailing newline, strings escaped by
//! `serde_json`. It does not depend on which `serde_json` map features are
//! enabled elsewhere in the build.

use std::fmt::Write as _;

use serde_json::Value;

/// Render `value` canonically, with a trailing newline.
pub fn to_canonical(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, 0, &mut out);
    out.push('\n');
    out
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_value(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            let _ = write!(out, "{value}");
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                indent(level + 1, out);
                write_value(item, level + 1, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(level, out);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push_str("{\n");
            for (i, key) in keys.iter().enumerate() {
                indent(level + 1, out);
                let _ = write!(out, "{}: ", Value::String((*key).clone()));
                if let Some(v) = map.get(*key) {
                    write_value(v, level + 1, out);
                }
                if i + 1 < keys.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(level, out);
            out.push('}');
        }
    }
}

/// Parse JSON text.
pub fn parse(text: &str, what: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("{what}: invalid JSON: {e}"))
}

/// `value[key]` as a string.
pub fn str_field<'a>(value: &'a Value, key: &str, ctx: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{ctx}: missing string field `{key}`"))
}

/// `value[key]` as an unsigned integer.
pub fn u64_field(value: &Value, key: &str, ctx: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{ctx}: missing integer field `{key}`"))
}

/// `value[key]` as an array.
pub fn array_field<'a>(value: &'a Value, key: &str, ctx: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{ctx}: missing array field `{key}`"))
}

/// `value[key]` decoded from hex.
pub fn hex_field(value: &Value, key: &str, ctx: &str) -> Result<Vec<u8>, String> {
    let text = str_field(value, key, ctx)?;
    crate::hex::decode(text).map_err(|e| format!("{ctx}: field `{key}`: {e}"))
}

/// Collect human-readable differences between `stored` and `computed`,
/// at most `limit` of them, with JSON-pointer-like paths.
pub fn diff(path: &str, stored: &Value, computed: &Value, out: &mut Vec<String>, limit: usize) {
    if out.len() >= limit || stored == computed {
        return;
    }
    match (stored, computed) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let p = format!("{path}/{k}");
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => diff(&p, x, y, out, limit),
                    (Some(_), None) => {
                        push(out, limit, format!("{p}: present in file, not generated"))
                    }
                    (None, Some(_)) => push(out, limit, format!("{p}: generated, missing in file")),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                push(
                    out,
                    limit,
                    format!(
                        "{path}: file has {} entries, generated {}",
                        a.len(),
                        b.len()
                    ),
                );
            }
            for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                diff(&format!("{path}/{i}"), x, y, out, limit);
            }
        }
        _ => push(
            out,
            limit,
            format!(
                "{path}: file has {}, generated {}",
                short(stored),
                short(computed)
            ),
        ),
    }
}

fn push(out: &mut Vec<String>, limit: usize, msg: String) {
    if out.len() < limit {
        out.push(msg);
    }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 80 {
        let head: String = s.chars().take(76).collect();
        format!("{head}...\"")
    } else {
        s
    }
}

/// First differing line between two texts: `(line_number, file_line, generated_line)`.
pub fn first_line_diff(file: &str, generated: &str) -> Option<(usize, String, String)> {
    let mut a = file.split('\n');
    let mut b = generated.split('\n');
    let mut n = 0usize;
    loop {
        n += 1;
        match (a.next(), b.next()) {
            (None, None) => return None,
            (x, y) if x == y => {}
            (x, y) => {
                return Some((
                    n,
                    x.unwrap_or("<end of file>").to_string(),
                    y.unwrap_or("<end of file>").to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_is_sorted_and_stable() {
        let a = json!({"b": 1, "a": [true, null, "x\"y"], "c": {"z": {}, "y": []}});
        let text = to_canonical(&a);
        let expected = "{\n  \"a\": [\n    true,\n    null,\n    \"x\\\"y\"\n  ],\n  \"b\": 1,\n  \"c\": {\n    \"y\": [],\n    \"z\": {}\n  }\n}\n";
        assert_eq!(text, expected);
        // Round trip through the parser reproduces the same bytes.
        let back = parse(&text, "t").unwrap();
        assert_eq!(to_canonical(&back), text);
        assert!(!text.contains('\r'));
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let mut m1 = serde_json::Map::new();
        m1.insert("x".into(), json!(1));
        m1.insert("a".into(), json!(2));
        let mut m2 = serde_json::Map::new();
        m2.insert("a".into(), json!(2));
        m2.insert("x".into(), json!(1));
        assert_eq!(
            to_canonical(&Value::Object(m1)),
            to_canonical(&Value::Object(m2))
        );
    }

    #[test]
    fn diff_reports_paths() {
        let a = json!({"v": [{"k": "00"}, {"k": "11"}]});
        let b = json!({"v": [{"k": "00"}, {"k": "12"}]});
        let mut out = Vec::new();
        diff("", &a, &b, &mut out, 10);
        assert_eq!(
            out,
            vec!["/v/1/k: file has \"11\", generated \"12\"".to_string()]
        );
    }

    #[test]
    fn first_line_diff_finds_line() {
        assert_eq!(first_line_diff("a\nb\n", "a\nb\n"), None);
        let d = first_line_diff("a\nb\nc\n", "a\nX\nc\n").unwrap();
        assert_eq!(d, (2, "b".to_string(), "X".to_string()));
    }
}
