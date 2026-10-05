//! JSON as sing-box reads it: with `//` and `/* */` comments, and a comma
//! after the last element or member. Both are blanked out, so that the
//! lines and columns of what is left stay where they were.

/// `text` with its comments and trailing commas turned into spaces.
pub fn strip(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    // A comma seen outside strings, not yet followed by anything but
    // spaces and comments.
    let mut pending_comma: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                pending_comma = None;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    // An escape takes the next byte with it.
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    if bytes[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
                // The closing `*/`, when there is one.
                let end = (i + 2).min(bytes.len());
                out[i..end].fill(b' ');
                i += 2;
            }
            b',' => {
                pending_comma = Some(i);
                i += 1;
            }
            b'}' | b']' => {
                if let Some(comma) = pending_comma.take() {
                    out[comma] = b' ';
                }
                i += 1;
            }
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            _ => {
                pending_comma = None;
                i += 1;
            }
        }
    }
    // Only ASCII was replaced, by ASCII: still UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

/// The first character of `text` that is not space or a comment, as
/// `strip(text).trim_start()` would start with, without the copy.
pub fn first(text: &str) -> Option<char> {
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.split_once('\n').map_or("", |(_, r)| r);
        } else if let Some(after) = rest.strip_prefix("/*") {
            // Unclosed, it runs to the end, as `strip` blanks it.
            rest = after.split_once("*/").map_or("", |(_, r)| r);
        } else {
            return rest.chars().next();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{first, strip};

    #[test]
    fn the_first_character_is_past_spaces_and_comments() {
        for text in [
            "{}",
            "  // a\n/* b */ {",
            "/* a */\n// b\n\t[1]",
            "",
            "// only",
            "/* open",
            "x: 1",
            "/**/{",
        ] {
            assert_eq!(
                first(text),
                strip(text).trim_start().chars().next(),
                "{:?}",
                text
            );
        }
    }

    #[test]
    fn comments_and_trailing_commas_become_spaces() {
        let text = "{\n  // a comment, with \"quotes\"\n  \"a\": \"x // not a comment\",\n  /* block\n  */ \"b\": [1, 2,],\n  \"c\": \"\\\" /* still a string */\", // end\n}";
        let stripped = strip(text);
        assert_eq!(stripped.len(), text.len());
        assert_eq!(stripped.lines().count(), text.lines().count());
        let value: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(value["a"], "x // not a comment");
        assert_eq!(value["b"], serde_json::json!([1, 2]));
        assert_eq!(value["c"], "\" /* still a string */");
    }

    #[test]
    fn a_comma_before_more_is_kept_and_errors_stay_in_place() {
        assert_eq!(strip("[1, /* x */ 2]"), "[1,         2]");
        let err = serde_json::from_str::<serde_json::Value>(&strip("{\n// c\n\"a\": nope\n}"))
            .unwrap_err();
        assert_eq!(err.line(), 3);
    }
}
