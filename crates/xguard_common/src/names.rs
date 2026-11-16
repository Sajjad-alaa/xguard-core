//! Names that admins give to objects and that the web UI shows, sometimes inside Markdown.

/// Punctuation allowed in names besides letters and digits.
const ALLOWED_SYMBOLS: [char; 8] = [' ', '-', '_', '.', '(', ')', ':', '/'];

/// Whether `name` is non-empty and uses only letters, digits and a few harmless symbols, so it
/// cannot inject HTML or Markdown where it is displayed.
#[must_use]
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || ALLOWED_SYMBOLS.contains(&c))
}

#[cfg(test)]
mod tests {
    use super::is_safe_name;

    #[test]
    fn safe_names() {
        for good in ["ci", "Deploy bot (prod)", "web: 443/tcp", "zażółć_1.0"] {
            assert!(is_safe_name(good), "{good}");
        }
        for bad in [
            "",
            "<b>x</b>",
            "[x](javascript:alert(1))",
            "a*b",
            "line\nbreak",
            "`x`",
        ] {
            assert!(!is_safe_name(bad), "{bad}");
        }
    }
}
