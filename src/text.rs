pub(crate) fn truncate_with_marker(text: &str, max_chars: usize, marker: &str) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated.push_str(marker);
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_limit_returns_original_text() {
        assert_eq!(truncate_with_marker("abc", 5, "..."), "abc");
    }

    #[test]
    fn exact_limit_returns_original_text() {
        assert_eq!(truncate_with_marker("abc", 3, "..."), "abc");
    }

    #[test]
    fn over_limit_appends_marker() {
        assert_eq!(truncate_with_marker("abcdef", 3, "..."), "abc...");
    }

    #[test]
    fn multibyte_characters_are_truncated_on_char_boundaries() {
        assert_eq!(truncate_with_marker("żółć", 3, "..."), "żół...");
        assert_eq!(truncate_with_marker("a🙂b", 2, "…"), "a🙂…");
    }
}
