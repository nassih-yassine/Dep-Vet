//! Version strings across nine ecosystems. Only one fact is needed: the
//! leading number, used to label a major jump. Nothing here orders versions.

/// First number in a version, ignoring a leading `v` and a PyPI epoch.
///
/// `v1.9.1` → 1, `1!2.0` → 2, `3.2.0.RELEASE` → 3, `abc` → None.
pub fn leading_number(version: &str) -> Option<u64> {
    let trimmed = version.trim();
    let without_v = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    let after_epoch = without_v
        .rsplit_once('!')
        .map(|(_, rest)| rest)
        .unwrap_or(without_v);
    let digits: String = after_epoch
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_leading_number_across_ecosystems() {
        assert_eq!(leading_number("1.2.3"), Some(1));
        assert_eq!(leading_number("v1.9.1"), Some(1));
        assert_eq!(leading_number("1!2.0"), Some(2));
        assert_eq!(leading_number("3.2.0.RELEASE"), Some(3));
        assert_eq!(leading_number("0.0.1"), Some(0));
        assert_eq!(leading_number("  v2.0 "), Some(2));
        assert_eq!(leading_number("abc"), None);
        assert_eq!(leading_number(""), None);
    }
}
