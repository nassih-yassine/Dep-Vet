//! SPDX license normalisation.
//!
//! Registries spell the same license in many ways ("MIT", "MIT License",
//! "Apache 2.0"). Policy compares one canonical id, so the aliases are mapped
//! here instead of asking every ecosystem to agree. A value that is not
//! recognised is kept verbatim rather than guessed.

/// Common spellings mapped to their SPDX identifier. Matching is
/// case-insensitive and ignores surrounding whitespace.
const ALIASES: &[(&str, &str)] = &[
    ("mit", "MIT"),
    ("mit license", "MIT"),
    ("expat", "MIT"),
    ("apache 2.0", "Apache-2.0"),
    ("apache-2.0", "Apache-2.0"),
    ("apache license 2.0", "Apache-2.0"),
    ("apache license, version 2.0", "Apache-2.0"),
    ("apache software license 2.0", "Apache-2.0"),
    ("apache software license", "Apache-2.0"),
    ("asl 2.0", "Apache-2.0"),
    ("bsd-3-clause", "BSD-3-Clause"),
    ("bsd 3-clause", "BSD-3-Clause"),
    ("new bsd license", "BSD-3-Clause"),
    ("revised bsd license", "BSD-3-Clause"),
    ("bsd-2-clause", "BSD-2-Clause"),
    ("bsd 2-clause", "BSD-2-Clause"),
    ("simplified bsd license", "BSD-2-Clause"),
    ("isc", "ISC"),
    ("isc license", "ISC"),
    ("mpl-2.0", "MPL-2.0"),
    ("mozilla public license 2.0", "MPL-2.0"),
    ("mozilla public license 2.0 (mpl 2.0)", "MPL-2.0"),
    ("gpl-2.0", "GPL-2.0-only"),
    ("gpl-2.0-only", "GPL-2.0-only"),
    ("gpl-2.0-or-later", "GPL-2.0-or-later"),
    ("gnu general public license v2", "GPL-2.0-only"),
    ("gnu general public license v2 (gplv2)", "GPL-2.0-only"),
    ("gpl-3.0", "GPL-3.0-only"),
    ("gpl-3.0-only", "GPL-3.0-only"),
    ("gpl-3.0-or-later", "GPL-3.0-or-later"),
    ("gnu general public license v3", "GPL-3.0-only"),
    ("gnu general public license v3 (gplv3)", "GPL-3.0-only"),
    ("lgpl-3.0", "LGPL-3.0-only"),
    ("lgpl-3.0-only", "LGPL-3.0-only"),
    (
        "gnu lesser general public license v3 (lgplv3)",
        "LGPL-3.0-only",
    ),
    ("agpl-3.0", "AGPL-3.0-only"),
    ("agpl-3.0-only", "AGPL-3.0-only"),
    ("unlicense", "Unlicense"),
    ("the unlicense", "Unlicense"),
    ("wtfpl", "WTFPL"),
    ("zlib", "Zlib"),
    ("cc0-1.0", "CC0-1.0"),
    ("cc0", "CC0-1.0"),
    ("creative commons zero v1.0 universal", "CC0-1.0"),
    ("python software foundation license", "PSF-2.0"),
    ("epl-2.0", "EPL-2.0"),
    ("artistic-2.0", "Artistic-2.0"),
    ("blueoak-1.0.0", "BlueOak-1.0.0"),
];

/// Canonicalise a registry license value. Empty and clearly invalid values
/// become `None`, which the report shows as not checked.
pub fn normalize(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('"').trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return None;
    }
    if !trimmed.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                '-' | '.' | '+' | '(' | ')' | ' ' | ',' | ':' | '/'
            )
    }) {
        return None;
    }
    let folded = trimmed.to_ascii_lowercase();
    if let Some((_, id)) = ALIASES.iter().find(|(alias, _)| *alias == folded) {
        return Some((*id).to_string());
    }
    // A phrase with spaces is only kept when it looks like an SPDX expression;
    // registry fields also hold prose such as "see LICENSE file".
    let upper = trimmed.to_ascii_uppercase();
    if trimmed.contains(' ')
        && ![" OR ", " AND ", " WITH "]
            .iter()
            .any(|operator| upper.contains(operator))
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// A registry license field may be a string or an object such as npm's
/// `{ "type": "MIT", "url": ... }`.
pub fn from_json(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) => normalize(raw),
        serde_json::Value::Object(map) => map
            .get("type")
            .and_then(serde_json::Value::as_str)
            .and_then(normalize),
        _ => None,
    }
}

/// Case-insensitive comparison against a configured list, after normalising
/// both sides so `MIT` and `MIT License` match. A compound expression such as
/// `MIT OR Apache-2.0` matches when any member is listed.
pub fn any_listed(list: &[String], license: &str) -> bool {
    members(license).iter().any(|member| {
        list.iter()
            .filter_map(|entry| normalize(entry))
            .any(|entry| entry.eq_ignore_ascii_case(member))
    })
}

/// The deny-unfriendly comparison: every member of an expression must be on
/// the list, so `MIT OR GPL-3.0-only` does not pass an `MIT` allowlist.
pub fn all_listed(list: &[String], license: &str) -> bool {
    let members = members(license);
    !members.is_empty()
        && members.iter().all(|member| {
            list.iter()
                .filter_map(|entry| normalize(entry))
                .any(|entry| entry.eq_ignore_ascii_case(member))
        })
}

fn members(license: &str) -> Vec<String> {
    let Some(license) = normalize(license) else {
        return Vec::new();
    };
    license
        .split(['(', ')'])
        .flat_map(|part| {
            part.split(" OR ")
                .flat_map(|part| part.split(" AND "))
                .flat_map(|part| part.split(" WITH "))
        })
        .filter_map(normalize)
        .collect()
}

/// SPDX's page for an identifier, used as finding evidence. An expression with
/// spaces or operators has no single page, so it gets the license list root.
pub fn reference(license: &str) -> String {
    let Some(license) = normalize(license) else {
        return "https://spdx.org/licenses/".to_string();
    };
    let single = license
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '+'));
    if single {
        format!("https://spdx.org/licenses/{license}.html")
    } else {
        "https://spdx.org/licenses/".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_fold_to_spdx_ids() {
        assert_eq!(normalize("MIT").as_deref(), Some("MIT"));
        assert_eq!(normalize(" mit license ").as_deref(), Some("MIT"));
        assert_eq!(
            normalize("Apache License, Version 2.0").as_deref(),
            Some("Apache-2.0")
        );
        assert_eq!(normalize("GPL-3.0").as_deref(), Some("GPL-3.0-only"));
        assert_eq!(normalize("BSD 3-Clause").as_deref(), Some("BSD-3-Clause"));
    }

    #[test]
    fn unknown_but_plausible_values_stay_verbatim() {
        assert_eq!(
            normalize("LicenseRef-Acme-Internal").as_deref(),
            Some("LicenseRef-Acme-Internal")
        );
        assert_eq!(
            normalize("MIT OR Apache-2.0").as_deref(),
            Some("MIT OR Apache-2.0")
        );
    }

    #[test]
    fn junk_is_not_a_license() {
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("   "), None);
        assert_eq!(normalize("see license file"), None);
        assert_eq!(normalize("<html>MIT</html>"), None);
        assert_eq!(normalize(&"a".repeat(129)), None);
    }

    #[test]
    fn list_matching_ignores_spelling_and_case() {
        let list = vec!["mit".to_string(), "Apache 2.0".to_string()];
        assert!(any_listed(&list, "MIT License"));
        assert!(any_listed(&list, "apache-2.0"));
        assert!(!any_listed(&list, "BSD-3-Clause"));
        assert!(!any_listed(&[], "MIT"));
        assert!(any_listed(&list, "MIT OR GPL-3.0-only"));
        assert!(!all_listed(&list, "MIT OR GPL-3.0-only"));
        assert!(all_listed(&list, "MIT OR Apache-2.0"));
    }

    #[test]
    fn json_license_objects_and_strings_are_read() {
        assert_eq!(
            from_json(&serde_json::json!("MIT")),
            Some("MIT".to_string())
        );
        assert_eq!(
            from_json(&serde_json::json!({"type": "Apache 2.0", "url": "x"})),
            Some("Apache-2.0".to_string())
        );
        assert_eq!(from_json(&serde_json::json!({"url": "x"})), None);
        assert_eq!(from_json(&serde_json::json!(42)), None);
    }

    #[test]
    fn reference_prefers_the_single_identifier_page() {
        assert_eq!(
            reference("MIT License"),
            "https://spdx.org/licenses/MIT.html"
        );
        assert_eq!(reference("MIT OR Apache-2.0"), "https://spdx.org/licenses/");
    }
}
