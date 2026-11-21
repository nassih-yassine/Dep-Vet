//! Typosquat detection: distance to popular package names.
//!
//! The candidate list is a curated seed, not a download ranking. It exists so
//! the signal works offline; a later release replaces it with the top-N names
//! by weekly downloads (npm's search endpoint is explicitly not a source).

/// Provisional seed list. Keep lowercase, sorted by hand not required.
const MIN_NAME_LEN: usize = 4;

pub const POPULAR: &[&str] = &[
    "accepts",
    "acorn",
    "ajv",
    "ansi-regex",
    "argparse",
    "async",
    "axios",
    "babel-core",
    "balanced-match",
    "body-parser",
    "brace-expansion",
    "braces",
    "camelcase",
    "chalk",
    "chokidar",
    "classnames",
    "cliui",
    "colors",
    "commander",
    "concat-stream",
    "content-type",
    "cookie",
    "core-js",
    "cors",
    "cross-env",
    "cross-spawn",
    "debug",
    "decamelize",
    "deepmerge",
    "define-property",
    "dotenv",
    "eslint",
    "esprima",
    "estraverse",
    "esutils",
    "eventemitter3",
    "execa",
    "express",
    "extend",
    "fast-deep-equal",
    "fast-glob",
    "fill-range",
    "find-up",
    "follow-redirects",
    "form-data",
    "fs-extra",
    "get-stream",
    "glob",
    "globals",
    "graceful-fs",
    "graphemer",
    "has-flag",
    "hasown",
    "iconv-lite",
    "ignore",
    "immer",
    "import-fresh",
    "inherits",
    "inquirer",
    "is-number",
    "isarray",
    "jest",
    "jquery",
    "js-tokens",
    "js-yaml",
    "json5",
    "jsonfile",
    "lodash",
    "loose-envify",
    "lru-cache",
    "mdast-util-to-string",
    "micromatch",
    "mime",
    "mime-db",
    "mime-types",
    "minimatch",
    "minimist",
    "mkdirp",
    "moment",
    "ms",
    "nanoid",
    "neo-async",
    "node-fetch",
    "normalize-path",
    "npm",
    "object-assign",
    "once",
    "open",
    "p-limit",
    "p-locate",
    "parse-json",
    "path-exists",
    "path-key",
    "path-parse",
    "picocolors",
    "picomatch",
    "postcss",
    "preact",
    "prettier",
    "prop-types",
    "punycode",
    "qs",
    "react",
    "react-dom",
    "readable-stream",
    "regenerator-runtime",
    "require-directory",
    "resolve",
    "resolve-from",
    "rimraf",
    "rxjs",
    "safe-buffer",
    "safer-buffer",
    "scheduler",
    "semver",
    "serialize-javascript",
    "shebang-command",
    "shebang-regex",
    "signal-exit",
    "source-map",
    "string-width",
    "strip-ansi",
    "strip-json-comments",
    "supports-color",
    "tar",
    "through2",
    "tmp",
    "to-regex-range",
    "tslib",
    "type-fest",
    "typescript",
    "undici",
    "universalify",
    "uri-js",
    "uuid",
    "vite",
    "webpack",
    "which",
    "wrap-ansi",
    "wrappy",
    "ws",
    "yallist",
    "yargs",
    "yargs-parser",
    "zod",
];

/// Provisional PyPI seed, same caveat as the npm list: curated, not ranked.
pub const POPULAR_PYPI: &[&str] = &[
    "accelerate",
    "aiohttp",
    "ansible",
    "anthropic",
    "apache-airflow",
    "arrow",
    "attrs",
    "azure-core",
    "bcrypt",
    "beautifulsoup4",
    "black",
    "boto3",
    "botocore",
    "cattrs",
    "celery",
    "certifi",
    "charset-normalizer",
    "click",
    "cryptography",
    "dbt-core",
    "django",
    "docker",
    "fastapi",
    "flask",
    "gensim",
    "google-api-core",
    "gunicorn",
    "h5py",
    "httpx",
    "huggingface-hub",
    "idna",
    "jinja2",
    "kubernetes",
    "lightgbm",
    "loguru",
    "lxml",
    "markupsafe",
    "marshmallow",
    "matplotlib",
    "mypy",
    "networkx",
    "nltk",
    "numpy",
    "oauthlib",
    "openai",
    "orjson",
    "packaging",
    "pandas",
    "paramiko",
    "pillow",
    "pip",
    "playwright",
    "polars",
    "prometheus-client",
    "protobuf",
    "psycopg2",
    "pydantic",
    "pyjwt",
    "pyopenssl",
    "pyspark",
    "pytest",
    "python-dateutil",
    "pytz",
    "pyyaml",
    "redis",
    "requests",
    "requests-oauthlib",
    "rich",
    "ruff",
    "safetensors",
    "scikit-learn",
    "scipy",
    "scrapy",
    "selenium",
    "sentry-sdk",
    "setuptools",
    "simplejson",
    "six",
    "spacy",
    "sqlalchemy",
    "starlette",
    "statsmodels",
    "structlog",
    "sympy",
    "tensorflow",
    "tokenizers",
    "torch",
    "tornado",
    "tox",
    "tqdm",
    "transformers",
    "twisted",
    "typing-extensions",
    "ujson",
    "urllib3",
    "uvicorn",
    "waitress",
    "werkzeug",
    "wheel",
    "xgboost",
];

/// A popular name that `name` is suspiciously close to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspect<'a> {
    pub candidate: &'a str,
    pub distance: usize,
    /// True when the names differ only by lookalike characters (`0`/`o`, `rn`/`m`).
    pub homoglyph: bool,
    /// True when the candidate came from the caller's lockfile, not the seed.
    pub local: bool,
}

/// Finds the closest popular name, ignoring exact matches.
///
/// A real popular package is never a suspect of itself, so an exact match
/// returns `None` instead of a distance-0 hit.
/// Finds the closest name among the seed and the caller's own dependencies.
///
/// `local` is the set of package names already trusted by the caller (the
/// base lockfile). A package that is itself well known is never flagged for
/// resembling something nearby: `preact` is not a typo of `react`.
pub fn closest<'a>(name: &str, popular: &'a [&'a str], local: &'a [String]) -> Option<Suspect<'a>> {
    let needle = name.to_ascii_lowercase();
    // Names this short sit within two edits of half the registry; reporting
    // them is pure noise.
    if needle.chars().count() < MIN_NAME_LEN {
        return None;
    }
    let known = popular.iter().any(|candidate| *candidate == needle)
        || local
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&needle));
    if known {
        return None;
    }

    let normalized = normalize(name);
    popular
        .iter()
        .map(|candidate| (*candidate, false))
        .chain(local.iter().map(|candidate| (candidate.as_str(), true)))
        .filter(|(candidate, _)| candidate.chars().count() >= MIN_NAME_LEN)
        .map(|(candidate, local)| {
            let folded = candidate.to_ascii_lowercase();
            let homoglyph = normalize(candidate) == normalized && folded != needle;
            let distance = if homoglyph {
                0
            } else {
                levenshtein(&needle, &folded)
            };
            Suspect {
                candidate,
                distance,
                homoglyph,
                local,
            }
        })
        .filter(|suspect| suspect.distance <= 2)
        .min_by(|a, b| {
            a.distance
                .cmp(&b.distance)
                // On a tie, the dependency you already trust is more actionable.
                .then_with(|| b.local.cmp(&a.local))
                .then_with(|| a.candidate.cmp(b.candidate))
        })
}

/// Folds lookalike characters so `1odash` and `lodash` compare equal.
pub fn normalize(name: &str) -> String {
    name.to_ascii_lowercase()
        .replace("rn", "m")
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            '7' => 't',
            'i' => 'l',
            other => other,
        })
        .collect()
}

pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];

    for (i, a_char) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, b_char) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_char != b_char);
            let insertion = current[j] + 1;
            let deletion = previous[j + 1] + 1;
            current[j + 1] = substitution.min(insertion).min(deletion);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_seed_is_clean() {
        let mut sorted = POPULAR_PYPI.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), POPULAR_PYPI.len(), "duplicate PyPI names");
        assert!(
            POPULAR_PYPI
                .iter()
                .all(|name| *name == name.to_ascii_lowercase()),
            "PyPI seed names must be lowercase"
        );
        for name in ["requests", "numpy", "django", "pydantic"] {
            assert!(POPULAR_PYPI.contains(&name), "missing {name}");
        }
    }

    #[test]
    fn popular_list_is_clean() {
        let mut sorted = POPULAR.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), POPULAR.len(), "duplicate popular names");
        assert!(
            POPULAR
                .iter()
                .all(|name| *name == name.to_ascii_lowercase()),
            "popular names must be lowercase"
        );
        for name in ["express", "react", "lodash", "axios", "typescript"] {
            assert!(POPULAR.contains(&name), "missing popular name {name}");
        }
    }

    #[test]
    fn exact_popular_name_is_not_a_suspect() {
        assert_eq!(closest("express", POPULAR, &[]), None);
        assert_eq!(closest("Express", POPULAR, &[]), None);
    }

    #[test]
    fn detects_single_edit_typosquat() {
        let suspect = closest("expres", POPULAR, &[]).unwrap();
        assert_eq!(suspect.candidate, "express");
        assert_eq!(suspect.distance, 1);
        assert!(!suspect.homoglyph);
    }

    #[test]
    fn detects_two_edit_typosquat() {
        let suspect = closest("expresss", POPULAR, &[]).unwrap();
        assert_eq!(suspect.candidate, "express");
        assert_eq!(suspect.distance, 1);
    }

    #[test]
    fn detects_digit_homoglyph() {
        let suspect = closest("1odash", POPULAR, &[]).unwrap();
        assert_eq!(suspect.candidate, "lodash");
        assert!(suspect.homoglyph);
        assert_eq!(suspect.distance, 0);
    }

    #[test]
    fn detects_multi_char_homoglyph() {
        // "rn" folds to "m", so "mornent" normalizes to "moment".
        let suspect = closest("mornent", POPULAR, &[]).unwrap();
        assert_eq!(suspect.candidate, "moment");
        assert!(suspect.homoglyph);
        assert_eq!(suspect.distance, 0);
    }

    #[test]
    fn finds_a_typosquat_of_a_local_dependency() {
        let local = vec!["cross-env".to_string()];
        let suspect = closest("crossenv", POPULAR, &local).unwrap();
        assert_eq!(suspect.candidate, "cross-env");
        assert!(suspect.local);
        assert_eq!(suspect.distance, 1);
    }

    #[test]
    fn local_dependency_matching_is_case_insensitive() {
        let local = vec!["Cross-Env".to_string()];
        assert_eq!(closest("cross-env", POPULAR, &local), None);
    }

    #[test]
    fn a_known_package_is_not_a_typo_of_a_similar_local_one() {
        // preact is in the seed; react in the lockfile must not make it a hit.
        let local = vec!["react".to_string()];
        assert_eq!(closest("preact", POPULAR, &local), None);
    }

    #[test]
    fn short_names_are_not_flagged() {
        assert_eq!(closest("ms", POPULAR, &[]), None);
        assert_eq!(closest("tmpl", POPULAR, &[]), None);
    }

    #[test]
    fn unrelated_name_has_no_suspect() {
        assert_eq!(closest("zzzzzzzzzzzzzzzz", POPULAR, &[]), None);
        assert_eq!(closest("dep-vet", POPULAR, &[]), None);
    }

    #[test]
    fn prefers_the_closest_candidate() {
        let suspect = closest("reactx", POPULAR, &[]).unwrap();
        assert_eq!(suspect.candidate, "react");
    }

    #[test]
    fn empty_name_is_not_a_suspect() {
        assert_eq!(closest("", POPULAR, &[]), None);
    }

    #[test]
    fn levenshtein_basics() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("flaw", "lawn"), 2);
    }

    #[test]
    fn levenshtein_handles_unicode() {
        assert_eq!(levenshtein("café", "cafe"), 1);
        assert_eq!(levenshtein("日本", "日木"), 1);
    }
}
