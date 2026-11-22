//! Outbound URL policy: what dep-vet is willing to fetch.
//!
//! Registry JSON is untrusted. Archive and provenance URLs from it are only
//! fetched after an https/host/address check, and every DNS answer is filtered
//! before a connection is made. Dev registry overrides are gated explicitly.

use std::net::{IpAddr, SocketAddr};

use url::Url;

use crate::model::Ecosystem;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("URL is not valid: {0}")]
    Invalid(String),
    #[error("URL must use https: {0}")]
    Scheme(String),
    #[error("URL must not contain credentials: {0}")]
    UserInfo(String),
    #[error("URL uses a port that is not allowed: {0}")]
    Port(String),
    #[error("URL host is not ASCII or punycode: {0}")]
    HostEncoding(String),
    #[error("URL resolves to a non-public address: {0}")]
    Address(String),
    #[error("archive host not trusted for {ecosystem}: {host}")]
    Untrusted {
        ecosystem: &'static str,
        host: String,
    },
    #[error("dist host not declared by package metadata: {0}")]
    ComposerHost(String),
    #[error("dist URL repository does not match package metadata: {0}")]
    ComposerRepo(String),
    #[error("dev registry overrides require DEPVET_ALLOW_INSECURE_BASES=1: {0}")]
    OverrideGate(String),
    #[error("no public address remains for {0}")]
    NoPublicAddress(String),
}

/// Explicitly enabled development overrides. Production runs have this empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub active: bool,
    pub bases: Vec<String>,
}

impl Overrides {
    pub fn from_env() -> Self {
        let active = std::env::var("DEPVET_ALLOW_INSECURE_BASES").as_deref() == Ok("1");
        let bases = std::env::vars()
            .filter(|(key, _)| key.starts_with("DEPVET_") && key.ends_with("_BASE"))
            .map(|(_, value)| value)
            .collect();
        Self { active, bases }
    }

    fn parsed(&self) -> impl Iterator<Item = Url> + '_ {
        self.bases.iter().filter_map(|base| Url::parse(base).ok())
    }

    fn allows(&self, url: &Url) -> bool {
        if !self.active {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let port = url.port_or_known_default();
        self.parsed().any(|base| {
            base.host_str().is_some_and(|allowed| {
                allowed.eq_ignore_ascii_case(host) && base.port_or_known_default() == port
            })
        })
    }
}

fn allowed_host(host: &str, allowed: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let allowed = allowed.to_ascii_lowercase();
    host == allowed || host.ends_with(&format!(".{allowed}"))
}

fn allowed_hosts(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &["registry.npmjs.org"],
        Ecosystem::Pypi => &["files.pythonhosted.org", "pypi.org"],
        Ecosystem::CratesIo => &["static.crates.io", "crates.io"],
        Ecosystem::Go => &["proxy.golang.org"],
        Ecosystem::RubyGems => &["rubygems.org"],
        Ecosystem::NuGet => &["api.nuget.org", "globalcdn.nuget.org"],
        Ecosystem::Maven => &["repo.maven.apache.org", "dl.google.com"],
        Ecosystem::Composer => &["repo.packagist.org", "dist.packagist.org"],
        Ecosystem::Jsr => &[],
    }
}

/// Composer package metadata: the source/dist hosts this package declared.
/// Code hosts (GitHub, GitLab, Bitbucket) are only accepted for the package
/// that named them, and GitHub URLs must also name the same owner/repo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComposerOrigin {
    hosts: Vec<String>,
    source_path: Option<String>,
}

impl ComposerOrigin {
    pub fn from_metadata(source: Option<&str>, dist: Option<&str>) -> Self {
        let mut hosts = Vec::new();
        for raw in [source, dist].into_iter().flatten() {
            if let Ok(url) = Url::parse(raw)
                && let Some(host) = url.host_str()
            {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        let source_path = source
            .and_then(|raw| Url::parse(raw).ok())
            .map(|url| url.path().trim_start_matches('/').to_string())
            .filter(|path| !path.is_empty());
        Self { hosts, source_path }
    }

    fn declares(&self, host: &str) -> bool {
        self.hosts.iter().any(|declared| declared == host)
            // GitHub's API redirects zipballs to codeload; both are the same
            // declared source, and the owner/repo check still applies.
            || (host == "codeload.github.com" && self.hosts.iter().any(|h| h == "github.com"))
    }

    fn github_owner_repo(&self) -> Option<(&str, &str)> {
        let path = self.source_path.as_deref()?.trim_end_matches(".git");
        let mut parts = path.split('/');
        let owner = parts.next()?;
        let repo = parts.next()?;
        (!owner.is_empty() && !repo.is_empty()).then_some((owner, repo))
    }
}

fn is_github_host(host: &str) -> bool {
    matches!(
        host,
        "github.com" | "api.github.com" | "codeload.github.com"
    )
}

/// Validate one outbound URL against the ecosystem allowlist and address rules.
pub fn validate_url(ecosystem: Ecosystem, raw: &str) -> Result<Url, PolicyError> {
    validate_with(ecosystem, raw, &Overrides::from_env())
}

pub fn validate_with(
    ecosystem: Ecosystem,
    raw: &str,
    overrides: &Overrides,
) -> Result<Url, PolicyError> {
    let url = validate_common(raw, overrides)?;
    if overrides.allows(&url) {
        return Ok(url);
    }
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if allowed_hosts(ecosystem)
        .iter()
        .any(|allowed| allowed_host(host, allowed))
    {
        Ok(url)
    } else {
        Err(PolicyError::Untrusted {
            ecosystem: ecosystem.cli_name(),
            host: host.to_string(),
        })
    }
}

/// Composer archives may live on code hosts, but only when the package's own
/// metadata declared that exact host. GitHub additionally needs owner/repo.
pub fn validate_composer_url(raw: &str, origin: &ComposerOrigin) -> Result<Url, PolicyError> {
    validate_composer_with(raw, origin, &Overrides::from_env())
}

pub fn validate_composer_with(
    raw: &str,
    origin: &ComposerOrigin,
    overrides: &Overrides,
) -> Result<Url, PolicyError> {
    let url = validate_common(raw, overrides)?;
    if overrides.allows(&url) {
        return Ok(url);
    }
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "repo.packagist.org" || host == "dist.packagist.org" {
        return Ok(url);
    }
    if !origin.declares(&host) {
        return Err(PolicyError::ComposerHost(host));
    }
    if is_github_host(&host) {
        let Some((owner, repo)) = origin.github_owner_repo() else {
            return Err(PolicyError::ComposerRepo(format!(
                "{host} URL has no owner/repo in the package source"
            )));
        };
        let path = url.path();
        let api = format!("/repos/{owner}/{repo}/");
        let plain = format!("/{owner}/{repo}/");
        if !path.starts_with(&api) && !path.starts_with(&plain) {
            return Err(PolicyError::ComposerRepo(format!(
                "{host} path does not match {owner}/{repo}"
            )));
        }
    }
    Ok(url)
}

/// Choose the Composer-aware validator when metadata is available.
pub fn validate_archive_with(
    ecosystem: Ecosystem,
    raw: &str,
    origin: Option<&ComposerOrigin>,
    overrides: &Overrides,
) -> Result<Url, PolicyError> {
    match (ecosystem, origin) {
        (Ecosystem::Composer, Some(origin)) => validate_composer_with(raw, origin, overrides),
        _ => validate_with(ecosystem, raw, overrides),
    }
}

pub fn validate_archive_url(
    ecosystem: Ecosystem,
    raw: &str,
    origin: Option<&ComposerOrigin>,
) -> Result<Url, PolicyError> {
    validate_archive_with(ecosystem, raw, origin, &Overrides::from_env())
}

fn validate_common(raw: &str, overrides: &Overrides) -> Result<Url, PolicyError> {
    let url = Url::parse(raw).map_err(|error| PolicyError::Invalid(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(PolicyError::Scheme(raw.to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PolicyError::UserInfo(raw.to_string()));
    }
    let Some(host) = url.host_str().filter(|host| !host.is_empty()) else {
        return Err(PolicyError::Invalid("URL has no host".to_string()));
    };
    let host = host.trim_end_matches('.');
    if !host.is_ascii() {
        return Err(PolicyError::HostEncoding(host.to_string()));
    }
    let override_ok = overrides.allows(&url);
    if url.scheme() == "http" && !override_ok {
        return Err(PolicyError::Scheme(raw.to_string()));
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = bare.parse::<IpAddr>()
        && !is_public_ip(address)
        && !override_ok
    {
        return Err(PolicyError::Address(host.to_string()));
    }
    if !override_ok {
        let expected = if url.scheme() == "https" { 443 } else { 80 };
        if url.port_or_known_default() != Some(expected) {
            return Err(PolicyError::Port(raw.to_string()));
        }
    }
    Ok(url)
}

/// Whether an address is globally routable for this tool's purposes.
pub fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                || octets[0] >= 240)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            // Refuse transition/documentation ranges even if an embedded
            // address looks public: Teredo, discard-only, and 3fff::/20.
            if (segments[0] == 0x2001 && segments[1] == 0)
                || (segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
            {
                return false;
            }
            if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                return false;
            }
            if address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
            {
                return false;
            }
            // NAT64 64:ff9b::/96.
            if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                return is_public_ip(IpAddr::V4(embedded_ipv4(segments[6], segments[7])));
            }
            // IPv4-compatible ::a.b.c.d (mapped forms were handled above).
            if segments[..6].iter().all(|segment| *segment == 0) {
                return is_public_ip(IpAddr::V4(embedded_ipv4(segments[6], segments[7])));
            }
            // 6to4 2002:V4ADDR::/48.
            if segments[0] == 0x2002 {
                return is_public_ip(IpAddr::V4(embedded_ipv4(segments[1], segments[2])));
            }
            true
        }
    }
}

fn embedded_ipv4(high: u16, low: u16) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
}

/// Keep only addresses that may be connected to. Used after one DNS lookup.
pub fn filter_resolved_addresses(
    host: &str,
    port: u16,
    addresses: impl IntoIterator<Item = IpAddr>,
    overrides: &Overrides,
) -> Result<Vec<SocketAddr>, PolicyError> {
    let override_ok = overrides.active
        && overrides.parsed().any(|base| {
            base.host_str().is_some_and(|allowed| {
                allowed.eq_ignore_ascii_case(host) && base.port_or_known_default() == Some(port)
            })
        });
    let override_ip = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .ok();
    let kept: Vec<SocketAddr> = addresses
        .into_iter()
        .filter(|address| {
            if override_ok {
                override_ip.is_none_or(|expected| *address == expected)
            } else {
                is_public_ip(*address)
            }
        })
        .map(|address| SocketAddr::new(address, port))
        .collect();
    if kept.is_empty() {
        Err(PolicyError::NoPublicAddress(host.to_string()))
    } else {
        Ok(kept)
    }
}

/// Reject any `DEPVET_*_BASE` override unless the explicit gate is set.
pub fn check_overrides_env() -> Result<(), PolicyError> {
    check_overrides(&std::env::vars().collect())
}

pub fn check_overrides(env: &std::collections::HashMap<String, String>) -> Result<(), PolicyError> {
    let gate = env
        .get("DEPVET_ALLOW_INSECURE_BASES")
        .is_some_and(|value| value == "1");
    for (key, value) in env {
        if key.starts_with("DEPVET_") && key.ends_with("_BASE") && !gate {
            return Err(PolicyError::OverrideGate(format!("{key}={value}")));
        }
    }
    Ok(())
}

pub fn insecure_active_with(overrides: &Overrides) -> bool {
    overrides.active && !overrides.bases.is_empty()
}

pub fn insecure_active() -> bool {
    insecure_active_with(&Overrides::from_env())
}

pub fn warn_once() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    if !insecure_active() {
        return;
    }
    WARNED.call_once(|| {
        eprintln!(
            "dep-vet: warning: an unofficial registry override is active; \
             results are not production registry data"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides(base: &str) -> Overrides {
        Overrides {
            active: true,
            bases: vec![base.to_string()],
        }
    }

    #[test]
    fn public_https_urls_on_each_allowlist_are_accepted() {
        for (ecosystem, url) in [
            (
                Ecosystem::Npm,
                "https://registry.npmjs.org/express/-/express-5.1.0.tgz",
            ),
            (
                Ecosystem::Pypi,
                "https://files.pythonhosted.org/packages/x.whl",
            ),
            (
                Ecosystem::CratesIo,
                "https://static.crates.io/crates/serde/serde-1.0.0.crate",
            ),
            (
                Ecosystem::Go,
                "https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.zip",
            ),
            (
                Ecosystem::RubyGems,
                "https://rubygems.org/gems/rack-3.0.0.gem",
            ),
            (
                Ecosystem::NuGet,
                "https://api.nuget.org/v3-flatcontainer/x/x.1.0.0.nupkg",
            ),
            (
                Ecosystem::Maven,
                "https://repo.maven.apache.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar",
            ),
            (
                Ecosystem::Composer,
                "https://repo.packagist.org/p2/vendor/pkg.json",
            ),
        ] {
            assert!(
                validate_with(ecosystem, url, &Overrides::default()).is_ok(),
                "{ecosystem}: {url}"
            );
        }
    }

    #[test]
    fn an_untrusted_public_host_is_rejected_for_every_ecosystem() {
        for ecosystem in [
            Ecosystem::Npm,
            Ecosystem::Pypi,
            Ecosystem::CratesIo,
            Ecosystem::Go,
            Ecosystem::RubyGems,
            Ecosystem::NuGet,
            Ecosystem::Maven,
            Ecosystem::Composer,
            Ecosystem::Jsr,
        ] {
            let error = validate_with(
                ecosystem,
                "https://evil.example/archive.tgz",
                &Overrides::default(),
            )
            .unwrap_err();
            assert!(
                matches!(error, PolicyError::Untrusted { .. }),
                "{ecosystem}: {error}"
            );
        }
    }

    #[test]
    fn http_userinfo_ports_and_untrusted_hosts_are_rejected() {
        let overrides = Overrides::default();
        assert!(matches!(
            validate_with(
                Ecosystem::Npm,
                "http://registry.npmjs.org/x.tgz",
                &overrides
            ),
            Err(PolicyError::Scheme(_))
        ));
        assert!(matches!(
            validate_with(
                Ecosystem::Npm,
                "https://user:pass@registry.npmjs.org/x.tgz",
                &overrides
            ),
            Err(PolicyError::UserInfo(_))
        ));
        assert!(matches!(
            validate_with(
                Ecosystem::Npm,
                "https://registry.npmjs.org:8443/x.tgz",
                &overrides
            ),
            Err(PolicyError::Port(_))
        ));
        assert!(matches!(
            validate_with(Ecosystem::Npm, "https://evilcrates.io/x", &overrides),
            Err(PolicyError::Untrusted { .. })
        ));
    }

    #[test]
    fn private_and_special_ip_literals_are_rejected() {
        for host in [
            "169.254.169.254",
            "127.0.0.1",
            "[::1]",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "[fc00::1]",
            "[fe80::1]",
            "[::ffff:10.0.0.1]",
            "[2001:db8::1]",
            "0.0.0.0",
            "2130706433",
            "0x7f000001",
        ] {
            let url = format!("https://{host}/x.tgz");
            let error = validate_with(Ecosystem::Npm, &url, &Overrides::default()).unwrap_err();
            assert!(
                matches!(
                    error,
                    PolicyError::Address(_) | PolicyError::Untrusted { .. }
                ),
                "{host}: {error}"
            );
        }
    }

    #[test]
    fn embedded_ipv4_and_transition_ranges_follow_their_embedded_address() {
        for private in [
            "64:ff9b::a9fe:a9fe",
            "::7f00:1",
            "2002:c0a8:0101::",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "100::1",
            "3fff::1",
            "2001:db8::1",
            "::",
            "::1",
        ] {
            assert!(
                !is_public_ip(private.parse().unwrap()),
                "{private} must not be public"
            );
        }
        for public in [
            "64:ff9b::0808:0808",
            "::0808:0808",
            "2002:0808:0808::",
            "2606:4700:4700::1111",
        ] {
            assert!(
                is_public_ip(public.parse().unwrap()),
                "{public} must stay public"
            );
        }
    }

    #[test]
    fn composer_code_hosts_need_metadata_and_the_same_github_repo() {
        let origin = ComposerOrigin::from_metadata(
            Some("https://github.com/acme/pkg.git"),
            Some("https://api.github.com/repos/acme/pkg/zipball/abc"),
        );
        let overrides = Overrides::default();
        assert!(
            validate_composer_with(
                "https://api.github.com/repos/acme/pkg/zipball/abc",
                &origin,
                &overrides
            )
            .is_ok()
        );
        assert!(
            validate_composer_with(
                "https://codeload.github.com/acme/pkg/legacy.zip/abc",
                &origin,
                &overrides
            )
            .is_ok()
        );
        assert!(matches!(
            validate_composer_with(
                "https://api.github.com/repos/evil/pkg/zipball/abc",
                &origin,
                &overrides
            ),
            Err(PolicyError::ComposerRepo(_))
        ));
        assert!(matches!(
            validate_composer_with("https://evil.gitlab.com/acme/pkg.zip", &origin, &overrides),
            Err(PolicyError::ComposerHost(_))
        ));
        assert!(matches!(
            validate_composer_with("https://evil.example/acme/pkg.zip", &origin, &overrides),
            Err(PolicyError::ComposerHost(_))
        ));

        let gitlab = ComposerOrigin::from_metadata(
            Some("https://gitlab.com/acme/pkg"),
            Some("https://gitlab.com/acme/pkg/-/archive/1.0/pkg.zip"),
        );
        assert!(
            validate_composer_with(
                "https://gitlab.com/acme/pkg/-/archive/1.0/pkg.zip",
                &gitlab,
                &overrides
            )
            .is_ok()
        );
    }

    #[test]
    fn the_override_gate_is_required_and_limited_to_its_exact_host() {
        let env = std::collections::HashMap::from([(
            "DEPVET_REGISTRY_BASE".to_string(),
            "http://127.0.0.1:8080".to_string(),
        )]);
        assert!(matches!(
            check_overrides(&env),
            Err(PolicyError::OverrideGate(_))
        ));

        let gated = overrides("http://127.0.0.1:8080");
        assert!(validate_with(Ecosystem::Npm, "http://127.0.0.1:8080/x.tgz", &gated).is_ok());
        assert!(validate_with(Ecosystem::Npm, "http://127.0.0.1:9090/x.tgz", &gated).is_err());
        assert!(validate_with(Ecosystem::Npm, "http://registry.npmjs.org/x.tgz", &gated).is_err());
    }

    #[test]
    fn resolver_filtering_drops_every_non_public_address() {
        let gated = overrides("http://127.0.0.1:8080");
        let kept = filter_resolved_addresses(
            "127.0.0.1",
            8080,
            [IpAddr::from([127, 0, 0, 1]), IpAddr::from([10, 0, 0, 1])],
            &gated,
        )
        .unwrap();
        assert_eq!(kept, vec![SocketAddr::from(([127, 0, 0, 1], 8080))]);

        let error = filter_resolved_addresses(
            "evil.example",
            443,
            [IpAddr::from([10, 0, 0, 1])],
            &Overrides::default(),
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::NoPublicAddress(_)));

        assert!(
            filter_resolved_addresses(
                "evil.example",
                443,
                [IpAddr::from([93, 184, 216, 34])],
                &Overrides::default(),
            )
            .is_ok()
        );
    }
}
