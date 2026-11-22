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
        Ecosystem::Composer => &[
            "repo.packagist.org",
            "dist.packagist.org",
            "api.github.com",
            "codeload.github.com",
            "gitlab.com",
            "bitbucket.org",
        ],
        Ecosystem::Jsr => &[],
    }
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
        // The url crate normalizes IDNs to punycode; a non-ASCII host here
        // means the parser did not, so refuse rather than guess.
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
        let trusted = allowed_hosts(ecosystem)
            .iter()
            .any(|allowed| allowed_host(host, allowed));
        if !trusted {
            return Err(PolicyError::Untrusted {
                ecosystem: ecosystem.cli_name(),
                host: host.to_string(),
            });
        }
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
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
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
                "https://api.github.com/repos/x/y/zipball/abc",
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
