//! Offline Sigstore verification of npm provenance attestations.
//!
//! The trusted root is the snapshot embedded in `sigstore-trust-root`; nothing
//! is fetched to verify, and no request is made beyond the attestation the
//! registry already publishes. Verification proves the bundle was signed by a
//! Fulcio certificate, logged, and names this artifact. It does not decide
//! whether that signer should be trusted for this package.

use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_types::Bundle;
use std::sync::OnceLock;

/// What cryptographic verification could establish.
#[derive(Debug, serde::Serialize)]
pub struct ProvenanceReport {
    /// `verified` or `unverified`. There is no "probably".
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub certificate: bool,
    pub sct: bool,
    pub tlog: bool,
}

impl ProvenanceReport {
    pub fn verified(&self) -> bool {
        self.status == "verified"
    }
}

/// A published attestation that could not be read is "not verified" with the
/// reason, never silently absent.
pub fn unverified(reason: impl Into<String>) -> ProvenanceReport {
    ProvenanceReport {
        status: "unverified",
        identity: None,
        issuer: None,
        reason: Some(reason.into()),
        certificate: false,
        sct: false,
        tlog: false,
    }
}

fn trusted_root() -> Option<&'static TrustedRoot> {
    static ROOT: OnceLock<Option<TrustedRoot>> = OnceLock::new();
    ROOT.get_or_init(|| TrustedRoot::from_embedded(SigstoreInstance::PublicGood).ok())
        .as_ref()
}

/// Verify every published bundle until one passes. A bundle signed with a
/// managed key instead of a Fulcio certificate cannot be checked without that
/// key, so it is reported as unverified rather than failed.
pub fn verify(body: &str, artifact: &[u8]) -> ProvenanceReport {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(body) else {
        return unverified("attestation response is not JSON");
    };
    let Some(bundles) = document
        .get("attestations")
        .and_then(|value| value.as_array())
    else {
        return unverified("attestation response has no bundles");
    };
    let Some(root) = trusted_root() else {
        return unverified("the embedded Sigstore trusted root could not be loaded");
    };
    let mut reason = "no bundle carried a Fulcio certificate".to_string();
    for entry in bundles {
        let Some(value) = entry.get("bundle") else {
            continue;
        };
        let bundle: Bundle = match serde_json::from_value(value.clone()) {
            Ok(bundle) => bundle,
            Err(error) => {
                reason = format!("bundle could not be parsed: {error}");
                continue;
            }
        };
        match sigstore_verify::verify(
            artifact,
            &bundle,
            &sigstore_verify::VerificationPolicy::any_identity(),
            root,
        ) {
            Ok(result) => {
                return ProvenanceReport {
                    status: "verified",
                    identity: result.identity().map(ToString::to_string),
                    issuer: result.issuer().map(str::to_string),
                    reason: None,
                    certificate: result.certificate_verified(),
                    sct: result.sct_verified(),
                    tlog: result.tlog_verified(),
                };
            }
            Err(error) => reason = format!("verification failed: {error}"),
        }
    }
    unverified(reason)
}

/// Publisher trust is a policy on top of verification: a signature can be
/// valid while the signer is not one this project allows. Empty policy means
/// "do not judge", so defaults never change a verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustPolicy {
    pub require_attestation: bool,
    pub require_verified_source: bool,
    pub github_organizations: Vec<String>,
    pub repositories: Vec<String>,
    pub workflows: Vec<String>,
}

/// One policy violation, ready to become an inspect finding. The signature may
/// still be valid; this says the signer or evidence does not meet the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustIssue {
    pub rule: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
    pub confidence: crate::model::Confidence,
    pub detail: String,
}

impl TrustPolicy {
    pub fn configured(&self) -> bool {
        self.require_attestation
            || self.require_verified_source
            || self.publisher_lists_configured()
    }

    fn publisher_lists_configured(&self) -> bool {
        !self.github_organizations.is_empty()
            || !self.repositories.is_empty()
            || !self.workflows.is_empty()
    }

    /// Evaluate a verified (or absent) provenance report. Never claims more
    /// than the report can support.
    pub fn check(&self, provenance: Option<&ProvenanceReport>) -> Vec<TrustIssue> {
        if !self.configured() {
            return Vec::new();
        }
        let Some(provenance) = provenance else {
            return if self.require_attestation
                || self.require_verified_source
                || self.publisher_lists_configured()
            {
                vec![TrustIssue {
                    rule: "PROVENANCE-TRUST-001",
                    title: "no provenance attestation was published",
                    description: "The policy requires an attestation or a trusted publisher, but this release publishes none.",
                    recommendation: "Review the release manually or relax the policy; absence is not a clean provenance result.",
                    confidence: crate::model::Confidence::High,
                    detail: "no attestation was published for this release".to_string(),
                }]
            } else {
                Vec::new()
            };
        };

        if !provenance.verified() {
            let reason = provenance
                .reason
                .as_deref()
                .unwrap_or("the attestation did not verify");
            return if self.require_verified_source || self.publisher_lists_configured() {
                vec![TrustIssue {
                    rule: "PROVENANCE-TRUST-002",
                    title: "provenance could not be verified",
                    description: "The published attestation did not pass offline Sigstore verification, so publisher identity cannot be trusted.",
                    recommendation: "Treat the release as unattested until the bundle verifies; do not count presence as trust.",
                    confidence: crate::model::Confidence::High,
                    detail: format!("verification failed: {reason}"),
                }]
            } else {
                Vec::new()
            };
        }

        if !self.publisher_lists_configured() {
            return Vec::new();
        }
        let identity = provenance.identity.as_deref();
        let issuer = provenance.issuer.as_deref();
        if issuer != Some(GITHUB_ACTIONS_ISSUER) {
            return vec![untrusted(format!(
                "issuer {} is not {GITHUB_ACTIONS_ISSUER}",
                issuer.unwrap_or("(none)")
            ))];
        }
        let Some(identity) = identity else {
            return vec![untrusted(
                "the verified certificate carries no signer identity".to_string(),
            )];
        };
        let Some(parsed) = github_identity(identity) else {
            return vec![untrusted(format!(
                "signer identity {identity} is not a GitHub repository workflow"
            ))];
        };
        if self.matches(&parsed) {
            Vec::new()
        } else {
            vec![untrusted(format!(
                "signer {identity} does not match trusted_publishers ({})",
                self.describe_lists()
            ))]
        }
    }

    fn matches(&self, identity: &GitHubIdentity<'_>) -> bool {
        let repository = format!("{}/{}", identity.org, identity.repo);
        let full_workflow = format!("{repository}/{}", identity.workflow);
        self.github_organizations
            .iter()
            .any(|org| org.eq_ignore_ascii_case(identity.org))
            || self
                .repositories
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&repository))
            || self.workflows.iter().any(|candidate| {
                candidate
                    .trim_start_matches('/')
                    .eq_ignore_ascii_case(identity.workflow)
                    || candidate
                        .trim_start_matches('/')
                        .eq_ignore_ascii_case(&full_workflow)
            })
    }

    fn describe_lists(&self) -> String {
        let mut parts = Vec::new();
        if !self.github_organizations.is_empty() {
            parts.push(format!(
                "organizations: {}",
                self.github_organizations.join(", ")
            ));
        }
        if !self.repositories.is_empty() {
            parts.push(format!("repositories: {}", self.repositories.join(", ")));
        }
        if !self.workflows.is_empty() {
            parts.push(format!("workflows: {}", self.workflows.join(", ")));
        }
        parts.join("; ")
    }
}

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

pub const TRUST_REFERENCES: &[&str] = &[
    "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
    "https://slsa.dev/spec/v1.0/verifying-artifacts",
];

fn untrusted(detail: String) -> TrustIssue {
    TrustIssue {
        rule: "PROVENANCE-TRUST-003",
        title: "publisher is not on the trusted list",
        description: "The signature is valid, but the signer is not a publisher this policy trusts.",
        recommendation: "Review the publisher identity, then extend trusted_publishers only if it is expected.",
        confidence: crate::model::Confidence::Medium,
        detail,
    }
}

struct GitHubIdentity<'a> {
    org: &'a str,
    repo: &'a str,
    workflow: &'a str,
}

/// Parse a Fulcio identity such as
/// `https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main`.
fn github_identity(identity: &str) -> Option<GitHubIdentity<'_>> {
    let rest = identity.strip_prefix("https://github.com/")?;
    let mut parts = rest.splitn(3, '/');
    let org = parts.next()?;
    let repo = parts.next()?;
    let rest = parts.next()?;
    let workflow = rest.split('@').next().unwrap_or(rest);
    if org.is_empty() || repo.is_empty() || workflow.is_empty() {
        return None;
    }
    Some(GitHubIdentity {
        org,
        repo,
        workflow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION: &str = include_str!("../tests/fixtures/semver-7.8.6-attestation.json");
    const TARBALL: &[u8] = include_bytes!("../tests/fixtures/semver-7.8.6.tgz");

    const SEMVER_IDENTITY: &str = "https://github.com/npm/node-semver/.github/workflows/release-integration.yml@refs/heads/main";

    fn verified(identity: &str, issuer: &str) -> ProvenanceReport {
        ProvenanceReport {
            status: "verified",
            identity: Some(identity.to_string()),
            issuer: Some(issuer.to_string()),
            reason: None,
            certificate: true,
            sct: true,
            tlog: true,
        }
    }

    #[test]
    fn an_unconfigured_policy_never_changes_a_result() {
        let policy = TrustPolicy::default();
        assert!(!policy.configured());
        assert!(policy.check(None).is_empty());
        assert!(policy.check(Some(&unverified("no bundle"))).is_empty());
    }

    #[test]
    fn required_attestation_and_verification_are_separate_requirements() {
        let missing = TrustPolicy {
            require_attestation: true,
            ..TrustPolicy::default()
        };
        let issues = missing.check(None);
        assert_eq!(issues[0].rule, "PROVENANCE-TRUST-001");

        let verified_required = TrustPolicy {
            require_verified_source: true,
            ..TrustPolicy::default()
        };
        assert_eq!(
            verified_required.check(None)[0].rule,
            "PROVENANCE-TRUST-001"
        );
        let issues = verified_required.check(Some(&unverified("bundle did not verify")));
        assert_eq!(issues[0].rule, "PROVENANCE-TRUST-002");
        // Presence alone satisfies require_attestation.
        assert!(
            missing
                .check(Some(&unverified("bundle did not verify")))
                .is_empty()
        );
    }

    #[test]
    fn trusted_organizations_repositories_and_workflows_match() {
        let report = verified(SEMVER_IDENTITY, GITHUB_ACTIONS_ISSUER);
        for policy in [
            TrustPolicy {
                github_organizations: vec!["npm".to_string()],
                ..TrustPolicy::default()
            },
            TrustPolicy {
                repositories: vec!["NPM/node-semver".to_string()],
                ..TrustPolicy::default()
            },
            TrustPolicy {
                workflows: vec![".github/workflows/release-integration.yml".to_string()],
                ..TrustPolicy::default()
            },
            TrustPolicy {
                workflows: vec![
                    "npm/node-semver/.github/workflows/release-integration.yml".to_string(),
                ],
                ..TrustPolicy::default()
            },
        ] {
            assert!(policy.check(Some(&report)).is_empty(), "{policy:?}");
        }
    }

    #[test]
    fn a_verified_signer_outside_the_policy_is_untrusted() {
        let report = verified(SEMVER_IDENTITY, GITHUB_ACTIONS_ISSUER);
        let policy = TrustPolicy {
            repositories: vec!["evil/repo".to_string()],
            ..TrustPolicy::default()
        };
        let issues = policy.check(Some(&report));
        assert_eq!(issues[0].rule, "PROVENANCE-TRUST-003");
        assert!(issues[0].detail.contains("npm/node-semver"), "{issues:?}");
        assert_eq!(issues[0].confidence, crate::model::Confidence::Medium);

        let wrong_issuer = TrustPolicy {
            github_organizations: vec!["npm".to_string()],
            ..TrustPolicy::default()
        };
        let report = verified(SEMVER_IDENTITY, "https://example.com/issuer");
        assert_eq!(
            wrong_issuer.check(Some(&report))[0].rule,
            "PROVENANCE-TRUST-003"
        );

        let unverified_report = unverified("signature failed");
        let policy = TrustPolicy {
            repositories: vec!["npm/node-semver".to_string()],
            ..TrustPolicy::default()
        };
        assert_eq!(
            policy.check(Some(&unverified_report))[0].rule,
            "PROVENANCE-TRUST-002"
        );
    }

    #[test]
    fn a_real_bundle_verifies_offline_against_the_embedded_root() {
        let report = verify(ATTESTATION, TARBALL);
        assert!(report.verified(), "{:?}", report.reason);
        assert!(report.certificate && report.sct && report.tlog);
        assert_eq!(
            report.identity.as_deref(),
            Some(
                "https://github.com/npm/node-semver/.github/workflows/release-integration.yml@refs/heads/main"
            )
        );
        assert_eq!(
            report.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
    }

    #[test]
    fn the_bundle_is_bound_to_the_artifact() {
        let mut tampered = TARBALL.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let report = verify(ATTESTATION, &tampered);
        assert!(!report.verified());
        assert!(
            report.reason.as_deref().unwrap_or("").contains("artifact"),
            "{:?}",
            report.reason
        );
    }

    #[test]
    fn a_managed_key_bundle_is_unverified_not_failed() {
        let body = r#"{"attestations":[{"bundle":{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2","verificationMaterial":{"publicKey":{"rawBytes":""}},"dsseEnvelope":{"payload":"","payloadType":"","signatures":[]}}}]}"#;
        let report = verify(body, TARBALL);
        assert!(!report.verified());
        assert!(report.reason.is_some());
    }

    #[test]
    fn an_unreadable_attestation_says_why() {
        let report = unverified("attestation fetch failed: connection refused");
        assert!(!report.verified());
        assert_eq!(
            report.reason.as_deref(),
            Some("attestation fetch failed: connection refused")
        );
    }

    #[test]
    fn malformed_attestations_stay_unverified() {
        for body in ["", "{}", "not json", r#"{"attestations":[]}"#] {
            let report = verify(body, TARBALL);
            assert!(!report.verified(), "{body}");
            assert!(report.reason.is_some(), "{body}");
            assert!(!report.certificate && !report.sct && !report.tlog);
        }
    }
}
