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

fn unverified(reason: impl Into<String>) -> ProvenanceReport {
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

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION: &str = include_str!("../tests/fixtures/semver-7.8.6-attestation.json");
    const TARBALL: &[u8] = include_bytes!("../tests/fixtures/semver-7.8.6.tgz");

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
    fn malformed_attestations_stay_unverified() {
        for body in ["", "{}", "not json", r#"{"attestations":[]}"#] {
            let report = verify(body, TARBALL);
            assert!(!report.verified(), "{body}");
            assert!(report.reason.is_some(), "{body}");
            assert!(!report.certificate && !report.sct && !report.tlog);
        }
    }
}
