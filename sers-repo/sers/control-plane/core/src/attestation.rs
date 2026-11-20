use sers_core::{AttestationStatus, Nonce32, TeeTechnology};

/// Opaque, technology-tagged attestation evidence (a hardware quote/report).
/// It is **never** interpreted as JSON claims: only a verifier that checks the
/// vendor's signature chain, measurements, TCB status and freshness may turn it
/// into a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub technology: TeeTechnology,
    pub quote: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationOutcome {
    pub status: AttestationStatus,
    /// The verifier established a genuine hardware-protected execution environment.
    pub hardware_backed: bool,
}

/// Verifies attestation evidence. A real implementation must check: evidence
/// authenticity against explicit trust roots, measurement policy, freshness
/// (bound to `challenge_nonce`), TCB status / revocation and security version.
pub trait AttestationVerifier: Send + Sync {
    fn verify(
        &self,
        evidence: Option<&AttestationEvidence>,
        challenge_nonce: &Nonce32,
    ) -> AttestationOutcome;
}

/// The only verifier shipped today: no TEE verification exists, so *nothing*
/// is ever verified. Applications with `hardware_required` therefore fail closed.
pub struct UnsupportedAttestationVerifier;

impl AttestationVerifier for UnsupportedAttestationVerifier {
    fn verify(
        &self,
        _evidence: Option<&AttestationEvidence>,
        _challenge_nonce: &Nonce32,
    ) -> AttestationOutcome {
        AttestationOutcome {
            status: AttestationStatus::Unverified,
            hardware_backed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_verifier_never_verifies_anything() {
        let evidence = AttestationEvidence {
            technology: TeeTechnology::IntelSgx,
            quote: vec![1, 2, 3],
        };
        let nonce = Nonce32::from_bytes([1; 32]);
        for e in [None, Some(&evidence)] {
            let out = UnsupportedAttestationVerifier.verify(e, &nonce);
            assert_eq!(out.status, AttestationStatus::Unverified);
            assert!(!out.hardware_backed);
        }
    }
}
