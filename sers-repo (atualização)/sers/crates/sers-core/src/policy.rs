use crate::{BackendCapabilities, SersError};
use serde::{Deserialize, Serialize};

/// Execution policy chosen by the application publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPolicy {
    SoftwareAllowed,
    HardwareRequired,
    RemoteExecutionRequired,
}

/// Result of attestation verification, produced by the Control Plane.
/// A client-supplied flag must never be mapped to `Verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    Unverified,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPlacement {
    LocalSoftware,
    LocalHardware,
    Remote,
}

/// Decides where protected code may run. Pure function; **never downgrades**:
/// `HardwareRequired` fails unless a hardware backend with attestation is
/// present *and* attestation was verified.
pub fn decide_placement(
    policy: ExecutionPolicy,
    caps: &BackendCapabilities,
    attestation: AttestationStatus,
) -> Result<ExecutionPlacement, SersError> {
    let hardware_ok = caps.hardware_backed_confidentiality
        && caps.remote_attestation
        && attestation == AttestationStatus::Verified;

    match policy {
        ExecutionPolicy::RemoteExecutionRequired => Ok(ExecutionPlacement::Remote),
        ExecutionPolicy::HardwareRequired => {
            if hardware_ok {
                Ok(ExecutionPlacement::LocalHardware)
            } else {
                Err(SersError::PolicyDenied(
                    "hardware execution required but no verified hardware backend is available",
                ))
            }
        }
        ExecutionPolicy::SoftwareAllowed => {
            if hardware_ok {
                Ok(ExecutionPlacement::LocalHardware)
            } else if caps.process_isolation {
                Ok(ExecutionPlacement::LocalSoftware)
            } else {
                Err(SersError::Unsupported("no execution backend available"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn software() -> BackendCapabilities {
        BackendCapabilities {
            process_isolation: true,
            ..Default::default()
        }
    }

    fn hardware() -> BackendCapabilities {
        BackendCapabilities {
            process_isolation: true,
            hardware_backed_confidentiality: true,
            remote_attestation: true,
            ..Default::default()
        }
    }

    #[test]
    fn hardware_required_never_downgrades_to_software() {
        let r = decide_placement(
            ExecutionPolicy::HardwareRequired,
            &software(),
            AttestationStatus::Verified,
        );
        assert!(matches!(r, Err(SersError::PolicyDenied(_))));
    }

    #[test]
    fn hardware_required_needs_verified_attestation() {
        let r = decide_placement(
            ExecutionPolicy::HardwareRequired,
            &hardware(),
            AttestationStatus::Unverified,
        );
        assert!(matches!(r, Err(SersError::PolicyDenied(_))));
    }

    #[test]
    fn hardware_required_succeeds_with_verified_hardware() {
        let r = decide_placement(
            ExecutionPolicy::HardwareRequired,
            &hardware(),
            AttestationStatus::Verified,
        );
        assert_eq!(r, Ok(ExecutionPlacement::LocalHardware));
    }

    #[test]
    fn software_allowed_prefers_verified_hardware() {
        let r = decide_placement(
            ExecutionPolicy::SoftwareAllowed,
            &hardware(),
            AttestationStatus::Verified,
        );
        assert_eq!(r, Ok(ExecutionPlacement::LocalHardware));
    }

    #[test]
    fn software_allowed_falls_back_to_software() {
        let r = decide_placement(
            ExecutionPolicy::SoftwareAllowed,
            &hardware(),
            AttestationStatus::Unverified,
        );
        assert_eq!(r, Ok(ExecutionPlacement::LocalSoftware));
    }

    #[test]
    fn software_allowed_without_any_backend_fails() {
        let r = decide_placement(
            ExecutionPolicy::SoftwareAllowed,
            &BackendCapabilities::default(),
            AttestationStatus::Unverified,
        );
        assert!(matches!(r, Err(SersError::Unsupported(_))));
    }

    #[test]
    fn remote_required_places_remote() {
        let r = decide_placement(
            ExecutionPolicy::RemoteExecutionRequired,
            &BackendCapabilities::default(),
            AttestationStatus::Unverified,
        );
        assert_eq!(r, Ok(ExecutionPlacement::Remote));
    }

    #[test]
    fn policy_serializes_as_snake_case() {
        let json = serde_json::to_string(&ExecutionPolicy::HardwareRequired).unwrap();
        assert_eq!(json, "\"hardware_required\"");
    }
}
