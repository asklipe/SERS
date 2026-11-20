//! Platform probing and backend inventory.
//!
//! **A probe is not a capability.** Finding `/dev/sgx_enclave` or
//! `/dev/sev-guest` only shows that the kernel exposes a device node. It does
//! not prove that attestation works, that the platform is on a trusted TCB
//! version, or that SERS has a backend for it. Hardware backends are not
//! implemented, so [`backends`] reports `implemented: false` and empty
//! capabilities for every TEE, whatever the probes found.
//!
//! All probing is parameterised by a filesystem root so it can be tested
//! against a fake tree.

use serde::Serialize;
use sers_core::{BackendCapabilities, TeeTechnology};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    NotDetected,
    /// A device node exists. Nothing more is implied.
    DevicePresent,
}

#[derive(Debug, Clone, Serialize)]
pub struct TeeProbe {
    pub technology: TeeTechnology,
    pub status: ProbeStatus,
    pub evidence_paths: Vec<String>,
    /// Always `false` until a real backend exists for this technology.
    pub backend_implemented: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SoftwareControls {
    /// The kernel reports a `Seccomp:` field (seccomp compiled in).
    pub seccomp_supported: bool,
    /// Unprivileged user namespaces look usable.
    pub unprivileged_user_namespaces: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformReport {
    pub os: String,
    pub arch: String,
    pub tee: Vec<TeeProbe>,
    /// A TPM device node exists (measured boot / key storage *candidate*).
    pub tpm_device_present: bool,
    pub software: SoftwareControls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Software,
    IntelSgx,
    IntelTdx,
    AmdSevSnp,
    ArmTrustZone,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    pub kind: BackendKind,
    pub implemented: bool,
    pub hardware_detected: bool,
    /// What the backend can enforce today. Empty for everything not implemented.
    pub capabilities: BackendCapabilities,
    pub note: &'static str,
}

fn probe_paths(root: &Path, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|rel| root.join(rel).exists())
        .map(|rel| format!("/{rel}"))
        .collect()
}

fn tee_probe(root: &Path, technology: TeeTechnology, candidates: &[&str]) -> TeeProbe {
    let evidence_paths = probe_paths(root, candidates);
    TeeProbe {
        technology,
        status: if evidence_paths.is_empty() {
            ProbeStatus::NotDetected
        } else {
            ProbeStatus::DevicePresent
        },
        evidence_paths,
        backend_implemented: false,
    }
}

/// `true` when `/proc/self/status` contains a `Seccomp:` line.
pub fn parse_seccomp_supported(proc_status: &str) -> bool {
    proc_status.lines().any(|l| l.starts_with("Seccomp:"))
}

/// Combines `/proc/sys/user/max_user_namespaces` and, where present,
/// `/proc/sys/kernel/unprivileged_userns_clone` (a Debian/Ubuntu switch).
pub fn parse_unprivileged_userns(
    max_user_namespaces: Option<&str>,
    unprivileged_userns_clone: Option<&str>,
) -> bool {
    let max = max_user_namespaces
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let clone_allowed = unprivileged_userns_clone
        .map(|s| s.trim() != "0")
        .unwrap_or(true);
    max > 0 && clone_allowed
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

pub fn detect_in(root: &Path) -> PlatformReport {
    let tee = vec![
        tee_probe(
            root,
            TeeTechnology::IntelSgx,
            &["dev/sgx_enclave", "dev/sgx/enclave", "dev/sgx_provision"],
        ),
        tee_probe(root, TeeTechnology::IntelTdx, &["dev/tdx_guest", "dev/tdx-guest"]),
        tee_probe(root, TeeTechnology::AmdSevSnp, &["dev/sev-guest"]),
        tee_probe(root, TeeTechnology::ArmTrustZone, &["dev/tee0", "dev/teepriv0"]),
    ];
    let seccomp_supported = read(root, "proc/self/status")
        .map(|s| parse_seccomp_supported(&s))
        .unwrap_or(false);
    let unprivileged_user_namespaces = parse_unprivileged_userns(
        read(root, "proc/sys/user/max_user_namespaces").as_deref(),
        read(root, "proc/sys/kernel/unprivileged_userns_clone").as_deref(),
    );
    PlatformReport {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        tee,
        tpm_device_present: !probe_paths(root, &["dev/tpmrm0", "dev/tpm0"]).is_empty(),
        software: SoftwareControls {
            seccomp_supported,
            unprivileged_user_namespaces,
        },
    }
}

/// Probes the running system.
pub fn detect() -> PlatformReport {
    detect_in(Path::new("/"))
}

fn tee_kind(t: TeeTechnology) -> BackendKind {
    match t {
        TeeTechnology::IntelSgx => BackendKind::IntelSgx,
        TeeTechnology::IntelTdx => BackendKind::IntelTdx,
        TeeTechnology::AmdSevSnp => BackendKind::AmdSevSnp,
        TeeTechnology::ArmTrustZone => BackendKind::ArmTrustZone,
    }
}

/// Inventory of every backend SERS knows about, with its real status.
pub fn backends(report: &PlatformReport) -> Vec<BackendInfo> {
    let mut out = vec![BackendInfo {
        kind: BackendKind::Software,
        implemented: false,
        hardware_detected: false,
        capabilities: BackendCapabilities::default(),
        note: "software isolation backend is not implemented yet; host controls are reported in PlatformReport.software",
    }];
    for p in &report.tee {
        out.push(BackendInfo {
            kind: tee_kind(p.technology),
            implemented: false,
            hardware_detected: p.status == ProbeStatus::DevicePresent,
            capabilities: BackendCapabilities::default(),
            note: "no backend implemented: interface and detection only; attestation is not supported",
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    fn probe_of(report: &PlatformReport, t: TeeTechnology) -> &TeeProbe {
        report.tee.iter().find(|p| p.technology == t).unwrap()
    }

    #[test]
    fn empty_root_detects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let r = detect_in(dir.path());
        assert!(r.tee.iter().all(|p| p.status == ProbeStatus::NotDetected));
        assert!(!r.tpm_device_present);
        assert!(!r.software.seccomp_supported);
        assert!(!r.software.unprivileged_user_namespaces);
    }

    #[test]
    fn device_nodes_are_reported_as_device_present_only() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "dev/sgx_enclave", "");
        touch(dir.path(), "dev/sev-guest", "");
        touch(dir.path(), "dev/tpmrm0", "");
        let r = detect_in(dir.path());
        let sgx = probe_of(&r, TeeTechnology::IntelSgx);
        assert_eq!(sgx.status, ProbeStatus::DevicePresent);
        assert_eq!(sgx.evidence_paths, vec!["/dev/sgx_enclave".to_owned()]);
        assert_eq!(probe_of(&r, TeeTechnology::AmdSevSnp).status, ProbeStatus::DevicePresent);
        assert_eq!(probe_of(&r, TeeTechnology::IntelTdx).status, ProbeStatus::NotDetected);
        assert!(r.tpm_device_present);
    }

    #[test]
    fn detected_hardware_never_becomes_an_implemented_backend() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "dev/sgx_enclave", "");
        touch(dir.path(), "dev/tdx_guest", "");
        touch(dir.path(), "dev/sev-guest", "");
        touch(dir.path(), "dev/tee0", "");
        let r = detect_in(dir.path());
        let list = backends(&r);
        assert_eq!(list.len(), 5);
        for b in &list {
            assert!(!b.implemented, "{:?}", b.kind);
            assert_eq!(b.capabilities, BackendCapabilities::default());
        }
        assert!(list.iter().filter(|b| b.hardware_detected).count() == 4);
    }

    #[test]
    fn seccomp_parsing() {
        assert!(parse_seccomp_supported("Name:\tx\nSeccomp:\t0\nSeccomp_filters:\t0\n"));
        assert!(!parse_seccomp_supported("Name:\tx\nUid:\t1000\n"));
        assert!(!parse_seccomp_supported(""));
    }

    #[test]
    fn userns_parsing() {
        assert!(parse_unprivileged_userns(Some("63000\n"), None));
        assert!(parse_unprivileged_userns(Some("63000"), Some("1\n")));
        assert!(!parse_unprivileged_userns(Some("63000"), Some("0\n")));
        assert!(!parse_unprivileged_userns(Some("0"), None));
        assert!(!parse_unprivileged_userns(Some("garbage"), None));
        assert!(!parse_unprivileged_userns(None, None));
    }

    #[test]
    fn fake_proc_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "proc/self/status", "Seccomp:\t0\n");
        touch(dir.path(), "proc/sys/user/max_user_namespaces", "1000\n");
        let r = detect_in(dir.path());
        assert!(r.software.seccomp_supported);
        assert!(r.software.unprivileged_user_namespaces);
    }

    #[test]
    fn report_serializes_to_json() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::to_string(&detect_in(dir.path())).unwrap();
        assert!(json.contains("intel_sgx"));
        assert!(json.contains("backend_implemented"));
    }
}
