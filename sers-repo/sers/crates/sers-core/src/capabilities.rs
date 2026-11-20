use serde::{Deserialize, Serialize};

/// What an execution backend can *actually* enforce.
///
/// Backends must derive these flags from implemented and detected controls,
/// never from configuration. The default is "nothing is guaranteed".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Protected code runs in a separate OS process.
    pub process_isolation: bool,
    /// Filesystem access of the protected process is restricted.
    pub filesystem_restrictions: bool,
    /// Network access of the protected process is restricted.
    pub network_restrictions: bool,
    /// A hardware TEE protects confidentiality of code/data in use.
    pub hardware_backed_confidentiality: bool,
    /// The backend can produce hardware attestation evidence.
    pub remote_attestation: bool,
}

/// Confidential-computing technologies SERS knows about. They are **not**
/// interchangeable: each has its own attestation format and trust roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeTechnology {
    IntelSgx,
    IntelTdx,
    AmdSevSnp,
    ArmTrustZone,
}
