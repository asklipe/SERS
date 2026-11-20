//! Client SDK for applications protected with SERS.
//!
//! An application trusts a set of publisher keys and the Control Plane's
//! authorization key, registers its installation, and then opens `.sers`
//! packages. Opening a package runs the whole protocol: local verification
//! (publisher, application, revocation, downgrade, module hashes), challenge and
//! response, verification of the signed authorization, and receipt of the
//! package key sealed to this session. Modules are decrypted on demand and only
//! while the authorization is valid.
//!
//! What this SDK does **not** do: it does not isolate the decrypted module. The
//! plaintext lives in this process (ABI 1, "data module"; see `docs/MODULE_ABI.md`).
//! Network transport is supplied by the caller through [`Transport`]; none ships yet.

pub mod app;
pub mod clock;
pub mod transport;

#[cfg(test)]
mod tests;

pub use app::{OpenedPackage, SersApplication, SersApplicationBuilder};
pub use clock::{Clock, SystemClock, MAX_CLOCK_REGRESSION_SECS};
pub use transport::{AuthorizationOutcome, ClientClaim, DenyKind, Grant, Transport};
