use crate::audit::AuditLog;
use sers_core::{
    ApplicationId, Digest32, ExecutionPolicy, InstallationId, LicenseId, PackageId, PublicKeyBytes,
    PublisherKeyId, TenantId,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallationStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageStatus {
    Active,
    Revoked,
}

pub(crate) struct Application {
    pub tenant: TenantId,
    pub execution_policy: ExecutionPolicy,
    pub publisher_keys: HashMap<PublisherKeyId, PublicKeyBytes>,
    pub min_version_counter: u64,
    pub status: AppStatus,
}

pub(crate) struct PackageRecord {
    pub tenant: TenantId,
    pub package_id: PackageId,
    pub version_counter: u64,
    pub status: PackageStatus,
    /// Package key wrapped by the `KeyProvider`; never stored in clear.
    pub wrapped_key: Vec<u8>,
}

pub(crate) struct Installation {
    pub tenant: TenantId,
    pub application_id: ApplicationId,
    pub public_key: PublicKeyBytes,
    pub license_id: LicenseId,
    pub status: InstallationStatus,
}

pub(crate) struct License {
    pub tenant: TenantId,
    pub application_id: ApplicationId,
    pub status: LicenseStatus,
    pub expires_at: Option<u64>,
    pub max_installations: u32,
    pub installations: HashSet<InstallationId>,
}

#[derive(Default)]
pub(crate) struct State {
    pub tenants: HashSet<TenantId>,
    pub api_keys: HashMap<[u8; 32], TenantId>,
    /// Application ids are globally unique: a client names only the
    /// application, so each id must resolve to exactly one tenant.
    pub apps: HashMap<ApplicationId, Application>,
    pub packages: HashMap<(ApplicationId, Digest32), PackageRecord>,
    pub installations: HashMap<InstallationId, Installation>,
    pub licenses: HashMap<LicenseId, License>,
    pub audit: AuditLog,
}
