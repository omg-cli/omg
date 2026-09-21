#[cfg(unix)]
pub mod artifact;
pub mod audit;
#[cfg(feature = "pgp")]
pub mod keyserver;
#[cfg(feature = "pgp")]
pub mod pgp;
pub mod policy;
pub mod sbom;
pub mod scan;
pub mod secrets;
pub mod slsa;
pub mod validation;
pub mod vulnerability;

pub use audit::{
    AuditError, AuditEventType, AuditLogger, AuditSeverity, audit_log_nonblocking,
    init_audit_logger,
};
pub use policy::{PolicyError, SecurityGrade, SecurityPolicy};
pub use sbom::{Sbom, SbomError, SbomGenerator};
pub use secrets::{SecretError, SecretScanResult, SecretScanner};
pub use slsa::{SlsaError, SlsaLevel, SlsaVerifier};
pub use validation::{
    ValidationError, is_local_debian_package_file, is_local_package_file,
    validate_debian_package_name_or_file, validate_debian_package_names_or_files,
    validate_debian_package_specs, validate_image_ref, validate_package_name,
    validate_package_name_or_file, validate_package_names, validate_package_names_or_files,
    validate_relative_path, validate_runtime_version, validate_version,
};
#[cfg(unix)]
pub use validation::{validate_local_debian_package_file, validate_local_package_file};

/// Require explicit consent when any target is a local archive file.
/// One gate so the ultra-fast root path and the normal install path cannot
/// diverge on which archives count as local.
///
/// Deliberately ungated: the install-path caller is unconditional, and the
/// body is portable (the Debian branch is inner-gated). Gating this would
/// silently drop a consent check under some feature sets.
pub fn ensure_local_archive_consent(packages: &[String], allowed: bool) -> anyhow::Result<()> {
    let includes_local_file = packages.iter().any(|package| {
        if is_local_package_file(package) {
            return true;
        }
        #[cfg(any(feature = "debian", feature = "debian-pure"))]
        if crate::core::env::distro::is_debian_like() && is_local_debian_package_file(package) {
            return true;
        }
        false
    });
    anyhow::ensure!(
        !includes_local_file || allowed,
        "Local package archives require explicit consent: pass --allow-local-file after reviewing the archive source"
    );
    Ok(())
}
pub use vulnerability::{VulnerabilityError, VulnerabilityScanner};
