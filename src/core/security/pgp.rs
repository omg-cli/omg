//! PGP signature verification using Sequoia-OpenPGP
//!
//! Verifies detached and inline PGP signatures for package integrity,
//! supports keyring management, and validates against trusted keys.

use std::io::{self, Cursor, Seek};
use std::path::Path;

use openpgp::Cert;
use openpgp::Packet;
use openpgp::cert::CertParser;
use openpgp::crypto::hash::Context;
use openpgp::parse::Parse;
use openpgp::parse::{PacketParser, PacketParserResult};
use openpgp::policy::{HashAlgoSecurity, Policy, StandardPolicy};
use sequoia_openpgp as openpgp;
use thiserror::Error;

/// Private bridge for upstream errors that Sequoia reports as
/// `anyhow::Error`. Keeps the public [`PgpError`]/[`SignatureFileError`]
/// variants fully typed while preserving the source error's `Display` and
/// `source()` chain.
#[derive(Debug, Error)]
#[error(transparent)]
#[doc(hidden)]
pub struct SequoiaSource(#[from] pub(super) anyhow::Error);

#[derive(Debug, Error)]
pub enum SignatureFileError {
    #[error("Package file missing for '{package_name}': {path}")]
    PackageMissing { package_name: String, path: String },
    #[error("PGP signature missing for '{package_name}': {path}")]
    SignatureMissing { package_name: String, path: String },
}

/// Failures loading a keyring or verifying a detached signature.
#[derive(Debug, Error)]
pub enum PgpError {
    #[error("System keyring not found at {path}")]
    KeyringMissing { path: String },
    #[error("Failed to open keyring '{path}'")]
    KeyringOpen {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Keyring '{path}' contains no certificates")]
    KeyringEmpty { path: String },
    #[error("Keyring '{path}' contains none of the allowed signing fingerprints")]
    KeyringNoAllowedFingerprint { path: String },
    #[error("Failed to parse keyring '{path}'")]
    KeyringParse {
        path: String,
        #[source]
        source: SequoiaSource,
    },
    #[error("Failed to open signature '{path}'")]
    SignatureOpen {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to parse signature '{path}'")]
    SignatureParse {
        path: String,
        #[source]
        source: SequoiaSource,
    },
    #[error("Failed to parse signature bytes")]
    SignatureBytesParse {
        #[source]
        source: SequoiaSource,
    },
    #[error("Failed to open package '{path}'")]
    PackageOpen {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to read package '{path}'")]
    PackageRead {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to initialize signature hash")]
    HashContext {
        #[source]
        source: SequoiaSource,
    },
    #[error("No valid signature found")]
    NoValidSignature,
}

/// PGP verification engine using Sequoia
pub struct PgpVerifier {
    policy: StandardPolicy<'static>,
    certs: Vec<Cert>,
}

fn system_keyring_path() -> Option<&'static str> {
    match crate::core::env::distro::detect_distro() {
        crate::core::env::distro::Distro::Debian | crate::core::env::distro::Distro::Ubuntu => {
            Some("/usr/share/keyrings/debian-archive-keyring.gpg")
        }
        crate::core::env::distro::Distro::Fedora => Some("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora"),
        crate::core::env::distro::Distro::Arch | crate::core::env::distro::Distro::Unknown => {
            Some("/usr/share/pacman/keyrings/archlinux.gpg")
        }
        crate::core::env::distro::Distro::MacOS => None,
    }
}

impl PgpVerifier {
    /// Load the distro keyring. Platforms without a default keyring get an
    /// empty trusted set; verify then fails with [`PgpError::NoValidSignature`].
    pub fn new() -> Result<Self, PgpError> {
        match system_keyring_path() {
            None => Ok(Self::empty()),
            Some(path) => Self::from_keyring(path),
        }
    }

    /// Empty trusted set. Every verify fails closed until certs are loaded.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            policy: StandardPolicy::new(),
            certs: Vec::new(),
        }
    }

    /// Load certificates from a keyring file. Missing, empty, and unreadable
    /// keyrings are errors — they are not treated as an empty trusted set.
    pub fn from_keyring(path: impl AsRef<Path>) -> Result<Self, PgpError> {
        let path = path.as_ref();
        let path_str = path.display().to_string();
        if !path.exists() {
            return Err(PgpError::KeyringMissing { path: path_str });
        }

        let mut file = std::fs::File::open(path).map_err(|source| PgpError::KeyringOpen {
            path: path_str.clone(),
            source,
        })?;
        let parser =
            CertParser::from_reader(&mut file).map_err(|source| PgpError::KeyringParse {
                path: path_str.clone(),
                source: source.into(),
            })?;
        let certs =
            parser
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| PgpError::KeyringParse {
                    path: path_str.clone(),
                    source: source.into(),
                })?;
        if certs.is_empty() {
            return Err(PgpError::KeyringEmpty { path: path_str });
        }

        Ok(Self {
            policy: StandardPolicy::new(),
            certs,
        })
    }

    /// Load only certificates whose primary fingerprint is explicitly allowed.
    /// This turns a remotely refreshed key bundle into a pinned trust root.
    pub fn from_keyring_with_allowed_fingerprints(
        path: impl AsRef<Path>,
        allowed: &[&str],
    ) -> Result<Self, PgpError> {
        let path = path.as_ref();
        let path_text = path.display().to_string();
        let mut verifier = Self::from_keyring(path)?;
        verifier.certs.retain(|cert| {
            let fingerprint = cert.fingerprint().to_hex().to_ascii_uppercase();
            allowed.iter().any(|allowed| {
                allowed
                    .chars()
                    .filter(|character| !character.is_ascii_whitespace())
                    .collect::<String>()
                    .to_ascii_uppercase()
                    == fingerprint
            })
        });
        if verifier.certs.is_empty() {
            return Err(PgpError::KeyringNoAllowedFingerprint { path: path_text });
        }
        Ok(verifier)
    }

    /// Verify a file against a detached signature using the loaded keyring.
    pub fn verify_detached(&self, file_path: &Path, sig_path: &Path) -> Result<(), PgpError> {
        let path = file_path.display().to_string();
        let mut data_file =
            std::fs::File::open(file_path).map_err(|source| PgpError::PackageOpen {
                path: path.clone(),
                source,
            })?;
        let mut sig_file =
            std::fs::File::open(sig_path).map_err(|source| PgpError::SignatureOpen {
                path: sig_path.display().to_string(),
                source,
            })?;

        let mut ppr = PacketParser::from_reader(&mut sig_file).map_err(|source| {
            PgpError::SignatureParse {
                path: sig_path.display().to_string(),
                source: source.into(),
            }
        })?;

        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(sig) = &pp.packet {
                let mut hasher = Self::signature_hasher(sig)?;
                data_file
                    .seek(io::SeekFrom::Start(0))
                    .map_err(|source| PgpError::PackageRead {
                        path: path.clone(),
                        source,
                    })?;
                std::io::copy(&mut data_file, &mut hasher).map_err(|source| {
                    PgpError::PackageRead {
                        path: path.clone(),
                        source,
                    }
                })?;

                if self.matches_any_trusted_cert(sig, &hasher) {
                    return Ok(());
                }
            }
            ppr = pp
                .next()
                .map_err(|source| PgpError::SignatureParse {
                    path: sig_path.display().to_string(),
                    source: source.into(),
                })?
                .1;
        }

        Err(PgpError::NoValidSignature)
    }

    /// Verify data against a detached signature (memory-based)
    pub fn verify_memory(&self, data: &[u8], signature: &[u8]) -> Result<(), PgpError> {
        let mut ppr = PacketParser::from_reader(Cursor::new(signature)).map_err(|source| {
            PgpError::SignatureBytesParse {
                source: source.into(),
            }
        })?;

        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(sig) = &pp.packet {
                let mut hasher = Self::signature_hasher(sig)?;
                hasher.update(data);

                if self.matches_any_trusted_cert(sig, &hasher) {
                    return Ok(());
                }
            }
            ppr = pp
                .next()
                .map_err(|source| PgpError::SignatureBytesParse {
                    source: source.into(),
                })?
                .1;
        }

        Err(PgpError::NoValidSignature)
    }

    /// Build the hash context for one signature packet.
    ///
    /// # Errors
    /// Returns [`PgpError::HashContext`] when the signature's hash algorithm
    /// has no usable context (unsupported or disabled algorithm).
    fn signature_hasher(sig: &openpgp::packet::Signature) -> Result<Context, PgpError> {
        Ok(sig
            .hash_algo()
            .context()
            .map_err(|source| PgpError::HashContext {
                source: SequoiaSource(source),
            })?
            .for_signature(sig.version()))
    }

    /// Try `sig` against every signing-capable key of every cert that
    /// plausibly issued it. Shared by [`Self::verify_detached`] and
    /// [`Self::verify_memory`]; returns true on the first successful check.
    fn matches_any_trusted_cert(&self, sig: &openpgp::packet::Signature, hasher: &Context) -> bool {
        if sig
            .signature_alive(None, Some(std::time::Duration::ZERO))
            .is_err()
        {
            return false;
        }
        if self
            .policy
            .signature(sig, HashAlgoSecurity::CollisionResistance)
            .is_err()
        {
            return false;
        }

        let issuers = sig.get_issuers();
        for cert in &self.certs {
            let relevant_cert = issuers.is_empty()
                || issuers
                    .iter()
                    .any(|issuer| cert.keys().any(|k| k.key().key_handle().aliases(issuer)));
            if !relevant_cert {
                continue;
            }

            for key in cert
                .keys()
                .with_policy(&self.policy, None)
                .alive()
                .revoked(false)
                .for_signing()
            {
                if sig.verify_hash(key.key(), hasher.clone()).is_ok() {
                    return true;
                }
            }
        }
        false
    }
}

/// Fail closed when a package blob or its detached `.sig` is missing.
/// Skipping unsigned packages is not verification.
pub fn require_detached_signature_files(
    package_name: &str,
    package_path: &Path,
    signature_path: &Path,
) -> Result<(), SignatureFileError> {
    if !package_path.exists() {
        return Err(SignatureFileError::PackageMissing {
            package_name: package_name.to_string(),
            path: package_path.display().to_string(),
        });
    }
    if !signature_path.exists() {
        return Err(SignatureFileError::SignatureMissing {
            package_name: package_name.to_string(),
            path: signature_path.display().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_verify_detached_missing_signature() {
        let verifier = PgpVerifier::empty();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.sig");

        let mut data_file = NamedTempFile::new().unwrap();
        writeln!(data_file, "test data").unwrap();
        data_file.flush().unwrap();

        let err = verifier
            .verify_detached(data_file.path(), &missing)
            .expect_err("missing signature must fail");
        assert!(
            matches!(
                &err,
                PgpError::SignatureOpen { path, source }
                    if path == &missing.display().to_string()
                        && source.kind() == std::io::ErrorKind::NotFound
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_verify_detached_missing_data_file() {
        let verifier = PgpVerifier::empty();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.data");

        let mut sig_file = NamedTempFile::new().unwrap();
        writeln!(sig_file, "fake signature").unwrap();
        sig_file.flush().unwrap();

        let err = verifier
            .verify_detached(&missing, sig_file.path())
            .expect_err("missing package blob must fail");
        assert!(
            matches!(
                &err,
                PgpError::PackageOpen { path, source }
                    if path == &missing.display().to_string()
                        && source.kind() == std::io::ErrorKind::NotFound
            ),
            "got: {err}"
        );
    }

    fn signed_fixture(hash: openpgp::types::HashAlgorithm) -> (PgpVerifier, Vec<u8>) {
        signed_fixture_at(
            hash,
            std::time::SystemTime::now(),
            std::time::Duration::from_hours(1),
        )
    }

    fn signed_fixture_at(
        hash: openpgp::types::HashAlgorithm,
        created: std::time::SystemTime,
        validity: std::time::Duration,
    ) -> (PgpVerifier, Vec<u8>) {
        use openpgp::cert::prelude::CertBuilder;
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::serialize::Serialize as _;
        use openpgp::types::SignatureType;

        let (cert, _) = CertBuilder::general_purpose(Some("omg-test@example.invalid"))
            .set_creation_time(std::time::SystemTime::now() - std::time::Duration::from_hours(24))
            .generate()
            .expect("generate test certificate");
        let policy = StandardPolicy::new();
        let mut signer = cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .for_signing()
            .next()
            .expect("test signing key")
            .key()
            .clone()
            .into_keypair()
            .expect("test keypair");
        let signature = SignatureBuilder::new(SignatureType::Binary)
            .set_hash_algo(hash)
            .set_signature_creation_time(created)
            .expect("signature creation time")
            .set_signature_validity_period(validity)
            .expect("signature validity")
            .sign_message(&mut signer, b"test data")
            .expect("sign test data");
        let mut serialized = Vec::new();
        Packet::from(signature)
            .serialize(&mut serialized)
            .expect("serialize signature");
        (
            PgpVerifier {
                policy: StandardPolicy::new(),
                certs: vec![cert],
            },
            serialized,
        )
    }

    #[test]
    fn valid_sha256_signature_is_accepted() {
        let (verifier, signature) = signed_fixture(openpgp::types::HashAlgorithm::SHA256);
        verifier
            .verify_memory(b"test data", &signature)
            .expect("valid trusted SHA-256 signature");
        assert!(matches!(
            verifier.verify_memory(b"altered data", &signature),
            Err(PgpError::NoValidSignature)
        ));

        let mut data_file = NamedTempFile::new().unwrap();
        data_file.write_all(b"test data").unwrap();
        data_file.flush().unwrap();
        let mut sig_file = NamedTempFile::new().unwrap();
        sig_file.write_all(&signature).unwrap();
        sig_file.flush().unwrap();

        verifier
            .verify_detached(data_file.path(), sig_file.path())
            .expect("valid trusted SHA-256 detached signature");
        std::fs::write(data_file.path(), b"altered data").unwrap();
        assert!(matches!(
            verifier.verify_detached(data_file.path(), sig_file.path()),
            Err(PgpError::NoValidSignature)
        ));
    }

    #[test]
    fn expired_and_future_signatures_are_rejected() {
        let now = std::time::SystemTime::now();
        for created in [
            now - std::time::Duration::from_hours(1),
            now + std::time::Duration::from_hours(1),
        ] {
            let (verifier, signature) = signed_fixture_at(
                openpgp::types::HashAlgorithm::SHA256,
                created,
                std::time::Duration::from_mins(1),
            );
            assert!(matches!(
                verifier.verify_memory(b"test data", &signature),
                Err(PgpError::NoValidSignature)
            ));
            let mut data = NamedTempFile::new().unwrap();
            data.write_all(b"test data").unwrap();
            let mut sig = NamedTempFile::new().unwrap();
            sig.write_all(&signature).unwrap();
            assert!(matches!(
                verifier.verify_detached(data.path(), sig.path()),
                Err(PgpError::NoValidSignature)
            ));
        }
    }

    #[test]
    fn sha1_signature_is_rejected_by_policy() {
        let (verifier, signature) = signed_fixture(openpgp::types::HashAlgorithm::SHA1);
        assert!(matches!(
            verifier.verify_memory(b"test data", &signature),
            Err(PgpError::NoValidSignature)
        ));
    }

    #[test]
    fn test_verify_memory_invalid_signature() {
        let verifier = PgpVerifier::empty();
        let err = verifier
            .verify_memory(b"test data", b"not a real signature")
            .expect_err("garbage signature bytes must fail");
        assert!(
            matches!(err, PgpError::SignatureBytesParse { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn test_verify_memory_empty_signature() {
        let verifier = PgpVerifier::empty();
        let err = verifier
            .verify_memory(b"test data", b"")
            .expect_err("empty signature must fail");
        assert!(matches!(err, PgpError::NoValidSignature), "got: {err}");
    }

    fn expect_pgp_err(result: Result<PgpVerifier, PgpError>, why: &str) -> PgpError {
        match result {
            Err(err) => err,
            Ok(_) => panic!("{why}"),
        }
    }

    #[test]
    fn missing_keyring_is_an_error() {
        let err = expect_pgp_err(
            PgpVerifier::from_keyring("/nonexistent-omg-keyring.gpg"),
            "missing keyring must fail closed",
        );
        assert!(matches!(err, PgpError::KeyringMissing { .. }), "got: {err}");
    }

    #[test]
    fn empty_keyring_file_is_an_error() {
        let empty = NamedTempFile::new().unwrap();
        let err = expect_pgp_err(
            PgpVerifier::from_keyring(empty.path()),
            "empty keyring must not become an empty trusted set",
        );
        assert!(matches!(err, PgpError::KeyringEmpty { .. }), "got: {err}");
    }

    #[test]
    fn corrupt_keyring_is_an_error() {
        let mut keyring = NamedTempFile::new().unwrap();
        writeln!(keyring, "this is not an OpenPGP keyring").unwrap();
        keyring.flush().unwrap();
        let err = expect_pgp_err(
            PgpVerifier::from_keyring(keyring.path()),
            "corrupt keyring must fail closed",
        );
        assert!(matches!(err, PgpError::KeyringParse { .. }), "got: {err}");
    }

    #[test]
    fn fingerprint_allowlist_filters_downloaded_keyrings() {
        use openpgp::cert::prelude::CertBuilder;
        use openpgp::serialize::Serialize as _;

        let (allowed, _) = CertBuilder::general_purpose(Some("allowed@example.invalid"))
            .generate()
            .unwrap();
        let (injected, _) = CertBuilder::general_purpose(Some("injected@example.invalid"))
            .generate()
            .unwrap();
        let allowed_fingerprint = allowed.fingerprint().to_hex();
        let mut keyring = NamedTempFile::new().unwrap();
        allowed.serialize(&mut keyring).unwrap();
        injected.serialize(&mut keyring).unwrap();
        keyring.flush().unwrap();

        let verifier = PgpVerifier::from_keyring_with_allowed_fingerprints(
            keyring.path(),
            &[&allowed_fingerprint],
        )
        .unwrap();
        assert_eq!(verifier.certs.len(), 1);
        assert_eq!(verifier.certs[0].fingerprint(), allowed.fingerprint());
        assert!(matches!(
            PgpVerifier::from_keyring_with_allowed_fingerprints(
                keyring.path(),
                &["0000000000000000000000000000000000000000"],
            ),
            Err(PgpError::KeyringNoAllowedFingerprint { .. })
        ));
    }

    #[test]
    fn empty_verifier_rejects_garbage_package_signature() {
        let verifier = PgpVerifier::empty();

        let mut pkg = NamedTempFile::new().unwrap();
        writeln!(pkg, "package data").unwrap();
        pkg.flush().unwrap();

        let mut sig = NamedTempFile::new().unwrap();
        writeln!(sig, "signature").unwrap();
        sig.flush().unwrap();

        let err = verifier
            .verify_detached(pkg.path(), sig.path())
            .expect_err("garbage signature must fail verification");
        assert!(matches!(err, PgpError::SignatureParse { .. }), "got: {err}");
    }

    #[test]
    fn missing_signature_file_is_not_skipped() {
        let mut pkg = NamedTempFile::new().unwrap();
        writeln!(pkg, "package data").unwrap();
        pkg.flush().unwrap();
        let err = require_detached_signature_files(
            "vim",
            pkg.path(),
            std::path::Path::new("/nonexistent.sig"),
        )
        .expect_err("unsigned packages must not proceed");
        assert!(
            matches!(err, SignatureFileError::SignatureMissing { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn missing_package_file_is_an_error() {
        let mut sig = NamedTempFile::new().unwrap();
        writeln!(sig, "sig").unwrap();
        sig.flush().unwrap();
        let err = require_detached_signature_files(
            "vim",
            std::path::Path::new("/nonexistent.pkg"),
            sig.path(),
        )
        .expect_err("missing package blob must fail");
        assert!(
            matches!(err, SignatureFileError::PackageMissing { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn present_package_and_signature_paths_are_accepted() {
        let mut pkg = NamedTempFile::new().unwrap();
        writeln!(pkg, "package data").unwrap();
        pkg.flush().unwrap();
        let mut sig = NamedTempFile::new().unwrap();
        writeln!(sig, "sig").unwrap();
        sig.flush().unwrap();
        assert!(require_detached_signature_files("vim", pkg.path(), sig.path()).is_ok());
    }
}
