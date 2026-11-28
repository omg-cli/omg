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
    #[error("Expected a cleartext-signed OpenPGP message")]
    CleartextFormat,
    #[error("Cleartext {kind} exceeds the {limit}-byte limit")]
    CleartextLimit { kind: &'static str, limit: usize },
    #[error("Cleartext signature authentication failed")]
    CleartextVerification {
        #[source]
        source: SequoiaSource,
    },
    #[error("Failed to parse the embedded public certificate bundle")]
    PublicKeyBundleParse {
        #[source]
        source: SequoiaSource,
    },
    #[error("The public certificate bundle contains secret material or no allowed certificates")]
    PublicKeyBundleRejected,
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
        verifier.retain_allowed_fingerprints(allowed);
        if verifier.certs.is_empty() {
            return Err(PgpError::KeyringNoAllowedFingerprint { path: path_text });
        }
        Ok(verifier)
    }

    pub(crate) fn from_public_key_bytes(bytes: &[u8], allowed: &[&str]) -> Result<Self, PgpError> {
        let parser =
            CertParser::from_bytes(bytes).map_err(|source| PgpError::PublicKeyBundleParse {
                source: source.into(),
            })?;
        let certs = parser.collect::<Result<Vec<_>, _>>().map_err(|source| {
            PgpError::PublicKeyBundleParse {
                source: source.into(),
            }
        })?;
        if certs.iter().any(Cert::is_tsk) {
            return Err(PgpError::PublicKeyBundleRejected);
        }
        let mut verifier = Self {
            policy: StandardPolicy::new(),
            certs,
        };
        verifier.retain_allowed_fingerprints(allowed);
        if verifier.certs.is_empty() {
            return Err(PgpError::PublicKeyBundleRejected);
        }
        Ok(verifier)
    }

    fn retain_allowed_fingerprints(&mut self, allowed: &[&str]) {
        self.certs.retain(|cert| {
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
    }

    /// Authenticate a bounded cleartext signature before returning its plaintext.
    pub fn verify_cleartext_memory(
        &self,
        signed: &[u8],
        max_plaintext: usize,
    ) -> Result<Vec<u8>, PgpError> {
        const LIMIT: usize = 1024 * 1024;
        if signed.len() > LIMIT {
            return Err(PgpError::CleartextLimit {
                kind: "signed input",
                limit: LIMIT,
            });
        }
        if !signed.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----") {
            return Err(PgpError::CleartextFormat);
        }
        self.verify_cleartext_message(signed, max_plaintext)
    }

    fn verify_cleartext_message(
        &self,
        signed: &[u8],
        max_plaintext: usize,
    ) -> Result<Vec<u8>, PgpError> {
        use openpgp::parse::stream::{
            MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder,
        };
        use openpgp::types::RevocationStatus;

        struct Helper<'a>(&'a PgpVerifier);
        impl VerificationHelper for Helper<'_> {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
                Ok(self.0.certs.clone())
            }

            fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
                let trusted =
                    structure.iter().any(|layer| {
                        let MessageLayer::SignatureGroup { results } = layer else {
                            return false;
                        };
                        results.iter().any(|result| {
                            let Ok(good) = result else {
                                return false;
                            };
                            if good
                                .sig
                                .signature_alive(None, Some(std::time::Duration::ZERO))
                                .is_err()
                                || self
                                    .0
                                    .policy
                                    .signature(good.sig, HashAlgoSecurity::CollisionResistance)
                                    .is_err()
                            {
                                return false;
                            }
                            self.0.certs.iter().any(|cert| {
                                if cert.fingerprint() != good.ka.cert().fingerprint() {
                                    return false;
                                }
                                let Ok(current) = cert.with_policy(&self.0.policy, None) else {
                                    return false;
                                };
                                current.alive().is_ok()
                                    && !matches!(
                                        current.revocation_status(),
                                        RevocationStatus::Revoked(_)
                                    )
                                    && current.keys().alive().revoked(false).for_signing().any(
                                        |key| {
                                            key.key().fingerprint() == good.ka.key().fingerprint()
                                        },
                                    )
                            })
                        })
                    });
                anyhow::ensure!(trusted, "No currently valid trusted cleartext signature");
                Ok(())
            }
        }
        let mut verifier = VerifierBuilder::from_bytes(signed)
            .and_then(|builder| builder.with_policy(&self.policy, None, Helper(self)))
            .map_err(|source| PgpError::CleartextVerification {
                source: source.into(),
            })?;
        let plaintext = Self::read_cleartext_plaintext(&mut verifier, max_plaintext)?;
        if verifier.processing_csf_message() != Some(true) {
            return Err(PgpError::CleartextFormat);
        }
        Ok(plaintext)
    }

    fn read_cleartext_plaintext(
        reader: &mut impl std::io::Read,
        max_plaintext: usize,
    ) -> Result<Vec<u8>, PgpError> {
        use std::io::Read as _;
        let limit = max_plaintext.min(1024 * 1024);
        let mut plaintext = Vec::new();
        reader
            .by_ref()
            .take((limit + 1) as u64)
            .read_to_end(&mut plaintext)
            .map_err(|source| PgpError::CleartextVerification {
                source: SequoiaSource(source.into()),
            })?;
        if plaintext.len() > limit {
            return Err(PgpError::CleartextLimit {
                kind: "plaintext",
                limit,
            });
        }
        Ok(plaintext)
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

        let mut hash_error: Option<PgpError> = None;

        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(sig) = &pp.packet {
                match Self::signature_hasher(sig) {
                    Ok(mut hasher) => {
                        data_file.seek(io::SeekFrom::Start(0)).map_err(|source| {
                            PgpError::PackageRead {
                                path: path.clone(),
                                source,
                            }
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
                    Err(error) => {
                        hash_error.get_or_insert(error);
                    }
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

        Err(hash_error.unwrap_or(PgpError::NoValidSignature))
    }

    /// Verify data against a detached signature (memory-based)
    pub fn verify_memory(&self, data: &[u8], signature: &[u8]) -> Result<(), PgpError> {
        let mut ppr = PacketParser::from_reader(Cursor::new(signature)).map_err(|source| {
            PgpError::SignatureBytesParse {
                source: source.into(),
            }
        })?;
        let mut hash_error: Option<PgpError> = None;

        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(sig) = &pp.packet {
                match Self::signature_hasher(sig) {
                    Ok(mut hasher) => {
                        hasher.update(data);

                        if self.matches_any_trusted_cert(sig, &hasher) {
                            return Ok(());
                        }
                    }
                    Err(error) => {
                        hash_error.get_or_insert(error);
                    }
                }
            }
            ppr = pp
                .next()
                .map_err(|source| PgpError::SignatureBytesParse {
                    source: source.into(),
                })?
                .1;
        }

        Err(hash_error.unwrap_or(PgpError::NoValidSignature))
    }

    /// Build the hash context for one signature packet.
    ///
    /// # Errors
    /// Returns [`PgpError::HashContext`] when the signature's hash algorithm
    /// has no usable context (unsupported or disabled algorithm).
    fn signature_hasher(sig: &openpgp::packet::Signature) -> Result<Context, PgpError> {
        let mut hasher = sig
            .hash_algo()
            .context()
            .map_err(|source| PgpError::HashContext {
                source: SequoiaSource(source),
            })?
            .for_signature(sig.version());
        if let Some(salt) = sig.salt() {
            hasher.update(salt);
        }
        Ok(hasher)
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
pub(crate) mod tests {
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
            openpgp::cert::CipherSuite::Cv25519,
            openpgp::Profile::RFC4880,
        )
    }

    fn signed_fixture_at(
        hash: openpgp::types::HashAlgorithm,
        created: std::time::SystemTime,
        validity: std::time::Duration,
        suite: openpgp::cert::CipherSuite,
        profile: openpgp::Profile,
    ) -> (PgpVerifier, Vec<u8>) {
        use openpgp::cert::prelude::CertBuilder;
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::serialize::Serialize as _;
        use openpgp::types::SignatureType;

        let (cert, _) = CertBuilder::general_purpose(Some("omg-test@example.invalid"))
            .set_cipher_suite(suite)
            .set_profile(profile)
            .expect("certificate profile")
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
                certs: vec![cert.strip_secret_key_material()],
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

    pub(crate) fn cleartext_fixture(
        data: &[u8],
        hash: openpgp::types::HashAlgorithm,
        created: std::time::SystemTime,
        signature_validity: std::time::Duration,
        certificate_validity: std::time::Duration,
        revoked: bool,
    ) -> (PgpVerifier, Vec<u8>) {
        use openpgp::cert::prelude::CertBuilder;
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::serialize::stream::{Message, Signer};
        use openpgp::types::SignatureType;

        let (cert, revocation) = CertBuilder::general_purpose(Some("cleartext@example.invalid"))
            .set_cipher_suite(openpgp::cert::CipherSuite::Cv25519)
            .set_profile(openpgp::Profile::RFC4880)
            .expect("certificate profile")
            .set_creation_time(std::time::SystemTime::now() - std::time::Duration::from_hours(24))
            .set_validity_period(certificate_validity)
            .generate()
            .expect("cleartext certificate");
        let signer = cert
            .keys()
            .secret()
            .with_policy(&StandardPolicy::new(), created)
            .for_signing()
            .next()
            .expect("cleartext signing key")
            .key()
            .clone()
            .into_keypair()
            .expect("cleartext keypair");
        let template = SignatureBuilder::new(SignatureType::Text)
            .set_hash_algo(hash)
            .set_signature_creation_time(created)
            .expect("cleartext creation time")
            .set_signature_validity_period(signature_validity)
            .expect("cleartext validity");
        let mut signed = Vec::new();
        let mut writer = Signer::with_template(Message::new(&mut signed), signer, template)
            .expect("cleartext signer")
            .hash_algo(hash)
            .expect("cleartext hash")
            .creation_time(created)
            .cleartext()
            .build()
            .expect("cleartext writer");
        writer.write_all(data).expect("cleartext write");
        writer.finalize().expect("cleartext finalization");
        let cert = if revoked {
            cert.insert_packets([revocation])
                .expect("revoke certificate")
                .0
        } else {
            cert
        };
        (
            PgpVerifier {
                policy: StandardPolicy::new(),
                certs: vec![cert.strip_secret_key_material()],
            },
            signed,
        )
    }

    #[test]
    fn cleartext_authenticates_lines_and_enforces_plaintext_bounds() {
        for data in [
            b"first\n- dash escaped\nlast\n".as_slice(),
            b"first\r\n- dash escaped\r\nlast\r\n",
        ] {
            let (verifier, signed) = cleartext_fixture(
                data,
                openpgp::types::HashAlgorithm::SHA256,
                std::time::SystemTime::now(),
                std::time::Duration::from_hours(1),
                std::time::Duration::from_hours(48),
                false,
            );
            let plaintext = verifier
                .verify_cleartext_memory(&signed, 1024)
                .expect("valid cleartext");
            assert_eq!(
                std::str::from_utf8(&plaintext)
                    .unwrap()
                    .lines()
                    .collect::<Vec<_>>(),
                ["first", "- dash escaped", "last"]
            );
            assert_eq!(
                verifier
                    .verify_cleartext_memory(&signed, plaintext.len())
                    .unwrap(),
                plaintext
            );
            assert!(
                verifier
                    .verify_cleartext_memory(&signed, plaintext.len() - 1)
                    .is_err()
            );
        }
    }

    #[test]
    fn cleartext_refuses_tampering_foreign_trust_unsigned_truncated_and_excessive_input() {
        let fixture = || {
            cleartext_fixture(
                b"authenticated manifest\n",
                openpgp::types::HashAlgorithm::SHA256,
                std::time::SystemTime::now(),
                std::time::Duration::from_hours(1),
                std::time::Duration::from_hours(48),
                false,
            )
        };
        let (verifier, signed) = fixture();
        assert!(verifier.verify_cleartext_memory(&signed, 1024).is_ok());
        let (foreign, _) = fixture();
        assert!(foreign.verify_cleartext_memory(&signed, 1024).is_err());
        assert!(
            PgpVerifier::empty()
                .verify_cleartext_memory(&signed, 1024)
                .is_err()
        );
        let tampered = String::from_utf8(signed.clone())
            .unwrap()
            .replace("authenticated manifest", "altered manifest");
        for invalid in [
            tampered.into_bytes(),
            signed[..signed.len() / 2].to_vec(),
            b"unsigned manifest\n".to_vec(),
            vec![b'x'; 1024 * 1024 + 1],
        ] {
            assert!(verifier.verify_cleartext_memory(&invalid, 1024).is_err());
        }
    }

    #[test]
    fn cleartext_refuses_weak_expired_and_future_signatures() {
        let now = std::time::SystemTime::now();
        for (hash, created) in [
            (openpgp::types::HashAlgorithm::SHA1, now),
            (
                openpgp::types::HashAlgorithm::SHA256,
                now - std::time::Duration::from_hours(2),
            ),
            (
                openpgp::types::HashAlgorithm::SHA256,
                now + std::time::Duration::from_hours(1),
            ),
        ] {
            let (verifier, signed) = cleartext_fixture(
                b"manifest\n",
                hash,
                created,
                std::time::Duration::from_hours(1),
                std::time::Duration::from_hours(48),
                false,
            );
            assert!(
                verifier.verify_cleartext_memory(&signed, 1024).is_err(),
                "{hash:?} {created:?}"
            );
        }
    }

    #[test]
    fn cleartext_requires_current_alive_nonrevoked_authorities() {
        for (revoked, certificate_validity) in [
            (true, std::time::Duration::from_hours(48)),
            (false, std::time::Duration::from_hours(23)),
        ] {
            let (verifier, signed) = cleartext_fixture(
                b"manifest\n",
                openpgp::types::HashAlgorithm::SHA256,
                std::time::SystemTime::now() - std::time::Duration::from_hours(2),
                std::time::Duration::from_hours(4),
                certificate_validity,
                revoked,
            );
            assert!(verifier.verify_cleartext_memory(&signed, 1024).is_err());
        }
    }

    #[test]
    fn cleartext_bounds_even_a_valid_signed_input() {
        let mut data = vec![b'x'; 1024 * 1024 - 100];
        data.push(b'\n');
        let (verifier, signed) = cleartext_fixture(
            &data,
            openpgp::types::HashAlgorithm::SHA256,
            std::time::SystemTime::now(),
            std::time::Duration::from_hours(1),
            std::time::Duration::from_hours(48),
            false,
        );
        assert!(data.len() < 1024 * 1024 && signed.len() > 1024 * 1024);
        assert!(matches!(
            verifier.verify_cleartext_memory(&signed, 1024 * 1024),
            Err(PgpError::CleartextLimit {
                kind: "signed input",
                limit: 1_048_576
            })
        ));
    }

    #[test]
    fn cleartext_inner_authentication_refuses_real_attached_messages_and_compression_containers() {
        use openpgp::cert::prelude::CertBuilder;
        use openpgp::serialize::stream::{Armorer, Compressor, LiteralWriter, Message, Signer};
        let (certificate, _) =
            CertBuilder::general_purpose(Some("format-boundary@example.invalid"))
                .set_cipher_suite(openpgp::cert::CipherSuite::Cv25519)
                .generate()
                .expect("controlled signing certificate");
        let verifier = PgpVerifier {
            policy: StandardPolicy::new(),
            certs: vec![certificate.clone().strip_secret_key_material()],
        };
        for compressed in [false, true] {
            let signing_key = certificate
                .keys()
                .secret()
                .with_policy(&verifier.policy, None)
                .for_signing()
                .next()
                .expect("controlled valid signing authority")
                .key()
                .clone()
                .into_keypair()
                .expect("controlled private signing key");
            let mut encoded = Vec::new();
            let message = Armorer::new(Message::new(&mut encoded))
                .kind(openpgp::armor::Kind::Message)
                .build()
                .expect("actual attached-message armor");
            // Algorithm 0 is a real OpenPGP compression container without an optional codec.
            let message = if compressed {
                Compressor::new(message)
                    .algo(openpgp::types::CompressionAlgorithm::Uncompressed)
                    .build()
                    .expect("actual OpenPGP compression container")
            } else {
                message
            };
            let message = Signer::new(message, signing_key)
                .expect("actual message signer")
                .hash_algo(openpgp::types::HashAlgorithm::SHA256)
                .expect("strong message digest")
                .build()
                .expect("actual signed message");
            let mut writer = LiteralWriter::new(message)
                .build()
                .expect("actual literal payload");
            writer
                .write_all(b"authenticated but not cleartext framed\n")
                .expect("controlled signed payload");
            writer.finalize().expect("complete attached signature");
            assert!(matches!(
                verifier.verify_cleartext_memory(&encoded, 1024),
                Err(PgpError::CleartextFormat)
            ));
            let error = verifier
                .verify_cleartext_message(&encoded, 1024)
                .expect_err("a valid signature cannot replace the inner cleartext format boundary");
            assert!(matches!(error, PgpError::CleartextFormat));
        }
    }

    #[test]
    fn bounded_cleartext_reader_keeps_real_io_failure_typed_and_never_returns_plaintext() {
        let file = NamedTempFile::new().expect("owned plaintext source");
        let mut write_only = std::fs::OpenOptions::new()
            .write(true)
            .open(file.path())
            .expect("real write-only source descriptor");
        let error = PgpVerifier::read_cleartext_plaintext(&mut write_only, 1024)
            .expect_err("reading an invalid source descriptor must refuse plaintext");
        assert!(matches!(&error, PgpError::CleartextVerification { .. }));
        let source = std::error::Error::source(&error)
            .expect("typed cleartext refusal must expose its public error source")
            .downcast_ref::<SequoiaSource>()
            .expect("public error source must retain the typed Sequoia bridge");
        assert!(
            source.0.downcast_ref::<std::io::Error>().is_some(),
            "the underlying OS read failure must remain inspectable"
        );
    }

    #[test]
    fn bounded_cleartext_reader_discards_plaintext_before_a_later_os_read_failure() {
        use std::io::Read as _;
        let file = NamedTempFile::new().expect("owned failing plaintext source");
        let write_only = std::fs::OpenOptions::new()
            .write(true)
            .open(file.path())
            .expect("real write-only descriptor for the later read");
        let prefix = b"plaintext read before the OS failure\n";
        let mut reader = Cursor::new(prefix.as_slice()).chain(write_only);
        let error = PgpVerifier::read_cleartext_plaintext(&mut reader, 1024)
            .expect_err("partial plaintext must not escape after a later source read fails");
        assert_eq!(
            reader.get_ref().0.position(),
            u64::try_from(prefix.len()).expect("bounded fixture prefix length"),
            "the failure must follow a successful plaintext read"
        );
        assert!(matches!(&error, PgpError::CleartextVerification { .. }));
        let source = std::error::Error::source(&error)
            .expect("partial-read refusal must expose its public error source")
            .downcast_ref::<SequoiaSource>()
            .expect("public source must remain the typed Sequoia bridge");
        let io = source
            .0
            .downcast_ref::<std::io::Error>()
            .expect("the real OS read cause must survive the public error chain");
        assert!(io.raw_os_error().is_some());
    }

    #[test]
    fn embedded_bundle_rejects_a_truncated_certificate_after_a_valid_pinned_one() {
        use openpgp::serialize::Serialize as _;
        let (verifier, _) = signed_fixture(openpgp::types::HashAlgorithm::SHA256);
        let certificate = &verifier.certs[0];
        let mut encoded = Vec::new();
        certificate
            .serialize(&mut encoded)
            .expect("serialize controlled public certificate");
        let fingerprint = certificate.fingerprint().to_hex();
        for end in [encoded.len() / 2, encoded.len() - 1] {
            let mut bundle = encoded.clone();
            bundle.extend_from_slice(&encoded[..end]);
            let error = PgpVerifier::from_public_key_bytes(&bundle, &[&fingerprint])
                .err()
                .expect("a partial trailing certificate must invalidate the complete bundle");
            assert!(
                matches!(error, PgpError::PublicKeyBundleParse { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn cleartext_refuses_a_future_signature_inside_the_upstream_clock_tolerance() {
        let (verifier, signed) = cleartext_fixture(
            b"exact publisher manifest\n",
            openpgp::types::HashAlgorithm::SHA256,
            std::time::SystemTime::now() + std::time::Duration::from_mins(1),
            std::time::Duration::from_hours(1),
            std::time::Duration::from_hours(48),
            false,
        );
        assert!(matches!(
            verifier.verify_cleartext_memory(&signed, 1024),
            Err(PgpError::CleartextVerification { .. })
        ));
    }

    #[test]
    fn cleartext_uses_a_policy_valid_certificate_among_same_fingerprint_variants() {
        let (mut verifier, signed) = cleartext_fixture(
            b"same primary fingerprint is not a certificate policy decision\n",
            openpgp::types::HashAlgorithm::SHA256,
            std::time::SystemTime::now(),
            std::time::Duration::from_hours(1),
            std::time::Duration::from_hours(48),
            false,
        );
        let bare = Cert::from_packets(verifier.certs[0].clone().into_packets().take(1))
            .expect("parse the real public primary packet without certification bindings");
        assert_eq!(bare.fingerprint(), verifier.certs[0].fingerprint());
        assert!(bare.with_policy(&verifier.policy, None).is_err());
        let unbound = PgpVerifier {
            policy: StandardPolicy::new(),
            certs: vec![bare.clone()],
        };
        assert!(unbound.verify_cleartext_memory(&signed, 1024).is_err());
        verifier.certs.insert(0, bare);
        assert_eq!(
            verifier.verify_cleartext_memory(&signed, 1024).expect(
                "valid authority must remain usable beside an unbound same-fingerprint copy"
            ),
            b"same primary fingerprint is not a certificate policy decision\n"
        );
    }

    #[test]
    fn large_cleartext_payload_authentication_never_returns_tampered_or_truncated_plaintext() {
        let data = b"authenticated manifest row\n".repeat(20_000);
        let (verifier, signed) = cleartext_fixture(
            &data,
            openpgp::types::HashAlgorithm::SHA256,
            std::time::SystemTime::now(),
            std::time::Duration::from_hours(1),
            std::time::Duration::from_hours(48),
            false,
        );
        assert!(signed.len() < 1024 * 1024);
        assert_eq!(
            verifier
                .verify_cleartext_memory(&signed, data.len())
                .expect("complete bounded publisher manifest"),
            data
        );
        let mut tampered = signed.clone();
        let offset = tampered
            .windows(b"authenticated manifest row".len())
            .rposition(|bytes| bytes == b"authenticated manifest row")
            .expect("owned manifest plaintext before its signature");
        tampered[offset] = b'u';
        let signature_start = signed
            .windows(b"-----BEGIN PGP SIGNATURE-----".len())
            .position(|bytes| bytes == b"-----BEGIN PGP SIGNATURE-----")
            .expect("controlled signature framing");
        let truncated_at = signature_start + (signed.len() - signature_start) / 2;
        for invalid in [tampered.as_slice(), &signed[..truncated_at]] {
            assert!(matches!(
                verifier.verify_cleartext_memory(invalid, data.len()),
                Err(PgpError::CleartextVerification { .. })
            ));
        }
    }

    #[test]
    fn embedded_public_key_loading_preserves_the_fingerprint_boundary() {
        use openpgp::serialize::Serialize as _;
        let (verifier, signature) = signed_fixture(openpgp::types::HashAlgorithm::SHA256);
        let fingerprint = verifier.certs[0].fingerprint().to_hex();
        let mut bytes = Vec::new();
        verifier.certs[0].serialize(&mut bytes).unwrap();
        let loaded = PgpVerifier::from_public_key_bytes(&bytes, &[&fingerprint]).unwrap();
        loaded.verify_memory(b"test data", &signature).unwrap();
        assert!(PgpVerifier::from_public_key_bytes(&bytes, &[]).is_err());
        assert!(
            PgpVerifier::from_public_key_bytes(
                &bytes,
                &["0000000000000000000000000000000000000000"]
            )
            .is_err()
        );
        assert!(
            PgpVerifier::from_public_key_bytes(b"invalid certificate", &[&fingerprint]).is_err()
        );
        assert!(PgpVerifier::from_public_key_bytes(b"", &[&fingerprint]).is_err());
        let (secret, _) =
            openpgp::cert::prelude::CertBuilder::general_purpose(Some("ephemeral@example.invalid"))
                .generate()
                .unwrap();
        let mut secret_bytes = Vec::new();
        secret.as_tsk().serialize(&mut secret_bytes).unwrap();
        assert!(matches!(
            PgpVerifier::from_public_key_bytes(&secret_bytes, &[&secret.fingerprint().to_hex()]),
            Err(PgpError::PublicKeyBundleRejected)
        ));
    }

    #[test]
    fn crypto_backend_retains_classical_and_post_quantum_signatures() {
        use openpgp::Profile::{RFC4880, RFC9580};
        use openpgp::cert::CipherSuite;
        use openpgp::types::HashAlgorithm;

        let (unknown_verifier, _) = signed_fixture(HashAlgorithm::SHA512);
        for (suite, profile) in [
            (CipherSuite::Cv25519, RFC4880),
            (CipherSuite::Cv448, RFC4880),
            (CipherSuite::RSA2k, RFC4880),
            (CipherSuite::P256, RFC4880),
            (CipherSuite::P384, RFC4880),
            (CipherSuite::P521, RFC4880),
            (CipherSuite::Cv25519, RFC9580),
            (CipherSuite::MLDSA65_Ed25519, RFC9580),
            (CipherSuite::MLDSA87_Ed448, RFC9580),
        ] {
            let (verifier, signature) = signed_fixture_at(
                HashAlgorithm::SHA512,
                std::time::SystemTime::now(),
                std::time::Duration::from_hours(1),
                suite,
                profile,
            );
            assert!(
                verifier.verify_memory(b"test data", &signature).is_ok(),
                "{suite:?} {profile:?} valid memory signature"
            );
            assert!(matches!(
                verifier.verify_memory(b"altered data", &signature),
                Err(PgpError::NoValidSignature)
            ));
            assert!(matches!(
                unknown_verifier.verify_memory(b"test data", &signature),
                Err(PgpError::NoValidSignature)
            ));

            let mut data_file = NamedTempFile::new().unwrap();
            data_file.write_all(b"test data").unwrap();
            data_file.flush().unwrap();
            let mut sig_file = NamedTempFile::new().unwrap();
            sig_file.write_all(&signature).unwrap();
            sig_file.flush().unwrap();
            assert!(
                verifier
                    .verify_detached(data_file.path(), sig_file.path())
                    .is_ok(),
                "{suite:?} {profile:?} valid detached signature"
            );
            assert!(matches!(
                unknown_verifier.verify_detached(data_file.path(), sig_file.path()),
                Err(PgpError::NoValidSignature)
            ));
            std::fs::write(data_file.path(), b"altered data").unwrap();
            assert!(matches!(
                verifier.verify_detached(data_file.path(), sig_file.path()),
                Err(PgpError::NoValidSignature)
            ));
        }
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
                openpgp::cert::CipherSuite::Cv25519,
                openpgp::Profile::RFC4880,
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

    #[test]
    fn multi_signature_continues_past_unsupported_hash_packet() {
        let (verifier, valid_sig) = signed_fixture(openpgp::types::HashAlgorithm::SHA256);
        // Clone the valid v4 EdDSA SHA-256 signature packet and replace its
        // hash algorithm byte (8 = SHA-256) with Unknown(99).
        let mut bad_packet = valid_sig.clone();
        let header_pos = bad_packet
            .windows(4)
            .position(|window| window == [4, 0, 22, 8])
            .expect("v4 EdDSA SHA-256 signature header");
        bad_packet[header_pos + 3] = 99;

        // Standalone unsupported-hash signature still returns HashContext error.
        assert!(matches!(
            verifier.verify_memory(b"test data", &bad_packet),
            Err(PgpError::HashContext { .. })
        ));

        // Combined with a valid SHA-256 signature, both verify_memory and verify_detached succeed.
        let mut combined = bad_packet;
        combined.extend_from_slice(&valid_sig);
        verifier
            .verify_memory(b"test data", &combined)
            .expect("valid second signature must verify in memory");

        let mut pkg = NamedTempFile::new().unwrap();
        pkg.write_all(b"test data").unwrap();
        pkg.flush().unwrap();
        let mut sig = NamedTempFile::new().unwrap();
        sig.write_all(&combined).unwrap();
        sig.flush().unwrap();
        verifier
            .verify_detached(pkg.path(), sig.path())
            .expect("valid second signature must verify from file");
    }
}
