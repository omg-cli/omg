//! PGP keyserver integration for automatic key fetching
//!
//! Fetches PGP keys from keyservers (Ubuntu keyserver by default)
//! with timeout handling for signature verification workflows.

use std::io;
use std::path::Path;
use std::time::Duration;

use futures::{StreamExt, stream};
use reqwest::Url;
use sequoia_openpgp::{Cert, KeyHandle, parse::Parse};
use thiserror::Error;

use crate::core::http::shared_client;

use super::pgp::SequoiaSource;

const DEFAULT_KEYSERVER: &str = "hkps://keyserver.ubuntu.com";
const KEYSERVER_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_KEY_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONCURRENT_KEY_FETCHES: usize = 8;

/// Failures fetching keys or reading a local keyring.
#[derive(Debug, Error)]
pub enum KeyserverError {
    #[error("Invalid key ID format: {key_id}")]
    InvalidKeyId {
        key_id: String,
        #[source]
        source: SequoiaSource,
    },
    #[error("Invalid keyserver URL: {url}")]
    InvalidUrl {
        url: String,
        #[source]
        source: SequoiaSource,
    },
    #[error("Keyserver URL must use hkps or https: {url}")]
    InsecureTransport { url: String },
    #[error("Keyserver URL must include a host: {url}")]
    MissingHost { url: String },
    #[error("Keyserver URL must not include credentials")]
    CredentialsNotAllowed,
    #[error("Failed to fetch key {key_id} from {keyserver}")]
    Fetch {
        key_id: String,
        keyserver: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Keyserver returned an error for key {key_id} from {keyserver}")]
    HttpStatus {
        key_id: String,
        keyserver: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Keyserver response for {key_id} exceeds {max_bytes} bytes")]
    ResponseTooLarge { key_id: String, max_bytes: usize },
    #[error("Failed to read keyserver response for key {key_id}")]
    ReadBody {
        key_id: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Failed to parse certificate response for {key_id}")]
    ParseResponse {
        key_id: String,
        #[source]
        source: SequoiaSource,
    },
    #[error("No certificates found for {key_id}")]
    NoCertificates { key_id: String },
    #[error("Failed to parse certificate for {key_id}")]
    ParseCertificate {
        key_id: String,
        #[source]
        source: SequoiaSource,
    },
    #[error("Keyserver returned a certificate that does not match {key_id}")]
    KeyMismatch { key_id: String },
    #[error("Timeout fetching key {key_id} from {keyserver}")]
    Timeout { key_id: String, keyserver: String },
    #[error("Invalid key ID")]
    InvalidLookupKeyId {
        #[source]
        source: SequoiaSource,
    },
    #[error("Failed to run GnuPG while {operation}")]
    GnuPgLaunch {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("GnuPG failed while {operation} (exit status: {status})")]
    GnuPgFailed {
        operation: &'static str,
        status: std::process::ExitStatus,
    },
    #[error("Failed to serialize certificate")]
    Serialize {
        #[source]
        source: SequoiaSource,
    },
}

/// Fetch a key from the default Ubuntu keyserver.
pub async fn fetch_key(key_id: &str) -> Result<Cert, KeyserverError> {
    fetch_key_from(key_id, DEFAULT_KEYSERVER).await
}

/// Fetch a key from an explicit keyserver URL (`hkps://` or `https://`).
///
/// The response is bounded in size, matched against the requested key
/// handle, and the whole fetch is bounded by a hard timeout.
async fn fetch_key_from(key_id: &str, keyserver_url: &str) -> Result<Cert, KeyserverError> {
    let key_handle: KeyHandle = key_id
        .parse()
        .map_err(|source| KeyserverError::InvalidKeyId {
            key_id: key_id.to_string(),
            source: SequoiaSource(source),
        })?;
    let (lookup_url, safe_keyserver) = keyserver_lookup_url(keyserver_url, &key_handle)?;

    let fetch = async {
        let response = shared_client()
            .get(lookup_url)
            .send()
            .await
            .map_err(|source| KeyserverError::Fetch {
                key_id: key_id.to_string(),
                keyserver: safe_keyserver.clone(),
                source,
            })?
            .error_for_status()
            .map_err(|source| KeyserverError::HttpStatus {
                key_id: key_id.to_string(),
                keyserver: safe_keyserver.clone(),
                source,
            })?;

        if let Some(content_length) = response.content_length()
            && content_length > MAX_KEY_RESPONSE_BYTES as u64
        {
            return Err(KeyserverError::ResponseTooLarge {
                key_id: key_id.to_string(),
                max_bytes: MAX_KEY_RESPONSE_BYTES,
            });
        }

        let mut body = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|source| KeyserverError::ReadBody {
                key_id: key_id.to_string(),
                source,
            })?;
            if body.len().saturating_add(chunk.len()) > MAX_KEY_RESPONSE_BYTES {
                return Err(KeyserverError::ResponseTooLarge {
                    key_id: key_id.to_string(),
                    max_bytes: MAX_KEY_RESPONSE_BYTES,
                });
            }
            body.extend_from_slice(&chunk);
        }

        let mut certs = sequoia_openpgp::cert::CertParser::from_bytes(&body).map_err(|source| {
            KeyserverError::ParseResponse {
                key_id: key_id.to_string(),
                source: SequoiaSource(source),
            }
        })?;
        let cert = certs.next().ok_or_else(|| KeyserverError::NoCertificates {
            key_id: key_id.to_string(),
        })?;
        let cert = cert.map_err(|source| KeyserverError::ParseCertificate {
            key_id: key_id.to_string(),
            source: SequoiaSource(source),
        })?;

        if !cert
            .keys()
            .any(|key| key.key().key_handle().aliases(&key_handle))
        {
            return Err(KeyserverError::KeyMismatch {
                key_id: key_id.to_string(),
            });
        }
        Ok(cert)
    };

    match tokio::time::timeout(KEYSERVER_TIMEOUT, fetch).await {
        Ok(result) => result,
        Err(_) => Err(KeyserverError::Timeout {
            key_id: key_id.to_string(),
            keyserver: safe_keyserver,
        }),
    }
}

fn keyserver_lookup_url(
    keyserver_url: &str,
    key_handle: &KeyHandle,
) -> Result<(Url, String), KeyserverError> {
    let normalized = if let Some(authority) = keyserver_url.strip_prefix("hkps://") {
        format!("https://{authority}")
    } else {
        keyserver_url.to_string()
    };
    let safe_keyserver = crate::core::http::redact_url(keyserver_url);
    let mut url = Url::parse(&normalized).map_err(|source| KeyserverError::InvalidUrl {
        url: safe_keyserver.clone(),
        source: SequoiaSource(source.into()),
    })?;

    if url.scheme() != "https" {
        return Err(KeyserverError::InsecureTransport {
            url: safe_keyserver,
        });
    }
    if url.host_str().is_none() {
        return Err(KeyserverError::MissingHost {
            url: safe_keyserver,
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(KeyserverError::CredentialsNotAllowed);
    }

    url.set_path("/pks/lookup");
    url.set_query(None);
    url.set_fragment(None);
    url.query_pairs_mut()
        .append_pair("op", "get")
        .append_pair("options", "mr")
        .append_pair("search", &format!("0x{key_handle:X}"));
    Ok((url, safe_keyserver))
}

/// Fetch many keys concurrently (bounded), keeping each key's result
/// separate. Discarding the returned results silently is almost always a
/// bug, hence `#[must_use]`.
fn deduplicate_key_ids(key_ids: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(key_ids.len());
    key_ids
        .iter()
        .filter(|key_id| seen.insert(key_id.as_str()))
        .cloned()
        .collect()
}

#[must_use]
pub async fn fetch_keys(key_ids: &[String]) -> Vec<(String, Result<Cert, KeyserverError>)> {
    stream::iter(deduplicate_key_ids(key_ids))
        .map(|key_id| async move {
            let result = fetch_key(&key_id).await;
            (key_id, result)
        })
        .buffered(MAX_CONCURRENT_KEY_FETCHES)
        .collect()
        .await
}

fn gnupg_listing_contains_key(listing: &str, key_id: &str) -> bool {
    let key_id = key_id.trim_start_matches("0x").to_ascii_uppercase();
    listing.lines().any(|line| {
        let mut fields = line.split(':');
        fields.next() == Some("fpr")
            && fields
                .nth(8)
                .is_some_and(|fingerprint| fingerprint.to_ascii_uppercase().ends_with(&key_id))
    })
}

fn gnupg_command(gnupg_home: &Path) -> Result<std::process::Command, KeyserverError> {
    gnupg_command_with(
        gnupg_home,
        crate::core::privilege::root_controlled_program_path,
    )
}

fn gnupg_command_with(
    gnupg_home: &Path,
    resolve: impl FnOnce(&str) -> anyhow::Result<std::path::PathBuf>,
) -> Result<std::process::Command, KeyserverError> {
    let program = resolve("gpg").map_err(|source| KeyserverError::GnuPgLaunch {
        operation: "resolving the trusted GnuPG executable",
        source: io::Error::new(io::ErrorKind::PermissionDenied, source.to_string()),
    })?;
    let mut command = std::process::Command::new(program);
    command
        .arg("--no-options")
        .arg("--batch")
        .arg("--homedir")
        .arg(gnupg_home);
    Ok(command)
}

/// Query GnuPG's native keybox instead of parsing `pubring.kbx` as OpenPGP packets.
pub fn is_key_in_gnupg(key_id: &str, gnupg_home: &Path) -> Result<bool, KeyserverError> {
    key_id
        .parse::<KeyHandle>()
        .map_err(|source| KeyserverError::InvalidLookupKeyId {
            source: SequoiaSource(source),
        })?;
    if !gnupg_home.exists() {
        return Ok(false);
    }

    let output = gnupg_command(gnupg_home)?
        .arg("--with-colons")
        .arg("--fingerprint")
        .arg("--list-keys")
        .arg(key_id)
        .output()
        .map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "listing keys",
            source,
        })?;
    if output.status.success() {
        return Ok(gnupg_listing_contains_key(
            &String::from_utf8_lossy(&output.stdout),
            key_id,
        ));
    }

    // A selector miss and a corrupt keybox both return non-zero. Validate the
    // keyring separately so corruption still fails closed.
    let status = gnupg_command(gnupg_home)?
        .arg("--list-keys")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "validating the keyring",
            source,
        })?;
    if status.success() {
        Ok(false)
    } else {
        Err(KeyserverError::GnuPgFailed {
            operation: "validating the keyring",
            status,
        })
    }
}

/// Re-validate a pre-existing GnuPG home: it must be a real directory
/// owned by this user with no group/world access and no symlink.
fn validate_gnupg_home(gnupg_home: &Path) -> Result<(), KeyserverError> {
    let meta =
        std::fs::symlink_metadata(gnupg_home).map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "inspecting the GnuPG home",
            source,
        })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(KeyserverError::GnuPgLaunch {
            operation: "refusing symlinked or non-directory GnuPG home",
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                gnupg_home.display().to_string(),
            ),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != nix::unistd::getuid().as_raw() || meta.mode() & 0o077 != 0 {
            return Err(KeyserverError::GnuPgLaunch {
                operation: "refusing weakly-permissioned GnuPG home",
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    gnupg_home.display().to_string(),
                ),
            });
        }
    }
    Ok(())
}

/// Import a verified certificate through GnuPG so it updates `pubring.kbx`
/// using the keybox format GnuPG owns.
pub fn import_key_into_gnupg(cert: &Cert, gnupg_home: &Path) -> Result<(), KeyserverError> {
    use sequoia_openpgp::serialize::Serialize;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    if gnupg_home.exists() {
        validate_gnupg_home(gnupg_home)?;
    } else {
        std::fs::create_dir(gnupg_home).map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "creating the GnuPG home",
            source,
        })?;
        std::fs::set_permissions(gnupg_home, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| KeyserverError::GnuPgLaunch {
                operation: "securing the GnuPG home",
                source,
            },
        )?;
    }

    // Trust-on-first-use: this key has no fingerprint pinning. Say so on
    // stderr so a silent import never surprises the operator.
    eprintln!(
        "Trust-on-first-use: importing PGP key {} into {}",
        cert.fingerprint(),
        gnupg_home.display()
    );
    let mut certificate =
        tempfile::NamedTempFile::new().map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "staging a certificate",
            source,
        })?;
    cert.serialize(&mut certificate)
        .map_err(|source| KeyserverError::Serialize {
            source: SequoiaSource(source),
        })?;
    certificate
        .flush()
        .and_then(|()| certificate.as_file().sync_all())
        .map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "staging a certificate",
            source,
        })?;

    let status = gnupg_command(gnupg_home)?
        .arg("--import")
        .arg(certificate.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|source| KeyserverError::GnuPgLaunch {
            operation: "importing a certificate",
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(KeyserverError::GnuPgFailed {
            operation: "importing a certificate",
            status,
        })
    }
}

/// Extract display information (fingerprint, user IDs) from a certificate.
#[must_use]
pub fn get_key_info(cert: &Cert) -> KeyInfo {
    let fingerprint = cert.fingerprint().to_hex();
    let user_ids: Vec<String> = cert
        .userids()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
        .collect();

    KeyInfo {
        fingerprint,
        user_ids,
    }
}

/// Display information about an OpenPGP certificate.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// Hex-encoded certificate fingerprint.
    pub fingerprint: String,
    /// User IDs attached to the certificate, lossily decoded as UTF-8.
    pub user_ids: Vec<String>,
}

impl std::fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.fingerprint)?;
        if !self.user_ids.is_empty() {
            write!(f, " ({})", self.user_ids.join(", "))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn gnupg_helper_resolves_outside_the_callers_path() {
        let command = gnupg_command_with(Path::new("/tmp/gnupg"), |program| {
            assert_eq!(program, "gpg");
            Ok(std::path::PathBuf::from("/usr/bin/gpg"))
        })
        .expect("trusted GnuPG installation");
        assert!(Path::new(command.get_program()).is_absolute());
    }

    fn test_key_handle() -> KeyHandle {
        KeyHandle::from(sequoia_openpgp::KeyID::from(0x0123_4567_89AB_CDEF))
    }

    #[test]
    fn keyserver_lookup_normalizes_hkps_and_replaces_untrusted_path() {
        let (url, _) = keyserver_lookup_url(
            "hkps://keyserver.ubuntu.com/untrusted?old=value#fragment",
            &test_key_handle(),
        )
        .expect("valid HKPS URL should produce a lookup URL");

        assert_eq!(
            url.as_str(),
            "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x0123456789ABCDEF"
        );
    }

    #[test]
    fn keyserver_lookup_rejects_insecure_transport() {
        let key_handle = test_key_handle();
        for url in [
            "hkp://keyserver.example.com",
            "http://keyserver.example.com",
        ] {
            let error = keyserver_lookup_url(url, &key_handle)
                .expect_err("insecure keyserver transport must be rejected");
            assert!(
                matches!(error, KeyserverError::InsecureTransport { .. }),
                "got: {error}"
            );
        }
    }

    #[test]
    fn keyserver_lookup_rejects_credentials() {
        let error = keyserver_lookup_url(
            "https://user:secret@keyserver.example.com",
            &test_key_handle(),
        )
        .expect_err("keyserver credentials must be rejected");

        assert!(
            matches!(error, KeyserverError::CredentialsNotAllowed),
            "got: {error}"
        );
    }

    #[test]
    fn key_fetches_deduplicate_ids_in_request_order() {
        let ids = vec!["AAAA".to_string(), "BBBB".to_string(), "AAAA".to_string()];
        assert_eq!(deduplicate_key_ids(&ids), ["AAAA", "BBBB"]);
    }

    #[test]
    fn test_key_info_display() {
        let info = KeyInfo {
            fingerprint: "ABCD1234".to_string(),
            user_ids: vec!["Test User <test@example.com>".to_string()],
        };
        assert_eq!(format!("{info}"), "ABCD1234 (Test User <test@example.com>)");
    }

    #[test]
    fn test_key_info_display_no_uid() {
        let info = KeyInfo {
            fingerprint: "ABCD1234".to_string(),
            user_ids: vec![],
        };
        assert_eq!(format!("{info}"), "ABCD1234");
    }

    #[test]
    fn gnupg_import_requires_a_trusted_launcher_before_native_keybox_round_trip() {
        if which::which("gpg").is_err() {
            return;
        }
        let home = tempfile::tempdir().expect("GnuPG home");
        // tempfile dirs inherit umask permissions; a GnuPG home must be
        // 0700 or validation correctly refuses it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure GnuPG home");
        }
        let (certificate, _) = sequoia_openpgp::cert::prelude::CertBuilder::new()
            .add_userid("keybox-test@example.invalid")
            .generate()
            .expect("test certificate");
        let fingerprint = certificate.fingerprint().to_hex();

        // A PATH-visible GnuPG installation need not meet the hardened launcher
        // policy (for example, a user-owned package-manager installation).
        // Exercise the rejection contract instead of assuming it may execute.
        if crate::core::privilege::root_controlled_program_path("gpg").is_err() {
            let error = import_key_into_gnupg(&certificate, home.path())
                .expect_err("an untrusted GnuPG launcher must never import a key");
            assert!(
                matches!(
                    error,
                    KeyserverError::GnuPgLaunch { ref source, .. }
                        if source.kind() == io::ErrorKind::PermissionDenied
                ),
                "expected a trusted-launcher rejection, got: {error}"
            );
            assert!(!home.path().join("pubring.kbx").exists());
            return;
        }

        import_key_into_gnupg(&certificate, home.path()).expect("GnuPG import");

        assert!(home.path().join("pubring.kbx").is_file());
        assert!(is_key_in_gnupg(&fingerprint, home.path()).expect("GnuPG lookup"));
    }

    #[test]
    fn gnupg_listing_matches_full_fingerprints_and_long_key_ids() {
        let listing = "pub:-:255:22:1234567890ABCDEF:0:0::::::\n\
                       fpr:::::::::00112233445566778899AABBCCDDEEFF00112233:\n";

        assert!(gnupg_listing_contains_key(
            listing,
            "00112233445566778899AABBCCDDEEFF00112233"
        ));
        assert!(gnupg_listing_contains_key(listing, "CCDDEEFF00112233"));
        assert!(!gnupg_listing_contains_key(listing, "FFFFFFFFFFFFFFFF"));
    }
}
