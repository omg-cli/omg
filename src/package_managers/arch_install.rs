use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::security::artifact;

const PREFIX: &str = "/__omg_install/";
const MAX_ITEMS: usize = 4096;
const MAX_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
pub const ELEVATED_INSTALL: &str = "install-plan";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum InstallIntent {
    Requested,
    Automatic,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialTarget {
    pub repository: String,
    pub name: String,
    pub relations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InstallTarget {
    Named(String),
    Resolved(OfficialTarget),
    Archive(String),
}

impl InstallTarget {
    pub(crate) fn argument(&self) -> String {
        match self {
            Self::Named(name) => name.clone(),
            Self::Resolved(target) => format!("{}/{}", target.repository, target.name),
            Self::Archive(handoff) => handoff.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallItem {
    pub target: InstallTarget,
    pub intent: InstallIntent,
}

#[derive(Debug)]
pub struct InstallRequest {
    items: Vec<InstallItem>,
}

impl InstallRequest {
    pub fn new(items: Vec<InstallItem>) -> Result<Self> {
        anyhow::ensure!(
            !items.is_empty() && items.len() <= MAX_ITEMS,
            "Invalid installation item count"
        );
        let archives = matches!(items[0].target, InstallTarget::Archive(_));
        let mut identities = HashSet::with_capacity(items.len());
        for item in &items {
            anyhow::ensure!(
                matches!(item.target, InstallTarget::Archive(_)) == archives,
                "Repository targets and built archives require separate installation requests"
            );
            let identity = match &item.target {
                InstallTarget::Named(name) => {
                    crate::core::security::validate_package_name(name)?;
                    name.rsplit_once('/')
                        .map_or(name.as_str(), |(_, name)| name)
                }
                InstallTarget::Resolved(target) => {
                    crate::core::security::validate_package_name(&target.repository)?;
                    crate::core::security::validate_package_name(&target.name)?;
                    anyhow::ensure!(
                        !target.repository.contains('/') && !target.name.contains('/'),
                        "Resolved repository and package names must be unqualified"
                    );
                    anyhow::ensure!(
                        !target.relations.is_empty(),
                        "Resolved installation target requires its original relations"
                    );
                    for relation in &target.relations {
                        anyhow::ensure!(
                            !relation.is_empty() && relation.len() <= 16 * 1024,
                            "Invalid installation relation length"
                        );
                        relation
                            .parse::<alpm_types::PackageRelation>()
                            .with_context(|| {
                                format!("Invalid installation relation '{relation}'")
                            })?;
                    }
                    target.name.as_str()
                }
                InstallTarget::Archive(handoff) => {
                    anyhow::ensure!(
                        handoff.len() <= 16 * 1024,
                        "Installation target is too long"
                    );
                    artifact::ArchiveSnapshot::from_handoff(handoff)?
                        .context("Built package requires a sealed archive handoff")?;
                    handoff.as_str()
                }
            };
            anyhow::ensure!(identities.insert(identity), "Duplicate installation target");
        }
        let request = Self { items };
        anyhow::ensure!(
            request.encode()?.len() as u64 <= MAX_DESCRIPTOR_BYTES,
            "Installation descriptor exceeds size limit"
        );
        Ok(request)
    }

    pub(crate) fn items(&self) -> &[InstallItem] {
        &self.items
    }

    pub(crate) fn kind(&self) -> super::TransactionKind {
        if matches!(self.items[0].target, InstallTarget::Archive(_)) {
            super::TransactionKind::InstallAurArtifact
        } else {
            super::TransactionKind::Install
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&WireRequest {
            version: 1,
            items: &self.items,
        })?)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_DESCRIPTOR_BYTES,
            "Installation descriptor exceeds size limit"
        );
        let wire: OwnedWireRequest = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            wire.version == 1,
            "Unsupported installation descriptor version"
        );
        Self::new(wire.items)
    }

    pub(crate) fn seal(&self) -> Result<SealedInstallRequest> {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
        let bytes = self.encode()?;
        let mut file = File::from(memfd_create(
            "omg-install",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        file.write_all(&bytes)?;
        file.flush()?;
        fcntl_add_seals(
            &file,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )?;
        Ok(SealedInstallRequest {
            file,
            digest: hex::encode(Sha256::digest(&bytes)),
        })
    }
}

#[derive(Serialize)]
struct WireRequest<'a> {
    version: u8,
    items: &'a [InstallItem],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedWireRequest {
    version: u8,
    items: Vec<InstallItem>,
}

pub(crate) struct SealedInstallRequest {
    file: File,
    digest: String,
}

impl SealedInstallRequest {
    pub(crate) fn handoff(&self) -> String {
        format!(
            "{PREFIX}{}/{}/{}",
            std::process::id(),
            self.file.as_raw_fd(),
            self.digest
        )
    }
}

fn read_handoff(handoff: &str) -> Result<InstallRequest> {
    use rustix::fs::{SealFlags, fcntl_get_seals};
    let rest = handoff
        .strip_prefix(PREFIX)
        .context("Invalid installation descriptor")?;
    let fields = rest.split('/').collect::<Vec<_>>();
    anyhow::ensure!(fields.len() == 3, "Malformed installation descriptor");
    let pid: u32 = fields[0].parse()?;
    let fd: u32 = fields[1].parse()?;
    let hash = fields[2];
    anyhow::ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid installation digest"
    );
    let mut file = File::open(format!("/proc/{pid}/fd/{fd}"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_DESCRIPTOR_BYTES,
        "Installation descriptor must be a bounded regular file"
    );
    anyhow::ensure!(
        fcntl_get_seals(&file)?
            .contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL),
        "Installation descriptor is not immutable"
    );
    file.rewind()?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_DESCRIPTOR_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_DESCRIPTOR_BYTES,
        "Installation descriptor exceeds size limit"
    );
    anyhow::ensure!(
        hex::encode(Sha256::digest(&bytes)) == hash,
        "Installation descriptor digest mismatch"
    );
    InstallRequest::decode(&bytes)
}

/// Private root re-exec entrypoint. This descriptor carries intent, never policy authority.
#[doc(hidden)]
pub fn execute_handoff(handoff: &str) -> Result<()> {
    anyhow::ensure!(crate::core::is_root(), "Installation handoff requires root");
    super::alpm_ops::execute_install_request(&read_handoff(handoff)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> InstallRequest {
        InstallRequest::new(vec![
            InstallItem {
                target: InstallTarget::Named("requested".to_owned()),
                intent: InstallIntent::Requested,
            },
            InstallItem {
                target: InstallTarget::Named("helper".to_owned()),
                intent: InstallIntent::Automatic,
            },
        ])
        .unwrap()
    }

    #[test]
    fn sealed_request_preserves_each_installation_intent() {
        let sealed = request().seal().unwrap();
        let decoded = read_handoff(&sealed.handoff()).unwrap();
        assert_eq!(
            decoded.items()[0].target,
            InstallTarget::Named("requested".to_owned())
        );
        assert_eq!(decoded.items()[0].intent, InstallIntent::Requested);
        assert_eq!(decoded.items()[0].target.argument(), "requested");
        assert_eq!(decoded.kind(), super::super::TransactionKind::Install);
        assert_eq!(
            decoded.items()[1].target,
            InstallTarget::Named("helper".to_owned())
        );
        assert_eq!(decoded.items()[1].intent, InstallIntent::Automatic);
    }

    #[test]
    fn selected_repository_and_all_relations_survive_sealed_handoff() {
        let target = OfficialTarget {
            repository: "low".to_owned(),
            name: "helper".to_owned(),
            relations: vec!["helper>=2".to_owned(), "virtual-helper<3".to_owned()],
        };
        let request = InstallRequest::new(vec![InstallItem {
            target: InstallTarget::Resolved(target.clone()),
            intent: InstallIntent::Automatic,
        }])
        .unwrap();
        let sealed = request.seal().unwrap();
        let decoded = read_handoff(&sealed.handoff()).unwrap();
        assert_eq!(decoded.items()[0].target, InstallTarget::Resolved(target));
        assert_eq!(decoded.items()[0].target.argument(), "low/helper");
        assert_eq!(decoded.items()[0].intent, InstallIntent::Automatic);
    }

    #[test]
    fn resolved_requests_validate_relations_and_concrete_identity() {
        let valid = serde_json::json!({"version": 1, "items": [{
            "target": {"Resolved": {"repository": "low", "name": "helper", "relations": ["helper>=2"]}},
            "intent": "Automatic"
        }]});
        assert!(InstallRequest::decode(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, value) in [
            ("repository", serde_json::json!("../low")),
            ("name", serde_json::json!("--helper")),
            ("name", serde_json::json!("other/helper")),
            ("repository", serde_json::json!("other/low")),
            ("relations", serde_json::json!([])),
            ("relations", serde_json::json!([""])),
            ("relations", serde_json::json!(["helper>==2"])),
            ("relations", serde_json::json!(["helper>=2", "helper>="])),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid["items"][0]["target"]["Resolved"][field] = value;
            assert!(
                InstallRequest::decode(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "{invalid}"
            );
        }
        let mut duplicate = valid.clone();
        let mut other_repo = duplicate["items"][0].clone();
        other_repo["target"]["Resolved"]["repository"] = serde_json::json!("high");
        duplicate["items"].as_array_mut().unwrap().push(other_repo);
        assert!(InstallRequest::decode(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let mut named_duplicate = valid.clone();
        named_duplicate["items"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "target": {"Named": "low/helper"}, "intent": "Requested"
            }));
        assert!(InstallRequest::decode(&serde_json::to_vec(&named_duplicate).unwrap()).is_err());
        let mut mixed = valid;
        mixed["items"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "target": {"Archive": "/__omg_artifact/not-a-handoff"}, "intent": "Requested"
            }));
        assert!(
            InstallRequest::decode(&serde_json::to_vec(&mixed).unwrap())
                .unwrap_err()
                .to_string()
                .contains("separate installation requests")
        );
    }

    #[test]
    fn malformed_or_unsealed_requests_are_rejected() {
        for bytes in [
            br#"{"version":2,"items":[{"target":{"Named":"helper"},"intent":"Automatic"}]}"#.as_slice(),
            br#"{"version":1,"items":[]}"#.as_slice(),
            br#"{"version":1,"items":[{"target":{"Named":"--overwrite"},"intent":"Requested"}]}"#.as_slice(),
            br#"{"version":1,"items":[{"target":{"Named":"helper"},"intent":"Other"}]}"#.as_slice(),
            br#"{"version":1,"items":[{"target":{"Named":"helper"},"intent":"Automatic","ignored":true}]}"#.as_slice(),
            br#"{"version":1,"items":[{"target":{"Named":"helper"},"intent":"Automatic"}],"ignored":true}"#.as_slice(),
            br#"{"version":1,"items":[{"target":{"Named":"helper"},"intent":"Automatic"},{"target":{"Named":"helper"},"intent":"Requested"}]}"#.as_slice(),
        ] { assert!(InstallRequest::decode(bytes).is_err(), "{bytes:?}"); }
        let file = tempfile::tempfile().unwrap();
        let bytes = request().encode().unwrap();
        (&file).write_all(&bytes).unwrap();
        let handoff = format!(
            "{PREFIX}{}/{}/{}",
            std::process::id(),
            file.as_raw_fd(),
            hex::encode(Sha256::digest(&bytes))
        );
        assert!(read_handoff(&handoff).is_err());
        let sealed = request().seal().unwrap();
        let wrong_digest = format!(
            "{PREFIX}{}/{}/{}",
            std::process::id(),
            sealed.file.as_raw_fd(),
            "0".repeat(64)
        );
        assert!(read_handoff(&wrong_digest).is_err());
    }
}

#[cfg(test)]
mod native_tests;
