//! Read the default DNF5 transaction journal without spawning DNF.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OpenFlags, config::DbConfig};

use super::{MAX_QUERY_BYTES, NativeTransaction, NativeTransactionPackage, rpm_database};

const JOURNAL: &str = "/usr/lib/sysimage/libdnf5/transaction_history.sqlite";
const SIDECARS: [&str; 2] = [
    "/usr/lib/sysimage/libdnf5/transaction_history.sqlite-wal",
    "/usr/lib/sysimage/libdnf5/transaction_history.sqlite-shm",
];

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

pub(super) struct Position {
    identity: FileIdentity,
    id: u64,
}

impl Position {
    pub(super) fn capture() -> Option<Self> {
        let result = (|| -> Result<Self> {
            ensure!(
                rpm_database::uses_default_journal(),
                "Custom DNF history configuration"
            );
            let identity = trusted_journal_identity()?;
            let id = newest_id(&open_default_journal()?)?;
            ensure!(
                identity == trusted_journal_identity()?,
                "DNF journal changed during inspection"
            );
            Ok(Self { identity, id })
        })();
        result
            .inspect_err(|error| {
                tracing::debug!("Using DNF command for transaction history: {error:#}");
            })
            .ok()
    }

    pub(super) fn id(&self) -> u64 {
        self.id
    }

    pub(super) fn observe(self, comment: &str) -> Result<Option<Vec<NativeTransaction>>> {
        self.verify_scope()?;
        let result = open_default_journal()
            .and_then(|mut connection| read_after(&mut connection, self.id, comment));
        self.verify_scope()?;
        match result {
            Ok(transaction) => Ok(Some(transaction.into_iter().collect())),
            Err(error) => {
                tracing::debug!("Using DNF command to read committed transaction: {error:#}");
                Ok(None)
            }
        }
    }

    fn verify_scope(&self) -> Result<()> {
        ensure!(
            rpm_database::uses_default_journal() && self.identity == trusted_journal_identity()?,
            "DNF history location changed while the package transaction was running"
        );
        Ok(())
    }
}

fn trusted_journal_identity() -> Result<FileIdentity> {
    let path = Path::new(JOURNAL);
    for dir in path
        .parent()
        .context("DNF journal has no parent")?
        .ancestors()
    {
        let metadata = fs::symlink_metadata(dir)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "DNF journal parent is not a protected directory: {}",
            dir.display()
        );
    }
    let metadata = protected_file(path)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn protected_file(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "DNF journal file is not protected: {}",
        path.display()
    );
    Ok(metadata)
}

fn open_default_journal() -> Result<Connection> {
    // With existing WAL files a read-only connection can use normal SQLite locking.
    for sidecar in SIDECARS {
        protected_file(Path::new(sidecar))?;
    }
    open_journal(Path::new(JOURNAL))
}

fn open_journal(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.busy_timeout(Duration::from_millis(100))?;
    Ok(connection)
}

fn newest_id(connection: &Connection) -> Result<u64> {
    let version: String = connection.query_row(
        "SELECT value FROM config WHERE key = 'version'",
        [],
        |row| row.get(0),
    )?;
    ensure!(version == "1.1", "Unsupported DNF journal format {version}");
    let id: i64 = connection.query_row("SELECT coalesce(max(id), 0) FROM trans", [], |row| {
        row.get(0)
    })?;
    Ok(u64::try_from(id)?)
}

fn read_after(
    connection: &mut Connection,
    before: u64,
    comment: &str,
) -> Result<Option<NativeTransaction>> {
    let view = connection.transaction()?;
    ensure!(
        newest_id(&view)? >= before,
        "DNF journal transaction IDs moved backward"
    );
    let mut headers = view.prepare(
        "SELECT id, state_id, coalesce(description, '') FROM trans WHERE id > ?1 AND comment = ?2 LIMIT 2",
    )?;
    let mut matching = headers.query((i64::try_from(before)?, comment))?;
    let Some(row) = matching.next()? else {
        return Ok(None);
    };
    let id: i64 = row.get(0)?;
    let status = match row.get::<_, u8>(1)? {
        1 => "Started",
        2 => "Ok",
        3 => "Error",
        other => anyhow::bail!("Unknown DNF journal transaction state {other}"),
    };
    let description = row.get_ref(2)?.as_str()?;
    ensure!(
        description.len() <= 64 * 1024,
        "DNF journal description exceeds limit"
    );
    let description = description.to_owned();
    ensure!(
        matching.next()?.is_none(),
        "Duplicate DNF transaction correlation"
    );

    let mut operations = view.prepare(
        "SELECT name.name, rpm.epoch, rpm.version, rpm.release, arch.name, item.action_id, repo.id
           FROM trans_item AS item
           JOIN rpm ON rpm.item_id = item.item_id
           LEFT JOIN pkg_name AS name ON name.id = rpm.name_id
           LEFT JOIN arch ON arch.id = rpm.arch_id
           LEFT JOIN repo ON repo.id = item.repo_id
          WHERE item.trans_id = ?1
          ORDER BY item.id",
    )?;
    let mut rows = operations.query([id])?;
    let mut packages = Vec::new();
    let mut bytes = 0;
    while let Some(row) = rows.next()? {
        let name = row.get_ref(0)?.as_str()?;
        let epoch: u32 = row.get(1)?;
        let version = row.get_ref(2)?.as_str()?;
        let release = row.get_ref(3)?.as_str()?;
        let architecture = row.get_ref(4)?.as_str()?;
        let _: i64 = row.get(6)?;
        let action = match row.get::<_, u8>(5)? {
            1 => "Install",
            2 => "Upgrade",
            3 => "Downgrade",
            4 => "Reinstall",
            5 => "Remove",
            6 => "Replaced",
            7 => "Reason Change",
            other => anyhow::bail!("Unknown DNF journal package action {other}"),
        };
        bytes += name.len() + version.len() + release.len() + architecture.len() + 32;
        ensure!(
            bytes as u64 <= MAX_QUERY_BYTES,
            "DNF journal package output exceeds limit"
        );
        packages.push(NativeTransactionPackage {
            nevra: format!("{name}-{epoch}:{version}-{release}.{architecture}"),
            action: action.to_owned(),
        });
    }

    Ok(Some(NativeTransaction {
        id: u64::try_from(id)?,
        comment: comment.to_owned(),
        status: status.to_owned(),
        description,
        packages,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_fixture(connection: &Connection) -> Result<()> {
        connection.execute_batch(
            "CREATE TABLE config(key PRIMARY KEY, value);
             INSERT INTO config VALUES('version','1.1');
             CREATE TABLE trans(id INTEGER PRIMARY KEY, comment, description, state_id);
             CREATE TABLE trans_item(id INTEGER PRIMARY KEY, trans_id, item_id, action_id, repo_id);
             CREATE TABLE rpm(item_id INTEGER PRIMARY KEY, name_id, epoch, version, release, arch_id);
             CREATE TABLE pkg_name(id INTEGER PRIMARY KEY, name);
             CREATE TABLE arch(id INTEGER PRIMARY KEY, name);
             CREATE TABLE repo(id INTEGER PRIMARY KEY);
             INSERT INTO pkg_name VALUES(1,'test-pkg');
             INSERT INTO arch VALUES(1,'x86_64'),(2,'i686');
             INSERT INTO repo VALUES(1);
             INSERT INTO rpm VALUES(1,1,0,'1.2','1.fc44',1),(2,1,2,'2.0','1.fc44',1),
                 (3,1,0,'1.2','1.fc44',2);
             INSERT INTO trans VALUES(1,'mine','old',2),(2,'theirs','other',2),
                 (3,'mine','replay fixture',2),(4,'after','later',1);
             INSERT INTO trans_item VALUES(1,3,1,6,1),(2,3,2,2,1),(3,3,3,5,1);",
        )?;
        Ok(())
    }

    #[test]
    fn selects_only_the_correlated_new_transaction_and_preserves_rpm_actions() -> Result<()> {
        let mut connection = Connection::open_in_memory()?;
        create_fixture(&connection)?;
        assert_eq!(newest_id(&connection)?, 4);
        let selected = read_after(&mut connection, 1, "mine")?.context("missing transaction")?;
        assert_eq!(
            (
                selected.id,
                selected.status.as_str(),
                selected.description.as_str()
            ),
            (3, "Ok", "replay fixture")
        );
        let packages: Vec<_> = selected
            .packages
            .iter()
            .map(|package| (package.nevra.as_str(), package.action.as_str()))
            .collect();
        assert_eq!(
            packages,
            [
                ("test-pkg-0:1.2-1.fc44.x86_64", "Replaced"),
                ("test-pkg-2:2.0-1.fc44.x86_64", "Upgrade"),
                ("test-pkg-0:1.2-1.fc44.i686", "Remove"),
            ]
        );
        assert!(read_after(&mut connection, 3, "mine")?.is_none());
        assert_eq!(
            read_after(&mut connection, 3, "after")?.unwrap().status,
            "Started"
        );
        assert!(read_after(&mut connection, 5, "mine").is_err());
        assert!(read_after(&mut connection, 0, "mine").is_err());
        Ok(())
    }

    #[test]
    fn sees_current_wal_rows_and_rejects_unsupported_schema_or_incomplete_rpm() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("transaction_history.sqlite");
        let writer = Connection::open(&path)?;
        writer.pragma_update(None, "journal_mode", "wal")?;
        create_fixture(&writer)?;
        let mut reader = open_journal(&path)?;
        assert_eq!(newest_id(&reader)?, 4);
        writer.execute("INSERT INTO trans VALUES (5,'new',NULL,3)", [])?;
        let failed = read_after(&mut reader, 4, "new")?.context("WAL transaction missing")?;
        assert_eq!(
            (
                failed.id,
                failed.status.as_str(),
                failed.description.as_str()
            ),
            (5, "Error", "")
        );
        writer.execute("UPDATE trans_item SET repo_id = 7 WHERE id = 1", [])?;
        assert!(read_after(&mut reader, 1, "mine").is_err());
        writer.execute("UPDATE config SET value = '2.0'", [])?;
        assert!(newest_id(&reader).is_err());
        Ok(())
    }
}
