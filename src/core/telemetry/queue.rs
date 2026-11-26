use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{MAX_QUEUE_BYTES, MAX_QUEUE_SIZE, QUEUE_FORMAT_VERSION, read_saved_telemetry};
use crate::core::telemetry_client::TelemetryEvent;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedQueue {
    format_version: u32,
    events: Vec<StoredEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StoredEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queue_id: Option<String>,
    #[serde(flatten)]
    pub(super) event: TelemetryEvent,
}

#[derive(Debug)]
pub(super) struct PendingEvent {
    queue_id: String,
    pub(super) event: Arc<TelemetryEvent>,
}

impl PendingEvent {
    pub(super) fn new(event: TelemetryEvent) -> Self {
        Self {
            queue_id: uuid::Uuid::new_v4().to_string(),
            event: Arc::new(event),
        }
    }
}

pub(super) struct QueueStore {
    path: PathBuf,
}

impl QueueStore {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.read().map(|_| ())
    }

    pub(super) fn append(&self, pending: &VecDeque<PendingEvent>) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let _mutation = self.mutation_lock()?;
        let mut queue = self.read()?;
        Self::assign_legacy_ids(&mut queue.events);
        let already_saved: HashSet<_> = queue
            .events
            .iter()
            .filter_map(|row| row.queue_id.as_deref())
            .collect();
        let additions: Vec<_> = pending
            .iter()
            .filter(|row| !already_saved.contains(row.queue_id.as_str()))
            .map(|row| StoredEvent {
                queue_id: Some(row.queue_id.clone()),
                event: row.event.as_ref().clone(),
            })
            .collect();
        queue.events.extend(additions);
        Self::retain_newest(&mut queue.events);
        self.publish(&queue)
    }

    /// Keep one sender active across processes while producers still append.
    pub(super) fn try_dispatch_lock(&self) -> Result<Option<File>> {
        let lock = open_lock(&self.path.with_extension("dispatch.lock"))?;
        match lock.try_lock() {
            Ok(()) => Ok(Some(lock)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => {
                Err(error).context("Failed to lock telemetry dispatch")
            }
        }
    }

    pub(super) fn prepare_batch(&self) -> Result<Vec<StoredEvent>> {
        let _mutation = self.mutation_lock()?;
        let mut queue = self.read()?;
        if Self::assign_legacy_ids(&mut queue.events) {
            self.publish(&queue)?;
        }
        Ok(queue.events)
    }

    pub(super) fn acknowledge(&self, sent: &[StoredEvent]) -> Result<()> {
        let ids: HashSet<_> = sent
            .iter()
            .filter_map(|row| row.queue_id.as_deref())
            .collect();
        let _mutation = self.mutation_lock()?;
        let mut queue = self.read()?;
        let before = queue.events.len();
        queue
            .events
            .retain(|row| row.queue_id.as_deref().is_none_or(|id| !ids.contains(id)));
        if queue.events.len() != before {
            self.publish(&queue)?;
        }
        Ok(())
    }

    fn mutation_lock(&self) -> Result<File> {
        let lock = open_lock(&self.path.with_extension("lock"))?;
        lock.lock().context("Failed to lock telemetry queue")?;
        Ok(lock)
    }

    fn read(&self) -> Result<PersistedQueue> {
        let Some(content) = read_saved_telemetry(&self.path, "Telemetry queue", MAX_QUEUE_BYTES)?
        else {
            return Ok(PersistedQueue {
                format_version: QUEUE_FORMAT_VERSION,
                events: Vec::new(),
            });
        };
        let mut queue: PersistedQueue = serde_json::from_str(&content)
            .with_context(|| format!("Malformed telemetry queue: {}", self.path.display()))?;
        anyhow::ensure!(
            queue.format_version == QUEUE_FORMAT_VERSION,
            "Unsupported telemetry queue format version {} (expected {})",
            queue.format_version,
            QUEUE_FORMAT_VERSION
        );
        let mut ids = HashSet::new();
        for id in queue
            .events
            .iter()
            .filter_map(|event| event.queue_id.as_deref())
        {
            let parsed = uuid::Uuid::parse_str(id).context("Invalid saved telemetry event ID")?;
            anyhow::ensure!(ids.insert(parsed), "Duplicate saved telemetry event ID");
        }
        Self::retain_newest(&mut queue.events);
        Ok(queue)
    }

    fn retain_newest(events: &mut Vec<StoredEvent>) {
        let excess = events.len().saturating_sub(MAX_QUEUE_SIZE);
        events.drain(..excess);
    }

    fn assign_legacy_ids(events: &mut [StoredEvent]) -> bool {
        let mut changed = false;
        for event in events {
            if event.queue_id.is_none() {
                event.queue_id = Some(uuid::Uuid::new_v4().to_string());
                changed = true;
            }
        }
        changed
    }

    fn publish(&self, queue: &PersistedQueue) -> Result<()> {
        let content = serde_json::to_vec(queue).context("Failed to serialize telemetry queue")?;
        anyhow::ensure!(
            content.len() as u64 <= MAX_QUEUE_BYTES,
            "Telemetry queue exceeds the {MAX_QUEUE_BYTES} byte limit"
        );
        crate::core::safe_ops::atomic_write_file_sync_private(&self.path, content)
            .with_context(|| format!("Failed to save telemetry queue: {}", self.path.display()))
    }
}

fn open_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let lock = options
        .open(path)
        .with_context(|| format!("Failed to open telemetry lock: {}", path.display()))?;
    anyhow::ensure!(
        lock.metadata()?.is_file(),
        "Telemetry lock must be a regular file: {}",
        path.display()
    );
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::telemetry_client::PerformanceEvent;

    fn event(duration_ms: u64) -> PendingEvent {
        PendingEvent::new(TelemetryEvent::Performance(PerformanceEvent {
            metric_type: "queue-test".into(),
            duration_ms,
        }))
    }

    #[test]
    fn acknowledgement_keeps_identical_event_from_another_writer() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("telemetry_queue.json");
        let first = QueueStore::new(path.clone());
        let second = QueueStore::new(path);
        first.append(&VecDeque::from([event(7)]))?;

        let lease = first.try_dispatch_lock()?.context("first sender lease")?;
        let sent = first.prepare_batch()?;
        second.append(&VecDeque::from([event(7)]))?;
        assert!(second.try_dispatch_lock()?.is_none());
        first.acknowledge(&sent)?;
        drop(lease);

        let _retry = second.try_dispatch_lock()?.context("next sender lease")?;
        let pending = second.prepare_batch()?;
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].queue_id, sent[0].queue_id);
        assert!(
            matches!(&pending[0].event, TelemetryEvent::Performance(row) if row.duration_ms == 7)
        );
        Ok(())
    }

    #[test]
    fn legacy_ids_are_published_before_issuing_a_batch() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("telemetry_queue.json");
        std::fs::write(
            &path,
            br#"{"format_version":1,"events":[
            {"type":"performance","metric_type":"queue-test","duration_ms":7},
            {"type":"performance","metric_type":"queue-test","duration_ms":7}
        ]}"#,
        )?;
        let store = QueueStore::new(path.clone());
        let sent = store.prepare_batch()?;
        assert_eq!(sent.len(), 2);
        assert_ne!(sent[0].queue_id, sent[1].queue_id);
        let retry = QueueStore::new(path).prepare_batch()?;
        assert_eq!(sent[0].queue_id, retry[0].queue_id);
        assert_eq!(sent[1].queue_id, retry[1].queue_id);
        Ok(())
    }

    #[test]
    fn retrying_the_same_pending_batch_does_not_duplicate_it() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = QueueStore::new(directory.path().join("telemetry_queue.json"));
        let pending = VecDeque::from([event(7)]);
        store.append(&pending)?;
        store.append(&pending)?;
        assert_eq!(store.prepare_batch()?.len(), 1);
        Ok(())
    }

    #[test]
    fn malformed_queue_survives_an_append_attempt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("telemetry_queue.json");
        let corrupt = b"{malformed";
        std::fs::write(&path, corrupt)?;
        let store = QueueStore::new(path.clone());
        let error = store
            .append(&VecDeque::from([event(7)]))
            .expect_err("reject damaged queue");
        assert!(error.to_string().contains("Malformed telemetry queue"));
        assert_eq!(std::fs::read(&path)?, corrupt);
        Ok(())
    }

    #[test]
    fn acknowledgement_after_eviction_keeps_later_persisted_events() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = QueueStore::new(directory.path().join("telemetry_queue.json"));
        store.append(&(0..MAX_QUEUE_SIZE as u64).map(event).collect())?;
        let sent = store.prepare_batch()?;
        store.append(&VecDeque::from([event(MAX_QUEUE_SIZE as u64)]))?;
        store.acknowledge(&sent)?;
        let pending = store.prepare_batch()?;
        assert_eq!(pending.len(), 1);
        assert!(matches!(&pending[0].event, TelemetryEvent::Performance(row)
            if row.duration_ms == MAX_QUEUE_SIZE as u64));
        Ok(())
    }
}
