CREATE TABLE runtime_source (
 cache_key TEXT PRIMARY KEY,
 source_url TEXT NOT NULL,
 checked_at TEXT NOT NULL,
 successful_at TEXT,
 revision TEXT,
 payload_sha256 TEXT,
 object_key TEXT,
 error TEXT,
 CHECK((successful_at IS NULL AND payload_sha256 IS NULL AND object_key IS NULL)
    OR (successful_at IS NOT NULL AND payload_sha256 IS NOT NULL AND object_key IS NOT NULL))
);
