CREATE TABLE epss_cache (
 cve_id TEXT PRIMARY KEY REFERENCES source_record(id),
 checked_at TEXT NOT NULL, fetched_at TEXT,
 payload_json TEXT NOT NULL, error INTEGER NOT NULL CHECK(error IN (0,1))
);
