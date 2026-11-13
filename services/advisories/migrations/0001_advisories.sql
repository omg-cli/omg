CREATE TABLE source_checkpoint (
 source TEXT PRIMARY KEY CHECK(source IN ('cve','arch','kev')),
 cursor TEXT, baseline_digest TEXT, checked_at TEXT, fetched_at TEXT, etag TEXT,
 complete INTEGER NOT NULL DEFAULT 0, bootstrap_complete INTEGER NOT NULL DEFAULT 0,
 error TEXT, object_key TEXT, payload_sha256 TEXT, revision TEXT
);
INSERT INTO source_checkpoint(source) VALUES ('cve'),('arch'),('kev');
CREATE TABLE source_record (
 id TEXT PRIMARY KEY, source TEXT NOT NULL, source_url TEXT NOT NULL,
 schema_version TEXT NOT NULL, state TEXT NOT NULL, published_at TEXT,
 modified_at TEXT NOT NULL, fetched_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
 object_key TEXT NOT NULL, normalization_version INTEGER NOT NULL, supported INTEGER NOT NULL
);
CREATE TABLE cve (
 id TEXT PRIMARY KEY REFERENCES source_record(id), state TEXT NOT NULL,
 modified_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL
);
CREATE TABLE ingestion_run (
 id TEXT PRIMARY KEY, source TEXT NOT NULL, started_at TEXT NOT NULL,
 finished_at TEXT, records INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE ingestion_lease (source TEXT PRIMARY KEY, owner TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE baseline_receipt (
 digest TEXT PRIMARY KEY, instance_id TEXT NOT NULL, session_id TEXT NOT NULL UNIQUE, endpoint TEXT NOT NULL, baseline_at TEXT NOT NULL, accepted INTEGER NOT NULL,
 exhausted INTEGER NOT NULL, caught_up INTEGER NOT NULL DEFAULT 0, completed_at TEXT
);
CREATE TABLE kev_annotation (
 cve_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, catalog_sha256 TEXT NOT NULL
);

CREATE TABLE mutation_fence (id INTEGER PRIMARY KEY CHECK(id=1), valid INTEGER NOT NULL CHECK(valid=1));

CREATE TABLE database_instance (id TEXT PRIMARY KEY);
INSERT INTO database_instance(id) VALUES(lower(hex(randomblob(16))));
CREATE TABLE baseline_member (session_id TEXT NOT NULL REFERENCES baseline_receipt(session_id), cve_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL, PRIMARY KEY(session_id,cve_id));
