CREATE TABLE baseline_import_blob (
    session_id TEXT NOT NULL REFERENCES baseline_receipt(session_id),
    cve_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
    git_blob_sha1 TEXT NOT NULL CHECK(length(git_blob_sha1)=40),
    PRIMARY KEY(session_id,cve_id)
);
CREATE TRIGGER baseline_import_blob_no_update BEFORE UPDATE ON baseline_import_blob BEGIN SELECT RAISE(ABORT,'baseline blob identity is immutable'); END;
CREATE TRIGGER baseline_import_blob_no_delete BEFORE DELETE ON baseline_import_blob BEGIN SELECT RAISE(ABORT,'baseline blob identity is immutable'); END;
CREATE TABLE baseline_publisher_proof (
    session_id TEXT PRIMARY KEY REFERENCES baseline_receipt(session_id),
    release_tag TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    asset_size INTEGER NOT NULL,
    archive_digest TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    root_tree_sha TEXT NOT NULL,
    cves_tree_sha TEXT NOT NULL,
    provenance_key TEXT NOT NULL,
    provenance_sha256 TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('traversing','reconciling','verified')),
    after_id TEXT NOT NULL DEFAULT '',
    expected_count INTEGER NOT NULL DEFAULT 0,
    verified_count INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    verified_at TEXT
);
CREATE TABLE baseline_publisher_tree (
    session_id TEXT NOT NULL REFERENCES baseline_publisher_proof(session_id),
    path TEXT NOT NULL,
    tree_sha TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)),
    object_key TEXT,
    payload_sha256 TEXT,
    PRIMARY KEY(session_id,path)
);
CREATE INDEX baseline_publisher_tree_pending ON baseline_publisher_tree(session_id,done,path);
CREATE TABLE baseline_expected_member (
    session_id TEXT NOT NULL REFERENCES baseline_publisher_proof(session_id),
    cve_id TEXT NOT NULL,
    path TEXT NOT NULL,
    git_blob_sha1 TEXT NOT NULL,
    PRIMARY KEY(session_id,cve_id),
    UNIQUE(session_id,path)
);
CREATE INDEX source_record_supported ON source_record(supported);
