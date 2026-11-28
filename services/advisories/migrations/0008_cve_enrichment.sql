CREATE TABLE IF NOT EXISTS cve_exploitation_evidence (
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('Project Zero', 'Vendor disclosure')),
    vendor TEXT,
    product TEXT NOT NULL,
    discovered_on TEXT,
    patched_on TEXT,
    evidence_url TEXT NOT NULL CHECK(evidence_url LIKE 'https://%'),
    vendor_url TEXT CHECK(vendor_url IS NULL OR vendor_url LIKE 'https://%'),
    catalog_year INTEGER CHECK(catalog_year IS NULL OR (catalog_year BETWEEN 1999 AND 2100)),
    archive_revision_sha256 TEXT NOT NULL CHECK(length(archive_revision_sha256) = 64),
    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
    first_seen_at TEXT NOT NULL,
    last_changed_at TEXT NOT NULL,
    baseline INTEGER NOT NULL CHECK(baseline IN (0, 1)),
    withdrawn_at TEXT,
    PRIMARY KEY(cve_id, source),
    CHECK(last_changed_at >= first_seen_at)
);

CREATE INDEX IF NOT EXISTS cve_exploitation_evidence_recent
    ON cve_exploitation_evidence(first_seen_at DESC, cve_id)
    WHERE withdrawn_at IS NULL;

CREATE TABLE IF NOT EXISTS cve_exploitation_source (
    source TEXT PRIMARY KEY CHECK(source IN ('Project Zero', 'Vendor disclosure')),
    checked_at TEXT NOT NULL,
    successful_at TEXT,
    coverage_years_json TEXT NOT NULL DEFAULT '[]',
    observed_count INTEGER NOT NULL CHECK(observed_count >= 0),
    matched_count INTEGER NOT NULL CHECK(matched_count BETWEEN 0 AND observed_count),
    complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
    error_code TEXT,
    pending_evidence_json TEXT NOT NULL DEFAULT '[]',
    CHECK(complete = 0 OR (successful_at IS NOT NULL AND error_code IS NULL))
);

CREATE TABLE IF NOT EXISTS cve_vendor_signal (
    provider TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    advisory_url TEXT NOT NULL CHECK(advisory_url LIKE 'https://%'),
    publisher_published_at TEXT NOT NULL,
    publisher_modified_at TEXT NOT NULL,
    reported_exploited INTEGER NOT NULL CHECK(reported_exploited IN (0, 1)),
    first_received_at TEXT NOT NULL,
    first_exploitation_received_at TEXT,
    baseline INTEGER NOT NULL CHECK(baseline IN (0, 1)),
    exploited_since TEXT,
    PRIMARY KEY(provider, advisory_url, cve_id)
);

CREATE INDEX IF NOT EXISTS cve_vendor_signal_lookup
    ON cve_vendor_signal(cve_id, reported_exploited DESC, first_received_at DESC);

CREATE INDEX IF NOT EXISTS cve_vendor_signal_provider_exploited
    ON cve_vendor_signal(provider, reported_exploited DESC, publisher_published_at DESC, cve_id DESC);

CREATE TABLE IF NOT EXISTS cve_vendor_signal_source (
    provider TEXT PRIMARY KEY,
    etag TEXT,
    checked_at TEXT NOT NULL,
    successful_at TEXT,
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1))
);

CREATE TABLE IF NOT EXISTS cve_package_advisory (
    id TEXT PRIMARY KEY,
    cve_id TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('reviewed', 'malware')),
    advisory_url TEXT NOT NULL,
    published_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    withdrawn_at TEXT,
    observed_at TEXT NOT NULL,
    packages_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS cve_package_advisory_recent
    ON cve_package_advisory(kind, published_at DESC, id DESC)
    WHERE withdrawn_at IS NULL;

CREATE TABLE IF NOT EXISTS cve_package_advisory_source (
    kind TEXT PRIMARY KEY CHECK(kind IN ('reviewed', 'malware')),
    window_from TEXT NOT NULL,
    window_until TEXT NOT NULL,
    cursor TEXT,
    revision INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT,
    successful_at TEXT,
    retry_at TEXT,
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
    CHECK(window_from <= window_until)
);

CREATE TABLE IF NOT EXISTS cve_osv_package_advisory (
    id TEXT PRIMARY KEY,
    cve_id TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('reviewed', 'malware')),
    advisory_url TEXT NOT NULL,
    published_at TEXT,
    revision TEXT NOT NULL,
    withdrawn_at TEXT,
    observed_at TEXT NOT NULL,
    packages_json TEXT NOT NULL DEFAULT '[]',
    package_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS cve_osv_package_advisory_recent
    ON cve_osv_package_advisory(kind, published_at DESC, id DESC)
    WHERE withdrawn_at IS NULL AND published_at IS NOT NULL AND package_count > 0;

CREATE TABLE IF NOT EXISTS cve_osv_package_source (
    ecosystem TEXT PRIMARY KEY CHECK(ecosystem IN ('npm', 'PyPI', '[EMPTY]')),
    checked_at TEXT NOT NULL,
    successful_at TEXT,
    complete INTEGER NOT NULL CHECK(complete IN (0, 1))
);
