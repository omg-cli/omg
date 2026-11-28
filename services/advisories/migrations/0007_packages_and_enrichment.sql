CREATE TABLE IF NOT EXISTS osv_package_advisory (
    id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    ecosystem_lower TEXT NOT NULL,
    package_name_lower TEXT NOT NULL,
    is_malware INTEGER NOT NULL DEFAULT 0 CHECK(is_malware IN (0, 1)),
    summary TEXT,
    severity TEXT,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    fixed_versions_json TEXT NOT NULL DEFAULT '[]',
    modified_at TEXT
);

CREATE INDEX IF NOT EXISTS osv_package_advisory_pkg_idx
    ON osv_package_advisory(ecosystem_lower, package_name_lower, is_malware DESC, modified_at DESC);

CREATE TABLE IF NOT EXISTS osv_package_alias (
    advisory_id TEXT NOT NULL REFERENCES osv_package_advisory(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    PRIMARY KEY(advisory_id, cve_id)
);

CREATE INDEX IF NOT EXISTS osv_package_alias_cve_idx
    ON osv_package_alias(cve_id);

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id TEXT PRIMARY KEY,
    epss REAL NOT NULL,
    percentile REAL NOT NULL,
    score_date TEXT
);

CREATE TABLE IF NOT EXISTS euvd_exploited (
    cve_id TEXT PRIMARY KEY,
    euvd_id TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS runtime_eol (
    product TEXT NOT NULL,
    cycle TEXT NOT NULL,
    eol TEXT,
    lts INTEGER NOT NULL DEFAULT 0,
    latest TEXT,
    release_date TEXT,
    support TEXT,
    updated_at TEXT,
    PRIMARY KEY(product, cycle)
);

CREATE INDEX IF NOT EXISTS runtime_eol_product_release_idx
    ON runtime_eol(product, release_date DESC, cycle DESC);
