"""
DuckDB access and schema bootstrap for DetectBot Portal.
"""

from datetime import datetime, timezone
from pathlib import Path

from lib.codebook import iter_code_dictionary_rows

try:
    import duckdb
except Exception as exc:  # pragma: no cover
    duckdb = None
    DUCKDB_IMPORT_ERROR = exc
else:
    DUCKDB_IMPORT_ERROR = None


PORTAL_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PORTAL_ROOT / "data"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "detectbot_portal.duckdb"


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def ensure_runtime_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_connection():
    if duckdb is None:
        raise RuntimeError(
            "duckdb 패키지가 필요합니다. `pip install duckdb` 후 다시 실행해 주세요."
        ) from DUCKDB_IMPORT_ERROR
    ensure_runtime_dirs()
    return duckdb.connect(str(DB_PATH))


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    server_name TEXT NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    environment TEXT,
    zone TEXT,
    os_type TEXT,
    web_server_type TEXT,
    service_name TEXT,
    criticality TEXT,
    owner_name TEXT,
    upload_enabled BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    notes TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_tags (
    id TEXT PRIMARY KEY,
    tag_name TEXT UNIQUE,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_tag_links (
    server_id TEXT,
    tag_id TEXT,
    created_at TIMESTAMP,
    PRIMARY KEY (server_id, tag_id)
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    policy_name TEXT UNIQUE,
    description TEXT,
    policy_mode TEXT,
    policy_version TEXT,
    allow_mime_json TEXT,
    allow_ext_json TEXT,
    exclude_paths_json TEXT,
    max_depth INTEGER,
    newer_than_hours INTEGER,
    size_threshold_mb INTEGER,
    compute_hash BOOLEAN,
    content_scan_enabled BOOLEAN,
    content_max_kb INTEGER,
    pii_scan_enabled BOOLEAN,
    custom_config_json TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id TEXT PRIMARY KEY,
    policy_id TEXT,
    rule_type TEXT,
    rule_key TEXT,
    rule_value TEXT,
    sort_order INTEGER,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS report_sources (
    id TEXT PRIMARY KEY,
    server_id TEXT,
    file_name TEXT,
    original_path TEXT,
    stored_path TEXT,
    scanner_version TEXT,
    input_type TEXT,
    uploaded_by TEXT,
    uploaded_at TIMESTAMP,
    report_generated_at TIMESTAMP,
    raw_summary_json TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    server_id TEXT,
    policy_id TEXT,
    report_source_id TEXT,
    scan_started_at TIMESTAMP,
    scan_finished_at TIMESTAMP,
    generated_at TIMESTAMP,
    scanner_version TEXT,
    input_type TEXT,
    active_rules_json TEXT,
    config_json TEXT,
    findings_count INTEGER,
    roots_count INTEGER,
    scanned_files INTEGER,
    severity_summary_json TEXT,
    latest_for_server BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_roots (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT,
    root_path TEXT,
    real_path TEXT,
    source_type TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT,
    server_id TEXT,
    path TEXT,
    real_path TEXT,
    root_matched TEXT,
    root_source TEXT,
    severity TEXT,
    size_bytes BIGINT,
    mod_time TIMESTAMP,
    perm TEXT,
    ext TEXT,
    mime_sniff TEXT,
    sha256 TEXT,
    url_exposure_heuristic TEXT,
    evidence_masked_json TEXT,
    content_flags_json TEXT,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS finding_reasons (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    reason_code TEXT,
    reason_meaning TEXT
);

CREATE TABLE IF NOT EXISTS finding_patterns (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    pattern_code TEXT,
    pattern_meaning TEXT
);

CREATE TABLE IF NOT EXISTS code_dictionary (
    code_type TEXT,
    code TEXT,
    meaning_ko TEXT,
    source TEXT,
    updated_at TIMESTAMP,
    PRIMARY KEY (code_type, code)
);

CREATE INDEX IF NOT EXISTS idx_servers_name ON servers(server_name);
CREATE INDEX IF NOT EXISTS idx_servers_hostname ON servers(hostname);
CREATE INDEX IF NOT EXISTS idx_scan_runs_server ON scan_runs(server_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_server ON findings(server_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
CREATE INDEX IF NOT EXISTS idx_finding_reasons_code ON finding_reasons(reason_code);
CREATE INDEX IF NOT EXISTS idx_finding_patterns_code ON finding_patterns(pattern_code);
"""


def init_db():
    ensure_runtime_dirs()
    conn = get_connection()
    try:
        conn.execute(SCHEMA_SQL)
        now = utcnow()
        for code_type, code, meaning, source in iter_code_dictionary_rows():
            conn.execute(
                """
                INSERT INTO code_dictionary (code_type, code, meaning_ko, source, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (code_type, code) DO UPDATE SET
                    meaning_ko = excluded.meaning_ko,
                    source = excluded.source,
                    updated_at = excluded.updated_at
                """,
                [code_type, code, meaning, source, now],
            )
    finally:
        conn.close()
