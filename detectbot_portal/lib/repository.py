"""
Repository layer for DetectBot Portal.
"""

import json
import uuid

from lib.codebook import get_pattern_meaning, get_reason_meaning
from lib.db import get_connection, utcnow
from lib.models import DEFAULT_ALLOW_EXT, DEFAULT_ALLOW_MIME, DEFAULT_EXCLUDE_PATHS


def _uuid():
    return str(uuid.uuid4())


def _json_dumps(value):
    return json.dumps(value or [], ensure_ascii=False)


def _json_loads(text, default=None):
    if not text:
        return default if default is not None else []
    try:
        return json.loads(text)
    except Exception:
        return default if default is not None else []


def fetch_df(query, params=None):
    conn = get_connection()
    try:
        return conn.execute(query, params or []).fetchdf()
    finally:
        conn.close()


def fetch_one(query, params=None):
    conn = get_connection()
    try:
        row = conn.execute(query, params or []).fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in conn.description]
        return dict(zip(columns, row))
    finally:
        conn.close()


def execute(query, params=None):
    conn = get_connection()
    try:
        conn.execute(query, params or [])
    finally:
        conn.close()


def dashboard_metrics():
    metrics = {}
    metrics["servers_total"] = fetch_one(
        "SELECT COUNT(*) AS value FROM servers WHERE is_active = TRUE"
    )["value"]
    metrics["recent_scanned_servers"] = fetch_one(
        """
        SELECT COUNT(DISTINCT server_id) AS value
        FROM scan_runs
        WHERE created_at >= NOW() - INTERVAL 30 DAY
        """
    )["value"]
    metrics["findings_total"] = fetch_one("SELECT COUNT(*) AS value FROM findings")["value"]
    severity_df = fetch_df(
        """
        SELECT severity, COUNT(*) AS count
        FROM findings
        GROUP BY severity
        """
    )
    metrics["severity_counts"] = {
        row["severity"]: int(row["count"]) for _, row in severity_df.iterrows()
    }
    return metrics


def recent_scan_runs(limit=10):
    return fetch_df(
        """
        SELECT
            sr.id,
            sr.server_id,
            sr.policy_id,
            s.server_name,
            s.hostname,
            sr.input_type,
            sr.scanner_version,
            sr.findings_count,
            sr.generated_at,
            sr.scan_started_at,
            sr.latest_for_server,
            p.policy_name
        FROM scan_runs sr
        LEFT JOIN servers s ON s.id = sr.server_id
        LEFT JOIN policies p ON p.id = sr.policy_id
        ORDER BY COALESCE(sr.generated_at, sr.created_at) DESC
        LIMIT ?
        """,
        [limit],
    )


def top_reason_counts(limit=10):
    return fetch_df(
        """
        SELECT
            reason_code,
            COALESCE(MAX(reason_meaning), MAX(cd.meaning_ko)) AS meaning,
            COUNT(*) AS count
        FROM finding_reasons fr
        LEFT JOIN code_dictionary cd
            ON cd.code_type = 'reason_code' AND cd.code = fr.reason_code
        GROUP BY reason_code
        ORDER BY count DESC, reason_code
        LIMIT ?
        """,
        [limit],
    )


def top_pattern_counts(limit=10):
    return fetch_df(
        """
        SELECT
            pattern_code,
            COALESCE(MAX(pattern_meaning), MAX(cd.meaning_ko)) AS meaning,
            COUNT(*) AS count
        FROM finding_patterns fp
        LEFT JOIN code_dictionary cd
            ON cd.code_type = 'pattern' AND cd.code = fp.pattern_code
        GROUP BY pattern_code
        ORDER BY count DESC, pattern_code
        LIMIT ?
        """,
        [limit],
    )


def list_servers(keyword="", environment="", zone="", active_only=False):
    where = ["1=1"]
    params = []
    if keyword:
        where.append(
            "(LOWER(server_name) LIKE ? OR LOWER(hostname) LIKE ? OR LOWER(ip_address) LIKE ? OR LOWER(service_name) LIKE ?)"
        )
        like = f"%{keyword.lower()}%"
        params.extend([like, like, like, like])
    if environment:
        where.append("environment = ?")
        params.append(environment)
    if zone:
        where.append("zone = ?")
        params.append(zone)
    if active_only:
        where.append("is_active = TRUE")
    return fetch_df(
        f"""
        SELECT
            id,
            server_name,
            hostname,
            ip_address,
            environment,
            zone,
            os_type,
            web_server_type,
            service_name,
            criticality,
            owner_name,
            upload_enabled,
            is_active,
            updated_at
        FROM servers
        WHERE {' AND '.join(where)}
        ORDER BY is_active DESC, criticality, server_name
        """,
        params,
    )


def get_server(server_id):
    return fetch_one("SELECT * FROM servers WHERE id = ?", [server_id])


def save_server(payload):
    now = utcnow()
    server_id = payload.get("id") or _uuid()
    existing = get_server(server_id)
    params = [
        server_id,
        payload.get("server_name", "").strip(),
        payload.get("hostname", "").strip(),
        payload.get("ip_address", "").strip(),
        payload.get("environment", "unknown"),
        payload.get("zone", "unknown"),
        payload.get("os_type", "unknown"),
        payload.get("web_server_type", "unknown"),
        payload.get("service_name", "").strip(),
        payload.get("criticality", "medium"),
        payload.get("owner_name", "").strip(),
        bool(payload.get("upload_enabled", True)),
        bool(payload.get("is_active", True)),
        payload.get("notes", "").strip(),
        existing["created_at"] if existing else now,
        now,
    ]
    conn = get_connection()
    try:
        if existing:
            conn.execute("DELETE FROM servers WHERE id = ?", [server_id])
        conn.execute(
            """
            INSERT INTO servers (
                id, server_name, hostname, ip_address, environment, zone, os_type,
                web_server_type, service_name, criticality, owner_name, upload_enabled,
                is_active, notes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            params,
        )
    finally:
        conn.close()
    return server_id


def find_server_by_hostname(hostname):
    if not hostname:
        return None
    return fetch_one(
        """
        SELECT *
        FROM servers
        WHERE LOWER(hostname) = LOWER(?)
        LIMIT 1
        """,
        [hostname],
    )


def list_policies(active_only=False):
    where = "WHERE is_active = TRUE" if active_only else ""
    return fetch_df(
        f"""
        SELECT
            id,
            policy_name,
            description,
            policy_mode,
            policy_version,
            max_depth,
            newer_than_hours,
            size_threshold_mb,
            compute_hash,
            content_scan_enabled,
            pii_scan_enabled,
            is_active,
            updated_at
        FROM policies
        {where}
        ORDER BY policy_name
        """
    )


def get_policy(policy_id):
    policy = fetch_one("SELECT * FROM policies WHERE id = ?", [policy_id])
    if not policy:
        return None
    policy["allow_mime"] = _json_loads(policy.get("allow_mime_json"), DEFAULT_ALLOW_MIME)
    policy["allow_ext"] = _json_loads(policy.get("allow_ext_json"), DEFAULT_ALLOW_EXT)
    policy["exclude_paths"] = _json_loads(
        policy.get("exclude_paths_json"), DEFAULT_EXCLUDE_PATHS
    )
    return policy


def save_policy(payload):
    now = utcnow()
    policy_id = payload.get("id") or _uuid()
    existing = get_policy(policy_id)
    conn = get_connection()
    try:
        if existing:
            conn.execute("DELETE FROM policy_rules WHERE policy_id = ?", [policy_id])
            conn.execute("DELETE FROM policies WHERE id = ?", [policy_id])

        conn.execute(
            """
            INSERT INTO policies (
                id, policy_name, description, policy_mode, policy_version,
                allow_mime_json, allow_ext_json, exclude_paths_json, max_depth,
                newer_than_hours, size_threshold_mb, compute_hash,
                content_scan_enabled, content_max_kb, pii_scan_enabled,
                custom_config_json, is_active, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                policy_id,
                payload.get("policy_name", "").strip(),
                payload.get("description", "").strip(),
                payload.get("policy_mode", "balanced"),
                payload.get("policy_version", "v1"),
                _json_dumps(payload.get("allow_mime")),
                _json_dumps(payload.get("allow_ext")),
                _json_dumps(payload.get("exclude_paths")),
                int(payload.get("max_depth", 10)),
                int(payload.get("newer_than_hours", 0)),
                int(payload.get("size_threshold_mb", 100)),
                bool(payload.get("compute_hash", False)),
                bool(payload.get("content_scan_enabled", True)),
                int(payload.get("content_max_kb", 1024)),
                bool(payload.get("pii_scan_enabled", True)),
                payload.get("custom_config_json", "").strip(),
                bool(payload.get("is_active", True)),
                existing["created_at"] if existing else now,
                now,
            ],
        )

        rules = []
        for index, value in enumerate(payload.get("allow_mime", [])):
            rules.append(("allow_mime", "mime", value, index))
        for index, value in enumerate(payload.get("allow_ext", [])):
            rules.append(("allow_ext", "ext", value, index))
        for index, value in enumerate(payload.get("exclude_paths", [])):
            rules.append(("exclude_path", "path", value, index))
        rules.extend(
            [
                ("scan_option", "max_depth", str(payload.get("max_depth", 10)), 1000),
                ("scan_option", "newer_than_hours", str(payload.get("newer_than_hours", 0)), 1001),
                ("scan_option", "size_threshold_mb", str(payload.get("size_threshold_mb", 100)), 1002),
                ("scan_option", "compute_hash", str(bool(payload.get("compute_hash", False))), 1003),
                ("scan_option", "content_scan_enabled", str(bool(payload.get("content_scan_enabled", True))), 1004),
                ("scan_option", "pii_scan_enabled", str(bool(payload.get("pii_scan_enabled", True))), 1005),
            ]
        )
        for rule_type, rule_key, rule_value, sort_order in rules:
            conn.execute(
                """
                INSERT INTO policy_rules (id, policy_id, rule_type, rule_key, rule_value, sort_order, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [_uuid(), policy_id, rule_type, rule_key, rule_value, sort_order, now],
            )
    finally:
        conn.close()
    return policy_id


def list_code_options(code_type):
    column = "reason_code" if code_type == "reason_code" else "pattern_code"
    table = "finding_reasons" if code_type == "reason_code" else "finding_patterns"
    meaning_col = "reason_meaning" if code_type == "reason_code" else "pattern_meaning"
    return fetch_df(
        f"""
        SELECT
            t.{column} AS code,
            COALESCE(MAX(cd.meaning_ko), MAX(t.{meaning_col})) AS meaning,
            COUNT(*) AS count
        FROM {table} t
        LEFT JOIN code_dictionary cd
            ON cd.code_type = ? AND cd.code = t.{column}
        GROUP BY t.{column}
        ORDER BY count DESC, code
        """,
        [code_type],
    )


def list_scan_runs(server_id="", limit=200):
    where = ["1=1"]
    params = []
    if server_id:
        where.append("sr.server_id = ?")
        params.append(server_id)
    params.append(limit)
    return fetch_df(
        f"""
        SELECT
            sr.id,
            s.server_name,
            s.hostname,
            sr.input_type,
            sr.scanner_version,
            sr.scan_started_at,
            sr.generated_at,
            sr.findings_count,
            sr.roots_count,
            sr.scanned_files,
            sr.latest_for_server,
            p.policy_name,
            rs.file_name,
            rs.stored_path
        FROM scan_runs sr
        LEFT JOIN servers s ON s.id = sr.server_id
        LEFT JOIN policies p ON p.id = sr.policy_id
        LEFT JOIN report_sources rs ON rs.id = sr.report_source_id
        WHERE {' AND '.join(where)}
        ORDER BY COALESCE(sr.generated_at, sr.created_at) DESC
        LIMIT ?
        """,
        params,
    )


def get_scan_run_detail(scan_run_id):
    run = fetch_one(
        """
        SELECT
            sr.*,
            s.server_name,
            s.hostname,
            s.environment,
            s.zone,
            p.policy_name,
            rs.file_name,
            rs.stored_path,
            rs.original_path
        FROM scan_runs sr
        LEFT JOIN servers s ON s.id = sr.server_id
        LEFT JOIN policies p ON p.id = sr.policy_id
        LEFT JOIN report_sources rs ON rs.id = sr.report_source_id
        WHERE sr.id = ?
        """,
        [scan_run_id],
    )
    if not run:
        return None
    return {
        "run": run,
        "roots": fetch_df(
            """
            SELECT root_path, real_path, source_type
            FROM scan_roots
            WHERE scan_run_id = ?
            ORDER BY root_path
            """,
            [scan_run_id],
        ),
        "severity_counts": fetch_df(
            """
            SELECT severity, COUNT(*) AS count
            FROM findings
            WHERE scan_run_id = ?
            GROUP BY severity
            ORDER BY count DESC
            """,
            [scan_run_id],
        ),
        "reason_counts": fetch_df(
            """
            SELECT reason_code, MAX(reason_meaning) AS meaning, COUNT(*) AS count
            FROM finding_reasons fr
            JOIN findings f ON f.id = fr.finding_id
            WHERE f.scan_run_id = ?
            GROUP BY reason_code
            ORDER BY count DESC, reason_code
            LIMIT 20
            """,
            [scan_run_id],
        ),
        "pattern_counts": fetch_df(
            """
            SELECT pattern_code, MAX(pattern_meaning) AS meaning, COUNT(*) AS count
            FROM finding_patterns fp
            JOIN findings f ON f.id = fp.finding_id
            WHERE f.scan_run_id = ?
            GROUP BY pattern_code
            ORDER BY count DESC, pattern_code
            LIMIT 20
            """,
            [scan_run_id],
        ),
    }


def search_findings(filters):
    where = ["1=1"]
    params = []
    if filters.get("server_id"):
        where.append("f.server_id = ?")
        params.append(filters["server_id"])
    if filters.get("severity"):
        where.append("f.severity = ?")
        params.append(filters["severity"])
    if filters.get("ext"):
        where.append("LOWER(f.ext) = LOWER(?)")
        params.append(filters["ext"])
    if filters.get("mime_keyword"):
        where.append("LOWER(f.mime_sniff) LIKE ?")
        params.append(f"%{filters['mime_keyword'].lower()}%")
    if filters.get("path_keyword"):
        where.append("(LOWER(f.path) LIKE ? OR LOWER(f.real_path) LIKE ?)")
        like = f"%{filters['path_keyword'].lower()}%"
        params.extend([like, like])
    if filters.get("date_from"):
        where.append("DATE(COALESCE(sr.scan_started_at, sr.generated_at, sr.created_at)) >= ?")
        params.append(str(filters["date_from"]))
    if filters.get("date_to"):
        where.append("DATE(COALESCE(sr.scan_started_at, sr.generated_at, sr.created_at)) <= ?")
        params.append(str(filters["date_to"]))
    if filters.get("reason_code"):
        where.append(
            "EXISTS (SELECT 1 FROM finding_reasons fr WHERE fr.finding_id = f.id AND fr.reason_code = ?)"
        )
        params.append(filters["reason_code"])
    if filters.get("pattern_code"):
        where.append(
            "EXISTS (SELECT 1 FROM finding_patterns fp WHERE fp.finding_id = f.id AND fp.pattern_code = ?)"
        )
        params.append(filters["pattern_code"])

    return fetch_df(
        f"""
        SELECT
            f.id,
            s.server_name,
            s.hostname,
            sr.id AS scan_run_id,
            sr.generated_at,
            f.severity,
            f.path,
            f.real_path,
            f.ext,
            f.mime_sniff,
            f.size_bytes,
            f.mod_time,
            f.sha256,
            f.url_exposure_heuristic,
            COALESCE(fr.reason_codes, '') AS reason_codes,
            COALESCE(fr.reason_meanings, '') AS reason_meanings,
            COALESCE(fp.pattern_codes, '') AS pattern_codes,
            COALESCE(fp.pattern_meanings, '') AS pattern_meanings
        FROM findings f
        LEFT JOIN scan_runs sr ON sr.id = f.scan_run_id
        LEFT JOIN servers s ON s.id = f.server_id
        LEFT JOIN (
            SELECT
                finding_id,
                string_agg(reason_code, ', ') AS reason_codes,
                string_agg(reason_meaning, ', ') AS reason_meanings
            FROM finding_reasons
            GROUP BY finding_id
        ) fr ON fr.finding_id = f.id
        LEFT JOIN (
            SELECT
                finding_id,
                string_agg(pattern_code, ', ') AS pattern_codes,
                string_agg(pattern_meaning, ', ') AS pattern_meanings
            FROM finding_patterns
            GROUP BY finding_id
        ) fp ON fp.finding_id = f.id
        WHERE {' AND '.join(where)}
        ORDER BY COALESCE(sr.generated_at, sr.created_at) DESC, f.severity, f.path
        """,
        params,
    )


def get_finding_detail(finding_id):
    return fetch_one(
        """
        SELECT
            f.*,
            s.server_name,
            s.hostname,
            sr.generated_at,
            sr.scan_started_at,
            rs.stored_path
        FROM findings f
        LEFT JOIN servers s ON s.id = f.server_id
        LEFT JOIN scan_runs sr ON sr.id = f.scan_run_id
        LEFT JOIN report_sources rs ON rs.id = sr.report_source_id
        WHERE f.id = ?
        """,
        [finding_id],
    )


def upsert_code_dictionary(code_type, code, meaning, source="ingested"):
    execute(
        """
        INSERT INTO code_dictionary (code_type, code, meaning_ko, source, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (code_type, code) DO UPDATE SET
            meaning_ko = excluded.meaning_ko,
            source = excluded.source,
            updated_at = excluded.updated_at
        """,
        [code_type, code, meaning, source, utcnow()],
    )


def seed_default_policy():
    existing = fetch_one("SELECT id FROM policies LIMIT 1")
    if existing:
        return existing["id"]
    return save_policy(
        {
            "policy_name": "Balanced Default",
            "description": "DMZ 웹루트 점검용 기본 균형 정책",
            "policy_mode": "balanced",
            "policy_version": "v1",
            "allow_mime": DEFAULT_ALLOW_MIME,
            "allow_ext": DEFAULT_ALLOW_EXT,
            "exclude_paths": DEFAULT_EXCLUDE_PATHS,
            "max_depth": 10,
            "newer_than_hours": 0,
            "size_threshold_mb": 100,
            "compute_hash": True,
            "content_scan_enabled": True,
            "content_max_kb": 1024,
            "pii_scan_enabled": True,
            "is_active": True,
        }
    )


def resolve_reason_meaning(reason_code):
    meaning = fetch_one(
        """
        SELECT meaning_ko
        FROM code_dictionary
        WHERE code_type = 'reason_code' AND code = ?
        """,
        [reason_code],
    )
    return meaning["meaning_ko"] if meaning else get_reason_meaning(reason_code)


def resolve_pattern_meaning(pattern_code):
    meaning = fetch_one(
        """
        SELECT meaning_ko
        FROM code_dictionary
        WHERE code_type = 'pattern' AND code = ?
        """,
        [pattern_code],
    )
    return meaning["meaning_ko"] if meaning else get_pattern_meaning(pattern_code)
