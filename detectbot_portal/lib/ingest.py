"""
Report ingestion logic for DetectBot Portal.
"""

import json
import uuid
from collections import Counter
from pathlib import Path

from lib.codebook import get_pattern_meaning, get_reason_meaning
from lib.db import REPORTS_DIR, get_connection, utcnow
from lib.repository import (
    find_server_by_hostname,
    resolve_pattern_meaning,
    resolve_reason_meaning,
    save_server,
    upsert_code_dictionary,
)


def _normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    return [value]


def _infer_input_type(report):
    config = report.get("config", {}) or {}
    if config.get("NginxDump"):
        return "nginx_dump"
    if config.get("ApacheDump"):
        return "apache_dump"
    if config.get("WatchDirs"):
        return "watch_dir"
    if report.get("inputs"):
        return "manual_json"
    return "unknown"


def _ensure_server(server_id, report, auto_create=True):
    if server_id:
        return server_id
    hostname = (report.get("host") or "").strip()
    existing = find_server_by_hostname(hostname)
    if existing:
        return existing["id"]
    if not auto_create:
        raise ValueError("리포트에 연결할 서버를 선택해 주세요.")
    return save_server(
        {
            "server_name": hostname or f"auto-{uuid.uuid4().hex[:8]}",
            "hostname": hostname,
            "ip_address": "",
            "environment": "unknown",
            "zone": "unknown",
            "os_type": "unknown",
            "web_server_type": "unknown",
            "service_name": "",
            "criticality": "medium",
            "owner_name": "자동등록",
            "upload_enabled": True,
            "is_active": True,
            "notes": "리포트 업로드 시 자동 등록된 자산",
        }
    )


def _store_report_file(file_name, report_bytes):
    stamp = uuid.uuid4().hex
    safe_name = Path(file_name or "report.json").name
    stored_path = REPORTS_DIR / f"{stamp}_{safe_name}"
    stored_path.write_bytes(report_bytes)
    return stored_path


def ingest_report(
    report_bytes,
    file_name,
    server_id=None,
    policy_id=None,
    input_type=None,
    uploaded_by="portal",
    original_path="",
    auto_create_server=True,
):
    report = json.loads(report_bytes.decode("utf-8"))
    now = utcnow()
    stored_path = _store_report_file(file_name, report_bytes)
    server_id = _ensure_server(server_id, report, auto_create=auto_create_server)

    findings = _normalize_list(report.get("findings"))
    roots = _normalize_list(report.get("roots"))
    stats = report.get("stats", {}) or {}
    resolved_input_type = input_type or _infer_input_type(report)
    scanner_version = report.get("report_version", "unknown")
    severity_counter = Counter(
        [(finding.get("severity") or "unknown").lower() for finding in findings]
    )

    conn = get_connection()
    try:
        report_source_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO report_sources (
                id, server_id, file_name, original_path, stored_path, scanner_version,
                input_type, uploaded_by, uploaded_at, report_generated_at, raw_summary_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                report_source_id,
                server_id,
                file_name,
                original_path,
                str(stored_path),
                scanner_version,
                resolved_input_type,
                uploaded_by,
                now,
                report.get("generated_at"),
                json.dumps(
                    {
                        "host": report.get("host"),
                        "findings_count": stats.get("findings_count", len(findings)),
                        "roots_count": stats.get("roots_count", len(roots)),
                    },
                    ensure_ascii=False,
                ),
            ],
        )

        conn.execute(
            "UPDATE scan_runs SET latest_for_server = FALSE WHERE server_id = ?",
            [server_id],
        )

        scan_run_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO scan_runs (
                id, server_id, policy_id, report_source_id, scan_started_at, scan_finished_at,
                generated_at, scanner_version, input_type, active_rules_json, config_json,
                findings_count, roots_count, scanned_files, severity_summary_json,
                latest_for_server, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                scan_run_id,
                server_id,
                policy_id,
                report_source_id,
                report.get("scan_started_at"),
                report.get("generated_at"),
                report.get("generated_at"),
                scanner_version,
                resolved_input_type,
                json.dumps(report.get("active_rules", []), ensure_ascii=False),
                json.dumps(report.get("config", {}), ensure_ascii=False),
                stats.get("findings_count", len(findings)),
                stats.get("roots_count", len(roots)),
                stats.get("scanned_files", 0),
                json.dumps(severity_counter, ensure_ascii=False),
                True,
                now,
            ],
        )

        for root in roots:
            conn.execute(
                """
                INSERT INTO scan_roots (id, scan_run_id, root_path, real_path, source_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    str(uuid.uuid4()),
                    scan_run_id,
                    root.get("path", ""),
                    root.get("real_path", ""),
                    root.get("source", ""),
                ],
            )

        for finding in findings:
            finding_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO findings (
                    id, scan_run_id, server_id, path, real_path, root_matched, root_source,
                    severity, size_bytes, mod_time, perm, ext, mime_sniff, sha256,
                    url_exposure_heuristic, evidence_masked_json, content_flags_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    finding_id,
                    scan_run_id,
                    server_id,
                    finding.get("path", ""),
                    finding.get("real_path", ""),
                    finding.get("root_matched", ""),
                    finding.get("root_source", ""),
                    (finding.get("severity") or "unknown").lower(),
                    finding.get("size_bytes"),
                    finding.get("mod_time"),
                    finding.get("perm", ""),
                    finding.get("ext", ""),
                    finding.get("mime_sniff", ""),
                    finding.get("sha256", ""),
                    finding.get("url_exposure_heuristic", ""),
                    json.dumps(_normalize_list(finding.get("evidence_masked")), ensure_ascii=False),
                    json.dumps(_normalize_list(finding.get("content_flags")), ensure_ascii=False),
                    now,
                ],
            )

            for reason_code in _normalize_list(finding.get("reasons")):
                reason_meaning = resolve_reason_meaning(reason_code)
                upsert_code_dictionary(
                    "reason_code", reason_code, get_reason_meaning(reason_code)
                )
                conn.execute(
                    """
                    INSERT INTO finding_reasons (id, finding_id, reason_code, reason_meaning)
                    VALUES (?, ?, ?, ?)
                    """,
                    [str(uuid.uuid4()), finding_id, reason_code, reason_meaning],
                )

            for pattern_code in _normalize_list(finding.get("matched_patterns")):
                pattern_meaning = resolve_pattern_meaning(pattern_code)
                upsert_code_dictionary(
                    "pattern", pattern_code, get_pattern_meaning(pattern_code)
                )
                conn.execute(
                    """
                    INSERT INTO finding_patterns (id, finding_id, pattern_code, pattern_meaning)
                    VALUES (?, ?, ?, ?)
                    """,
                    [str(uuid.uuid4()), finding_id, pattern_code, pattern_meaning],
                )
    finally:
        conn.close()

    return {
        "scan_run_id": scan_run_id,
        "report_source_id": report_source_id,
        "server_id": server_id,
        "stored_path": str(stored_path),
        "findings_count": len(findings),
    }
