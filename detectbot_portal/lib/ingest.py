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
    find_server_by_ip_address,
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


def _normalize_host(report):
    raw_host = report.get("host")
    host = {
        "hostname": "",
        "ip_addresses": [],
        "primary_ip": "",
        "os_type": "unknown",
        "os_name": "",
        "os_version": "",
        "platform": "",
        "collected_at": "",
    }

    if isinstance(raw_host, dict):
        host["hostname"] = str(raw_host.get("hostname") or "").strip()
        host["ip_addresses"] = [
            str(value).strip()
            for value in _normalize_list(raw_host.get("ip_addresses"))
            if str(value).strip()
        ]
        host["primary_ip"] = str(raw_host.get("primary_ip") or "").strip()
        host["os_type"] = str(raw_host.get("os_type") or "unknown").strip().lower() or "unknown"
        host["os_name"] = str(raw_host.get("os_name") or "").strip()
        host["os_version"] = str(raw_host.get("os_version") or "").strip()
        host["platform"] = str(raw_host.get("platform") or "").strip()
        host["collected_at"] = str(raw_host.get("collected_at") or "").strip()
    elif isinstance(raw_host, str):
        host["hostname"] = raw_host.strip()

    if not host["primary_ip"] and host["ip_addresses"]:
        host["primary_ip"] = host["ip_addresses"][0]
    if host["primary_ip"] and host["primary_ip"] not in host["ip_addresses"]:
        host["ip_addresses"].insert(0, host["primary_ip"])

    return host


def _normalize_roots(report):
    return _normalize_list(report.get("roots") or report.get("scan_roots"))


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


def _default_server_name(host):
    return host["hostname"] or host["primary_ip"] or f"auto-{uuid.uuid4().hex[:8]}"


def _server_payload(existing, host):
    payload = dict(existing or {})
    payload.update(
        {
            "id": payload.get("id"),
            "server_name": payload.get("server_name") or _default_server_name(host),
            "hostname": host["hostname"] or payload.get("hostname", ""),
            "ip_address": host["primary_ip"] or payload.get("ip_address", ""),
            "environment": payload.get("environment", "unknown"),
            "zone": payload.get("zone", "unknown"),
            "os_type": host["os_type"] or payload.get("os_type", "unknown"),
            "os_name": host["os_name"] or payload.get("os_name", ""),
            "os_version": host["os_version"] or payload.get("os_version", ""),
            "platform": host["platform"] or payload.get("platform", ""),
            "web_server_type": payload.get("web_server_type", "unknown"),
            "service_name": payload.get("service_name", ""),
            "criticality": payload.get("criticality", "medium"),
            "owner_name": payload.get("owner_name", "자동등록"),
            "upload_enabled": payload.get("upload_enabled", True),
            "is_active": payload.get("is_active", True),
            "notes": payload.get("notes", "리포트 업로드로 자동 등록/보정된 자산"),
        }
    )
    return payload


def _ensure_server(server_id, report, auto_create=True):
    if server_id:
        return server_id

    host = _normalize_host(report)
    existing = None
    if host["hostname"]:
        existing = find_server_by_hostname(host["hostname"])
    if not existing and host["primary_ip"]:
        existing = find_server_by_ip_address(host["primary_ip"])

    if existing:
        save_server(_server_payload(existing, host))
        return existing["id"]

    if not auto_create:
        raise ValueError("리포트에 연결할 서버를 선택해 주세요.")

    return save_server(_server_payload({}, host))


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
    host = _normalize_host(report)
    now = utcnow()
    stored_path = _store_report_file(file_name, report_bytes)
    server_id = _ensure_server(server_id, report, auto_create=auto_create_server)

    findings = _normalize_list(report.get("findings"))
    roots = _normalize_roots(report)
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
                        "host": host,
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
                findings_count, roots_count, scanned_files, host_hostname, host_primary_ip,
                host_os_type, host_os_name, host_platform, severity_summary_json,
                latest_for_server, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                host["hostname"],
                host["primary_ip"],
                host["os_type"],
                host["os_name"],
                host["platform"],
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
        "host": host,
    }
