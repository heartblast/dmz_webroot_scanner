from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import date, datetime, time, timezone
from pathlib import Path

import pandas as pd

from config.settings import load_settings
from db.base import utcnow
from db.factory import session_scope
from db.models import ScanFinding, ScanJob, ScanResultSummary
from lib.codebook import get_pattern_meaning, get_reason_meaning
from repositories.finding_repository import FindingRepository
from repositories.policy_repository import PolicyRepository
from repositories.scan_job_repository import ScanJobRepository
from repositories.scan_result_repository import ScanResultRepository
from repositories.server_repository import ServerRepository


def _normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    return [value]


def _json_dumps(value) -> str:
    return json.dumps(value or [], ensure_ascii=False)


def _json_loads(value, default=None):
    if not value:
        return default if default is not None else []
    try:
        return json.loads(value)
    except Exception:
        return default if default is not None else []


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, time.min, tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


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


def _server_to_dict(server) -> dict:
    return {
        "id": server.id,
        "server_name": server.server_name,
        "hostname": server.hostname or "",
        "ip_address": server.ip_address or "",
        "environment": server.environment,
        "zone": server.zone,
        "os_type": server.os_type,
        "os_name": server.os_name or "",
        "os_version": server.os_version or "",
        "platform": server.platform or "",
        "web_server_type": server.web_server_type,
        "service_name": server.service_name or "",
        "criticality": server.criticality,
        "owner_name": server.owner_name or "",
        "upload_enabled": bool(server.upload_enabled),
        "is_active": bool(server.is_active),
        "notes": server.notes or "",
        "created_at": server.created_at,
        "updated_at": server.updated_at,
    }


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
            "owner_name": payload.get("owner_name", "auto-discovered"),
            "upload_enabled": payload.get("upload_enabled", True),
            "is_active": payload.get("is_active", True),
            "notes": payload.get("notes", "Auto-created from uploaded report."),
        }
    )
    return payload


def _scan_job_to_dict(scan_job: ScanJob) -> dict:
    summary = scan_job.result_summary
    server = scan_job.server
    policy = scan_job.policy
    return {
        "id": scan_job.id,
        "server_id": scan_job.server_id or "",
        "policy_id": scan_job.policy_id or "",
        "server_name": server.server_name if server else "",
        "hostname": server.hostname if server else "",
        "ip_address": server.ip_address if server else "",
        "os_type": server.os_type if server else "",
        "os_name": server.os_name if server else "",
        "platform": server.platform if server else "",
        "environment": server.environment if server else "",
        "zone": server.zone if server else "",
        "input_type": scan_job.input_type or "",
        "scanner_version": scan_job.scanner_version or "",
        "scan_started_at": scan_job.scan_started_at,
        "generated_at": scan_job.generated_at,
        "findings_count": summary.findings_count if summary else 0,
        "roots_count": summary.roots_count if summary else 0,
        "scanned_files": summary.scanned_files if summary else 0,
        "host_hostname": scan_job.host_hostname or "",
        "host_primary_ip": scan_job.host_primary_ip or "",
        "host_os_type": scan_job.host_os_type or "",
        "host_os_name": scan_job.host_os_name or "",
        "host_platform": scan_job.host_platform or "",
        "latest_for_server": bool(scan_job.latest_for_server),
        "policy_name": policy.policy_name if policy else "",
        "file_name": scan_job.report_file_name or "",
        "stored_path": scan_job.report_stored_path or "",
        "original_path": scan_job.report_original_path or "",
        "config_json": scan_job.config_json or "",
        "active_rules_json": scan_job.active_rules_json or "",
        "uploaded_by": scan_job.uploaded_by or "",
        "uploaded_at": scan_job.uploaded_at,
        "created_at": scan_job.created_at,
    }


def _finding_to_dict(finding: ScanFinding, scan_job: ScanJob | None = None) -> dict:
    reason_codes = _json_loads(finding.reasons_json, [])
    pattern_codes = _json_loads(finding.matched_patterns_json, [])
    server = scan_job.server if scan_job and scan_job.server else None
    row = {
        "id": finding.id,
        "scan_run_id": finding.scan_job_id,
        "server_id": finding.server_id or "",
        "server_name": server.server_name if server else "",
        "hostname": server.hostname if server else "",
        "generated_at": scan_job.generated_at if scan_job else None,
        "severity": finding.severity,
        "path": finding.path,
        "real_path": finding.real_path or "",
        "ext": finding.ext or "",
        "mime_sniff": finding.mime_sniff or "",
        "size_bytes": finding.size_bytes,
        "mod_time": finding.mod_time,
        "sha256": finding.sha256 or "",
        "url_exposure_heuristic": finding.url_exposure_heuristic or "",
        "reason_codes": ", ".join(reason_codes),
        "reason_meanings": ", ".join(get_reason_meaning(code) for code in reason_codes),
        "pattern_codes": ", ".join(pattern_codes),
        "pattern_meanings": ", ".join(get_pattern_meaning(code) for code in pattern_codes),
        "reasons": reason_codes,
        "matched_patterns": pattern_codes,
        "evidence_masked": _json_loads(finding.evidence_masked_json, []),
        "content_flags": _json_loads(finding.content_flags_json, []),
        "created_at": finding.created_at,
    }
    return row


def _load_report_json(stored_path: str) -> tuple[dict | None, str | None]:
    path_text = str(stored_path or "").strip()
    if not path_text:
        return None, "stored_path is empty"
    report_path = Path(path_text)
    if not report_path.is_file():
        return None, f"report file not found: {report_path}"
    try:
        return json.loads(report_path.read_text(encoding="utf-8")), None
    except Exception as exc:
        return None, f"failed to read report: {exc}"


class ScanService:
    def list_scan_runs_df(self, *, server_id: str = "", limit: int = 200) -> pd.DataFrame:
        with session_scope() as session:
            scan_jobs = ScanJobRepository(session).list_scan_jobs(server_id=server_id, limit=limit)
            return pd.DataFrame([_scan_job_to_dict(scan_job) for scan_job in scan_jobs])

    def get_scan_run_detail(self, scan_run_id: str) -> dict | None:
        with session_scope() as session:
            scan_job = ScanJobRepository(session).get_by_id(scan_run_id)
            if scan_job is None:
                return None
            summary = scan_job.result_summary
            findings = [_finding_to_dict(finding, scan_job) for finding in scan_job.findings]
            severity_counter = Counter(
                [finding["severity"] for finding in findings if finding.get("severity")]
            )
            reason_counter = Counter()
            pattern_counter = Counter()
            for finding in findings:
                reason_counter.update(finding["reasons"])
                pattern_counter.update(finding["matched_patterns"])
            run_row = _scan_job_to_dict(scan_job)
            raw_report, report_error = _load_report_json(run_row.get("stored_path", ""))
            return {
                "run": run_row,
                "roots": pd.DataFrame(_json_loads(summary.roots_json if summary else "[]", [])),
                "severity_counts": pd.DataFrame(
                    [{"severity": key, "count": value} for key, value in severity_counter.items()]
                ),
                "reason_counts": pd.DataFrame(
                    [
                        {"reason_code": key, "meaning": get_reason_meaning(key), "count": value}
                        for key, value in reason_counter.most_common()
                    ]
                ),
                "pattern_counts": pd.DataFrame(
                    [
                        {"pattern_code": key, "meaning": get_pattern_meaning(key), "count": value}
                        for key, value in pattern_counter.most_common()
                    ]
                ),
                "findings": pd.DataFrame(findings),
                "raw_report": raw_report,
                "report_error": report_error,
            }

    def search_findings_df(self, filters: dict) -> pd.DataFrame:
        with session_scope() as session:
            findings = FindingRepository(session).search(
                server_id=filters.get("server_id", ""),
                severity=filters.get("severity", ""),
                ext=filters.get("ext", ""),
                mime_keyword=filters.get("mime_keyword", ""),
                path_keyword=filters.get("path_keyword", ""),
            )
            scan_job_repository = ScanJobRepository(session)
            scan_job_map = {}
            rows = []
            for finding in findings:
                scan_job = scan_job_map.get(finding.scan_job_id)
                if scan_job is None:
                    scan_job = scan_job_repository.get_by_id(finding.scan_job_id)
                    scan_job_map[finding.scan_job_id] = scan_job
                row = _finding_to_dict(finding, scan_job)
                rows.append(row)

        df = pd.DataFrame(rows)
        if df.empty:
            return df
        if filters.get("reason_code"):
            df = df[df["reasons"].apply(lambda values: filters["reason_code"] in values)]
        if filters.get("pattern_code"):
            df = df[df["matched_patterns"].apply(lambda values: filters["pattern_code"] in values)]
        date_from = _parse_dt(filters.get("date_from"))
        if date_from is not None:
            df = df[pd.to_datetime(df["generated_at"], errors="coerce", utc=True) >= date_from]
        date_to = _parse_dt(filters.get("date_to"))
        if date_to is not None:
            df = df[pd.to_datetime(df["generated_at"], errors="coerce", utc=True) <= date_to]
        return df.reset_index(drop=True)

    def get_finding_detail(self, finding_id: str) -> dict | None:
        with session_scope() as session:
            finding = FindingRepository(session).get_by_id(finding_id)
            if finding is None:
                return None
            scan_job = ScanJobRepository(session).get_by_id(finding.scan_job_id)
            row = _finding_to_dict(finding, scan_job)
            if scan_job:
                row["stored_path"] = scan_job.report_stored_path or ""
                row["scan_started_at"] = scan_job.scan_started_at
            return row

    def ingest_report(
        self,
        report_bytes: bytes,
        file_name: str,
        *,
        server_id: str | None = None,
        policy_id: str | None = None,
        input_type: str | None = None,
        uploaded_by: str = "portal",
        original_path: str = "",
        auto_create_server: bool = True,
    ) -> dict:
        report = json.loads(report_bytes.decode("utf-8"))
        host = _normalize_host(report)
        findings = _normalize_list(report.get("findings"))
        roots = _normalize_roots(report)
        stats = report.get("stats", {}) or {}
        scanner_version = report.get("report_version", "unknown")
        resolved_input_type = input_type or _infer_input_type(report)
        severity_counter = Counter(
            [(finding.get("severity") or "unknown").lower() for finding in findings]
        )
        settings = load_settings()
        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        stored_path = settings.reports_dir / f"{uuid.uuid4().hex}_{Path(file_name or 'report.json').name}"
        stored_path.write_bytes(report_bytes)

        with session_scope() as session:
            server_repository = ServerRepository(session)
            scan_job_repository = ScanJobRepository(session)
            summary_repository = ScanResultRepository(session)
            finding_repository = FindingRepository(session)

            if not server_id:
                existing = None
                if host["hostname"]:
                    existing = server_repository.find_by_hostname(host["hostname"])
                if existing is None and host["primary_ip"]:
                    existing = server_repository.find_by_ip_address(host["primary_ip"])
                if existing is not None:
                    server = server_repository.save(_server_payload(_server_to_dict(existing), host))
                elif auto_create_server:
                    server = server_repository.save(_server_payload({}, host))
                else:
                    raise ValueError("A matching server was not found for the uploaded report.")
                server_id = server.id
            else:
                server = server_repository.get_by_id(server_id)
                if server is None:
                    raise ValueError(f"Server not found: {server_id}")

            if policy_id:
                policy = PolicyRepository(session).get_by_id(policy_id)
                if policy is None:
                    raise ValueError(f"Policy not found: {policy_id}")

            scan_job_repository.clear_latest_flag_for_server(server_id)
            now = utcnow()
            scan_job = scan_job_repository.add(
                ScanJob(
                    server_id=server_id,
                    policy_id=policy_id,
                    report_file_name=file_name,
                    report_original_path=original_path or None,
                    report_stored_path=str(stored_path),
                    scanner_version=scanner_version,
                    input_type=resolved_input_type,
                    uploaded_by=uploaded_by,
                    uploaded_at=now,
                    scan_started_at=_parse_dt(report.get("scan_started_at")),
                    scan_finished_at=_parse_dt(report.get("generated_at")),
                    generated_at=_parse_dt(report.get("generated_at")),
                    host_hostname=host["hostname"] or None,
                    host_primary_ip=host["primary_ip"] or None,
                    host_os_type=host["os_type"] or None,
                    host_os_name=host["os_name"] or None,
                    host_platform=host["platform"] or None,
                    latest_for_server=True,
                    active_rules_json=json.dumps(report.get("active_rules", []), ensure_ascii=False),
                    config_json=json.dumps(report.get("config", {}), ensure_ascii=False),
                    created_at=now,
                    updated_at=now,
                )
            )
            summary_repository.add(
                ScanResultSummary(
                    scan_job_id=scan_job.id,
                    findings_count=int(stats.get("findings_count", len(findings)) or 0),
                    roots_count=int(stats.get("roots_count", len(roots)) or 0),
                    scanned_files=int(stats.get("scanned_files", 0) or 0),
                    severity_summary_json=json.dumps(dict(severity_counter), ensure_ascii=False),
                    roots_json=json.dumps(
                        [
                            {
                                "root_path": root.get("path", ""),
                                "real_path": root.get("real_path", ""),
                                "source_type": root.get("source", ""),
                            }
                            for root in roots
                        ],
                        ensure_ascii=False,
                    ),
                    raw_summary_json=json.dumps(
                        {
                            "host": host,
                            "findings_count": stats.get("findings_count", len(findings)),
                            "roots_count": stats.get("roots_count", len(roots)),
                        },
                        ensure_ascii=False,
                    ),
                    created_at=now,
                    updated_at=now,
                )
            )

            finding_rows = []
            for finding in findings:
                finding_rows.append(
                    ScanFinding(
                        scan_job_id=scan_job.id,
                        server_id=server_id,
                        path=str(finding.get("path", "")),
                        real_path=str(finding.get("real_path", "")) or None,
                        root_matched=str(finding.get("root_matched", "")) or None,
                        root_source=str(finding.get("root_source", "")) or None,
                        severity=(finding.get("severity") or "unknown").lower(),
                        size_bytes=finding.get("size_bytes"),
                        mod_time=_parse_dt(finding.get("mod_time")),
                        perm=str(finding.get("perm", "")) or None,
                        ext=str(finding.get("ext", "")) or None,
                        mime_sniff=str(finding.get("mime_sniff", "")) or None,
                        sha256=str(finding.get("sha256", "")) or None,
                        url_exposure_heuristic=str(finding.get("url_exposure_heuristic", "")) or None,
                        reasons_json=_json_dumps(_normalize_list(finding.get("reasons"))),
                        matched_patterns_json=_json_dumps(
                            _normalize_list(finding.get("matched_patterns"))
                        ),
                        evidence_masked_json=_json_dumps(
                            _normalize_list(finding.get("evidence_masked"))
                        ),
                        content_flags_json=_json_dumps(
                            _normalize_list(finding.get("content_flags"))
                        ),
                        created_at=now,
                        updated_at=now,
                    )
                )
            finding_repository.add_all(finding_rows)

            return {
                "scan_run_id": scan_job.id,
                "server_id": server_id,
                "stored_path": str(stored_path),
                "findings_count": len(findings),
                "host": host,
            }
