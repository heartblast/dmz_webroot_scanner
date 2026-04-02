from __future__ import annotations

from collections import Counter

import pandas as pd

from db.factory import session_scope
from lib.codebook import get_pattern_meaning, get_reason_meaning
from repositories.finding_repository import FindingRepository
from repositories.scan_job_repository import ScanJobRepository
from repositories.server_repository import ServerRepository
from services.scan_service import _json_loads, _scan_job_to_dict


class DashboardService:
    def get_dashboard_metrics(self) -> dict:
        with session_scope() as session:
            servers = ServerRepository(session).list_servers(active_only=True)
            scan_jobs = ScanJobRepository(session).list_scan_jobs(limit=1000)
            findings = FindingRepository(session).search()
        recent_scanned_servers = {scan_job.server_id for scan_job in scan_jobs if scan_job.server_id}
        severity_counter = Counter(
            [finding.severity for finding in findings if getattr(finding, "severity", None)]
        )
        return {
            "servers_total": len(servers),
            "recent_scanned_servers": len(recent_scanned_servers),
            "findings_total": len(findings),
            "severity_counts": dict(severity_counter),
        }

    def recent_scan_runs_df(self, *, limit: int = 10) -> pd.DataFrame:
        with session_scope() as session:
            scan_jobs = ScanJobRepository(session).list_scan_jobs(limit=limit)
            return pd.DataFrame([_scan_job_to_dict(scan_job) for scan_job in scan_jobs])

    def top_reason_counts_df(self, *, limit: int = 10) -> pd.DataFrame:
        with session_scope() as session:
            findings = FindingRepository(session).search()
        counter = Counter()
        for finding in findings:
            counter.update(_json_loads(finding.reasons_json, []))
        return pd.DataFrame(
            [
                {"reason_code": code, "meaning": get_reason_meaning(code), "count": count}
                for code, count in counter.most_common(limit)
            ]
        )

    def top_pattern_counts_df(self, *, limit: int = 10) -> pd.DataFrame:
        with session_scope() as session:
            findings = FindingRepository(session).search()
        counter = Counter()
        for finding in findings:
            counter.update(_json_loads(finding.matched_patterns_json, []))
        return pd.DataFrame(
            [
                {"pattern_code": code, "meaning": get_pattern_meaning(code), "count": count}
                for code, count in counter.most_common(limit)
            ]
        )
