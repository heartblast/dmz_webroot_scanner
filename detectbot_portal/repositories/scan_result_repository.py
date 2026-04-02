from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import ScanResultSummary


class ScanResultRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_scan_job_id(self, scan_job_id: str) -> ScanResultSummary | None:
        stmt = select(ScanResultSummary).where(ScanResultSummary.scan_job_id == scan_job_id)
        return self.session.scalar(stmt)

    def add(self, summary: ScanResultSummary) -> ScanResultSummary:
        self.session.add(summary)
        self.session.flush()
        return summary
