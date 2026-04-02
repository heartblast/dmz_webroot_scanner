from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from db.base import utcnow
from db.models import ScanJob


class ScanJobRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_scan_jobs(self, *, server_id: str = "", limit: int = 200) -> list[ScanJob]:
        stmt = (
            select(ScanJob)
            .options(
                selectinload(ScanJob.server),
                selectinload(ScanJob.policy),
                selectinload(ScanJob.result_summary),
            )
            .order_by(desc(ScanJob.generated_at), desc(ScanJob.created_at))
            .limit(limit)
        )
        if server_id:
            stmt = stmt.where(ScanJob.server_id == server_id)
        return list(self.session.scalars(stmt))

    def get_by_id(self, scan_job_id: str) -> ScanJob | None:
        stmt = (
            select(ScanJob)
            .where(ScanJob.id == scan_job_id)
            .options(
                selectinload(ScanJob.server),
                selectinload(ScanJob.policy),
                selectinload(ScanJob.result_summary),
                selectinload(ScanJob.findings),
            )
        )
        return self.session.scalar(stmt)

    def clear_latest_flag_for_server(self, server_id: str) -> None:
        if not server_id:
            return
        for scan_job in self.session.scalars(select(ScanJob).where(ScanJob.server_id == server_id)):
            scan_job.latest_for_server = False
            scan_job.updated_at = utcnow()

    def add(self, scan_job: ScanJob) -> ScanJob:
        self.session.add(scan_job)
        self.session.flush()
        return scan_job
