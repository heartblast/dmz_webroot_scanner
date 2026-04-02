from __future__ import annotations

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from db.models import ScanFinding


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_by_scan_job_id(self, scan_job_id: str) -> list[ScanFinding]:
        stmt = (
            select(ScanFinding)
            .where(ScanFinding.scan_job_id == scan_job_id)
            .order_by(ScanFinding.severity.asc(), ScanFinding.path.asc())
        )
        return list(self.session.scalars(stmt))

    def search(
        self,
        *,
        server_id: str = "",
        severity: str = "",
        ext: str = "",
        mime_keyword: str = "",
        path_keyword: str = "",
    ) -> list[ScanFinding]:
        stmt = select(ScanFinding).order_by(desc(ScanFinding.created_at), ScanFinding.path.asc())
        if server_id:
            stmt = stmt.where(ScanFinding.server_id == server_id)
        if severity:
            stmt = stmt.where(ScanFinding.severity == severity)
        if ext:
            stmt = stmt.where(func.lower(func.coalesce(ScanFinding.ext, "")) == ext.lower())
        if mime_keyword:
            stmt = stmt.where(
                func.lower(func.coalesce(ScanFinding.mime_sniff, "")).like(f"%{mime_keyword.lower()}%")
            )
        if path_keyword:
            like = f"%{path_keyword.lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(func.coalesce(ScanFinding.path, "")).like(like),
                    func.lower(func.coalesce(ScanFinding.real_path, "")).like(like),
                )
            )
        return list(self.session.scalars(stmt))

    def get_by_id(self, finding_id: str) -> ScanFinding | None:
        return self.session.get(ScanFinding, finding_id)

    def add_all(self, findings: list[ScanFinding]) -> None:
        self.session.add_all(findings)
        self.session.flush()
