from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.base import utcnow
from db.models import ServerInventory


class ServerRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_servers(
        self,
        *,
        keyword: str = "",
        environment: str = "",
        zone: str = "",
        active_only: bool = False,
    ) -> list[ServerInventory]:
        stmt = select(ServerInventory)
        if keyword:
            like = f"%{keyword.strip().lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(ServerInventory.server_name).like(like),
                    func.lower(func.coalesce(ServerInventory.hostname, "")).like(like),
                    func.lower(func.coalesce(ServerInventory.ip_address, "")).like(like),
                    func.lower(func.coalesce(ServerInventory.service_name, "")).like(like),
                )
            )
        if environment:
            stmt = stmt.where(ServerInventory.environment == environment)
        if zone:
            stmt = stmt.where(ServerInventory.zone == zone)
        if active_only:
            stmt = stmt.where(ServerInventory.is_active.is_(True))
        stmt = stmt.order_by(
            ServerInventory.is_active.desc(),
            ServerInventory.criticality.asc(),
            ServerInventory.server_name.asc(),
        )
        return list(self.session.scalars(stmt))

    def get_by_id(self, server_id: str) -> ServerInventory | None:
        return self.session.get(ServerInventory, server_id)

    def find_by_hostname(self, hostname: str) -> ServerInventory | None:
        if not hostname:
            return None
        stmt = select(ServerInventory).where(
            func.lower(func.coalesce(ServerInventory.hostname, "")) == hostname.strip().lower()
        )
        return self.session.scalar(stmt)

    def find_by_ip_address(self, ip_address: str) -> ServerInventory | None:
        if not ip_address:
            return None
        stmt = select(ServerInventory).where(ServerInventory.ip_address == ip_address.strip())
        return self.session.scalar(stmt)

    def save(self, payload: dict) -> ServerInventory:
        server = self.get_by_id(payload.get("id", "")) if payload.get("id") else None
        now = utcnow()
        if server is None:
            server = ServerInventory(created_at=now)
            self.session.add(server)
        server.server_name = str(payload.get("server_name", "")).strip()
        server.hostname = str(payload.get("hostname", "")).strip() or None
        server.ip_address = str(payload.get("ip_address", "")).strip() or None
        server.environment = str(payload.get("environment", "unknown")).strip() or "unknown"
        server.zone = str(payload.get("zone", "unknown")).strip() or "unknown"
        server.os_type = str(payload.get("os_type", "unknown")).strip() or "unknown"
        server.os_name = str(payload.get("os_name", "")).strip() or None
        server.os_version = str(payload.get("os_version", "")).strip() or None
        server.platform = str(payload.get("platform", "")).strip() or None
        server.web_server_type = (
            str(payload.get("web_server_type", "unknown")).strip() or "unknown"
        )
        server.service_name = str(payload.get("service_name", "")).strip() or None
        server.criticality = str(payload.get("criticality", "medium")).strip() or "medium"
        server.owner_name = str(payload.get("owner_name", "")).strip() or None
        server.upload_enabled = bool(payload.get("upload_enabled", True))
        server.is_active = bool(payload.get("is_active", True))
        server.notes = str(payload.get("notes", "")).strip() or None
        server.updated_at = now
        self.session.flush()
        return server

    def delete(self, server_id: str) -> bool:
        server = self.get_by_id(server_id)
        if server is None:
            return False
        self.session.delete(server)
        self.session.flush()
        return True
