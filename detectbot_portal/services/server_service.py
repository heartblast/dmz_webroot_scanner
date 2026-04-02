from __future__ import annotations

import pandas as pd

from db.factory import session_scope
from db.models import ServerInventory
from repositories.server_repository import ServerRepository


def _server_to_dict(server: ServerInventory) -> dict:
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


class ServerService:
    def list_servers_df(
        self,
        *,
        keyword: str = "",
        environment: str = "",
        zone: str = "",
        active_only: bool = False,
    ) -> pd.DataFrame:
        with session_scope() as session:
            servers = ServerRepository(session).list_servers(
                keyword=keyword,
                environment=environment,
                zone=zone,
                active_only=active_only,
            )
            return pd.DataFrame([_server_to_dict(server) for server in servers])

    def get_server(self, server_id: str) -> dict | None:
        with session_scope() as session:
            server = ServerRepository(session).get_by_id(server_id)
            return _server_to_dict(server) if server else None

    def save_server(self, payload: dict) -> str:
        with session_scope() as session:
            server = ServerRepository(session).save(payload)
            return server.id

    def delete_server(self, server_id: str) -> bool:
        with session_scope() as session:
            return ServerRepository(session).delete(server_id)

    def find_server_by_hostname(self, hostname: str) -> dict | None:
        with session_scope() as session:
            server = ServerRepository(session).find_by_hostname(hostname)
            return _server_to_dict(server) if server else None

    def find_server_by_ip_address(self, ip_address: str) -> dict | None:
        with session_scope() as session:
            server = ServerRepository(session).find_by_ip_address(ip_address)
            return _server_to_dict(server) if server else None
