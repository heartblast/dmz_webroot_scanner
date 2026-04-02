from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.base import utcnow
from db.models import ScanPolicy


class PolicyRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_policies(self, *, active_only: bool = False) -> list[ScanPolicy]:
        stmt = select(ScanPolicy).order_by(ScanPolicy.policy_name.asc())
        if active_only:
            stmt = stmt.where(ScanPolicy.is_active.is_(True))
        return list(self.session.scalars(stmt))

    def get_by_id(self, policy_id: str) -> ScanPolicy | None:
        return self.session.get(ScanPolicy, policy_id)

    def get_first(self) -> ScanPolicy | None:
        return self.session.scalar(select(ScanPolicy).order_by(ScanPolicy.created_at.asc()).limit(1))

    def save(self, payload: dict) -> ScanPolicy:
        policy = self.get_by_id(payload.get("id", "")) if payload.get("id") else None
        now = utcnow()
        if policy is None:
            policy = ScanPolicy(created_at=now)
            self.session.add(policy)
        policy.policy_name = str(payload.get("policy_name", "")).strip()
        policy.description = str(payload.get("description", "")).strip() or None
        policy.policy_mode = str(payload.get("policy_mode", "balanced")).strip() or "balanced"
        policy.policy_version = str(payload.get("policy_version", "v1")).strip() or "v1"
        policy.allow_mime_json = payload["allow_mime_json"]
        policy.allow_ext_json = payload["allow_ext_json"]
        policy.exclude_paths_json = payload["exclude_paths_json"]
        policy.max_depth = int(payload.get("max_depth", 10))
        policy.newer_than_hours = int(payload.get("newer_than_hours", 0))
        policy.size_threshold_mb = int(payload.get("size_threshold_mb", 100))
        policy.compute_hash = bool(payload.get("compute_hash", False))
        policy.content_scan_enabled = bool(payload.get("content_scan_enabled", True))
        policy.content_max_kb = int(payload.get("content_max_kb", 1024))
        policy.pii_scan_enabled = bool(payload.get("pii_scan_enabled", True))
        policy.custom_config_json = str(payload.get("custom_config_json", "")).strip() or None
        policy.is_active = bool(payload.get("is_active", True))
        policy.updated_at = now
        self.session.flush()
        return policy

    def delete(self, policy_id: str) -> bool:
        policy = self.get_by_id(policy_id)
        if policy is None:
            return False
        self.session.delete(policy)
        self.session.flush()
        return True
