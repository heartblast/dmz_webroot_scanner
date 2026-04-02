from __future__ import annotations

import json

import pandas as pd

from db.factory import session_scope
from db.models import ScanPolicy
from lib.models import DEFAULT_ALLOW_EXT, DEFAULT_ALLOW_MIME, DEFAULT_EXCLUDE_PATHS
from repositories.policy_repository import PolicyRepository


def _json_loads(value: str | None, fallback):
    if not value:
        return list(fallback)
    try:
        return json.loads(value)
    except Exception:
        return list(fallback)


def _json_dumps(value) -> str:
    return json.dumps(value or [], ensure_ascii=False)


def _policy_to_dict(policy: ScanPolicy) -> dict:
    return {
        "id": policy.id,
        "policy_name": policy.policy_name,
        "description": policy.description or "",
        "policy_mode": policy.policy_mode,
        "policy_version": policy.policy_version,
        "allow_mime": _json_loads(policy.allow_mime_json, DEFAULT_ALLOW_MIME),
        "allow_ext": _json_loads(policy.allow_ext_json, DEFAULT_ALLOW_EXT),
        "exclude_paths": _json_loads(policy.exclude_paths_json, DEFAULT_EXCLUDE_PATHS),
        "max_depth": policy.max_depth,
        "newer_than_hours": policy.newer_than_hours,
        "size_threshold_mb": policy.size_threshold_mb,
        "compute_hash": bool(policy.compute_hash),
        "content_scan_enabled": bool(policy.content_scan_enabled),
        "content_max_kb": policy.content_max_kb,
        "pii_scan_enabled": bool(policy.pii_scan_enabled),
        "custom_config_json": policy.custom_config_json or "",
        "is_active": bool(policy.is_active),
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }


class PolicyService:
    def list_policies_df(self, *, active_only: bool = False) -> pd.DataFrame:
        with session_scope() as session:
            policies = PolicyRepository(session).list_policies(active_only=active_only)
            return pd.DataFrame([_policy_to_dict(policy) for policy in policies])

    def get_policy(self, policy_id: str) -> dict | None:
        with session_scope() as session:
            policy = PolicyRepository(session).get_by_id(policy_id)
            return _policy_to_dict(policy) if policy else None

    def save_policy(self, payload: dict) -> str:
        with session_scope() as session:
            prepared = dict(payload)
            prepared["allow_mime_json"] = _json_dumps(payload.get("allow_mime"))
            prepared["allow_ext_json"] = _json_dumps(payload.get("allow_ext"))
            prepared["exclude_paths_json"] = _json_dumps(payload.get("exclude_paths"))
            policy = PolicyRepository(session).save(prepared)
            return policy.id

    def delete_policy(self, policy_id: str) -> bool:
        with session_scope() as session:
            return PolicyRepository(session).delete(policy_id)

    def ensure_default_policy(self) -> str:
        with session_scope() as session:
            repository = PolicyRepository(session)
            existing = repository.get_first()
            if existing:
                return existing.id
            policy = repository.save(
                {
                    "policy_name": "Balanced Default",
                    "description": "Default scan policy for DetectBot Portal",
                    "policy_mode": "balanced",
                    "policy_version": "v1",
                    "allow_mime_json": _json_dumps(DEFAULT_ALLOW_MIME),
                    "allow_ext_json": _json_dumps(DEFAULT_ALLOW_EXT),
                    "exclude_paths_json": _json_dumps(DEFAULT_EXCLUDE_PATHS),
                    "max_depth": 10,
                    "newer_than_hours": 0,
                    "size_threshold_mb": 100,
                    "compute_hash": True,
                    "content_scan_enabled": True,
                    "content_max_kb": 1024,
                    "pii_scan_enabled": True,
                    "custom_config_json": "",
                    "is_active": True,
                }
            )
            return policy.id
