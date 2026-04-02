from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from config.crypto import SettingsCryptoError, encrypt_secret
from config.settings import DEFAULT_CONFIG_PATH, load_settings


class SettingsService:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or Path(os.getenv("DETECTBOT_CONFIG_FILE", DEFAULT_CONFIG_PATH))

    def load_editor_state(self) -> dict[str, Any]:
        raw = self._read_yaml()
        settings = load_settings()
        database = raw.get("database", {})
        postgresql = database.get("postgresql", {})
        editor_state = {
            "database": {
                "backend": database.get("backend", settings.database.backend),
                "sqlite": {
                    "path": database.get("sqlite", {}).get(
                        "path", str(settings.database.sqlite_path)
                    ),
                    "busy_timeout_ms": database.get("sqlite", {}).get(
                        "busy_timeout_ms", settings.database.sqlite_busy_timeout_ms
                    ),
                },
                "postgresql": {
                    "host": postgresql.get("host", settings.database.postgresql_host),
                    "port": postgresql.get("port", settings.database.postgresql_port),
                    "database": postgresql.get(
                        "database", settings.database.postgresql_database
                    ),
                    "user": postgresql.get("user", settings.database.postgresql_user),
                    "password": "",
                    "password_configured": bool(
                        postgresql.get("password_enc") or postgresql.get("password")
                    ),
                    "pool_pre_ping": postgresql.get(
                        "pool_pre_ping", settings.database.pool_pre_ping
                    ),
                    "pool_size": postgresql.get("pool_size", settings.database.pool_size),
                    "max_overflow": postgresql.get(
                        "max_overflow", settings.database.max_overflow
                    ),
                },
            },
            "app": {
                "reports_dir": raw.get("app", {}).get("reports_dir", str(settings.reports_dir)),
                "auto_seed_demo_data": raw.get("app", {}).get(
                    "auto_seed_demo_data", settings.auto_seed_demo_data
                ),
            },
            "config_path": str(self.config_path),
            "config_error": settings.config_error,
        }
        return editor_state

    def save_editor_state(self, payload: dict[str, Any]) -> None:
        document = self._read_yaml()
        database = document.setdefault("database", {})
        database["backend"] = payload["database"]["backend"]
        database["sqlite"] = {
            "path": payload["database"]["sqlite"]["path"],
            "busy_timeout_ms": int(payload["database"]["sqlite"]["busy_timeout_ms"]),
        }

        pg_payload = payload["database"]["postgresql"]
        existing_pg = database.get("postgresql", {})
        postgresql = {
            "host": pg_payload["host"],
            "port": int(pg_payload["port"]),
            "database": pg_payload["database"],
            "user": pg_payload["user"],
            "pool_pre_ping": bool(pg_payload["pool_pre_ping"]),
            "pool_size": int(pg_payload["pool_size"]),
            "max_overflow": int(pg_payload["max_overflow"]),
        }

        password = str(pg_payload.get("password", "") or "")
        if password:
            postgresql["password_enc"] = encrypt_secret(password)
        elif existing_pg.get("password_enc"):
            postgresql["password_enc"] = existing_pg["password_enc"]
        elif existing_pg.get("password"):
            postgresql["password_enc"] = encrypt_secret(str(existing_pg["password"]))

        database["postgresql"] = postgresql
        database["postgresql"].pop("password", None)

        document["app"] = {
            "reports_dir": payload["app"]["reports_dir"],
            "auto_seed_demo_data": bool(payload["app"]["auto_seed_demo_data"]),
        }
        self._write_yaml(document)

    def _read_yaml(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            return {}
        loaded = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        return loaded if isinstance(loaded, dict) else {}

    def _write_yaml(self, document: dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            yaml.safe_dump(document, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
