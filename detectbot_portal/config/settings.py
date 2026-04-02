from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from config.crypto import SettingsCryptoError, decrypt_secret


PORTAL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PORTAL_ROOT / "config" / "settings.yaml"
DEFAULT_SQLITE_PATH = PORTAL_ROOT / "data" / "detectbot_portal.sqlite3"
DEFAULT_REPORTS_DIR = PORTAL_ROOT / "data" / "reports"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return loaded if isinstance(loaded, dict) else {}


@dataclass(frozen=True)
class DatabaseSettings:
    backend: str
    sqlite_path: Path
    sqlite_busy_timeout_ms: int
    postgresql_host: str
    postgresql_port: int
    postgresql_database: str
    postgresql_user: str
    postgresql_password: str
    pool_pre_ping: bool
    pool_size: int
    max_overflow: int

    @property
    def sqlalchemy_url(self) -> str:
        if self.backend == "sqlite":
            return f"sqlite+pysqlite:///{self.sqlite_path.as_posix()}"
        if self.backend == "postgresql":
            return (
                "postgresql+psycopg://"
                f"{self.postgresql_user}:{self.postgresql_password}"
                f"@{self.postgresql_host}:{self.postgresql_port}/{self.postgresql_database}"
            )
        raise ValueError(f"Unsupported database backend: {self.backend}")


@dataclass(frozen=True)
class AppSettings:
    database: DatabaseSettings
    reports_dir: Path
    auto_seed_demo_data: bool
    config_error: str | None = None


def load_settings() -> AppSettings:
    defaults: dict[str, Any] = {
        "database": {
            "backend": "sqlite",
            "sqlite": {
                "path": str(DEFAULT_SQLITE_PATH),
                "busy_timeout_ms": 5000,
            },
            "postgresql": {
                "host": "localhost",
                "port": 5432,
                "database": "detectbot_portal",
                "user": "detectbot",
                "password": "",
                "password_enc": "",
                "pool_pre_ping": True,
                "pool_size": 5,
                "max_overflow": 10,
            },
        },
        "app": {
            "reports_dir": str(DEFAULT_REPORTS_DIR),
            "auto_seed_demo_data": True,
        },
    }

    config_path = Path(os.getenv("DETECTBOT_CONFIG_FILE", DEFAULT_CONFIG_PATH))
    merged = _deep_merge(defaults, _load_yaml_config(config_path))

    env_backend = os.getenv("DETECTBOT_DATABASE_BACKEND")
    if env_backend:
        merged["database"]["backend"] = env_backend

    env_sqlite_path = os.getenv("DETECTBOT_SQLITE_PATH")
    if env_sqlite_path:
        merged["database"]["sqlite"]["path"] = env_sqlite_path

    pg_config = merged["database"]["postgresql"]
    config_error: str | None = None
    password_from_yaml = str(pg_config.get("password", "") or "")
    password_enc = str(pg_config.get("password_enc", "") or "")
    if password_enc:
        try:
            password_from_yaml = decrypt_secret(password_enc)
        except SettingsCryptoError as exc:
            config_error = str(exc)
    pg_config["host"] = os.getenv("DETECTBOT_POSTGRES_HOST", pg_config["host"])
    pg_config["port"] = int(os.getenv("DETECTBOT_POSTGRES_PORT", pg_config["port"]))
    pg_config["database"] = os.getenv("DETECTBOT_POSTGRES_DB", pg_config["database"])
    pg_config["user"] = os.getenv("DETECTBOT_POSTGRES_USER", pg_config["user"])
    pg_config["password"] = os.getenv("DETECTBOT_POSTGRES_PASSWORD", password_from_yaml)
    pg_config["pool_pre_ping"] = str(
        os.getenv("DETECTBOT_POSTGRES_POOL_PRE_PING", pg_config["pool_pre_ping"])
    ).lower() in {"1", "true", "yes", "on"}
    pg_config["pool_size"] = int(os.getenv("DETECTBOT_POSTGRES_POOL_SIZE", pg_config["pool_size"]))
    pg_config["max_overflow"] = int(
        os.getenv("DETECTBOT_POSTGRES_MAX_OVERFLOW", pg_config["max_overflow"])
    )

    sqlite_config = merged["database"]["sqlite"]
    sqlite_path = Path(sqlite_config["path"])
    if not sqlite_path.is_absolute():
        sqlite_path = (PORTAL_ROOT / sqlite_path).resolve()

    reports_dir = Path(os.getenv("DETECTBOT_REPORTS_DIR", merged["app"]["reports_dir"]))
    if not reports_dir.is_absolute():
        reports_dir = (PORTAL_ROOT / reports_dir).resolve()

    database = DatabaseSettings(
        backend=str(merged["database"]["backend"]).strip().lower(),
        sqlite_path=sqlite_path,
        sqlite_busy_timeout_ms=int(sqlite_config["busy_timeout_ms"]),
        postgresql_host=str(pg_config["host"]),
        postgresql_port=int(pg_config["port"]),
        postgresql_database=str(pg_config["database"]),
        postgresql_user=str(pg_config["user"]),
        postgresql_password=str(pg_config["password"]),
        pool_pre_ping=bool(pg_config["pool_pre_ping"]),
        pool_size=int(pg_config["pool_size"]),
        max_overflow=int(pg_config["max_overflow"]),
    )
    return AppSettings(
        database=database,
        reports_dir=reports_dir,
        auto_seed_demo_data=str(
            os.getenv("DETECTBOT_AUTO_SEED_DEMO_DATA", merged["app"]["auto_seed_demo_data"])
        ).lower()
        in {"1", "true", "yes", "on"},
        config_error=config_error,
    )
