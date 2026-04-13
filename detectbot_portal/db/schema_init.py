from __future__ import annotations

from sqlalchemy import inspect, select, text

from config.settings import load_settings
from db.base import utcnow
from db.factory import get_engine, session_scope
from db.models import AppSetting
from db.models import Base


SCHEMA_VERSION = "2026-04-13-user-profile"


def _ensure_portal_user_profile_columns() -> None:
    engine = get_engine()
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if "portal_user" not in table_names:
        return

    existing_columns = {column["name"] for column in inspector.get_columns("portal_user")}
    columns = {
        "full_name": "VARCHAR(255)",
        "department": "VARCHAR(255)",
        "email": "VARCHAR(255)",
    }
    missing_columns = [name for name in columns if name not in existing_columns]
    if not missing_columns:
        return

    with engine.begin() as connection:
        for column_name in missing_columns:
            connection.execute(
                text(f"ALTER TABLE portal_user ADD COLUMN {column_name} {columns[column_name]}")
            )


def initialize_schema() -> None:
    settings = load_settings()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=get_engine())
    _ensure_portal_user_profile_columns()
    with session_scope() as session:
        schema_setting = session.scalar(
            select(AppSetting).where(AppSetting.setting_key == "schema_version")
        )
        if schema_setting is None:
            schema_setting = AppSetting(
                setting_key="schema_version",
                setting_value=SCHEMA_VERSION,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            session.add(schema_setting)
        else:
            schema_setting.setting_value = SCHEMA_VERSION
            schema_setting.updated_at = utcnow()
