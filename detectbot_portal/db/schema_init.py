from __future__ import annotations

from sqlalchemy import select

from config.settings import load_settings
from db.base import utcnow
from db.factory import get_engine, session_scope
from db.models import AppSetting
from db.models import Base


SCHEMA_VERSION = "2026-04-02"


def initialize_schema() -> None:
    settings = load_settings()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=get_engine())
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
