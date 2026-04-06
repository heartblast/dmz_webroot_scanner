import streamlit as st

from config.crypto import ENCRYPTION_KEY_ENV, SettingsCryptoError
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from services.settings_service import SettingsService


st.set_page_config(page_title="DetectBot Portal - Settings", page_icon="ST", layout="wide")

settings = load_settings()
settings_service = SettingsService()
editor_state = settings_service.load_editor_state()
render_portal_sidebar(settings)

st.title("Settings")
st.caption("관리자용 설정 UI입니다. YAML 기반 설정을 조회/수정하고 PostgreSQL 비밀번호는 암호화해서 저장합니다.")

st.info(
    f"Encryption key env: `{ENCRYPTION_KEY_ENV}`. "
    "키가 없으면 PostgreSQL 비밀번호 저장/복호화가 실패합니다."
)

if editor_state.get("config_error"):
    st.warning(editor_state["config_error"])

st.code(editor_state["config_path"], language="text")

with st.form("settings_editor_form"):
    st.markdown("### Database")
    backend = st.selectbox(
        "Backend",
        options=["sqlite", "postgresql"],
        index=["sqlite", "postgresql"].index(editor_state["database"]["backend"]),
    )

    st.markdown("#### SQLite")
    sqlite_path = st.text_input(
        "SQLite Path",
        value=editor_state["database"]["sqlite"]["path"],
    )
    sqlite_busy_timeout_ms = st.number_input(
        "SQLite Busy Timeout (ms)",
        min_value=100,
        value=int(editor_state["database"]["sqlite"]["busy_timeout_ms"]),
    )

    st.markdown("#### PostgreSQL")
    pg_host = st.text_input("Host", value=editor_state["database"]["postgresql"]["host"])
    pg_port = st.number_input(
        "Port",
        min_value=1,
        max_value=65535,
        value=int(editor_state["database"]["postgresql"]["port"]),
    )
    pg_database = st.text_input(
        "Database",
        value=editor_state["database"]["postgresql"]["database"],
    )
    pg_user = st.text_input("User", value=editor_state["database"]["postgresql"]["user"])
    st.caption(
        "Encrypted password is already configured."
        if editor_state["database"]["postgresql"]["password_configured"]
        else "No encrypted PostgreSQL password is stored yet."
    )
    pg_password = st.text_input(
        "Password",
        value="",
        type="password",
        help="Leave blank to keep the currently stored encrypted password.",
    )
    pg_pool_pre_ping = st.checkbox(
        "Pool Pre Ping",
        value=bool(editor_state["database"]["postgresql"]["pool_pre_ping"]),
    )
    pg_pool_size = st.number_input(
        "Pool Size",
        min_value=1,
        value=int(editor_state["database"]["postgresql"]["pool_size"]),
    )
    pg_max_overflow = st.number_input(
        "Max Overflow",
        min_value=0,
        value=int(editor_state["database"]["postgresql"]["max_overflow"]),
    )

    st.markdown("### App")
    reports_dir = st.text_input("Reports Directory", value=editor_state["app"]["reports_dir"])
    auto_seed_demo_data = st.checkbox(
        "Auto Seed Demo Data",
        value=bool(editor_state["app"]["auto_seed_demo_data"]),
    )

    submitted = st.form_submit_button("Save Settings", width="stretch")
    if submitted:
        try:
            settings_service.save_editor_state(
                {
                    "database": {
                        "backend": backend,
                        "sqlite": {
                            "path": sqlite_path,
                            "busy_timeout_ms": int(sqlite_busy_timeout_ms),
                        },
                        "postgresql": {
                            "host": pg_host,
                            "port": int(pg_port),
                            "database": pg_database,
                            "user": pg_user,
                            "password": pg_password,
                            "pool_pre_ping": bool(pg_pool_pre_ping),
                            "pool_size": int(pg_pool_size),
                            "max_overflow": int(pg_max_overflow),
                        },
                    },
                    "app": {
                        "reports_dir": reports_dir,
                        "auto_seed_demo_data": bool(auto_seed_demo_data),
                    },
                }
            )
            st.success("settings.yaml saved successfully.")
            st.rerun()
        except SettingsCryptoError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Failed to save settings: {exc}")
