import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.ui import dataframe_or_info, format_timestamp_columns, render_metric_cards, render_portal_header
from services.dashboard_service import DashboardService


st.set_page_config(page_title="DetectBot Portal", page_icon="DB", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
dashboard_service = DashboardService()

render_portal_header(
    "DetectBot Portal",
    "SQLite/PostgreSQL 공용 DB 구조 위에서 서버 인벤토리, 스캔 결과, 정책, 대시보드를 함께 관리합니다.",
)

if settings.config_error:
    st.warning(f"Settings warning: {settings.config_error}")

with st.sidebar:
    st.markdown("### DetectBot Portal")
    st.caption(f"backend: `{settings.database.backend}`")
    st.page_link("app.py", label="Home")
    st.page_link("pages/01_server_inventory.py", label="Server Inventory")
    st.page_link("pages/02_scan_results.py", label="Scan Results")
    st.page_link("pages/03_scan_policies.py", label="Scan Policies")
    st.page_link("pages/04_dashboard.py", label="Dashboard")
    st.page_link("pages/05_detection_report_viewer.py", label="Report Viewer")
    st.page_link("pages/06_settings_admin.py", label="Settings")
    st.page_link("pages/07_option_generator.py", label="Option Generator")
    st.page_link("pages/08_scenario_generator.py", label="Scenario Generator")

metrics = dashboard_service.get_dashboard_metrics()
render_metric_cards(metrics)

recent_runs_df = format_timestamp_columns(
    dashboard_service.recent_scan_runs_df(limit=10),
    ["scan_started_at", "generated_at", "uploaded_at"],
)
reason_df = dashboard_service.top_reason_counts_df(limit=10)
pattern_df = dashboard_service.top_pattern_counts_df(limit=10)

left, right = st.columns((1.2, 1))
with left:
    st.markdown("### Recent Scan Runs")
    dataframe_or_info(recent_runs_df, "No scan history yet.")

with right:
    st.markdown("### Top Reason Codes")
    dataframe_or_info(reason_df, "No reason-code statistics yet.")
    if reason_df is not None and not reason_df.empty:
        st.bar_chart(reason_df.set_index("reason_code")["count"])

st.markdown("### Top Pattern Codes")
chart_col, table_col = st.columns(2)
with chart_col:
    if pattern_df is not None and not pattern_df.empty:
        st.bar_chart(pattern_df.set_index("pattern_code")["count"])
    else:
        st.info("No pattern statistics yet.")
with table_col:
    dataframe_or_info(pattern_df, "No pattern statistics yet.")
