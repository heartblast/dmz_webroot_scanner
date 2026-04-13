import streamlit as st

from auth.session import require_login
from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.ui import dataframe_or_info, format_timestamp_columns, render_metric_cards, render_portal_header
from services.dashboard_service import DashboardService


st.set_page_config(page_title="DetectBot Portal - Dashboard", page_icon="DS", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
current_user = require_login()
render_portal_sidebar(settings, current_user)
dashboard_service = DashboardService()

render_portal_header(
    "Dashboard",
    "최근 스캔 결과 요약과 severity/reason_code 통계를 보여줍니다.",
)

metrics = dashboard_service.get_dashboard_metrics()
render_metric_cards(metrics)

recent_runs_df = format_timestamp_columns(
    dashboard_service.recent_scan_runs_df(limit=20),
    ["scan_started_at", "generated_at", "uploaded_at"],
)
reason_df = dashboard_service.top_reason_counts_df(limit=10)
pattern_df = dashboard_service.top_pattern_counts_df(limit=10)

st.markdown("### Recent Scan Summary")
dataframe_or_info(recent_runs_df, "No scan runs available.")

charts_left, charts_right = st.columns(2)
with charts_left:
    st.markdown("### Severity Summary")
    severity_counts = metrics.get("severity_counts", {})
    if severity_counts:
        st.bar_chart(severity_counts)
    else:
        st.info("No severity statistics yet.")
with charts_right:
    st.markdown("### Reason Code Summary")
    dataframe_or_info(reason_df, "No reason code statistics yet.")
    if reason_df is not None and not reason_df.empty:
        st.bar_chart(reason_df.set_index("reason_code")["count"])

st.markdown("### Pattern Summary")
dataframe_or_info(pattern_df, "No pattern statistics yet.")
if pattern_df is not None and not pattern_df.empty:
    st.bar_chart(pattern_df.set_index("pattern_code")["count"])
