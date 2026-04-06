import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.navigation import render_portal_sidebar
from lib.ui import dataframe_or_info, format_timestamp_columns, render_metric_cards, render_portal_header
from services.dashboard_service import DashboardService


st.set_page_config(page_title="DetectBot 포털", page_icon="DB", layout="wide")

settings = load_settings()
bootstrap_portal(seed_demo_data=settings.auto_seed_demo_data)
dashboard_service = DashboardService()


def build_home_recent_runs_display_df(df):
    if df is None or df.empty:
        return df

    display = df.copy()
    display["서버명"] = display["server_name"].fillna("")
    display["호스트명"] = display["host_hostname"].fillna(display.get("hostname", "")).fillna("")
    display["IP"] = display["host_primary_ip"].fillna(display.get("ip_address", "")).fillna("")
    display["입력 유형"] = display["input_type"].fillna("")
    display["정책명"] = display["policy_name"].fillna("")
    display["탐지 건수"] = display["findings_count"].fillna(0).astype(int)
    display["스캔 시각"] = display["generated_at"].fillna(display.get("scan_started_at", "")).fillna("")
    display["리포트 파일명"] = display["file_name"].fillna("")
    return display[
        [
            "서버명",
            "호스트명",
            "IP",
            "입력 유형",
            "정책명",
            "탐지 건수",
            "스캔 시각",
            "리포트 파일명",
        ]
    ]


def build_reason_display_df(df):
    if df is None or df.empty:
        return df
    display = df.copy()
    display["사유 코드"] = display["reason_code"]
    display["의미"] = display["meaning"]
    display["건수"] = display["count"]
    return display[["사유 코드", "의미", "건수"]]


def build_pattern_display_df(df):
    if df is None or df.empty:
        return df
    display = df.copy()
    display["패턴 코드"] = display["pattern_code"]
    display["의미"] = display["meaning"]
    display["건수"] = display["count"]
    return display[["패턴 코드", "의미", "건수"]]


render_portal_sidebar(settings)

render_portal_header(
    "DetectBot 포털",
    "최근 업로드 리포트와 탐지 현황을 한눈에 확인하고, 좌측 메뉴에서 서버, Findings, 리포트 이력 화면으로 이동할 수 있습니다.",
)

if settings.config_error:
    st.warning(f"설정 경고: {settings.config_error}")

st.info("이 화면은 운영 현황을 빠르게 파악하는 첫 화면입니다. 핵심 지표를 확인한 뒤 필요한 상세 화면으로 이동해 주세요.")

metrics = dashboard_service.get_dashboard_metrics()
render_metric_cards(metrics)

recent_runs_df = format_timestamp_columns(
    dashboard_service.recent_scan_runs_df(limit=10),
    ["scan_started_at", "generated_at", "uploaded_at"],
)
reason_df = dashboard_service.top_reason_counts_df(limit=10)
pattern_df = dashboard_service.top_pattern_counts_df(limit=10)

recent_runs_display_df = build_home_recent_runs_display_df(recent_runs_df)
reason_display_df = build_reason_display_df(reason_df)
pattern_display_df = build_pattern_display_df(pattern_df)

left, right = st.columns((1.25, 1))
with left:
    st.markdown("### 최근 스캔 이력")
    dataframe_or_info(recent_runs_display_df, "아직 표시할 스캔 이력이 없습니다.")

with right:
    st.markdown("### 주요 사유 코드")
    dataframe_or_info(reason_display_df, "아직 사유 코드 통계가 없습니다.")
    if reason_df is not None and not reason_df.empty:
        st.bar_chart(reason_df.set_index("reason_code")["count"])

st.markdown("### 주요 패턴 코드")
chart_col, table_col = st.columns((1.1, 1))
with chart_col:
    if pattern_df is not None and not pattern_df.empty:
        st.bar_chart(pattern_df.set_index("pattern_code")["count"])
    else:
        st.info("아직 패턴 통계가 없습니다.")
with table_col:
    dataframe_or_info(pattern_display_df, "아직 패턴 통계가 없습니다.")
