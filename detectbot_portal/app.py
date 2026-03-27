import streamlit as st

from lib.db import DB_PATH, init_db
from lib.repository import (
    dashboard_metrics,
    recent_scan_runs,
    top_pattern_counts,
    top_reason_counts,
)
from lib.seed import bootstrap_demo_data
from lib.ui import (
    dataframe_or_info,
    format_timestamp_columns,
    render_metric_cards,
    render_portal_header,
)


st.set_page_config(
    page_title="DetectBot Portal",
    page_icon="🛡️",
    layout="wide",
)

init_db()
bootstrap_demo_data()

render_portal_header(
    "DetectBot Portal",
    "서버 자산, 점검 결과, 탐지 상세, 정책 설정을 추적 관리하는 1단계 운영 포털입니다.",
)

with st.sidebar:
    st.markdown("### DetectBot Portal")
    st.caption("운영 포털 MVP")
    st.write(f"DB 파일: `{DB_PATH}`")
    st.page_link("app.py", label="대시보드")
    st.page_link("pages/01_server_inventory.py", label="서버 인벤토리")
    st.page_link("pages/02_scan_results.py", label="점검 결과 관리")
    st.page_link("pages/03_findings.py", label="탐지 상세 조회")
    st.page_link("pages/04_policies.py", label="정책 / 옵션 관리")
    st.page_link("pages/05_detection_report_viewer.py", label="탐지결과조회")

metrics = dashboard_metrics()
render_metric_cards(metrics)

st.markdown("## 운영 현황")
left, right = st.columns((1.2, 1))

with left:
    st.markdown("### 최근 점검 이력")
    runs_df = format_timestamp_columns(
        recent_scan_runs(limit=10),
        ["scan_started_at", "generated_at"],
    )
    dataframe_or_info(runs_df, "등록된 점검 이력이 없습니다.")

with right:
    st.markdown("### 최근 많이 발생한 탐지 사유")
    reasons_df = top_reason_counts(limit=10)
    dataframe_or_info(reasons_df, "탐지 사유 집계가 없습니다.")
    if reasons_df is not None and not reasons_df.empty:
        st.bar_chart(reasons_df.set_index("reason_code")["count"])

st.markdown("## 패턴 추이 기초 지표")
patterns_df = top_pattern_counts(limit=10)
chart_col, table_col = st.columns((1, 1))
with chart_col:
    st.markdown("### 패턴 Top N")
    if patterns_df is not None and not patterns_df.empty:
        st.bar_chart(patterns_df.set_index("pattern_code")["count"])
    else:
        st.info("패턴 집계가 없습니다.")
with table_col:
    st.markdown("### 패턴 상세")
    dataframe_or_info(patterns_df, "패턴 집계가 없습니다.")

st.markdown("## 2단계 확장 메모")
st.info(
    "현재 1단계는 DuckDB 기반 추적 관리 MVP입니다. 2단계에서는 일자별 추이 테이블, "
    "서버/정책 기준 비교, 조치상태 워크플로우, 외부 수집 파이프라인 연계를 확장할 수 있도록 "
    "스캔 실행 이력과 개별 탐지 이력을 분리 저장하도록 설계했습니다."
)
