from datetime import date, timedelta

import streamlit as st

from lib.db import init_db
from lib.repository import (
    get_finding_detail,
    list_code_options,
    list_servers,
    search_findings,
)
from lib.seed import bootstrap_demo_data
from lib.ui import dataframe_or_info, format_timestamp_columns, render_portal_header


st.set_page_config(
    page_title="DetectBot Portal - 탐지 상세 조회",
    page_icon="🛰️",
    layout="wide",
)
init_db()
bootstrap_demo_data()

render_portal_header(
    "탐지 상세 조회",
    "서버, 파일 경로, 확장자, MIME, 탐지사유, 패턴, 위험도, 기간 기준으로 탐지 결과를 검색합니다.",
)

servers_df = list_servers(active_only=False)
reason_codes_df = list_code_options("reason_code")
pattern_codes_df = list_code_options("pattern")

filter_row1 = st.columns(4)
with filter_row1[0]:
    server_id = st.selectbox(
        "서버명",
        options=[""]
        + (
            servers_df["id"].tolist()
            if servers_df is not None and not servers_df.empty
            else []
        ),
        format_func=lambda value: (
            "전체 서버"
            if not value
            else f"{servers_df.loc[servers_df['id'] == value, 'server_name'].iloc[0]}"
        ),
    )
with filter_row1[1]:
    path_keyword = st.text_input("파일 경로", placeholder="/var/www 또는 .env")
with filter_row1[2]:
    ext = st.text_input("확장자", placeholder=".php")
with filter_row1[3]:
    mime_keyword = st.text_input("MIME", placeholder="text/plain")

filter_row2 = st.columns(4)
with filter_row2[0]:
    reason_code = st.selectbox(
        "reason_code",
        options=[""]
        + (
            reason_codes_df["code"].tolist()
            if reason_codes_df is not None and not reason_codes_df.empty
            else []
        ),
        format_func=lambda value: (
            "전체 사유"
            if not value
            else f"{value} | {reason_codes_df.loc[reason_codes_df['code'] == value, 'meaning'].iloc[0]}"
        ),
    )
with filter_row2[1]:
    pattern_code = st.selectbox(
        "pattern",
        options=[""]
        + (
            pattern_codes_df["code"].tolist()
            if pattern_codes_df is not None and not pattern_codes_df.empty
            else []
        ),
        format_func=lambda value: (
            "전체 패턴"
            if not value
            else f"{value} | {pattern_codes_df.loc[pattern_codes_df['code'] == value, 'meaning'].iloc[0]}"
        ),
    )
with filter_row2[2]:
    severity = st.selectbox("위험도", ["", "critical", "high", "medium", "low", "unknown"])
with filter_row2[3]:
    days = st.selectbox("최근 기간", [7, 30, 90, 180, 365], index=1)

date_from = date.today() - timedelta(days=days)
date_to = date.today()

findings_df = format_timestamp_columns(
    search_findings(
        {
            "server_id": server_id,
            "path_keyword": path_keyword,
            "ext": ext,
            "mime_keyword": mime_keyword,
            "reason_code": reason_code,
            "pattern_code": pattern_code,
            "severity": severity,
            "date_from": date_from,
            "date_to": date_to,
        }
    ),
    ["generated_at", "mod_time"],
)

st.markdown("### 탐지 결과 목록")
dataframe_or_info(findings_df, "조건에 맞는 탐지 결과가 없습니다.")

if findings_df is not None and not findings_df.empty:
    selected_finding_id = st.selectbox(
        "상세 탐지 선택",
        options=findings_df["id"].tolist(),
        format_func=lambda value: (
            f"{findings_df.loc[findings_df['id'] == value, 'server_name'].iloc[0]} / "
            f"{findings_df.loc[findings_df['id'] == value, 'path'].iloc[0]}"
        ),
    )
    detail = get_finding_detail(selected_finding_id)
    if detail:
        st.markdown("### 탐지 상세")
        st.json(detail, expanded=False)
