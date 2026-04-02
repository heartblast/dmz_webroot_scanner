from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from bootstrap import bootstrap_portal
from config.settings import load_settings
from lib.models import INPUT_TYPES
from lib.ui import (
    build_scan_run_display_df,
    dataframe_or_info,
    format_timestamp_columns,
    inject_portal_css,
    render_portal_header,
)
from services.policy_service import PolicyService
from services.scan_service import ScanService
from services.server_service import ServerService


st.set_page_config(page_title="DetectBot Portal - Scan Results", page_icon="SC", layout="wide")

bootstrap_portal(seed_demo_data=load_settings().auto_seed_demo_data)
inject_portal_css()

scan_service = ScanService()
server_service = ServerService()
policy_service = PolicyService()


def server_label(servers_df, server_id):
    if not server_id:
        return "All Servers"
    matched = servers_df.loc[servers_df["id"] == server_id, "server_name"]
    return matched.iloc[0] if not matched.empty else server_id


def policy_label(policies_df, policy_id):
    if not policy_id:
        return "All Policies"
    matched = policies_df.loc[policies_df["id"] == policy_id, "policy_name"]
    return matched.iloc[0] if not matched.empty else policy_id


render_portal_header(
    "Scan Results",
    "ScanService를 통해 리포트 적재, 스캔 이력 조회, 상세 finding 조회를 처리합니다.",
)

for key, value in {
    "scan_results_server_filter": "",
    "scan_results_policy_filter": "",
    "scan_results_input_type_filter": "",
    "scan_results_latest_only": False,
    "scan_results_findings_only": False,
    "scan_results_recent_days": 30,
    "scan_results_selected_run_id": "",
}.items():
    st.session_state.setdefault(key, value)

focus_server_id = st.session_state.pop("scan_results_focus_server_id", "")
if focus_server_id:
    st.session_state["scan_results_server_filter"] = focus_server_id

servers_df = server_service.list_servers_df(active_only=False)
policies_df = policy_service.list_policies_df(active_only=False)
all_runs_df = format_timestamp_columns(
    scan_service.list_scan_runs_df(limit=500),
    ["scan_started_at", "generated_at", "uploaded_at"],
)

tab_upload, tab_history = st.tabs(["Upload Report", "History"])

with tab_upload:
    with st.form("scan_upload_form"):
        uploaded_file = st.file_uploader("JSON Report", type=["json"])
        original_path = st.text_input("Original Report Path")
        uploaded_by = st.text_input("Uploaded By", value="portal-admin")
        selected_server_id = st.selectbox(
            "Target Server",
            options=["AUTO"] + (servers_df["id"].tolist() if not servers_df.empty else []),
            format_func=lambda value: "AUTO" if value == "AUTO" else server_label(servers_df, value),
        )
        selected_policy_id = st.selectbox(
            "Policy",
            options=[""] + (policies_df["id"].tolist() if not policies_df.empty else []),
            format_func=lambda value: policy_label(policies_df, value),
        )
        input_type = st.selectbox("Input Type", options=[""] + INPUT_TYPES)
        auto_create_server = st.checkbox("Auto-create server when missing", value=True)
        submitted = st.form_submit_button("Ingest Report", width="stretch")
        if submitted:
            if uploaded_file is None:
                st.error("Choose a JSON report first.")
            else:
                result = scan_service.ingest_report(
                    uploaded_file.getvalue(),
                    uploaded_file.name,
                    server_id=None if selected_server_id == "AUTO" else selected_server_id,
                    policy_id=selected_policy_id or None,
                    input_type=input_type or None,
                    uploaded_by=uploaded_by,
                    original_path=original_path,
                    auto_create_server=auto_create_server,
                )
                st.session_state["scan_results_selected_run_id"] = result["scan_run_id"]
                st.success(f"Report ingested. scan_run_id={result['scan_run_id']}")
                st.rerun()

with tab_history:
    filter_cols = st.columns(5)
    with filter_cols[0]:
        st.selectbox(
            "Server",
            options=[""] + (servers_df["id"].tolist() if not servers_df.empty else []),
            format_func=lambda value: server_label(servers_df, value),
            key="scan_results_server_filter",
        )
    with filter_cols[1]:
        st.selectbox(
            "Policy",
            options=[""] + (policies_df["id"].tolist() if not policies_df.empty else []),
            format_func=lambda value: policy_label(policies_df, value),
            key="scan_results_policy_filter",
        )
    with filter_cols[2]:
        st.selectbox("Input Type", options=[""] + INPUT_TYPES, key="scan_results_input_type_filter")
    with filter_cols[3]:
        st.selectbox("Recent Days", options=[7, 30, 90, 180, 0], key="scan_results_recent_days")
    with filter_cols[4]:
        st.checkbox("Latest Only", key="scan_results_latest_only")
    st.checkbox("Findings Only", key="scan_results_findings_only")

    filtered = all_runs_df.copy()
    if st.session_state["scan_results_server_filter"]:
        filtered = filtered[filtered["server_id"] == st.session_state["scan_results_server_filter"]]
    if st.session_state["scan_results_policy_filter"]:
        filtered = filtered[filtered["policy_id"] == st.session_state["scan_results_policy_filter"]]
    if st.session_state["scan_results_input_type_filter"]:
        filtered = filtered[filtered["input_type"] == st.session_state["scan_results_input_type_filter"]]
    if st.session_state["scan_results_latest_only"]:
        filtered = filtered[filtered["latest_for_server"] == True]
    if st.session_state["scan_results_findings_only"]:
        filtered = filtered[filtered["findings_count"].fillna(0).astype(int) > 0]
    if st.session_state["scan_results_recent_days"] != 0 and not filtered.empty:
        cutoff = pd.Timestamp(datetime.now() - timedelta(days=int(st.session_state["scan_results_recent_days"])))
        filtered = filtered[pd.to_datetime(filtered["generated_at"], errors="coerce") >= cutoff]

    st.markdown("### Scan History")
    dataframe_or_info(build_scan_run_display_df(filtered), "No scan runs match the current filters.")

    if filtered is not None and not filtered.empty:
        run_ids = filtered["id"].tolist()
        if st.session_state["scan_results_selected_run_id"] not in run_ids:
            st.session_state["scan_results_selected_run_id"] = run_ids[0]
        selected_run_id = st.selectbox(
            "Select Run",
            options=run_ids,
            index=run_ids.index(st.session_state["scan_results_selected_run_id"]),
            format_func=lambda value: (
                f"{filtered.loc[filtered['id'] == value, 'server_name'].iloc[0]} / "
                f"{filtered.loc[filtered['id'] == value, 'generated_at'].iloc[0]}"
            ),
        )
        st.session_state["scan_results_selected_run_id"] = selected_run_id
        detail = scan_service.get_scan_run_detail(selected_run_id)
        if detail:
            st.markdown("### Run Detail")
            st.json(detail["run"], expanded=False)
            summary_col1, summary_col2 = st.columns(2)
            with summary_col1:
                dataframe_or_info(detail["severity_counts"], "No severity stats.")
                if detail["severity_counts"] is not None and not detail["severity_counts"].empty:
                    st.bar_chart(detail["severity_counts"].set_index("severity")["count"])
            with summary_col2:
                dataframe_or_info(detail["reason_counts"], "No reason stats.")
            st.markdown("### Findings")
            findings_df = format_timestamp_columns(detail["findings"], ["generated_at", "mod_time", "created_at"])
            dataframe_or_info(findings_df, "No findings for this run.")
            if findings_df is not None and not findings_df.empty:
                finding_id = st.selectbox(
                    "Finding Detail",
                    options=findings_df["id"].tolist(),
                    format_func=lambda value: findings_df.loc[findings_df["id"] == value, "path"].iloc[0],
                )
                st.json(scan_service.get_finding_detail(finding_id), expanded=False)
