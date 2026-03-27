import json

import pandas as pd
import streamlit as st

from lib.codebook import get_pattern_meaning, get_reason_meaning
from lib.db import init_db
from lib.report_viewer import (
    SEVERITY_ORDER,
    build_findings_df,
    build_roots_df,
    filter_findings_df,
    fmt_dt,
    host_summary_text,
    interpret_finding,
    normalize_host_info,
    normalize_list,
    normalize_roots,
    summarize_findings,
)
from lib.repository import list_scan_runs, list_servers, load_scan_run_report
from lib.seed import bootstrap_demo_data
from lib.ui import (
    dataframe_or_info,
    format_timestamp_columns,
    inject_portal_css,
    render_metric_summary,
    render_portal_header,
)


st.set_page_config(
    page_title="DetectBot Portal - 탐지결과조회",
    page_icon="🔎",
    layout="wide",
)
init_db()
bootstrap_demo_data()
inject_portal_css()


def _server_label(servers_df, server_id):
    if not server_id:
        return "전체 서버"
    matched = servers_df.loc[servers_df["id"] == server_id, "server_name"]
    return matched.iloc[0] if not matched.empty else server_id


def _apply_focus_from_other_pages():
    focus_server_id = st.session_state.pop("report_viewer_focus_server_id", "")
    focus_run_id = st.session_state.pop("report_viewer_focus_run_id", "")
    if focus_server_id:
        st.session_state["report_viewer_server_id"] = focus_server_id
    if focus_run_id:
        st.session_state["report_viewer_run_id"] = focus_run_id
    return bool(focus_server_id or focus_run_id)


def _choose_default_run_id(runs_df):
    current_run_id = st.session_state.get("report_viewer_run_id", "")
    if runs_df is None or runs_df.empty:
        st.session_state["report_viewer_run_id"] = ""
        return ""

    run_ids = runs_df["id"].tolist()
    if current_run_id in run_ids:
        return current_run_id

    latest_candidates = runs_df.loc[runs_df["latest_for_server"] == True, "id"].tolist()
    default_run_id = latest_candidates[0] if latest_candidates else run_ids[0]
    st.session_state["report_viewer_run_id"] = default_run_id
    return default_run_id


render_portal_header(
    "탐지결과조회",
    "서버와 스캔 이력을 기준으로 저장된 리포트를 선택하고, 탐지 결과를 운영 포털 안에서 상세 해석합니다.",
)

focus_applied = _apply_focus_from_other_pages()

servers_df = list_servers(active_only=False)
if servers_df is None:
    servers_df = format_timestamp_columns(servers_df, [])

server_options = [""]
if servers_df is not None and not servers_df.empty:
    server_options.extend(servers_df["id"].tolist())

selected_server_id = st.selectbox(
    "서버 선택",
    options=server_options,
    index=server_options.index(st.session_state.get("report_viewer_server_id", ""))
    if st.session_state.get("report_viewer_server_id", "") in server_options
    else 0,
    format_func=lambda value: _server_label(servers_df, value),
    key="report_viewer_server_id",
)

server_runs_df = format_timestamp_columns(
    list_scan_runs(server_id=selected_server_id, limit=100) if selected_server_id else None,
    ["scan_started_at", "generated_at"],
)

if focus_applied:
    st.info("다른 페이지에서 선택한 서버/실행 기준으로 탐지결과조회 화면이 열렸습니다. 여기서 서버나 실행을 자유롭게 바꿀 수 있습니다.")

if not selected_server_id:
    st.info("탐지결과를 보려면 먼저 서버를 선택해 주세요.")
    st.stop()

if server_runs_df is None or server_runs_df.empty:
    st.info("선택한 서버에 연결된 스캔 이력이 없습니다.")
    st.stop()

selected_run_id = _choose_default_run_id(server_runs_df)
selected_run_id = st.selectbox(
    "스캔 실행 선택",
    options=server_runs_df["id"].tolist(),
    index=server_runs_df["id"].tolist().index(selected_run_id),
    format_func=lambda value: (
        f"{server_runs_df.loc[server_runs_df['id'] == value, 'generated_at'].iloc[0] or server_runs_df.loc[server_runs_df['id'] == value, 'scan_started_at'].iloc[0]} / "
        f"findings {int(server_runs_df.loc[server_runs_df['id'] == value, 'findings_count'].iloc[0] or 0)} / "
        f"{server_runs_df.loc[server_runs_df['id'] == value, 'input_type'].iloc[0] or '-'}"
    ),
    key="report_viewer_run_id",
)

loaded = load_scan_run_report(selected_run_id)
run_meta = loaded.get("run")
report = loaded.get("report")
load_error = loaded.get("error")

if load_error:
    st.error(f"선택한 실행의 원본 리포트를 불러오지 못했습니다. {load_error}")
    st.stop()

findings = normalize_list(report.get("findings"))
roots = normalize_roots(report)
host = normalize_host_info(report)
config = report.get("config", {}) or {}
active_rules = normalize_list(report.get("active_rules"))
stats = report.get("stats", {}) or {}
findings_df = build_findings_df(findings)
roots_df = build_roots_df(roots)
severity_counter, reason_counter, pattern_counter = summarize_findings(findings_df)

render_metric_summary(
    [
        {"label": "선택 서버", "value": _server_label(servers_df, selected_server_id)},
        {"label": "실행 시각", "value": fmt_dt(report.get("scan_started_at") or report.get("generated_at"))},
        {"label": "Findings", "value": stats.get("findings_count", len(findings))},
        {"label": "Roots", "value": stats.get("roots_count", len(roots))},
        {"label": "Host", "value": host_summary_text(host)},
    ]
)

with st.expander("리포트 기본 정보", expanded=True):
    left, right = st.columns(2)
    with left:
        os_detail = " ".join([part for part in [host.get("os_name"), host.get("os_version")] if part])
        st.write(f"**report_version**: {report.get('report_version', '-')}")
        st.write(f"**hostname**: {host.get('hostname') or '알 수 없음'}")
        st.write(f"**primary_ip**: {host.get('primary_ip') or '알 수 없음'}")
        st.write(f"**os_type**: {host.get('os_type') or '알 수 없음'}")
        st.write(f"**os_detail**: {os_detail or '알 수 없음'}")
        st.write(f"**platform**: {host.get('platform') or '알 수 없음'}")
        st.write(f"**generated_at**: {fmt_dt(report.get('generated_at'))}")
        st.write(f"**scan_started_at**: {fmt_dt(report.get('scan_started_at'))}")
        st.write(f"**active_rules**: {', '.join(active_rules) if active_rules else '-'}")
    with right:
        st.write(f"**server_name**: {server_runs_df.loc[server_runs_df['id'] == selected_run_id, 'server_name'].iloc[0] or '-'}")
        st.write(f"**file_name**: {run_meta.get('file_name') or '-'}")
        st.write(f"**stored_path**: {run_meta.get('stored_path') or '-'}")
        st.write(f"**roots_count**: {stats.get('roots_count', len(roots))}")
        st.write(f"**scanned_files**: {stats.get('scanned_files', '-')}")
        st.write(f"**findings_count**: {stats.get('findings_count', len(findings))}")

tab_summary, tab_roots, tab_findings, tab_config, tab_raw = st.tabs(
    ["요약", "Roots", "Findings", "Config", "원본 JSON"]
)

with tab_summary:
    if findings_df is None or findings_df.empty:
        st.success("탐지 결과가 없습니다. 선택한 실행은 탐지 없는 정상 리포트입니다.")
    else:
        sev_rows = [
            {"severity": severity, "count": severity_counter.get(severity, 0)}
            for severity in SEVERITY_ORDER
            if severity_counter.get(severity, 0) > 0
        ]
        reason_rows = [
            {
                "reason_code": code,
                "meaning": get_reason_meaning(code),
                "count": count,
            }
            for code, count in reason_counter.most_common(20)
        ]
        pattern_rows = [
            {
                "pattern": code,
                "meaning": get_pattern_meaning(code),
                "count": count,
            }
            for code, count in pattern_counter.most_common(20)
        ]
        col1, col2 = st.columns(2)
        with col1:
            dataframe_or_info(pd.DataFrame(sev_rows), "위험도 집계가 없습니다.")
            if sev_rows:
                st.bar_chart(pd.DataFrame(sev_rows).set_index("severity")["count"])
        with col2:
            dataframe_or_info(pd.DataFrame(reason_rows), "탐지 사유 집계가 없습니다.")
        st.markdown("#### 패턴 Top")
        dataframe_or_info(pd.DataFrame(pattern_rows), "탐지 패턴 집계가 없습니다.")

with tab_roots:
    st.markdown("### 추출된 스캔 루트")
    dataframe_or_info(roots_df, "루트 정보가 없습니다.")

with tab_findings:
    st.markdown("### 탐지 결과")
    if findings_df is None or findings_df.empty:
        st.success("탐지 결과가 없습니다.")
    else:
        filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
        with filter_col1:
            selected_severity = st.multiselect(
                "위험도",
                options=SEVERITY_ORDER,
                default=[sev for sev in SEVERITY_ORDER if sev in findings_df["severity"].unique()],
            )
        all_reasons = sorted({reason for reasons in findings_df["reasons"] for reason in reasons})
        with filter_col2:
            selected_reasons = st.multiselect("탐지 사유", options=all_reasons, default=[])
        all_patterns = sorted({pattern for patterns in findings_df["matched_patterns"] for pattern in patterns})
        with filter_col3:
            selected_patterns = st.multiselect("탐지 패턴", options=all_patterns, default=[])
        with filter_col4:
            keyword = st.text_input("경로/루트 검색", value="").strip()

        min_size_mb = st.number_input("최소 크기(MB)", min_value=0.0, value=0.0, step=1.0)
        filtered_df = filter_findings_df(
            findings_df,
            severities=selected_severity,
            reasons=selected_reasons,
            patterns=selected_patterns,
            keyword=keyword,
            min_size_mb=min_size_mb,
        )

        display_cols = [
            "severity",
            "path",
            "size_human",
            "mod_time_fmt",
            "ext",
            "mime_sniff",
            "root_source",
            "reasons_text",
            "matched_patterns_text",
        ]
        st.write(f"조회 결과: **{len(filtered_df)}건**")
        st.dataframe(
            filtered_df[display_cols],
            width="stretch",
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )

        selected_idx = st.session_state.get("report_viewer_selected_finding_idx", 0)
        if len(filtered_df) > 0:
            selected_idx = min(selected_idx, len(filtered_df) - 1)
            selected_idx = st.selectbox(
                "상세 해석 대상 선택",
                options=filtered_df.index.tolist(),
                index=filtered_df.index.tolist().index(filtered_df.index[selected_idx]),
                format_func=lambda index: (
                    f"[{filtered_df.loc[index, 'severity']}] {filtered_df.loc[index, 'path']}"
                ),
                key="report_viewer_selected_finding_idx",
            )
            row = filtered_df.loc[selected_idx]

            st.markdown("#### 상세 해석")
            st.markdown(interpret_finding(row))

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("#### 메타 정보")
                st.write(f"**path**: {row['path']}")
                st.write(f"**real_path**: {row['real_path'] or '-'}")
                st.write(f"**root_matched**: {row['root_matched'] or '-'}")
                st.write(f"**root_source**: {row['root_source'] or '-'}")
                st.write(f"**size**: {row['size_human']}")
                st.write(f"**mod_time**: {row['mod_time_fmt']}")
                st.write(f"**perm**: {row['perm'] or '-'}")
                st.write(f"**ext**: {row['ext'] or '-'}")
                st.write(f"**mime_sniff**: {row['mime_sniff'] or '-'}")
                st.write(f"**sha256**: {row['sha256'] or '-'}")
            with c2:
                st.markdown("#### 탐지 정보")
                st.write(f"**severity**: {row['severity']}")
                st.write(f"**reasons**: {', '.join(row['reasons']) if row['reasons'] else '-'}")
                st.write(f"**matched_patterns**: {', '.join(row['matched_patterns']) if row['matched_patterns'] else '-'}")
                st.write(f"**content_flags**: {', '.join(row['content_flags']) if row['content_flags'] else '-'}")
                st.write(f"**url_exposure_heuristic**: {row['url_exposure_heuristic'] or '-'}")

            st.markdown("#### 마스킹된 증거")
            if row["evidence_masked"]:
                for evidence in row["evidence_masked"]:
                    st.code(evidence)
            else:
                st.info("evidence_masked 값이 없습니다.")

with tab_config:
    st.markdown("### 실행 설정")
    if config:
        st.json(config, expanded=False)
    else:
        st.info("config 정보가 없습니다.")

with tab_raw:
    st.markdown("### 원본 JSON")
    st.json(report, expanded=False)
    with st.expander("원본 JSON 텍스트", expanded=False):
        st.code(json.dumps(report, ensure_ascii=False, indent=2), language="json")
