import pandas as pd
import streamlit as st

from lib.db import init_db
from lib.models import CRITICALITIES, ENVIRONMENTS, OS_TYPES, WEB_SERVER_TYPES, ZONES
from lib.repository import get_server, list_scan_runs, list_servers, save_server
from lib.seed import bootstrap_demo_data
from lib.ui import (
    build_scan_run_display_df,
    build_server_inventory_display_df,
    format_timestamp_columns,
    inject_portal_css,
    render_metric_summary,
    render_portal_header,
    render_selected_server_banner,
    render_selected_server_focus_card,
    render_server_identity,
    render_server_overview,
    style_scan_run_table,
)


ALL_OPTION = "전체"
ACTIVE_LABEL = "운영중"
INACTIVE_LABEL = "비활성"
UPLOAD_ON_LABEL = "가능"
UPLOAD_OFF_LABEL = "제한"


st.set_page_config(
    page_title="DetectBot Portal - 서버 인벤토리",
    page_icon="🖥️",
    layout="wide",
)
init_db()
bootstrap_demo_data()
inject_portal_css()


def reset_inventory_filters():
    defaults = {
        "inventory_keyword": "",
        "inventory_environment": ALL_OPTION,
        "inventory_zone": ALL_OPTION,
        "inventory_criticality": ALL_OPTION,
        "inventory_active_status": ALL_OPTION,
        "inventory_upload_status": ALL_OPTION,
        "inventory_selected_server_id": None,
    }
    for key, value in defaults.items():
        st.session_state[key] = value


def ensure_selected_server_id(current_ids):
    selected_server_id = st.session_state.get("inventory_selected_server_id")
    if selected_server_id in current_ids:
        return selected_server_id

    selected_server_id = current_ids[0] if current_ids else None
    st.session_state["inventory_selected_server_id"] = selected_server_id
    return selected_server_id


def filter_servers(df):
    filtered = df.copy()

    active_status = st.session_state.get("inventory_active_status", ALL_OPTION)
    if active_status == ACTIVE_LABEL:
        filtered = filtered[filtered["is_active"] == True]
    elif active_status == INACTIVE_LABEL:
        filtered = filtered[filtered["is_active"] == False]

    upload_status = st.session_state.get("inventory_upload_status", ALL_OPTION)
    if upload_status == UPLOAD_ON_LABEL:
        filtered = filtered[filtered["upload_enabled"] == True]
    elif upload_status == UPLOAD_OFF_LABEL:
        filtered = filtered[filtered["upload_enabled"] == False]

    criticality = st.session_state.get("inventory_criticality", ALL_OPTION)
    if criticality != ALL_OPTION:
        filtered = filtered[filtered["criticality"] == criticality]

    return filtered.reset_index(drop=True)


def sort_servers_for_operations(df):
    if df is None or df.empty:
        return df

    criticality_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    environment_rank = {"prod": 0, "dr": 1, "uat": 2, "dev": 3, "test": 4, "unknown": 5}
    zone_rank = {"dmz": 0, "internal": 1, "cloud": 2, "partner": 3, "unknown": 4}

    ranked = df.copy()
    ranked["_active_rank"] = ranked["is_active"].apply(lambda value: 0 if bool(value) else 1)
    ranked["_criticality_rank"] = ranked["criticality"].apply(
        lambda value: criticality_rank.get((value or "low").lower(), 9)
    )
    ranked["_environment_rank"] = ranked["environment"].apply(
        lambda value: environment_rank.get((value or "unknown").lower(), 9)
    )
    ranked["_zone_rank"] = ranked["zone"].apply(
        lambda value: zone_rank.get((value or "unknown").lower(), 9)
    )
    ranked["_server_name"] = ranked["server_name"].fillna("").str.lower()
    ranked["_updated_at"] = pd.to_datetime(ranked["updated_at"], errors="coerce")

    ranked = ranked.sort_values(
        by=[
            "_active_rank",
            "_criticality_rank",
            "_environment_rank",
            "_zone_rank",
            "_updated_at",
            "_server_name",
        ],
        ascending=[True, True, True, True, False, True],
        na_position="last",
    ).reset_index(drop=True)
    return ranked.drop(
        columns=[
            "_active_rank",
            "_criticality_rank",
            "_environment_rank",
            "_zone_rank",
            "_server_name",
            "_updated_at",
        ]
    )


def render_server_form(editing_server=None, form_key="server_form"):
    with st.form(form_key):
        server_name = st.text_input(
            "서버명",
            value=(editing_server or {}).get("server_name", ""),
            placeholder="예: web-dmz-01",
        )
        hostname = st.text_input(
            "Hostname",
            value=(editing_server or {}).get("hostname", ""),
            placeholder="예: web-dmz-01.example.local",
        )
        ip_address = st.text_input(
            "IP 주소",
            value=(editing_server or {}).get("ip_address", ""),
            placeholder="예: 10.10.10.21",
        )
        service_name = st.text_input(
            "서비스명",
            value=(editing_server or {}).get("service_name", ""),
        )
        owner_name = st.text_input(
            "담당자 / 관리자",
            value=(editing_server or {}).get("owner_name", ""),
        )

        env_col, zone_col = st.columns(2)
        with env_col:
            selected_environment = st.selectbox(
                "운영구분",
                ENVIRONMENTS,
                index=ENVIRONMENTS.index((editing_server or {}).get("environment", "unknown")),
            )
        with zone_col:
            selected_zone = st.selectbox(
                "Zone",
                ZONES,
                index=ZONES.index((editing_server or {}).get("zone", "unknown")),
            )

        os_col, web_col = st.columns(2)
        with os_col:
            os_type = st.selectbox(
                "OS 유형",
                OS_TYPES,
                index=OS_TYPES.index((editing_server or {}).get("os_type", "unknown")),
            )
        with web_col:
            web_server_type = st.selectbox(
                "웹서버 유형",
                WEB_SERVER_TYPES,
                index=WEB_SERVER_TYPES.index(
                    (editing_server or {}).get("web_server_type", "unknown")
                ),
            )

        os_detail_col1, os_detail_col2 = st.columns(2)
        with os_detail_col1:
            os_name = st.text_input(
                "OS 상세명",
                value=(editing_server or {}).get("os_name", ""),
                placeholder="예: Rocky Linux",
            )
        with os_detail_col2:
            platform = st.text_input(
                "Platform",
                value=(editing_server or {}).get("platform", ""),
                placeholder="예: linux/amd64",
            )

        criticality = st.selectbox(
            "중요도",
            CRITICALITIES,
            index=CRITICALITIES.index((editing_server or {}).get("criticality", "medium")),
        )
        toggle_col1, toggle_col2 = st.columns(2)
        with toggle_col1:
            upload_enabled = st.checkbox(
                "업로드 가능",
                value=bool((editing_server or {}).get("upload_enabled", True)),
            )
        with toggle_col2:
            is_active = st.checkbox(
                "활성 자산",
                value=bool((editing_server or {}).get("is_active", True)),
            )

        notes = st.text_area(
            "메모",
            value=(editing_server or {}).get("notes", ""),
            height=120,
            placeholder="운영 메모, 점검 특이사항, 담당 조직 정보를 적어둘 수 있습니다.",
        )

        submit_label = "서버 등록" if editing_server is None else "수정 내용 저장"
        submitted = st.form_submit_button(submit_label, width="stretch")
        if not submitted:
            return

        if not server_name.strip():
            st.error("서버명은 필수입니다. 운영자가 쉽게 식별할 수 있는 이름을 입력해 주세요.")
            return

        server_id = save_server(
            {
                "id": (editing_server or {}).get("id"),
                "server_name": server_name,
                "hostname": hostname,
                "ip_address": ip_address,
                "environment": selected_environment,
                "zone": selected_zone,
                "os_type": os_type,
                "os_name": os_name,
                "platform": platform,
                "web_server_type": web_server_type,
                "service_name": service_name,
                "criticality": criticality,
                "owner_name": owner_name,
                "upload_enabled": upload_enabled,
                "is_active": is_active,
                "notes": notes,
            }
        )
        st.session_state["inventory_selected_server_id"] = server_id
        message = (
            f"신규 서버가 등록되었습니다. ID: {server_id}"
            if editing_server is None
            else f"서버 정보가 수정되었습니다. ID: {server_id}"
        )
        st.success(message)
        st.rerun()


def open_server_scan_results(server_id):
    st.session_state["scan_results_focus_server_id"] = server_id
    st.session_state["scan_results_focus_origin"] = "server_inventory"
    st.switch_page("pages/02_scan_results.py")


def open_detection_report_viewer(server_id, scan_run_id=""):
    st.session_state["report_viewer_focus_server_id"] = server_id
    if scan_run_id:
        st.session_state["report_viewer_focus_run_id"] = scan_run_id
    st.switch_page("pages/05_detection_report_viewer.py")


render_portal_header(
    "서버 인벤토리",
    "운영 우선순위가 높은 자산을 먼저 보고, 서버 인벤토리 목록에서 직접 선택한 서버를 상세 및 수정 흐름으로 이어서 관리합니다.",
)

for key, value in {
    "inventory_keyword": "",
    "inventory_environment": ALL_OPTION,
    "inventory_zone": ALL_OPTION,
    "inventory_criticality": ALL_OPTION,
    "inventory_active_status": ALL_OPTION,
    "inventory_upload_status": ALL_OPTION,
    "inventory_selected_server_id": None,
}.items():
    st.session_state.setdefault(key, value)

filter_box = st.container(border=True)
with filter_box:
    st.markdown("### 빠른 검색 / 필터")
    row1 = st.columns((1.8, 1, 1, 1, 1, 0.7))
    with row1[0]:
        st.text_input(
            "검색어",
            key="inventory_keyword",
            placeholder="서버명, hostname, IP, 서비스명으로 검색",
        )
    with row1[1]:
        st.selectbox("운영구분", [ALL_OPTION] + ENVIRONMENTS, key="inventory_environment")
    with row1[2]:
        st.selectbox("Zone", [ALL_OPTION] + ZONES, key="inventory_zone")
    with row1[3]:
        st.selectbox("중요도", [ALL_OPTION] + CRITICALITIES, key="inventory_criticality")
    with row1[4]:
        st.selectbox(
            "활성 여부",
            [ALL_OPTION, ACTIVE_LABEL, INACTIVE_LABEL],
            key="inventory_active_status",
        )
    with row1[5]:
        st.selectbox(
            "업로드",
            [ALL_OPTION, UPLOAD_ON_LABEL, UPLOAD_OFF_LABEL],
            key="inventory_upload_status",
        )

    action_col1, action_col2 = st.columns((0.22, 0.78))
    with action_col1:
        if st.button("필터 초기화", width="stretch"):
            reset_inventory_filters()
            st.rerun()
    with action_col2:
        st.caption("운영중, 중요도 높음, PROD, DMZ 순으로 우선 정렬됩니다.")

all_servers_df = format_timestamp_columns(
    list_servers(
        keyword=st.session_state["inventory_keyword"],
        environment=""
        if st.session_state["inventory_environment"] == ALL_OPTION
        else st.session_state["inventory_environment"],
        zone="" if st.session_state["inventory_zone"] == ALL_OPTION else st.session_state["inventory_zone"],
        active_only=False,
    ),
    ["updated_at", "created_at"],
)
servers_df = sort_servers_for_operations(filter_servers(all_servers_df))

render_metric_summary(
    [
        {"label": "검색 결과", "value": len(servers_df)},
        {
            "label": "운영중 서버",
            "value": int(servers_df["is_active"].fillna(False).sum()) if not servers_df.empty else 0,
        },
        {
            "label": "업로드 가능",
            "value": int(servers_df["upload_enabled"].fillna(False).sum()) if not servers_df.empty else 0,
        },
        {
            "label": "고위험 자산",
            "value": int(servers_df["criticality"].isin(["critical", "high"]).sum()) if not servers_df.empty else 0,
        },
    ]
)

selected_server = None
recent_runs_df = pd.DataFrame()

if servers_df.empty:
    st.info("조건에 맞는 서버가 없습니다. 필터를 줄이거나 신규 등록 탭에서 서버를 추가해 주세요.")
else:
    current_ids = servers_df["id"].tolist()
    selected_server_id = ensure_selected_server_id(current_ids)
    if selected_server_id:
        selected_server = get_server(selected_server_id)
        recent_runs_df = format_timestamp_columns(
            list_scan_runs(server_id=selected_server_id, limit=5),
            ["scan_started_at", "generated_at"],
        )

render_selected_server_banner(selected_server, context_label="현재 선택 서버")

tabs = st.tabs(["목록", "상세", "신규 등록", "수정"])
tab_list, tab_detail, tab_create, tab_edit = tabs

with tab_list:
    st.markdown("### 서버 목록")
    st.caption("서버 인벤토리 목록에서 직접 선택하면 상세/수정 탭의 현재 서버가 함께 갱신됩니다.")
    display_df = build_server_inventory_display_df(servers_df)
    if display_df is None or display_df.empty:
        st.info("표시할 서버가 없습니다.")
    else:
        selection = st.dataframe(
            display_df,
            width="stretch",
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )
        selected_rows = []
        try:
            selected_rows = selection.selection.rows
        except Exception:
            try:
                selected_rows = selection.get("selection", {}).get("rows", [])
            except Exception:
                selected_rows = []

        if selected_rows:
            next_selected_server_id = servers_df.iloc[selected_rows[0]]["id"]
            if next_selected_server_id != st.session_state.get("inventory_selected_server_id"):
                st.session_state["inventory_selected_server_id"] = next_selected_server_id
                st.rerun()

with tab_detail:
    st.markdown("### 서버 상세")
    if not selected_server:
        st.info("상세 조회할 서버가 없습니다. 목록 탭에서 서버를 선택해 주세요.")
    else:
        render_selected_server_focus_card(selected_server, mode="detail")
        render_server_identity(selected_server)
        render_server_overview(selected_server)

        st.markdown("#### 이 서버의 최근 스캔 이력")
        if recent_runs_df is None or recent_runs_df.empty:
            st.info("이 서버에 연결된 스캔 이력이 아직 없습니다.")
        else:
            latest_run = recent_runs_df.iloc[0]
            summary_cols = st.columns(4)
            summary_cols[0].metric(
                "최근 스캔 시각",
                latest_run.get("generated_at") or latest_run.get("scan_started_at") or "-",
            )
            summary_cols[1].metric(
                "최근 findings",
                int(latest_run.get("findings_count") or 0),
            )
            summary_cols[2].metric(
                "최근 실행 상태",
                "최신" if bool(latest_run.get("latest_for_server")) else "이력",
            )
            summary_cols[3].metric(
                "최근 입력 유형",
                latest_run.get("input_type") or "-",
            )

            action_col1, action_col2 = st.columns((0.35, 0.65))
            with action_col1:
                if st.button("이 서버의 스캔 이력 보기", key="open_server_scan_results", width="stretch"):
                    open_server_scan_results(selected_server["id"])
            with action_col2:
                st.caption("스캔 결과 관리 페이지로 이동하면서 이 서버 기준 필터를 자동 적용합니다.")

            viewer_col1, viewer_col2 = st.columns((0.35, 0.65))
            with viewer_col1:
                if st.button("이 서버의 탐지결과조회", key="open_detection_report_viewer", width="stretch"):
                    open_detection_report_viewer(selected_server["id"], latest_run.get("id") or "")
            with viewer_col2:
                st.caption("탐지결과조회 페이지에서 최신 실행 리포트를 바로 해석합니다.")

            st.dataframe(
                style_scan_run_table(build_scan_run_display_df(recent_runs_df)),
                width="stretch",
                hide_index=True,
            )

        with st.expander("원본 상세 정보 보기", expanded=False):
            st.json(selected_server, expanded=False)

with tab_create:
    st.markdown("### 신규 서버 등록")
    st.caption("신규 자산을 등록합니다. 등록 후에는 자동으로 현재 작업 대상 서버로 선택됩니다.")
    render_server_form(editing_server=None, form_key="create_server_form")

with tab_edit:
    st.markdown("### 기존 서버 수정")
    if not selected_server:
        st.info("수정할 서버가 없습니다. 목록 탭에서 서버를 먼저 선택해 주세요.")
    else:
        render_selected_server_focus_card(selected_server, mode="edit")
        render_server_identity(selected_server)
        render_server_form(editing_server=selected_server, form_key="edit_server_form")
